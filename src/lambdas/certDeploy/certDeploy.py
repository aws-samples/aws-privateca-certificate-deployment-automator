"""
Certificate Deployment Lambda

Retrieves signed certificates from AWS Private CA and deploys them to instances
via SSM. Validates with IAM Roles Anywhere and updates DynamoDB.
Triggered by EventBridge on PCA certificate issuance events.
"""

import os
import time
import json
import boto3
import logging
import re
import shlex
from datetime import timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from models import sanitize_host_id, sanitize_path
from error_handler import handle_lambda_error, SSMError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

PCA = boto3.client('acm-pca')
SSM = boto3.client('ssm')
DYNAMODB = boto3.resource('dynamodb')
SNS = boto3.client('sns')


def main(event, context):
    DEFAULT_CACERT_PATH = os.getenv('DEFAULT_CACERT_PATH')
    DEFAULT_CERT_PATH = os.getenv('DEFAULT_CERT_PATH')
    DEFAULT_KEY_PATH = os.getenv('DEFAULT_KEY_PATH')
    IAM_RA_PROFILE_ARN = os.getenv('IAMRAProfileARN')
    IAM_RA_ROLE_ARN = os.getenv('IAMRARoleARN')
    IAM_RA_TRUST_ANCHOR_ARN = os.getenv('IAMRATrustAnchorARN')
    DEFAULT_AWS_SIGNING_HELPER_PATH = os.getenv('DEFAULT_AWSSigningHelperPath')
    SNS_TOPIC_ARN = os.getenv('SNS_TOPIC_ARN')

    logger.info(f"Incoming Event: {json.dumps(event)}")

    ca_arn = event["resources"][0]
    cert_arn = event["resources"][1]

    pattern = r"^arn:aws:[a-z0-9\-]*:[a-z0-9\-]*:[0-9]{12}:[a-zA-Z0-9\-\/_]*$"
    if not re.match(pattern, ca_arn) or not re.match(pattern, cert_arn):
        raise ValueError("Invalid ARN format")

    try:
        response = PCA.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)
        ca_certificate = response["CertificateChain"]
        certificate = response["Certificate"]

        cert_bytes = certificate.encode('utf-8')
        cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
        common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        serial = hex(cert.serial_number)[2:].upper()
        expiry = cert.not_valid_after

        logger.info(f"Certificate - CN: {common_name}, Serial: {serial}, Expiry: {expiry.strftime('%Y-%m-%d %H:%M:%S')}")

        # Get host config from DynamoDB
        table_name = os.getenv('DYNAMODB_TABLE_NAME', 'certificates')
        table = DYNAMODB.Table(table_name)
        item = table.get_item(Key={'hostID': common_name})['Item']

        cacert_path = item.get('cacertPath') or DEFAULT_CACERT_PATH
        key_path = item.get('keyPath') or DEFAULT_KEY_PATH
        cert_path = item.get('certPath') or DEFAULT_CERT_PATH
        AWSSigningHelperPath = item.get('signinghelperPath') or DEFAULT_AWS_SIGNING_HELPER_PATH
        platform = item.get('platform', 'linux')

        logger.info(f"Paths - cert: {cert_path}, key: {key_path}, cacert: {cacert_path}, platform: {platform}")

        if platform == 'windows':
            signing_helper = f"{AWSSigningHelperPath}\\aws_signing_helper.exe"
            commands = [
                f'$ErrorActionPreference = "Stop"',
                f'Set-Content -Path "{cert_path}\\{common_name}-new.crt" -Value @"\n{certificate}\n"@',
                f'Set-Content -Path "{cacert_path}\\ca_chain_certificate.crt" -Value @"\n{ca_certificate}\n"@',
                f'if (Test-Path "{signing_helper}") {{',
                f'  $result = & "{signing_helper}" credential-process --certificate "{cert_path}\\{common_name}-new.crt" --intermediates "{cacert_path}\\ca_chain_certificate.crt" --private-key "{key_path}\\{common_name}-new.key" --profile-arn "{IAM_RA_PROFILE_ARN}" --role-arn "{IAM_RA_ROLE_ARN}" --trust-anchor-arn "{IAM_RA_TRUST_ANCHOR_ARN}" 2>&1',
                f'  if ($result -match "SessionToken") {{ Write-Output "[SUCCESS] IAMRA validation successful" }}',
                f'  else {{ Write-Output "[WARNING] IAMRA validation failed - continuing" }}',
                f'}} else {{ Write-Output "[INFO] Signing helper not found - skipping IAMRA validation" }}',
                f'Move-Item -Path "{cert_path}\\{common_name}-new.crt" -Destination "{cert_path}\\{common_name}.crt" -Force',
                f'Move-Item -Path "{key_path}\\{common_name}-new.key" -Destination "{key_path}\\{common_name}.key" -Force',
                f'Write-Output "[SUCCESS] Certificate deployment completed"',
            ]
            document_name = 'AWS-RunPowerShellScript'
        else:
            cert_new_file = shlex.quote(f"{cert_path}/{common_name}-new.crt")
            cert_file = shlex.quote(f"{cert_path}/{common_name}.crt")
            ca_cert_file = shlex.quote(f"{cacert_path}/ca_chain_certificate.crt")
            key_new_file = shlex.quote(f"{key_path}/{common_name}-new.key")
            key_file = shlex.quote(f"{key_path}/{common_name}.key")
            signing_helper = shlex.quote(f"{AWSSigningHelperPath}/aws_signing_helper")

            commands = [
                f'cat > {cert_new_file} << \'EOF\'\n{certificate}\nEOF',
                f'cat > {ca_cert_file} << \'EOF\'\n{ca_certificate}\nEOF',
                f'if [ -f {signing_helper} ]; then',
                f'  {signing_helper} credential-process --certificate {cert_new_file} --intermediates {ca_cert_file} --private-key {key_new_file} --profile-arn {shlex.quote(IAM_RA_PROFILE_ARN)} --role-arn {shlex.quote(IAM_RA_ROLE_ARN)} --trust-anchor-arn {shlex.quote(IAM_RA_TRUST_ANCHOR_ARN)} | grep -q "SessionToken"',
                f'  if [ $? -eq 0 ]; then echo "[SUCCESS] IAMRA validation successful"',
                f'  else echo "[WARNING] IAMRA validation failed - continuing"; fi',
                f'else echo "[INFO] Signing helper not found - skipping IAMRA validation"; fi',
                f'mv {cert_new_file} {cert_file}',
                f'mv {key_new_file} {key_file}',
                f'echo "[SUCCESS] Certificate deployment completed"',
            ]
            document_name = 'AWS-RunShellScript'

        response = SSM.send_command(
            Targets=[{'Key': 'InstanceIDs', 'Values': [common_name]}],
            DocumentName=document_name,
            TimeoutSeconds=123,
            Comment=f'Pushing cert for {common_name}',
            Parameters={'commands': commands}
        )

        command_id = response['Command']['CommandId']
        command_status = 'Pending'
        while command_status in ['Pending', 'InProgress']:
            time.sleep(.5)
            response = SSM.get_command_invocation(CommandId=command_id, InstanceId=common_name)
            command_status = response.get('Status')

        if command_status != 'Success':
            error = response.get('StandardErrorContent', '')
            raise RuntimeError(f"Deployment failed ({command_status}): {error}")

        logger.info(f"SSM Command {command_id} succeeded for {common_name}")

        # Update DynamoDB
        renewal_threshold_days = int(os.getenv('RENEWAL_THRESHOLD_DAYS', '2'))
        renewal_date = expiry - timedelta(days=renewal_threshold_days)

        table.update_item(
            Key={'hostID': common_name},
            UpdateExpression="set serial = :s, expiry = :e, #status = :st, renewalDate = :rd",
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={
                ':s': str(serial),
                ':e': expiry.strftime('%Y-%m-%d %H:%M:%S'),
                ':st': 'DEPLOYED',
                ':rd': renewal_date.strftime('%Y-%m-%d')
            },
            ConditionExpression="attribute_exists(hostID)"
        )

        logger.info(f"DynamoDB updated - Host: {common_name}, Serial: {serial}, Expiry: {expiry}")

    except Exception as e:
        logger.error(f"Certificate deployment failed: {str(e)}")
        if SNS_TOPIC_ARN:
            try:
                SNS.publish(TopicArn=SNS_TOPIC_ARN,
                           Message=f"Certificate deployment failed for host: {str(e)}")
            except Exception:
                logger.error("Failed to send SNS alert")
        raise


@handle_lambda_error
def lambda_handler(event, context):
    main(event, context)
    return {'statusCode': 200}
