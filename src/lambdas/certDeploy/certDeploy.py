"""
Certificate Deployment Lambda

This Lambda function retrieves signed certificates from AWS Private Certificate Authority (PCA)
and deploys them to EC2 instances via AWS Systems Manager (SSM). It also validates the
certificates using IAM Roles Anywhere and updates the certificate status in DynamoDB.

The function is triggered by EventBridge when PCA completes certificate issuance and handles
the final deployment step of the certificate automation workflow.
"""

import os
import time
import json
import traceback
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

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients outside handler for connection reuse across invocations
PCA = boto3.client('acm-pca')
SSM = boto3.client('ssm')
DYNAMODB = boto3.resource('dynamodb')
STEPFUNCTIONS = boto3.client('stepfunctions')

def main(event, context):

    # Get environment variables
    DEFAULT_CACERT_PATH = os.getenv('DEFAULT_CACERT_PATH')
    DEFAULT_CERT_PATH = os.getenv('DEFAULT_CERT_PATH')
    DEFAULT_KEY_PATH = os.getenv('DEFAULT_KEY_PATH')
    IAM_RA_PROFILE_ARN = os.getenv('IAMRAProfileARN')
    IAM_RA_ROLE_ARN = os.getenv('IAMRARoleARN')
    IAM_RA_TRUST_ANCHOR_ARN = os.getenv('IAMRATrustAnchorARN')
    DEFAULT_AWS_SIGNING_HELPER_PATH = os.getenv('DEFAULT_AWSSigningHelperPath') 

    # Log the incoming event
    logger.info(f"Incoming Event : {json.dumps(event)}")

    # Extract Certificate Authority ARN and Certificate ARN from the event
    ca_arn = event["resources"][0]
    cert_arn = event["resources"][1]

    # Validate the ARNs
    pattern = r"^arn:aws:[a-z0-9\-]*:[a-z0-9\-]*:[0-9]{12}:[a-zA-Z0-9\-\/_]*$"
    if not re.match(pattern, ca_arn) or not re.match(pattern, cert_arn):
        logger.error("Invalid ARN format for ca_arn or cert_arn")
        raise ValueError("Invalid ARN format")

    task_token = None
    try:
        # Request the certificate from the Certificate Manager
        response = PCA.get_certificate(
            CertificateAuthorityArn=ca_arn,
            CertificateArn=cert_arn
        )

        # Extract certificate and its chain from the response
        ca_certificate = response["CertificateChain"]
        certificate = response["Certificate"]

        # Convert certificate to bytes, then load to x509 format
        cert_bytes = certificate.encode('utf-8')
        cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())

        # Get the subject, common name, serial number, and expiration date from the certificate
        subject = cert.subject
        common_name = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        serial = hex(cert.serial_number)[2:].upper()
        expiry = cert.not_valid_after

        # Log extracted details
        logger.info(f"Extracted details - Common Name: {common_name}, Serial: {serial}, Expiry: {expiry.strftime('%Y-%m-%d %H:%M:%S')}")

        # Get certPath, keyPath, and task token from DynamoDB
        table_name = os.getenv('DYNAMODB_TABLE_NAME', 'certificates')
        table = DYNAMODB.Table(table_name)
        response = table.get_item(
            Key={
                'hostID': common_name
            }
        )
        item = response['Item']
        
        # Get task token for Step Functions callback
        task_token = item.get('taskToken')
        logger.info(f"Retrieved task token for host {common_name}: {'Present' if task_token else 'Not found'}")
        
        # Use default paths if the ones from DynamoDB are empty
        cacert_path = item.get('cacertPath') or DEFAULT_CACERT_PATH
        key_path = item.get('keyPath') or DEFAULT_KEY_PATH
        cert_path = item.get('certPath') or DEFAULT_CERT_PATH
        AWSSigningHelperPath = item.get('signinghelperPath') or DEFAULT_AWS_SIGNING_HELPER_PATH
        
        # Add logging to check the values being used
        logger.info(f"Using paths - cacert_path: {cacert_path}, key_path: {key_path}, cert_path: {cert_path}, AWSSigningHelperPath: {AWSSigningHelperPath}")

        # Send the certificate to instances via the Simple Systems Manager (SSM) with proper escaping
        cert_new_file = shlex.quote(f"{cert_path}/{common_name}-new.crt")
        cert_file = shlex.quote(f"{cert_path}/{common_name}.crt")
        ca_cert_file = shlex.quote(f"{cacert_path}/ca_chain_certificate.crt")
        key_new_file = shlex.quote(f"{key_path}/{common_name}-new.key")
        key_file = shlex.quote(f"{key_path}/{common_name}.key")
        signing_helper = shlex.quote(f"{AWSSigningHelperPath}/aws_signing_helper")
        
        response = SSM.send_command(
            Targets=[{'Key': 'InstanceIDs', 'Values': [common_name]}],
            DocumentName='AWS-RunShellScript',
            TimeoutSeconds=123,
            Comment=f'Pushing cert for {common_name}',
            Parameters={
                'commands': [
                    f'cat > {cert_new_file} << \'EOF\'\n{certificate}\nEOF',
                    f'cat > {ca_cert_file} << \'EOF\'\n{ca_certificate}\nEOF',
                    f'echo "Certificate and CA chain files created successfully"',
                    
                    # Conditional IAMRA testing - don't fail deployment if IAMRA fails
                    f'if [ -f {signing_helper} ]; then',
                    f'  echo "AWS Signing Helper found - testing IAMRA credential exchange"',
                    f'  {signing_helper} credential-process --certificate {cert_new_file} --intermediates {ca_cert_file} --private-key {key_new_file} --profile-arn {shlex.quote(IAM_RA_PROFILE_ARN)} --role-arn {shlex.quote(IAM_RA_ROLE_ARN)} --trust-anchor-arn {shlex.quote(IAM_RA_TRUST_ANCHOR_ARN)} | grep -q "SessionToken"',
                    f'  IAMRA_TEST=$?',
                    f'  if [ $IAMRA_TEST -eq 0 ]; then',
                    f'    echo "[SUCCESS] IAMRA validation successful - certificate works with IAM Roles Anywhere"',
                    f'  else',
                    f'    echo "[WARNING] IAMRA validation failed - certificate may not work with IAM Roles Anywhere, but continuing with deployment"',
                    f'  fi',
                    f'else',
                    f'  echo "[INFO] AWS Signing Helper not found at {AWSSigningHelperPath}/aws_signing_helper - skipping IAMRA validation"',
                    f'  echo "       Certificate will be deployed for general use (non-IAMRA scenarios)"',
                    f'fi',
                    
                    # Always deploy the certificate regardless of IAMRA test results
                    f'echo "Deploying certificate files"',
                    f'mv {cert_new_file} {cert_file}',
                    f'if [ $? -eq 0 ]; then',
                    f'  echo "[SUCCESS] Certificate moved to final location: {cert_path}/{common_name}.crt"',
                    f'else',
                    f'  echo "[ERROR] Failed to move certificate to final location"',
                    f'  exit 1',
                    f'fi',
                    
                    f'mv {key_new_file} {key_file}',
                    f'if [ $? -eq 0 ]; then',
                    f'  echo "[SUCCESS] Private key moved to final location: {key_path}/{common_name}.key"',
                    f'else',
                    f'  echo "[ERROR] Failed to move private key to final location"',
                    f'  exit 1',
                    f'fi',
                    
                    f'echo "[SUCCESS] Certificate deployment completed successfully"',
                    f'echo "         Certificate: {cert_path}/{common_name}.crt"',
                    f'echo "         Private Key: {key_path}/{common_name}.key"',
                    f'echo "         CA Chain: {cacert_path}/ca_chain_certificate.crt"'
                ]
            }
        )

        # Get the command ID
        command_id = response['Command']['CommandId']

        # Initialize command status as Pending
        command_status = 'Pending'

        # Check SSM command status until it's no longer pending or in progress
        while command_status in ['Pending', 'InProgress']:
            time.sleep(.5)
            response = SSM.get_command_invocation(
                CommandId=command_id,
                InstanceId=common_name,
            )
            command_status = response.get('Status', 'Status not found in response')
            
        # Log the command status and the output
        command_output = response.get('StandardOutputContent', 'Output not found in response')
        command_error = response.get('StandardErrorContent', '')
        logger.info(f"SSM Command - ID: {command_id}, Status: {command_status}")
        logger.info(f"Command Output: {command_output}")
        if command_error:
            logger.info(f"Command Error Output: {command_error}")

        # If the command didn't succeed, raise an error with more context
        if command_status != 'Success':
            error_msg = f"Certificate deployment failed with status: {command_status}"
            if command_error:
                error_msg += f". Error: {command_error}"
            if command_output:
                error_msg += f". Output: {command_output}"
            logger.error(error_msg)
            raise RuntimeError(error_msg)

        # Calculate renewal date (expiry date minus renewal threshold)
        # Default to 2 days before expiry for short-lived certificates
        renewal_threshold_days = int(os.getenv('RENEWAL_THRESHOLD_DAYS', '2'))
        renewal_date = expiry - timedelta(days=renewal_threshold_days)
        
        # Update the certificate details in DynamoDB while preserving custom path attributes
        table = DYNAMODB.Table(table_name)
        
        # Build update expression to preserve custom path attributes if they exist in the current item
        update_expression = "set serial = :s, expiry = :e, #status = :st, renewalDate = :rd"
        expression_values = {
            ':s': str(serial),
            ':e': expiry.strftime('%Y-%m-%d %H:%M:%S'),
            ':st': 'DEPLOYED',
            ':rd': renewal_date.strftime('%Y-%m-%d')
        }
        expression_names = {'#status': 'status'}
        
        # Preserve custom path attributes if they exist and are not default values
        if item.get('cacertPath') and item.get('cacertPath') != DEFAULT_CACERT_PATH:
            update_expression += ", cacertPath = :cp"
            expression_values[':cp'] = item['cacertPath']
            
        if item.get('keyPath') and item.get('keyPath') != DEFAULT_KEY_PATH:
            update_expression += ", keyPath = :kp"
            expression_values[':kp'] = item['keyPath']
            
        if item.get('certPath') and item.get('certPath') != DEFAULT_CERT_PATH:
            update_expression += ", certPath = :ctp"
            expression_values[':ctp'] = item['certPath']
            
        if item.get('signinghelperPath') and item.get('signinghelperPath') != DEFAULT_AWS_SIGNING_HELPER_PATH:
            update_expression += ", signinghelperPath = :shp"
            expression_values[':shp'] = item['signinghelperPath']
        
        # Remove taskToken
        update_expression += " REMOVE taskToken"
        
        response = table.update_item(
            Key={'hostID': common_name},
            UpdateExpression=update_expression,
            ExpressionAttributeNames=expression_names,
            ExpressionAttributeValues=expression_values,
            ConditionExpression="attribute_exists(hostID)"
        )

        # Log update details
        logger.info(f"DynamoDB update details - Host ID: {common_name}, Serial: {str(serial)}, Expiry: {expiry.strftime('%Y-%m-%d %H:%M:%S')}")

        # Send success callback to Step Functions if task token exists
        if task_token:
            STEPFUNCTIONS.send_task_success(
                taskToken=task_token,
                output=json.dumps({
                    'hostID': common_name,
                    'status': 'DEPLOYED',
                    'serial': str(serial),
                    'expiry': expiry.strftime('%Y-%m-%d %H:%M:%S'),
                    'certificateArn': cert_arn
                })
            )
            logger.info(f"Sent success callback to Step Functions for host: {common_name}")
        else:
            logger.info(f"No task token found for host {common_name} - skipping Step Functions callback")

    except Exception as e:
        logger.error(f"Certificate deployment failed: {str(e)}")
        
        # Send failure callback to Step Functions if task token exists
        if task_token:
            try:
                STEPFUNCTIONS.send_task_failure(
                    taskToken=task_token,
                    error='CertificateDeploymentFailed',
                    cause=str(e)
                )
                logger.info(f"Sent failure callback to Step Functions")
            except Exception as callback_error:
                logger.error(f"Failed to send failure callback: {str(callback_error)}")
        
        # Re-raise the original exception
        raise


@handle_lambda_error
def lambda_handler(event, context):
    main(event, context)
    return {'statusCode': 200}