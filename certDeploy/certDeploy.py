import os
import time
import json
import traceback
import boto3
import logging
import re
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    try:
        # Define AWS service clients
        PCA = boto3.client('acm-pca')
        SSM = boto3.client('ssm')
        DYNAMODB = boto3.resource('dynamodb')

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
            raise ValueError("Invalid ARN format")
        

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
        logger.info(f"Extracted details - Common Name: {common_name}, Serial: {serial}, Expiry: {expiry}")

        # Get certPath and keyPath from DynamoDB
        table = DYNAMODB.Table('certificates')
        response = table.get_item(
            Key={
                'hostID': common_name
            }
        )
        item = response['Item']
        
        # Use default paths if the ones from DynamoDB are empty
        cacert_path = item.get('cacertPath') or DEFAULT_CACERT_PATH
        key_path = item.get('keyPath') or DEFAULT_KEY_PATH
        cert_path = item.get('certPath') or DEFAULT_CERT_PATH
        AWSSigningHelperPath = item.get('signinghelperPath') or DEFAULT_AWS_SIGNING_HELPER_PATH
        
        # Add logging to check the values being used
        logger.info(f"Using cacert_path: {cacert_path}")
        logger.info(f"Using key_path: {key_path}")
        logger.info(f"Using cert_path: {cert_path}")
        logger.info(f"Using AWSSigningHelperPath: {AWSSigningHelperPath}")



        # Send the certificate to instances via the Simple Systems Manager (SSM)
        response = SSM.send_command(
            Targets=[{'Key': 'InstanceIDs', 'Values': [common_name]}],
            DocumentName='AWS-RunShellScript',
            DocumentVersion='1',
            DocumentHash='99749de5e62f71e5ebe9a55c2321e2c394796afe7208cff048696541e6f6771e',
            DocumentHashType='Sha256',
            TimeoutSeconds=123,
            Comment=f'Pushing cert for {common_name}',
            Parameters={
                'commands': [
                    f'echo "{certificate}" > {cert_path}/{common_name}-new.crt',
                    f'echo "{ca_certificate}" > {cacert_path}/ca_chain_certificate.crt',
                    f'if [ ! -f {AWSSigningHelperPath}/aws_signing_helper ]; then echo "{AWSSigningHelperPath}/aws_signing_helper not found" >&2; exit 1; fi',
                    f'{AWSSigningHelperPath}/aws_signing_helper credential-process --certificate {cert_path}/{common_name}-new.crt --intermediates {cacert_path}/ca_chain_certificate.crt --private-key {key_path}/{common_name}-new.key --profile-arn {IAM_RA_PROFILE_ARN} --role-arn {IAM_RA_ROLE_ARN} --trust-anchor-arn {IAM_RA_TRUST_ANCHOR_ARN} | grep -q "Expiration"',
                    f'if [ $? -eq 0 ]; then mv {cert_path}/{common_name}-new.crt {cert_path}/{common_name}.crt && mv {key_path}/{common_name}-new.key {key_path}/{common_name}.key; else exit 1; fi',
                ]
            }
        )


        # Get the command ID
        command_id = response['Command']['CommandId']

        # Log the command ID
        logger.info(f"SSM Command ID: {command_id}")

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
        logger.info(f"SSM Command Status: {command_status}")
        logger.info(f"SSM Command Output: {command_output}")

        # If the command didn't succeed, raise an error
        if command_status != 'Success':
            logger.error(f"SSM command failed with status: {command_status}")
            raise RuntimeError("SSM command failed with status: " + command_status)


        # Update the certificate details in DynamoDB
        table = DYNAMODB.Table('certificates')
        response = table.update_item(
            Key={'hostID': common_name},
            UpdateExpression="set serial = :s, expiry = :e",
            ExpressionAttributeValues={
                ':s': str(serial),
                ':e': expiry.strftime('%Y-%m-%d %H:%M:%S')
            },
            ConditionExpression="attribute_exists(hostID)"
        )

        # Log update details
        logger.info(f"DynamoDB update details - Host ID: {common_name}, Serial: {str(serial)}, Expiry: {expiry.strftime('%Y-%m-%d %H:%M:%S')}")

        # Return a successful response
        return {'statusCode': 200}

    except Exception as e:
        # Print and raise any exceptions that occurred during execution
        error_message = f"An error occurred: {str(e)}, traceback: {traceback.format_exc()}"
        send_sns_alert(f"Certificate rotation failed for {common_name}: {e}")
        logger.error(error_message)
        raise RuntimeError(error_message)
    
def send_sns_alert(message):
    sns = boto3.client('sns')
    sns_topic_arn = os.environ['SNS_TOPIC_ARN']  # Retrieve the ARN from environment variables
    sns.publish(
        TopicArn=sns_topic_arn,  # Use the ARN from environment variables
        Message=json.dumps({'default': json.dumps(message)}),
        MessageStructure='json'
    )