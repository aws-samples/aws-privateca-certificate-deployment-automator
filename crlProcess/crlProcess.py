import boto3
import json
import os
import logging
from cryptography import x509
from cryptography.hazmat.primitives import serialization

# Setup logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize the S3 client
s3 = boto3.client('s3')

# Initialize the IAM Roles Anywhere client
iamra_client = boto3.client('rolesanywhere')

def convert_der_to_pem(der_data):
    crl = x509.load_der_x509_crl(der_data)
    pem_data = crl.public_bytes(encoding=serialization.Encoding.PEM)
    return pem_data

def import_crl(bucket, key, trust_anchor_arn):
    # Fetch CRL from S3
    s3_object = s3.get_object(Bucket=bucket, Key=key)
    crl_data_der = s3_object['Body'].read()

    # Convert DER to PEM
    crl_data_pem = convert_der_to_pem(crl_data_der)
    
    # Prepare parameters
    params = {
        'crlData': crl_data_pem,
        'enabled': True,
        'name': 'CRL',
        'trustAnchorArn': trust_anchor_arn
    }
    
    # Call IAM Roles Anywhere API to import CRL
    response = iamra_client.import_crl(**params)
    logger.info(f"Successfully imported CRL: {response}")

def main(event, context):
    bucket = event['detail']['bucket']['name']
    key = event['detail']['object']['key']
    
    if not key.endswith('.crl'):
        logger.info("Object is not a CRL. Skipping.")
        return
    
    trust_anchor_arn = os.environ['IAMRATrustAnchorARN']
    import_crl(bucket, key, trust_anchor_arn)

def lambda_handler(event, context):
    try:
        main(event, context)
    except Exception as e:
        logger.error("Failed to import CRL: ", exc_info=True)
        send_sns_alert(f"Failed to import CRL: {e}")
        raise e

def send_sns_alert(message):
    sns = boto3.client('sns')
    sns_topic_arn = os.environ['SNS_TOPIC_ARN']
    sns.publish(
        TopicArn=sns_topic_arn,
        Message=json.dumps({'default': json.dumps(message)}),
        MessageStructure='json'
    )
