import boto3
import json
import os
from cryptography import x509
from cryptography.hazmat.primitives import serialization

# Initialize the S3 client
s3 = boto3.client('s3')

# Initialize the IAM Roles Anywhere client
iamra_client = boto3.client('rolesanywhere')

def convert_der_to_pem(der_data):
    crl = x509.load_der_x509_crl(der_data)
    pem_data = crl.public_bytes(encoding=serialization.Encoding.PEM)
    return pem_data

def lambda_handler(event, context):
    
    # Extract bucket and file key from EventBridge Event
    bucket = event['detail']['bucket']['name']
    key = event['detail']['object']['key']
    
    # Check if the object ends with .crl
    if not key.endswith('.crl'):
        print("Object is not a CRL. Skipping.")
        return

    # Fetch CRL from S3
    s3_object = s3.get_object(Bucket=bucket, Key=key)
    crl_data_der = s3_object['Body'].read()

    # Convert DER to PEM
    crl_data_pem = convert_der_to_pem(crl_data_der)
    
    trust_anchor_arn = os.environ['IAMRATrustAnchorARN']
    
    # Prepare parameters
    params = {
        'crlData': crl_data_pem,
        'enabled': True,
        'name': 'CRL',
        'trustAnchorArn': trust_anchor_arn
    }
    
    # Call IAM Roles Anywhere API to import CRL
    try:
        response = iamra_client.import_crl(**params)
        print("Successfully imported CRL: ", response)
    except Exception as e:
        print("Failed to import CRL: ", e)
