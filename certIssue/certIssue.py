import json
import boto3
import time
import os
import logging
import re

# Initialize AWS clients
ssm = boto3.client('ssm')
pca = boto3.client('acm-pca')
dynamodb = boto3.client('dynamodb')

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Get environment variables
SigningAlgorithm = os.environ['SigningAlgorithm']
PCAarn = os.environ['PCAarn']
csr_path = os.environ['CSR_PATH']

def lambda_handler(event, context):
    try:
        # Extract hostID, certPath, and keyPath from the event
        host = event["hostID"]
        cert_path = event["certPath"]
        key_path = event["keyPath"]
        
        # Sanitize the host input
        host = re.sub('[^0-9a-zA-Z\-]+', '', host)

        # Construct the SSM command
        commands = [
            '#!/bin/bash',
            f'openssl req -nodes -newkey rsa:2048 -keyout "{key_path}/{host}-new.key" -out "{csr_path}/{host}.csr" -subj "/CN={host}"',
            f'cat "{csr_path}/{host}.csr"',
        ]
        command_str = '\n'.join(commands)

        # Send the SSM command to generate CSR
        response = ssm.send_command(
            Targets=[
                {
                    'Key': 'InstanceIDs',
                    'Values': [
                        f'{host}'
                    ]
                },
            ],
            DocumentName='AWS-RunShellScript',
            DocumentVersion='1',
            DocumentHash='99749de5e62f71e5ebe9a55c2321e2c394796afe7208cff048696541e6f6771e',
            DocumentHashType='Sha256',
            TimeoutSeconds=123,
            Comment=f'Generating CSR for {host}',
            Parameters={
                'commands': [command_str]
            }
        )
        commandID = response['Command']['CommandId']

        # Wait for the SSM command to complete
        max_retries = 5
        retry_count = 0
        sleep_duration = .5
        while retry_count < max_retries:
            time.sleep(sleep_duration)

            response = ssm.get_command_invocation(
                CommandId=commandID,
                InstanceId=host,
            )

            # Check if the SSM command is still in progress
            if 'Status' in response and response['Status'] == 'InProgress':
                retry_count += 1
            else:
                break

        # Check if the SSM command was successful
        if 'Status' in response and response['Status'] != 'Success':
            error_message = f"SSM command failed with status: {response['Status']}"
            logger.error(error_message)
            raise RuntimeError(error_message)

        # Extract the CSR from the SSM command output
        csr = response["StandardOutputContent"]

        # Issue the certificate using ACM PCA
        response = pca.issue_certificate(
            CertificateAuthorityArn=PCAarn,
            Csr=csr,
            SigningAlgorithm=SigningAlgorithm,
            Validity={
                'Value': 7,
                'Type': 'DAYS'
            }
        )

        logger.info(f"Certificate signing issued to PCA successfully for host: {host}")
        logger.info(response)

        return {
            'statusCode': 200
        }
    
    except Exception as e:
        logger.error(str(e))
        raise