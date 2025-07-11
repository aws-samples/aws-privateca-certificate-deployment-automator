"""
Certificate Signing Request (CSR) Generation Lambda

This Lambda function generates a Certificate Signing Request (CSR) and private key
on EC2 instances via AWS Systems Manager (SSM). It's part of an asynchronous
certificate automation workflow that can process thousands of certificates in parallel.

The function submits an SSM command to generate the CSR and returns immediately,
allowing the Step Functions workflow to check status asynchronously.
"""

import boto3
import json
import time
import os
from datetime import datetime
from typing import Dict, Any

# Initialize SSM client outside handler for connection reuse across invocations
ssm = boto3.client('ssm')

def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Generate CSR and private key on target EC2 instance via SSM.
    
    This function creates an OpenSSL command to generate a 2048-bit RSA private key
    and corresponding Certificate Signing Request (CSR) on the target instance.
    The function returns immediately after submitting the SSM command.
    
    Args:
        event: Dictionary containing:
            - hostID (str): EC2 instance ID where CSR will be generated
            - certPath (str, optional): Path to store certificate files (default: /tmp)
            - keyPath (str, optional): Path to store private key files (default: /tmp)
        context: AWS Lambda context object
        
    Returns:
        Dictionary containing:
            - hostID: Original instance ID
            - certPath: Certificate storage path
            - keyPath: Private key storage path  
            - commandId: SSM command ID for status tracking
            - status: "submitted" indicating command was sent
            - submittedAt: ISO timestamp when command was submitted
    """
    
    host_id = event['hostID']
    cert_path = event.get('certPath', '/tmp')
    key_path = event.get('keyPath', '/tmp')
    
    print(f"Generating CSR for host: {host_id}")
    print(f"Certificate path: {cert_path}")
    print(f"Key path: {key_path}")
    
    try:
        # Build SSM command to generate CSR and private key
        # Uses OpenSSL to create 2048-bit RSA key and CSR with instance ID as Common Name
        commands = [
            "#!/bin/bash",
            f"INSTANCE_ID={host_id}",
            f"echo \"Generating CSR for instance: $INSTANCE_ID\"",
            f"openssl req -nodes -newkey rsa:2048 -keyout {key_path}/{host_id}-new.key -out {cert_path}/{host_id}.csr -subj \"/CN=$INSTANCE_ID\"",
            f"echo \"CSR generation completed\"",
            f"echo \"Generated files:\"",
            f"ls -la {cert_path}/{host_id}.csr {key_path}/{host_id}-new.key",
            f"chmod 400 {key_path}/{host_id}-new.key",
            f"echo \"Private key permissions set to 400\"",
            f"echo \"CSR content:\"",
            f"cat {cert_path}/{host_id}.csr",
            f"echo \"CSR stored at: {cert_path}/{host_id}.csr\"",
            f"echo \"Private key stored at: {key_path}/{host_id}-new.key\""
        ]
        
        print(f"Sending SSM command to instance: {host_id}")
        
        # Send SSM command
        response = ssm.send_command(
            DocumentName='AWS-RunShellScript',
            Targets=[{'Key': 'InstanceIds', 'Values': [host_id]}],
            Parameters={'commands': commands},
            TimeoutSeconds=300,
            Comment=f'Generate CSR for certificate renewal - Instance {host_id}'
        )
        
        command_id = response['Command']['CommandId']
        print(f"SSM Command ID: {command_id}")
        print(f"CSR generation command submitted for instance: {host_id}")
        
        # Return immediately with command details - no waiting
        return {
            'hostID': host_id,
            'certPath': cert_path,
            'keyPath': key_path,
            'commandId': command_id,
            'status': 'submitted',
            'submittedAt': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        print(f"Error generating CSR: {str(e)}")
        
        # Note: SNS notifications are handled by Step Functions after retries are exhausted
        # This avoids duplicate notifications during retry attempts
        
        raise e


def main(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Main function wrapper for error handling and logging.
    """
    try:
        print(f"CSR Generation Lambda started")
        print(f"Event: {json.dumps(event, default=str)}")
        
        result = lambda_handler(event, context)
        
        print(f"CSR Generation completed successfully")
        return result
        
    except Exception as e:
        print(f"CSR Generation failed: {str(e)}")
        raise e
