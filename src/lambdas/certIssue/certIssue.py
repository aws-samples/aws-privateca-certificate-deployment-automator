"""
Certificate Issuance Lambda

Generates CSR on host via SSM, waits for completion, then issues certificate
via AWS Private CA. Handles both Linux and Windows hosts.
Aligned with the blog architecture where CertIssue handles the full flow.
"""

import json
import boto3
import time
import os
import logging
import re
from models import sanitize_host_id, sanitize_path
from error_handler import handle_lambda_error, PCAError, ValidationError, log_structured

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ssm = boto3.client('ssm')
pca = boto3.client('acm-pca')
sns = boto3.client('sns')


def generate_csr_commands(host_id, cert_path, key_path, platform):
    """Return SSM commands and document name for CSR generation."""
    if platform == 'windows':
        inf_path = f'{cert_path}\\{host_id}.inf'
        csr_file = f'{cert_path}\\{host_id}.csr'
        key_file = f'{key_path}\\{host_id}-new.key'
        commands = [
            f'$ErrorActionPreference = "Stop"',
            f'$inf = @"',
            f'[Version]',
            f'Signature="$Windows NT$"',
            f'[NewRequest]',
            f'Subject = "CN={host_id}"',
            f'KeySpec = 1',
            f'KeyLength = 2048',
            f'Exportable = TRUE',
            f'MachineKeySet = TRUE',
            f'SMIME = FALSE',
            f'PrivateKeyArchive = FALSE',
            f'UserProtected = FALSE',
            f'UseExistingKeySet = FALSE',
            f'ProviderName = "Microsoft RSA SChannel Cryptographic Provider"',
            f'ProviderType = 12',
            f'RequestType = PKCS10',
            f'KeyUsage = 0xa0',
            f'"@',
            f'$inf | Out-File -FilePath "{inf_path}" -Encoding ASCII',
            f'certreq -new -f "{inf_path}" "{csr_file}"',
            f'if (-not (Test-Path "{csr_file}")) {{ throw "CSR generation failed" }}',
            # Export private key from cert store to PEM via PowerShell
            f'$cert = Get-ChildItem -Path Cert:\\LocalMachine\\REQUEST | Where-Object {{ $_.Subject -eq "CN={host_id}" }} | Sort-Object NotBefore -Descending | Select-Object -First 1',
            f'if (-not $cert) {{ throw "Certificate not found in REQUEST store" }}',
            f'$privKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)',
            f'$keyBytes = $privKey.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)',
            f'$b64 = [System.Convert]::ToBase64String($keyBytes, [System.Base64FormattingOptions]::InsertLineBreaks)',
            f'$pem = "-----BEGIN PRIVATE KEY-----`r`n$b64`r`n-----END PRIVATE KEY-----"',
            f'Set-Content -Path "{key_file}" -Value $pem -Encoding ASCII',
            f'Get-Content "{csr_file}"',
        ]
        return commands, 'AWS-RunPowerShellScript'
    else:
        commands = [
            "#!/bin/bash",
            f"openssl req -nodes -newkey rsa:2048 -keyout {key_path}/{host_id}-new.key -out {cert_path}/{host_id}.csr -subj \"/CN={host_id}\"",
            f"chmod 400 {key_path}/{host_id}-new.key",
            f"cat {cert_path}/{host_id}.csr",
        ]
        return commands, 'AWS-RunShellScript'


def extract_csr_from_output(output):
    """Extract PEM-formatted CSR from SSM command output."""
    # certreq uses "NEW CERTIFICATE REQUEST", openssl uses "CERTIFICATE REQUEST"
    csr_pattern = r'-----BEGIN (?:NEW )?CERTIFICATE REQUEST-----.*?-----END (?:NEW )?CERTIFICATE REQUEST-----'
    match = re.search(csr_pattern, output, re.DOTALL)
    if not match:
        logger.error(f"CSR not found in output (length={len(output)}): {output[:500]}")
        raise ValidationError("Could not find valid CSR in command output")
    csr = match.group(0).replace('\\n', '\n')
    # Normalize certreq header to standard PKCS#10 header for PCA compatibility
    csr = csr.replace('BEGIN NEW CERTIFICATE REQUEST', 'BEGIN CERTIFICATE REQUEST')
    csr = csr.replace('END NEW CERTIFICATE REQUEST', 'END CERTIFICATE REQUEST')
    return csr


def send_ssm_and_wait(host_id, commands, document_name, max_wait=180):
    """Send SSM command and poll until completion."""
    response = ssm.send_command(
        DocumentName=document_name,
        Targets=[{'Key': 'InstanceIds', 'Values': [host_id]}],
        Parameters={'commands': commands},
        TimeoutSeconds=300,
        Comment=f'Generate CSR for {host_id}'
    )
    command_id = response['Command']['CommandId']
    logger.info(f"SSM Command {command_id} sent to {host_id}")

    # Poll for completion
    elapsed = 0
    interval = 15
    while elapsed < max_wait:
        time.sleep(interval)
        elapsed += interval
        try:
            result = ssm.get_command_invocation(CommandId=command_id, InstanceId=host_id)
            status = result['Status']
            if status == 'Success':
                return result.get('StandardOutputContent', '')
            elif status in ('Failed', 'Cancelled', 'TimedOut'):
                error = result.get('StandardErrorContent', 'Unknown error')
                raise RuntimeError(f"SSM command {status} for {host_id}: {error}")
        except ssm.exceptions.InvocationDoesNotExist:
            logger.info(f"Command invocation not yet available, waiting...")

    raise RuntimeError(f"SSM command timed out after {max_wait}s for {host_id}")


def main(event, context):
    signing_algorithm = os.environ['SigningAlgorithm']
    pca_arn = os.environ['PCAarn']
    sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')

    host_id = sanitize_host_id(event['hostID'])
    platform = event.get('platform', 'linux')
    cert_path = event.get('certPath', '/tmp')
    key_path = event.get('keyPath', '/tmp')

    logger.info(f"Processing certificate for {host_id} (platform: {platform})")

    # Step 1: Generate CSR on host via SSM
    commands, doc_name = generate_csr_commands(host_id, cert_path, key_path, platform)
    output = send_ssm_and_wait(host_id, commands, doc_name)

    # Step 2: Extract CSR
    csr = extract_csr_from_output(output)
    log_structured('INFO', 'CSR extracted', host_id=host_id, csr_length=len(csr))

    # Step 3: Issue certificate via PCA
    response = pca.issue_certificate(
        CertificateAuthorityArn=pca_arn,
        Csr=csr,
        SigningAlgorithm=signing_algorithm,
        Validity={'Value': 7, 'Type': 'DAYS'}
    )

    log_structured('INFO', 'Certificate issued',
                  host_id=host_id,
                  certificate_arn=response['CertificateArn'])

    return {
        'statusCode': 200,
        'body': {
            'certificateArn': response['CertificateArn'],
            'hostID': host_id
        }
    }


@handle_lambda_error
def lambda_handler(event, context):
    try:
        return main(event, context)
    except Exception as e:
        # Send SNS notification on failure
        sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
        host_id = event.get('hostID', 'unknown')
        if sns_topic_arn:
            try:
                sns.publish(
                    TopicArn=sns_topic_arn,
                    Message=f"Certificate issuance failed for host {host_id}: {str(e)}"
                )
            except Exception:
                logger.error(f"Failed to send SNS alert for {host_id}")
        raise
