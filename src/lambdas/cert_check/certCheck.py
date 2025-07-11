"""
Certificate Check Lambda

This Lambda function scans the DynamoDB certificate table to identify certificates
that need renewal. It's the entry point for the certificate automation workflow
and determines which certificates require processing.

The function uses the renewalDate field to efficiently identify certificates that
are approaching expiration, supporting high-scale operations with thousands of certificates.
"""

import json
import os
import boto3
import logging
from datetime import datetime, timedelta
from error_handler import handle_lambda_error, log_structured

# Setup logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def main(event, context):
    """
    Scan DynamoDB table to find certificates requiring renewal.
    
    This function identifies certificates that need renewal by checking the renewalDate
    field against the current date plus a configurable threshold. It returns a list
    of certificates for the Step Functions workflow to process in parallel.
    
    Args:
        event: Lambda event (typically empty for scheduled execution)
        context: AWS Lambda context object
        
    Returns:
        Dictionary containing:
            - certificates: List of certificate objects needing renewal
            - totalCount: Total number of certificates found
    """
    
    # Initialize DynamoDB client
    dynamodb = boto3.resource('dynamodb', region_name=os.environ['AWSREGION'])
    
    # Get configuration from environment variables
    default_cert_path = os.environ.get('DEFAULT_CERT_PATH')
    default_key_path = os.environ.get('DEFAULT_KEY_PATH')
    default_cacert_path = os.environ.get('DEFAULT_CACERT_PATH')
    default_signing_helper_path = os.environ.get('DEFAULT_AWSSigningHelperPath')
    table_name = os.environ.get('DYNAMODB_TABLE_NAME', 'certificates')
    renewal_threshold_days = int(os.environ.get('RENEWAL_THRESHOLD_DAYS', '2'))
    
    # Validate required environment variables
    if not default_cert_path or not default_key_path:
        raise ValueError("Required environment variables DEFAULT_CERT_PATH and DEFAULT_KEY_PATH not found")
    
    table = dynamodb.Table(table_name)
    
    from boto3.dynamodb.conditions import Attr
    today = datetime.now()
    threshold_date = (today + timedelta(days=renewal_threshold_days)).strftime('%Y-%m-%d')
    
    # Single scan to find hosts that need certificates:
    # 1. Hosts without renewalDate field (new hosts needing initial certificates)
    # 2. Hosts with renewalDate <= threshold_date (certificates expiring within X days)
    response = table.scan(
        FilterExpression=Attr('renewalDate').not_exists() | Attr('renewalDate').lte(threshold_date),
        ProjectionExpression='hostID, expiry, certPath, keyPath, cacertPath, signinghelperPath, renewalDate'
    )
    logger.info(f"Found {len(response['Items'])} hosts that need certificate processing (threshold: {renewal_threshold_days} days)")

    # Process items in batches for better performance at scale
    certificates_to_renew = []
    
    for item in response['Items']:
        host_id = item.get('hostID')
        cert_path = item.get('certPath') or default_cert_path
        key_path = item.get('keyPath') or default_key_path
        cacert_path = item.get('cacertPath') or default_cacert_path
        signing_helper_path = item.get('signinghelperPath') or default_signing_helper_path

        certificates_to_renew.append({
            "hostID": host_id,
            "certPath": cert_path,
            "keyPath": key_path,
            "cacertPath": cacert_path,
            "signinghelperPath": signing_helper_path
        })
    
    log_structured('INFO', 'Certificate renewal batch prepared',
                  certificate_count=len(certificates_to_renew),
                  renewal_threshold_days=renewal_threshold_days)
    
    return {
        "certificates": certificates_to_renew,
        "totalCount": len(certificates_to_renew)
    }
                
@handle_lambda_error
def lambda_handler(event, context):
    result = main(event, context)
    log_structured('INFO', 'Certificate check completed', 
                  certificates_found=result["totalCount"],
                  certificate_list=[cert['hostID'] for cert in result['certificates']])
    return result



