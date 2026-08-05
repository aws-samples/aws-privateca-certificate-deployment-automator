"""
Certificate Check Lambda

Scans DynamoDB for certificates needing renewal and asynchronously invokes
CertIssue for each host. Aligned with the blog architecture pattern.
"""

import json
import os
import boto3
import logging
from datetime import datetime, timedelta
from error_handler import handle_lambda_error, log_structured

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def main(event, context):
    dynamodb = boto3.resource('dynamodb', region_name=os.environ['AWSREGION'])
    lambda_client = boto3.client('lambda')

    default_cert_path = os.environ.get('DEFAULT_CERT_PATH')
    default_key_path = os.environ.get('DEFAULT_KEY_PATH')
    default_cacert_path = os.environ.get('DEFAULT_CACERT_PATH')
    default_signing_helper_path = os.environ.get('DEFAULT_AWSSigningHelperPath')
    cert_issue_arn = os.environ.get('LAMBDA_CERT_ISSUE_ARN')
    table_name = os.environ.get('DYNAMODB_TABLE_NAME', 'certificates')
    renewal_threshold_days = int(os.environ.get('RENEWAL_THRESHOLD_DAYS', '2'))
    sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')

    if not default_cert_path or not default_key_path:
        raise ValueError("Required environment variables DEFAULT_CERT_PATH and DEFAULT_KEY_PATH not found")

    table = dynamodb.Table(table_name)

    from boto3.dynamodb.conditions import Attr
    threshold_date = (datetime.now() + timedelta(days=renewal_threshold_days)).strftime('%Y-%m-%d')

    response = table.scan(
        FilterExpression=Attr('renewalDate').not_exists() | Attr('renewalDate').lte(threshold_date),
        ProjectionExpression='hostID, expiry, certPath, keyPath, cacertPath, signinghelperPath, renewalDate, platform'
    )
    logger.info(f"Found {len(response['Items'])} hosts needing certificate processing")

    sns = boto3.client('sns')

    for item in response['Items']:
        host_id = item.get('hostID')
        payload = {
            "hostID": host_id,
            "platform": item.get('platform', 'linux'),
            "certPath": item.get('certPath') or default_cert_path,
            "keyPath": item.get('keyPath') or default_key_path,
            "cacertPath": item.get('cacertPath') or default_cacert_path,
            "signinghelperPath": item.get('signinghelperPath') or default_signing_helper_path
        }

        try:
            lambda_client.invoke(
                FunctionName=cert_issue_arn,
                InvocationType='Event',  # Async invocation per blog pattern
                Payload=json.dumps(payload)
            )
            logger.info(f"Invoked CertIssue for host: {host_id}")
        except Exception as e:
            logger.error(f"Failed to invoke CertIssue for {host_id}: {str(e)}")
            try:
                sns.publish(
                    TopicArn=sns_topic_arn,
                    Message=f"Failed to invoke CertIssue for host {host_id}: {str(e)}"
                )
            except Exception:
                logger.error(f"Failed to send SNS alert for {host_id}")

    return {
        "certificates": [item.get('hostID') for item in response['Items']],
        "totalCount": len(response['Items'])
    }

@handle_lambda_error
def lambda_handler(event, context):
    result = main(event, context)
    log_structured('INFO', 'Certificate check completed',
                  certificates_found=result["totalCount"])
    return result
