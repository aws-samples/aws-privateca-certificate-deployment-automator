import json
import os
import boto3
import logging
from datetime import datetime, timedelta

# Setup logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def main(event, context):
    # Instantiate AWS services clients
    dynamodb = boto3.client('dynamodb', region_name=os.environ['AWSREGION'])
    # Retrieve environment variables
    lambda_cert_issue_arn = os.environ.get('LAMBDA_CERT_ISSUE_ARN')
    default_cert_path = os.environ.get('DEFAULT_CERT_PATH')
    default_key_path = os.environ.get('DEFAULT_KEY_PATH')
    
    # Ensure the required environment variables are present
    if not lambda_cert_issue_arn or not default_cert_path or not default_key_path:
        raise ValueError("Required environment variables not found.")
    
    # Execute DynamoDB statement to retrieve certificates
    response = dynamodb.execute_statement(Statement='SELECT hostID, expiry, certPath, keyPath FROM certificates')

    # Loop through the items retrieved from DynamoDB
    for item in response["Items"]:
        host_id = item.get("hostID", {}).get("S")
        cert_path = item.get("certPath", {}).get("S") or default_cert_path
        key_path = item.get("keyPath", {}).get("S") or default_key_path

        reissue_certificate = False
        
        if "expiry" in item and len(item["expiry"]["S"]) != 0:
            today = datetime.now()
            future_date = today + timedelta(days=1)

            expiry_date = datetime.strptime(item["expiry"]["S"], "%Y-%m-%d %H:%M:%S")

            # Calculate the time until expiration
            time_until_expiry = expiry_date - today

            # Check if the certificate has already expired or will expire in the next 24 hours
            if time_until_expiry <= timedelta(seconds=0):
                logger.info(f"Certificate for host {host_id} has expired and needs to be reissued")
                reissue_certificate = True
            elif time_until_expiry <= timedelta(days=1):
                hours_until_expiry = time_until_expiry.total_seconds() // 3600  # Convert timedelta to hours
                logger.info(f"Certificate for host {host_id} is expiring soon ({hours_until_expiry} hours). It needs to be reissued")
                reissue_certificate = True
            else:
                logger.info(f"Certificate for host {host_id} is valid and does not need to be reissued")


        else:
            logger.info(f"No expiry found for host: {host_id}. A certificate will be issued.")
            reissue_certificate = True
        
        if reissue_certificate:
            issue_certificate(lambda_cert_issue_arn, host_id, cert_path, key_path)
                
def lambda_handler(event, context):
    try:
        logger.info('Starting the certificate check process')
        main(event, context)
    except Exception as e:
        logger.error("An error occurred: ", exc_info=True)
        send_sns_alert(f"Certificate rotation trigger failed: {e}")
        raise e


def issue_certificate(lambda_cert_issue_arn, host_id, cert_path, key_path):
    lmb = boto3.client('lambda')
    lmb.invoke(
        FunctionName=lambda_cert_issue_arn,
        InvocationType='Event',
        Payload=json.dumps({
            "hostID": host_id,
            "certPath": cert_path,
            "keyPath": key_path
        })
    )
    logger.info(f"Invoked the certificate issue lambda for host: {host_id}")

def send_sns_alert(message):
    sns = boto3.client('sns')
    sns_topic_arn = os.environ['SNS_TOPIC_ARN']  # Retrieve the ARN from environment variables
    sns.publish(
        TopicArn=sns_topic_arn,  # Use the ARN from environment variables
        Message=json.dumps({'default': json.dumps(message)}),
        MessageStructure='json'
    )
