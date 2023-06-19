import json
import os
import boto3
import logging
from datetime import datetime, timedelta

# Setup logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    logger.info('Starting the certificate check process')

    # Instantiate AWS services clients
    dynamodb = boto3.client('dynamodb', region_name=os.environ['AWSREGION'])
    lmb = boto3.client('lambda')

    try:
        # Retrieve environment variable
        lambda_cert_issue_arn = os.environ.get('LAMBDA_CERT_ISSUE_ARN')
        if not lambda_cert_issue_arn:
            raise ValueError("Environment variable 'LAMBDA_CERT_ISSUE_ARN' not found.")

        # Execute DynamoDB statement to retrieve certificates
        response = dynamodb.execute_statement(Statement='SELECT hostID, expiry FROM certificates')

        for item in response["Items"]:
            if "expiry" in item and len(item["expiry"]["S"]) != 0:
                today = datetime.now()
                future_date = today + timedelta(days=2)

                expiry_date = datetime.strptime(item["expiry"]["S"], "%Y-%m-%d %H:%M:%S")

                if expiry_date <= today:
                    host_id = item["hostID"]["S"]
                    logger.info(f"Certificate for host {host_id} has expired and needs to be reissued")
                    lmb.invoke(
                        FunctionName=lambda_cert_issue_arn,
                        InvocationType='Event',
                        Payload=json.dumps({"hostID": host_id})
                    )
                    logger.info(f"Invoked the certificate issue lambda for host: {host_id}")
                elif expiry_date <= future_date:
                    host_id = item["hostID"]["S"]
                    days_until_expiry = (expiry_date - today).days
                    logger.info(f"Certificate for host {host_id} is expiring soon ({days_until_expiry} days). It needs to be reissued")
                    lmb.invoke(
                        FunctionName=lambda_cert_issue_arn,
                        InvocationType='Event',
                        Payload=json.dumps({"hostID": host_id})
                    )
                    logger.info(f"Invoked the certificate issue lambda for host: {host_id}")
                else:
                    host_id = item["hostID"]["S"]
                    logger.info(f"Certificate for host {host_id} is valid and does not need to be reissued")
            else:
                host_id = item["hostID"]["S"]
                logger.info(f"No expiry found for host: {host_id}. A certificate will be issued.")
                lmb.invoke(
                    FunctionName=lambda_cert_issue_arn,
                    InvocationType='Event',
                    Payload=json.dumps({"hostID": host_id})
                )
                logger.info(f"Invoked the certificate issue lambda for host: {host_id}")
    except Exception as e:
        logger.error("An error occurred: ", exc_info=True)
        raise e