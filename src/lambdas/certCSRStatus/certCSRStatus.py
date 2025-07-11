"""
CSR Status Check Lambda

This Lambda function checks the status of Certificate Signing Request (CSR) generation
commands submitted via AWS Systems Manager (SSM). It's part of the asynchronous
certificate automation workflow.

The function polls SSM to determine if CSR generation has completed, failed, or is
still in progress, allowing the Step Functions workflow to make decisions about
whether to proceed or retry.
"""

import boto3
import json
import os
from datetime import datetime
from typing import Dict, Any
from error_handler import handle_lambda_error, log_structured

# Initialize SSM client outside handler for connection reuse across invocations
ssm = boto3.client('ssm')

def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Check the status of an SSM command for CSR generation.
    
    This function queries SSM to determine the current status of a CSR generation
    command. It returns the original event data plus status information for the
    Step Functions workflow to process.
    
    Args:
        event: Dictionary containing:
            - hostID (str): EC2 instance ID
            - csrResult (dict): Contains commandId from CSR generation step
            - Other certificate processing data passed through
        context: AWS Lambda context object
        
    Returns:
        Dictionary containing:
            - All original event data (passed through)
            - csrStatus (str): Command status (Success, Failed, InProgress, Pending, etc.)
            - csrOutput (str, optional): Command output if successful
            - csrError (str, optional): Error details if failed
            - checkedAt (str): ISO timestamp when status was checked
    """
    
    # Extract parameters from event
    # The commandId is nested in csrResult from the previous GenerateCSR step
    host_id = event['hostID']
    
    if 'csrResult' in event and 'commandId' in event['csrResult']:
        command_id = event['csrResult']['commandId']
    elif 'commandId' in event:
        # Fallback for direct commandId (legacy support)
        command_id = event['commandId']
    else:
        raise ValueError("No commandId found in event. Expected in csrResult.commandId or commandId")
    
    print(f"Checking CSR status for host: {host_id}, command: {command_id}")
    
    try:
        # Get command invocation status
        result = ssm.get_command_invocation(
            CommandId=command_id,
            InstanceId=host_id
        )
        
        status = result['Status']
        print(f"Command status: {status}")
        
        # Prepare response with original event data plus status
        response = {
            **event,  # Include all original event data
            'csrStatus': status,
            'checkedAt': datetime.utcnow().isoformat()
        }
        
        if status == 'Success':
            # Command completed successfully
            output = result.get('StandardOutputContent', '')
            response['csrOutput'] = output
            print(f"CSR generation completed successfully for {host_id}")
            log_structured('INFO', 'CSR generation completed', 
                          host_id=host_id, 
                          command_id=command_id,
                          output_length=len(output))
            
        elif status == 'Failed':
            # Command failed
            error_content = result.get('StandardErrorContent', 'Unknown error')
            response['csrError'] = error_content
            print(f"CSR generation failed for {host_id}: {error_content}")
            log_structured('ERROR', 'CSR generation failed',
                          host_id=host_id,
                          command_id=command_id,
                          error=error_content)
            
        elif status in ['InProgress', 'Pending']:
            # Command still running
            print(f"CSR generation still {status} for {host_id}")
            log_structured('INFO', 'CSR generation in progress',
                          host_id=host_id,
                          command_id=command_id,
                          status=status)
            
        elif status == 'Cancelled':
            # Command was cancelled
            print(f"CSR generation was cancelled for {host_id}")
            log_structured('WARNING', 'CSR generation cancelled',
                          host_id=host_id,
                          command_id=command_id)
            
        elif status == 'TimedOut':
            # Command timed out
            print(f"CSR generation timed out for {host_id}")
            log_structured('ERROR', 'CSR generation timed out',
                          host_id=host_id,
                          command_id=command_id)
            
        else:
            # Unexpected status
            print(f"Unexpected CSR status for {host_id}: {status}")
            log_structured('WARNING', 'Unexpected CSR status',
                          host_id=host_id,
                          command_id=command_id,
                          status=status)
        
        return response
        
    except ssm.exceptions.InvocationDoesNotExist:
        # Command invocation not yet available (very recent submission)
        print(f"Command invocation not yet available for {host_id}, command may be very recent")
        return {
            **event,
            'csrStatus': 'Pending',
            'csrNote': 'Command invocation not yet available',
            'checkedAt': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        print(f"Error checking CSR status for {host_id}: {str(e)}")
        log_structured('ERROR', 'Error checking CSR status',
                      host_id=host_id,
                      command_id=command_id,
                      error=str(e))
        raise e

@handle_lambda_error
def main(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Main function wrapper for error handling and logging.
    """
    print(f"CSR Status Check Lambda started")
    print(f"Event: {json.dumps(event, default=str)}")
    
    result = lambda_handler(event, context)
    
    print(f"CSR Status Check completed")
    return result