"""
Certificate Automation Error Handler

This module provides standardized error handling, logging, and alerting for the
certificate automation system. It includes decorators for Lambda functions,
structured JSON logging.

The error handler ensures consistent error reporting across all Lambda functions
and provides operational visibility into system failures.
"""

import json
import logging
import traceback
import uuid
from datetime import datetime

logger = logging.getLogger()

def setup_structured_logging():
    """
    Configure structured JSON logging for Lambda functions.
    
    Sets up logging to output JSON-formatted log entries that are easily
    parsed by CloudWatch and other log analysis tools.
    """
    logging.basicConfig(
        level=logging.INFO,
        format='%(message)s'
    )

def log_structured(level: str, message: str, **kwargs):
    """
    Create structured JSON log entries with consistent formatting.
    
    Args:
        level (str): Log level (INFO, WARNING, ERROR)
        message (str): Human-readable log message
        **kwargs: Additional structured data to include in log entry
    """
    log_entry = {
        'timestamp': datetime.utcnow().isoformat(),
        'level': level,
        'message': message,
        **kwargs
    }
    
    if level.upper() == 'ERROR':
        logger.error(json.dumps(log_entry))
    elif level.upper() == 'WARNING':
        logger.warning(json.dumps(log_entry))
    else:
        logger.info(json.dumps(log_entry))

def generate_correlation_id() -> str:
    """Generate correlation ID for request tracking"""
    return str(uuid.uuid4())[:8]



def handle_lambda_error(func):
    """Decorator for standardized Lambda error handling with structured logging"""
    def wrapper(event, context):
        correlation_id = generate_correlation_id()
        setup_structured_logging()
        
        try:
            log_structured('INFO', f'Starting {func.__name__}', 
                         correlation_id=correlation_id,
                         function_name=func.__name__,
                         aws_request_id=context.aws_request_id if context else None,
                         event=event)
            
            result = func(event, context)
            
            log_structured('INFO', f'Successfully completed {func.__name__}',
                         correlation_id=correlation_id,
                         function_name=func.__name__,
                         duration_ms=context.get_remaining_time_in_millis() if context else None)
            
            return result
        except Exception as e:
            error_msg = f"{func.__name__} failed: {str(e)}"
            
            log_structured('ERROR', error_msg,
                         correlation_id=correlation_id,
                         function_name=func.__name__,
                         aws_request_id=context.aws_request_id if context else None,
                         error_type=type(e).__name__,
                         traceback=traceback.format_exc())
            
            # Note: SNS notifications are handled by Step Functions workflow
            # to avoid duplicate alerts during retry attempts
            
            raise
    return wrapper

class CertificateError(Exception):
    """Base exception for certificate operations"""
    pass

class ValidationError(CertificateError):
    """Input validation error"""
    pass

class SSMError(CertificateError):
    """SSM command error"""
    pass

class PCAError(CertificateError):
    """Private CA error"""
    pass