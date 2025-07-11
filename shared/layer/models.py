"""
Certificate Automation Security Models

This module provides input validation and sanitization functions to prevent
security vulnerabilities in the certificate automation system. It validates
host IDs and file paths to prevent injection attacks and directory traversal.

All user inputs should be validated through these functions before being used
in system commands or file operations.
"""

import re


def sanitize_host_id(host_id: str) -> str:
    """
    Validate and sanitize EC2 instance IDs and hostnames.
    
    Ensures the host ID contains only safe characters to prevent command injection
    when used in SSM commands or other system operations.
    
    Args:
        host_id (str): EC2 instance ID or hostname to validate
        
    Returns:
        str: The validated host ID
        
    Raises:
        ValueError: If host ID is invalid or contains unsafe characters
    """
    if not host_id or not isinstance(host_id, str):
        raise ValueError("Host ID must be a non-empty string")
    
    # Allow only alphanumeric characters, hyphens, and dots (safe for AWS instance IDs and hostnames)
    if not re.match(r'^[a-zA-Z0-9\-\.]+$', host_id):
        raise ValueError("Host ID contains invalid characters")
    
    return host_id


def sanitize_path(path: str) -> str:
    """
    Validate and sanitize file system paths.
    
    Ensures file paths are safe to use in system commands and prevents
    directory traversal attacks.
    
    Args:
        path (str): File system path to validate
        
    Returns:
        str: The validated path
        
    Raises:
        ValueError: If path is invalid or contains unsafe patterns
    """
    if not path or not isinstance(path, str):
        raise ValueError("Path must be a non-empty string")
    
    # Require absolute paths for security
    if not path.startswith('/'):
        raise ValueError("Path must be absolute")
    
    # Block directory traversal and other dangerous patterns
    if '..' in path or '~' in path:
        raise ValueError("Path contains dangerous patterns")
    
    return path