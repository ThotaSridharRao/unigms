"""
Error handling utilities for ticket management system
"""

from fastapi import HTTPException, status
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import logging

# Configure logging for ticket errors
ticket_logger = logging.getLogger("ticket_system")


class TicketError(Exception):
    """Base exception for ticket-related errors"""
    def __init__(self, message: str, error_code: str = None, details: Dict[str, Any] = None):
        self.message = message
        self.error_code = error_code or "TICKET_ERROR"
        self.details = details or {}
        super().__init__(self.message)


class TicketValidationError(TicketError):
    """Exception for ticket validation errors"""
    def __init__(self, message: str, field: str = None, value: Any = None):
        super().__init__(message, "VALIDATION_ERROR")
        self.field = field
        self.value = value
        if field:
            self.details = {"field": field, "value": str(value) if value else None}


class TicketNotFoundError(TicketError):
    """Exception for ticket not found errors"""
    def __init__(self, ticket_id: str):
        super().__init__(f"Ticket not found: {ticket_id}", "TICKET_NOT_FOUND")
        self.ticket_id = ticket_id
        self.details = {"ticketId": ticket_id}


class TicketPermissionError(TicketError):
    """Exception for ticket permission errors"""
    def __init__(self, message: str, user_id: str = None, ticket_id: str = None):
        super().__init__(message, "PERMISSION_DENIED")
        self.user_id = user_id
        self.ticket_id = ticket_id
        self.details = {"userId": user_id, "ticketId": ticket_id}


class TicketRateLimitError(TicketError):
    """Exception for rate limiting errors"""
    def __init__(self, message: str, retry_after: int = None):
        super().__init__(message, "RATE_LIMIT_EXCEEDED")
        self.retry_after = retry_after
        if retry_after:
            self.details = {"retryAfter": retry_after}


def create_error_response(
    success: bool = False,
    message: str = "An error occurred",
    error_code: str = None,
    errors: List[str] = None,
    details: Dict[str, Any] = None,
    status_code: int = 400
) -> Dict[str, Any]:
    """
    Create a standardized error response
    
    Args:
        success: Success status (always False for errors)
        message: Main error message
        error_code: Specific error code
        errors: List of detailed error messages
        details: Additional error details
        status_code: HTTP status code
        
    Returns:
        Dict: Standardized error response
    """
    response = {
        "success": success,
        "message": message,
        "timestamp": datetime.utcnow().isoformat()
    }
    
    if error_code:
        response["errorCode"] = error_code
    
    if errors:
        response["errors"] = errors
    
    if details:
        response["details"] = details
    
    return response


def handle_ticket_exception(e: Exception, operation: str = "ticket operation") -> HTTPException:
    """
    Convert ticket exceptions to HTTP exceptions with proper logging
    
    Args:
        e: The exception to handle
        operation: Description of the operation that failed
        
    Returns:
        HTTPException: Properly formatted HTTP exception
    """
    timestamp = datetime.utcnow().isoformat()
    
    if isinstance(e, TicketValidationError):
        ticket_logger.warning(f"Validation error in {operation}: {e.message}")
        return HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=create_error_response(
                message=e.message,
                error_code=e.error_code,
                details=e.details
            )
        )
    
    elif isinstance(e, TicketNotFoundError):
        ticket_logger.warning(f"Ticket not found in {operation}: {e.ticket_id}")
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=create_error_response(
                message=e.message,
                error_code=e.error_code,
                details=e.details
            )
        )
    
    elif isinstance(e, TicketPermissionError):
        ticket_logger.warning(f"Permission denied in {operation}: {e.message}")
        return HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=create_error_response(
                message=e.message,
                error_code=e.error_code,
                details=e.details
            )
        )
    
    elif isinstance(e, TicketRateLimitError):
        ticket_logger.warning(f"Rate limit exceeded in {operation}: {e.message}")
        headers = {}
        if e.retry_after:
            headers["Retry-After"] = str(e.retry_after)
        
        return HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=create_error_response(
                message=e.message,
                error_code=e.error_code,
                details=e.details
            ),
            headers=headers
        )
    
    elif isinstance(e, TicketError):
        ticket_logger.error(f"Ticket error in {operation}: {e.message}")
        return HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=create_error_response(
                message=e.message,
                error_code=e.error_code,
                details=e.details
            )
        )
    
    else:
        # Generic error handling
        ticket_logger.error(f"Unexpected error in {operation}: {str(e)}")
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=create_error_response(
                message="An unexpected error occurred. Please try again later.",
                error_code="INTERNAL_ERROR"
            )
        )


def validate_ticket_data(ticket_data: Dict[str, Any]) -> List[str]:
    """
    Validate ticket data and return list of validation errors
    
    Args:
        ticket_data: Ticket data to validate
        
    Returns:
        List[str]: List of validation error messages
    """
    errors = []
    
    # Required fields
    required_fields = ["issueType", "priority", "subject", "description"]
    for field in required_fields:
        if not ticket_data.get(field):
            errors.append(f"Field '{field}' is required")
    
    # Validate issue type
    valid_issue_types = ["tournament", "payment", "technical", "account", "other"]
    if ticket_data.get("issueType") and ticket_data["issueType"] not in valid_issue_types:
        errors.append(f"Invalid issue type. Must be one of: {', '.join(valid_issue_types)}")
    
    # Validate priority
    valid_priorities = ["low", "medium", "high", "critical"]
    if ticket_data.get("priority") and ticket_data["priority"] not in valid_priorities:
        errors.append(f"Invalid priority. Must be one of: {', '.join(valid_priorities)}")
    
    # Validate subject length
    subject = ticket_data.get("subject", "")
    if subject and (len(subject) < 5 or len(subject) > 100):
        errors.append("Subject must be between 5 and 100 characters")
    
    # Validate description length
    description = ticket_data.get("description", "")
    if description and (len(description) < 10 or len(description) > 2000):
        errors.append("Description must be between 10 and 2000 characters")
    
    # Validate attachments
    attachments = ticket_data.get("attachments", [])
    if attachments:
        if len(attachments) > 5:
            errors.append("Maximum 5 attachments allowed")
        
        valid_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.doc', '.docx', '.txt']
        for attachment in attachments:
            if attachment:
                import os
                _, ext = os.path.splitext(attachment.lower())
                if ext not in valid_extensions:
                    errors.append(f"Invalid file type: {ext}. Allowed types: {', '.join(valid_extensions)}")
    
    return errors


def log_ticket_error(error: Exception, context: Dict[str, Any] = None):
    """
    Log ticket errors with context information
    
    Args:
        error: The error to log
        context: Additional context information
    """
    timestamp = datetime.utcnow().isoformat()
    error_info = {
        "timestamp": timestamp,
        "error_type": type(error).__name__,
        "error_message": str(error),
        "context": context or {}
    }
    
    if isinstance(error, TicketError):
        error_info["error_code"] = error.error_code
        error_info["details"] = error.details
    
    ticket_logger.error(f"Ticket Error: {error_info}")


def create_success_response(
    data: Any = None,
    message: str = "Operation completed successfully",
    ticket_id: str = None
) -> Dict[str, Any]:
    """
    Create a standardized success response
    
    Args:
        data: Response data
        message: Success message
        ticket_id: Ticket ID if applicable
        
    Returns:
        Dict: Standardized success response
    """
    response = {
        "success": True,
        "message": message,
        "timestamp": datetime.utcnow().isoformat()
    }
    
    if data is not None:
        response["data"] = data
    
    if ticket_id:
        response["ticketId"] = ticket_id
    
    return response


# Rate limiting utilities
class RateLimiter:
    """Simple in-memory rate limiter for ticket operations"""
    
    def __init__(self):
        self.requests = {}  # {user_id: [timestamp1, timestamp2, ...]}
    
    def is_rate_limited(self, user_id: str, max_requests: int = 5, window_minutes: int = 60) -> bool:
        """
        Check if user is rate limited
        
        Args:
            user_id: User ID to check
            max_requests: Maximum requests allowed
            window_minutes: Time window in minutes
            
        Returns:
            bool: True if rate limited
        """
        now = datetime.utcnow()
        window_start = now - timedelta(minutes=window_minutes)
        
        # Clean old requests
        if user_id in self.requests:
            self.requests[user_id] = [
                req_time for req_time in self.requests[user_id]
                if req_time > window_start
            ]
        else:
            self.requests[user_id] = []
        
        # Check if rate limited
        if len(self.requests[user_id]) >= max_requests:
            return True
        
        # Add current request
        self.requests[user_id].append(now)
        return False
    
    def get_retry_after(self, user_id: str, window_minutes: int = 60) -> int:
        """
        Get retry after time in seconds
        
        Args:
            user_id: User ID
            window_minutes: Time window in minutes
            
        Returns:
            int: Seconds until user can make another request
        """
        if user_id not in self.requests or not self.requests[user_id]:
            return 0
        
        oldest_request = min(self.requests[user_id])
        window_end = oldest_request + timedelta(minutes=window_minutes)
        now = datetime.utcnow()
        
        if window_end > now:
            return int((window_end - now).total_seconds())
        
        return 0


# Global rate limiter instance
ticket_rate_limiter = RateLimiter()