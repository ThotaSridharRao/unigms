"""
Utility functions for ticket management system
"""

import uuid
import re
import html
from datetime import datetime
from typing import Optional, Dict, Any


def generate_ticket_id() -> str:
    """
    Generate a unique ticket ID in the format TKT-YYYYMMDD-XXXX
    
    Returns:
        str: Unique ticket ID
    """
    # Get current date in YYYYMMDD format
    date_str = datetime.utcnow().strftime("%Y%m%d")
    
    # Generate a 4-character random suffix
    random_suffix = str(uuid.uuid4()).replace('-', '')[:4].upper()
    
    return f"TKT-{date_str}-{random_suffix}"


def sanitize_html_input(text: str) -> str:
    """
    Sanitize HTML input to prevent XSS attacks
    
    Args:
        text: Input text that may contain HTML
        
    Returns:
        str: Sanitized text with HTML tags removed
    """
    if not text:
        return ""
    
    # First escape HTML entities
    sanitized = html.escape(text.strip())
    
    # Remove any remaining HTML tags
    sanitized = re.sub(r'<[^>]+>', '', sanitized)
    
    # Normalize whitespace
    sanitized = re.sub(r'\s+', ' ', sanitized)
    
    return sanitized.strip()


def validate_ticket_category(category: str) -> bool:
    """
    Validate if the ticket category is allowed
    
    Args:
        category: Category to validate
        
    Returns:
        bool: True if valid category
    """
    valid_categories = ['tournament', 'payment', 'technical', 'account', 'other']
    return category.lower() in valid_categories


def validate_ticket_priority(priority: str) -> bool:
    """
    Validate if the ticket priority is allowed
    
    Args:
        priority: Priority to validate
        
    Returns:
        bool: True if valid priority
    """
    valid_priorities = ['low', 'medium', 'high', 'critical']
    return priority.lower() in valid_priorities


def validate_ticket_status(status: str) -> bool:
    """
    Validate if the ticket status is allowed
    
    Args:
        status: Status to validate
        
    Returns:
        bool: True if valid status
    """
    valid_statuses = ['open', 'in_progress', 'resolved', 'closed']
    return status.lower() in valid_statuses


def format_ticket_for_response(ticket_data: Dict[str, Any], include_messages: bool = False) -> Dict[str, Any]:
    """
    Format ticket data for API response
    
    Args:
        ticket_data: Raw ticket data from database
        include_messages: Whether to include message history
        
    Returns:
        Dict: Formatted ticket data
    """
    if not ticket_data:
        return {}
    
    # Convert ObjectId to string if present
    if '_id' in ticket_data:
        ticket_data['_id'] = str(ticket_data['_id'])
    
    # Format timestamps
    for timestamp_field in ['createdAt', 'updatedAt', 'resolvedAt']:
        if timestamp_field in ticket_data and ticket_data[timestamp_field]:
            if isinstance(ticket_data[timestamp_field], datetime):
                ticket_data[timestamp_field] = ticket_data[timestamp_field].isoformat()
    
    # Format messages if included
    if include_messages and 'messages' in ticket_data:
        formatted_messages = []
        for message in ticket_data.get('messages', []):
            if isinstance(message.get('timestamp'), datetime):
                message['timestamp'] = message['timestamp'].isoformat()
            formatted_messages.append(message)
        ticket_data['messages'] = formatted_messages
    elif not include_messages:
        # Remove messages from response if not requested
        ticket_data.pop('messages', None)
    
    return ticket_data


def calculate_ticket_age_hours(created_at: datetime) -> float:
    """
    Calculate the age of a ticket in hours
    
    Args:
        created_at: Ticket creation timestamp
        
    Returns:
        float: Age in hours
    """
    if not created_at:
        return 0.0
    
    if isinstance(created_at, str):
        try:
            created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
        except ValueError:
            return 0.0
    
    age_delta = datetime.utcnow() - created_at
    return age_delta.total_seconds() / 3600


def get_priority_weight(priority: str) -> int:
    """
    Get numeric weight for priority sorting
    
    Args:
        priority: Priority level
        
    Returns:
        int: Numeric weight (higher = more urgent)
    """
    priority_weights = {
        'critical': 4,
        'high': 3,
        'medium': 2,
        'low': 1
    }
    return priority_weights.get(priority.lower(), 1)


def validate_file_attachment(file_path: str) -> Dict[str, Any]:
    """
    Validate file attachment
    
    Args:
        file_path: Path to the file
        
    Returns:
        Dict: Validation result with success status and details
    """
    import os
    
    result = {
        'valid': False,
        'error': None,
        'file_info': {}
    }
    
    if not file_path:
        result['error'] = "File path is empty"
        return result
    
    # Check file extension
    allowed_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.doc', '.docx', '.txt']
    _, ext = os.path.splitext(file_path.lower())
    
    if ext not in allowed_extensions:
        result['error'] = f"File type {ext} not allowed. Allowed types: {', '.join(allowed_extensions)}"
        return result
    
    # Check if file exists (if it's a local path)
    if os.path.isfile(file_path):
        try:
            file_size = os.path.getsize(file_path)
            max_size = 10 * 1024 * 1024  # 10MB
            
            if file_size > max_size:
                result['error'] = f"File size {file_size} bytes exceeds maximum allowed size of {max_size} bytes"
                return result
            
            result['file_info'] = {
                'size': file_size,
                'extension': ext,
                'name': os.path.basename(file_path)
            }
        except OSError as e:
            result['error'] = f"Error accessing file: {str(e)}"
            return result
    
    result['valid'] = True
    return result


def create_ticket_search_query(search_term: Optional[str], filters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create MongoDB query for ticket search and filtering
    
    Args:
        search_term: Text to search for in subject and description
        filters: Additional filters (status, category, priority, etc.)
        
    Returns:
        Dict: MongoDB query object
    """
    query = {}
    
    # Add text search if provided
    if search_term:
        sanitized_search = sanitize_html_input(search_term)
        if sanitized_search:
            query['$or'] = [
                {'subject': {'$regex': sanitized_search, '$options': 'i'}},
                {'description': {'$regex': sanitized_search, '$options': 'i'}},
                {'ticketId': {'$regex': sanitized_search, '$options': 'i'}}
            ]
    
    # Add filters
    for field, value in filters.items():
        if value is not None:
            if field in ['status', 'category', 'priority']:
                query[field] = value
            elif field == 'userId':
                query['userId'] = value
            elif field == 'assignedTo':
                query['assignedTo'] = value
            elif field == 'dateFrom':
                if 'createdAt' not in query:
                    query['createdAt'] = {}
                query['createdAt']['$gte'] = value
            elif field == 'dateTo':
                if 'createdAt' not in query:
                    query['createdAt'] = {}
                query['createdAt']['$lte'] = value
    
    return query


def log_ticket_operation(operation: str, ticket_id: str, user_id: str, details: str = ""):
    """
    Log ticket operations for audit purposes
    
    Args:
        operation: Type of operation (create, update, delete, etc.)
        ticket_id: Ticket ID
        user_id: User performing the operation
        details: Additional details about the operation
    """
    timestamp = datetime.utcnow().isoformat()
    log_entry = f"🎫 TICKET LOG [{timestamp}]: {operation} ticket '{ticket_id}' by user '{user_id}'"
    if details:
        log_entry += f" - {details}"
    print(log_entry)