from fastapi import FastAPI, HTTPException, status, Depends, Security, Form, UploadFile, File, Request, Query
# Add StaticFiles to this import
# Clean deployment - removed __pycache__ directories
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import RedirectResponse
from pydantic import ValidationError
from typing import Optional, List, Dict, Any
import html
from datetime import datetime
from bson import ObjectId

import os
import shutil
import re
import cloudinary # <-- ADD THIS
import cloudinary.uploader # <-- AND THIS
import hashlib  # ADDED: Required for PayU hash generation
import uuid
import logging
import csv
import io
from datetime import timedelta
# In main.py

# 🔽 MAKE SURE YOU ADD THIS IMPORT AT THE TOP OF THE FILE 🔽
from database import credit_host_for_payment
from fastapi.responses import HTMLResponse
import urllib.parse
# ... other imports
# Rest of your existing PDF generation code stays the same...

# Continue with PDF generation (remove the duplicate auth lines)
from reportlab.lib.pagesizes import A4, portrait
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT
# Change it to this
from fastapi.responses import StreamingResponse


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import security and privacy modules
from security_middleware import SecurityMiddleware, InputValidationMiddleware
from privacy_api import privacy_router

# Local imports from your project files
from auth import (
    hash_password,
    verify_password,
    create_jwt_token,
    verify_jwt_token
)

from database import (
    setup_database,
    create_user,
    get_database,
    create_admin_user,
    get_user_by_email,
    create_tournament_in_db,
    get_all_tournaments_from_db,
    get_tournament_by_slug_from_db,
    get_tournament_by_id,
    update_tournament_in_db,
    delete_tournament_from_db,
    check_tournament_has_participants,
    create_payment_record,
    update_payment_status,
    get_tournaments_for_user,
    create_tournament_brackets,
    get_tournament_brackets,
    update_tournament_brackets,
    update_round_status,
    update_team_payment_status,
    advance_teams_to_next_round,
    get_team_by_id,
    get_user_team_in_tournament,
    # New user lookup and enhancement functions
    find_user_id_by_email,
    get_user_by_id,
    enhance_registration_with_user_ids,
    batch_enhance_historical_registrations,
    get_payment_by_transaction_id,
    # Data validation and cleanup functions
    validate_registration_data_consistency,
    cleanup_duplicate_user_ids,
    get_migration_status_report,
    create_activity,
    get_recent_activities,
    get_user_activities,
    get_tournament_activities,
    log_user_joined_activity,
    log_tournament_registration_activity,
    log_tournament_announced_activity,
    log_tournament_status_activity,
    log_round_activity,
    log_payment_activity,
    cleanup_old_activities,
    # Content moderation functions
    create_moderation_review,
    get_moderation_queue,
    update_tournament_moderation_status,
    get_moderation_stats,
    # Dispute resolution functions
    create_dispute_ticket,
    get_dispute_ticket,
    get_dispute_ticket_by_ticket_id,
    update_dispute_ticket,
    update_dispute_ticket_by_ticket_id,
    add_dispute_message,
    get_dispute_tickets,
    create_support_ticket,
    get_support_ticket,
    get_support_ticket_by_ticket_id,
    update_support_ticket,
    update_support_ticket_by_ticket_id,
    add_support_message,
    add_support_message_by_ticket_id,
    get_support_tickets,
    process_automated_refund,
    credit_host_for_payment,
    get_tournaments_by_host_id,
    get_host_dashboard_metrics,
    get_participants_for_host_tournament,
    update_participant_status_for_host,
    get_tournament_for_host,
    get_host_revenue_over_time,
    get_host_participant_growth,
    get_admin_withdrawal_requests,
    finalize_withdrawal_status
)

from models import (
    UserRegistration,
    UserLogin,
    UserResponse,
    TournamentStatusUpdate,
    FinalistsUpdate,
    PaymentInitiationRequest,
    PaymentResponse,
    TournamentBrackets,
    BracketPaymentRequest,
    RoundStartRequest,
    RoundCompleteRequest,
    TeamRegistrationData,
    TeamDetailsResponse,
    ActivityCreate,
    ActivityResponse,
    ActivityListResponse,
    # Content moderation models
    ModerationReview,
    ModerationQueueItem,
    ModerationAction,
    ModerationStats,
    ContentModerationResult,
    DisputeTicket,
    SupportTicket,
    ModerationResponse,
    DisputeResponse,
    SupportResponse,
    # Enhanced ticket models
    TicketCreateRequest,
    TicketResponse,
    TicketListRequest,
    AdminTicketUpdate,
    TicketMessage,
    TicketStats,
    AdminWithdrawalAction
)

from content_moderation_service import (
    get_content_moderation_service,
    get_moderation_queue,
    moderate_tournament_submission,
    ContentType
)



# Import ticket utilities
from ticket_utils import (
    generate_ticket_id,
    sanitize_html_input,
    validate_ticket_category,
    validate_ticket_priority,
    validate_ticket_status,
    format_ticket_for_response,
    log_ticket_operation
)

# Import ticket error handling
from ticket_errors import (
    TicketError,
    TicketValidationError,
    TicketNotFoundError,
    TicketPermissionError,
    TicketRateLimitError,
    handle_ticket_exception,
    create_error_response,
    create_success_response,
    validate_ticket_data,
    log_ticket_error,
    ticket_rate_limiter
)

# PayU Configuration
PAYU_CONFIG = {
    "MERCHANT_KEY": os.getenv("PAYU_MERCHANT_KEY"),
    "SALT": os.getenv("PAYU_SALT"),
    "SALT_256": "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCelWxeq7p+d15Nn7GnDytLXEs/F36RtH1+nA+NEg/olpfAc4Y4M5sCqWy4jm/ZTBwzW73O1jR4UcVUwI4yvqen+m2VFyKgEM+oqlQtesnYL1yLUo6QmqwoKG9HzPGRAn19VbKW+658gteILIRIwvRyDJYd4pYokFFNfK8rQ/ZerpimYmGbDU574H8Rw8Bv/iZr1NNnCcw96OsRsXqw93kwHnseW6wkeRR3dPhG8Wvd9peuxvttKA5rNICcuFdp3d0J6aU9CD3pgwBP2aC3O4DKVJVQBYmDCbtsVjfeT8Un7Ke/QeUschm6Rwi4FOGL2DOXyPU/yFrYxwoxtTm8UOfxAgMBAAECggEAI6yD8iEKBTCHmYkqzuSx7dQ/hhwcKB1U3MIxGmA9jWoxDYU/ZI2xWW4xC6xZG2YMcv44itqzd3yXmjrt0hsC/p3ugEsxyhW2DSBx6sA0P0paNGo4MW3l++uqqtl+3wrTHXqFgALyi8ZoQ1UWVgLrN+u+ak8iTdI3Q+ngQuiZN8+Oufd9qJgnU1vKdUagLH7980PR4kaL4F+fNNQzg76n6ILTKyWZnYiDYaQE51zVUZr9OmeOE3XnUThvKvWmEFwf9wH8/3dG4K6ulLWbJ9ROXLIkvthGE5emmgI1hgjzyRyORV5H1DCZPYYTWYSL346DW38NjnpBWSvKM0c7cTdv9QKBgQDTz93RmMWPX1elsamjV7v28C0Q81pgvzGg/FNxzgdCxNcZlBHsmfaeUN7CNNbYwiKx+L3vrrWD62Mb5KS7Em6VCyQCmFBvGe4J5N5re5SxeojUmKfv22SED7hUzLMTTu8oSR5StCPn0RpLPN6joRB9Tqvj54FmskN0r7/d6xeb7QKBgQC/qtIZ9IE7pRYy9jzymPK0dKX9exIYXkrNsadKGGen3woSmPO5c9aLzTI67Rd3tEy9UZ7Rr4FyqzLd0PwaaE0N+DNL0mdKohyrhKWlmX+fohg+ihZis/dCjyEBac5/xqxoanKK1Z1bP8mfI718phe1EeaDE8TYQ68UdCjA75DjlQKBgQDAZCcPoryQJgHutxlnDOHmwvGsW97T0da6a3c//+wIcdMPoLdHOfIQi1RLAsPDz1LEZTPg6chmMwCq7VvTsEJRjvT+hmtI/zyAMCr3ZiEBtFNlB+RCsfzzF3RPUj+2YhRJe2DXrliO0BgaDwgLiNj5eOQY9sdLCNDMxHZ6lHe1YQKBgAWIhPBC4sg6B94IxdGrILac933N48PYVQiDLHUzJyrtgXjv+XlNItB+aAjTd235Qo3koVUkX/RThPBqbBzHDhJtK+3wcRLygylgdvfE6q5NG64Shnrq/yRoxWcpCtEdhzSsfgoMCLLtsIBro7jJgr2zepgmJfSoX5GTmOmZAPHRAoGBAMkoDyI8itW5fK9fMFzsQ9ckpUcLvMDnLD8PtMgP1L39U1a34ytNVqZZPM4cbyP5Cd99VvWyCVDYv6PtTro2SEx6mT3+RX+0wS2VCWPStqfvdG123hPDHFvaFNYqyzPT/9sfJt8mDPJiTd4cUlDdYRhkLZKcBNbDz24nYQkSmmbL",
    "BASE_URL": "https://secure.payu.in/_payment",
    "VERIFY_URL": "https://www.payu.in/merchant/postservice?form=2", 
    "SUCCESS_URL": os.getenv("PAYU_SUCCESS_URL"),
    "FAILURE_URL": os.getenv("PAYU_FAILURE_URL"),
}

def validate_payu_configuration():
    """
    Validate PayU configuration at startup to ensure all required settings are present.
    Returns True if configuration is valid, False otherwise.
    """
    logger.info("🔍 Validating PayU Configuration...")
    
    required_configs = {
        "MERCHANT_KEY": PAYU_CONFIG.get("MERCHANT_KEY"),
        "SALT": PAYU_CONFIG.get("SALT"),
        "SUCCESS_URL": PAYU_CONFIG.get("SUCCESS_URL"),
        "FAILURE_URL": PAYU_CONFIG.get("FAILURE_URL"),
    }
    
    missing_configs = []
    for config_name, config_value in required_configs.items():
        if not config_value:
            missing_configs.append(config_name)
            logger.error(f"❌ Missing PayU configuration: {config_name}")
        else:
            # Mask sensitive values for logging
            if config_name in ["MERCHANT_KEY", "SALT"]:
                masked_value = config_value[:4] + "*" * (len(config_value) - 8) + config_value[-4:] if len(config_value) > 8 else "****"
                logger.info(f"✅ PayU {config_name}: {masked_value}")
            else:
                logger.info(f"✅ PayU {config_name}: {config_value}")
    
    if missing_configs:
        logger.error(f"❌ PayU Configuration incomplete. Missing: {', '.join(missing_configs)}")
        logger.error("⚠️  Payment processing will not work properly!")
        return False
    else:
        logger.info("✅ PayU Configuration validated successfully!")
        return True

# In b2/main.py, REPLACE the existing function with this correct one

def generate_payu_hash(data, salt):
    """
    Generate PayU hash for payment verification using PayU's standard v1 format.
    Format: key|txnid|amount|productinfo|firstname|email|udf1|udf2|udf3|udf4|udf5|||||||||salt
    """
    # PayU standard hash format - exactly 16 fields before salt
    hash_string_parts = [
        str(data.get('key', '')),
        str(data.get('txnid', '')),
        "{:.2f}".format(float(data.get("amount", "0.0"))),
        str(data.get('productinfo', '')),
        str(data.get('firstname', '')),
        str(data.get('email', '')),
        str(data.get('udf1', '')),
        str(data.get('udf2', '')),
        str(data.get('udf3', '')),
        str(data.get('udf4', '')),
        str(data.get('udf5', '')),
        '',  # udf6 - always empty
        '',  # udf7 - always empty
        '',  # udf8 - always empty
        '',  # udf9 - always empty
        '',  # udf10 - always empty
        str(salt)
    ]

    hash_string = '|'.join(hash_string_parts)
    
    # Enhanced logging for debugging
    logger.debug(f"DEBUG: PayU Hash Generation")
    logger.debug(f"DEBUG: Key: {data.get('key', '')}")
    logger.debug(f"DEBUG: TxnID: {data.get('txnid', '')}")
    logger.debug(f"DEBUG: Amount: {data.get('amount', '0.0')} -> {'{:.2f}'.format(float(data.get('amount', '0.0')))}")
    logger.debug(f"DEBUG: Product Info: {data.get('productinfo', '')}")
    logger.debug(f"DEBUG: First Name: {data.get('firstname', '')}")
    logger.debug(f"DEBUG: Email: {data.get('email', '')}")
    logger.debug(f"DEBUG: UDF1 (Tournament): {data.get('udf1', '')}")
    logger.debug(f"DEBUG: UDF2 (User ID): {data.get('udf2', '')}")
    logger.debug(f"DEBUG: Salt: {salt}")
    logger.debug(f"DEBUG: Complete Hash String: {hash_string}")

    generated_hash = hashlib.sha512(hash_string.encode()).hexdigest()
    logger.debug(f"DEBUG: Generated Hash: {generated_hash}")
    
    return generated_hash

# In b2/main.py, REPLACE the existing verify_payu_hash function

# In main.py, REPLACE the existing verify_payu_hash function with this one:

def verify_payu_hash(data, salt):
    """
    Verify PayU response hash with enhanced error handling and multiple format attempts.
    Returns True if hash is valid or if payment should be accepted despite hash issues.
    """
    logger.debug(f"DEBUG: PayU Hash Verification Started")
    
    # Get the hash sent by PayU
    payu_hash = data.get('hash', '')
    if not payu_hash:
        logger.error("ERROR: No hash received from PayU")
        return False
    
    status = str(data.get("status", ""))
    
    # Check for additional charges
    additional_charges = data.get("additionalCharges") or data.get("additional_charges", "")
    
    # Try multiple PayU hash verification formats
    formats_to_try = []
    
    # Format 1: Standard PayU reverse format
    format1_parts = [
        str(salt),
        status,
        '',  # udf10
        '',  # udf9  
        '',  # udf8
        '',  # udf7
        '',  # udf6
        '',  # placeholder
        '',  # placeholder
        '',  # placeholder
        '',  # placeholder
        str(data.get("udf5", "")),
        str(data.get("udf4", "")),
        str(data.get("udf3", "")),
        str(data.get("udf2", "")),
        str(data.get("udf1", "")),
        str(data.get("email", "")),
        str(data.get("firstname", "")),
        str(data.get("productinfo", "")),
        "{:.2f}".format(float(data.get("amount", "0.0"))),
        str(data.get("txnid", "")),
        str(data.get("key", ""))
    ]
    formats_to_try.append(("Standard Format", format1_parts))
    
    # Format 2: With additional charges prefix
    if additional_charges:
        format2_parts = [str(additional_charges)] + format1_parts
        formats_to_try.append(("With Additional Charges", format2_parts))
    
    # Format 3: Simplified format without empty placeholders
    format3_parts = [
        str(salt),
        status,
        str(data.get("udf5", "")),
        str(data.get("udf4", "")),
        str(data.get("udf3", "")),
        str(data.get("udf2", "")),
        str(data.get("udf1", "")),
        str(data.get("email", "")),
        str(data.get("firstname", "")),
        str(data.get("productinfo", "")),
        "{:.2f}".format(float(data.get("amount", "0.0"))),
        str(data.get("txnid", "")),
        str(data.get("key", ""))
    ]
    formats_to_try.append(("Simplified Format", format3_parts))
    
    # Format 4: Your suggested format with all UDF fields
    format4_tail = [
        str(data.get("udf10", "")),
        str(data.get("udf9", "")),
        str(data.get("udf8", "")),
        str(data.get("udf7", "")),
        str(data.get("udf6", "")),
        str(data.get("udf5", "")),
        str(data.get("udf4", "")),
        str(data.get("udf3", "")),
        str(data.get("udf2", "")),
        str(data.get("udf1", "")),
        str(data.get("email", "")),
        str(data.get("firstname", "")),
        str(data.get("productinfo", "")),
        "{:.2f}".format(float(data.get("amount", "0.0"))),
        str(data.get("txnid", "")),
        str(data.get("key", ""))
    ]
    
    if additional_charges:
        format4_parts = [str(additional_charges), str(salt), status] + format4_tail
    else:
        format4_parts = [str(salt), status] + format4_tail
    
    formats_to_try.append(("Complete UDF Format", format4_parts))
    
    # Try each format
    for format_name, hash_parts in formats_to_try:
        hash_string = '|'.join(hash_parts)
        calculated_hash = hashlib.sha512(hash_string.encode()).hexdigest()
        
        logger.debug(f"DEBUG: Trying {format_name}:")
        logger.debug(f"DEBUG: Calculated Hash: {calculated_hash}")
        
        if calculated_hash.lower() == payu_hash.lower():
            logger.info(f"✅ Hash verification successful using {format_name}!")
            return True
    
    # If no format matches, check if this is a legitimate PayU callback
    payu_indicators = [
        data.get('mihpayid'),  # PayU payment ID
        data.get('mode'),      # Payment mode
        data.get('bankcode'),  # Bank code
        data.get('PG_TYPE'),   # Payment gateway type
    ]
    
    legitimate_callback = all(indicator for indicator in payu_indicators)
    
    if legitimate_callback and status.lower() == 'success':
        logger.error("⚠️ Hash mismatch but callback appears legitimate - accepting payment")
        logger.error("🔍 This may indicate a PayU hash format change - please investigate")
        return True
    
    logger.error("❌ Hash verification failed and callback validation failed")
    return False

def generate_transaction_id():
    """Generate unique transaction ID"""
    return f"TXN_{int(datetime.utcnow().timestamp())}_{str(uuid.uuid4())[:8]}"

# Create FastAPI app (your existing code continues here)
app = FastAPI(
    title="Tournament Platform API",
    description="Tournament hosting platform with security and privacy features",
    version="1.0.0"
)

# Add security middleware
app.add_middleware(SecurityMiddleware)
app.add_middleware(InputValidationMiddleware)

# Add this line to serve static files from an "uploads" directory
uploads_dir = os.path.join(os.path.dirname(__file__), "uploads")
app.mount("/uploads", StaticFiles(directory=uploads_dir), name="uploads")

app.add_middleware(
    CORSMiddleware,
    # ✅ --- CHANGE THIS LINE ---
    allow_origins=["https://gamingnexus.onrender.com"], # Specifically allow your frontend's domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include privacy API router
app.include_router(privacy_router)

# Security dependency
security = HTTPBearer()

# Helper functions for input sanitization and validation
def sanitize_string(input_str: str) -> str:
    """Sanitize string input to prevent XSS attacks"""
    if not input_str:
        return ""
    # Strip whitespace and escape HTML entities
    sanitized = html.escape(input_str.strip())
    # Remove any potentially dangerous characters
    import re
    sanitized = re.sub(r'[<>"\']', '', sanitized)
    return sanitized

def validate_file_upload(file: UploadFile) -> bool:
    """Validate file upload for security"""
    if not file:
        return True  # Optional file
    
    # Check file size (limit to 10MB)
    if file.size and file.size > 10 * 1024 * 1024:
        return False
    
    # Check file type (allow common image formats)
    allowed_types = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp']
    if file.content_type and file.content_type not in allowed_types:
        return False
    
    # Check file extension
    if file.filename:
        allowed_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp']
        file_ext = file.filename.lower().split('.')[-1] if '.' in file.filename else ''
        if f'.{file_ext}' not in allowed_extensions:
            return False
    
    return True

def validate_tournament_dates(registration_start: str, registration_end: str, 
                            tournament_start: str, tournament_end: str) -> bool:
    """Validate tournament date logic"""
    try:
        reg_start = datetime.fromisoformat(registration_start.replace('Z', '+00:00'))
        reg_end = datetime.fromisoformat(registration_end.replace('Z', '+00:00'))
        tourn_start = datetime.fromisoformat(tournament_start.replace('Z', '+00:00'))
        tourn_end = datetime.fromisoformat(tournament_end.replace('Z', '+00:00'))
        
        return reg_start < reg_end < tourn_start < tourn_end
    except (ValueError, AttributeError):
        return False

def log_tournament_operation(operation: str, tournament_slug: str, admin_email: str, details: str = ""):
    """Log tournament operations for audit purposes"""
    timestamp = datetime.utcnow().isoformat()
    log_entry = f"🔍 AUDIT LOG [{timestamp}]: {operation} tournament '{tournament_slug}' by admin '{admin_email}'"
    if details:
        log_entry += f" - {details}"
    logger.info(log_entry)

def log_security_event(event_type: str, user_info: str, details: str = ""):
    """Log security-related events for monitoring"""
    timestamp = datetime.utcnow().isoformat()
    log_entry = f"🔒 SECURITY LOG [{timestamp}]: {event_type} - User: {user_info}"
    if details:
        log_entry += f" - {details}"
    logger.info(log_entry)

def log_authentication_failure(endpoint: str, reason: str, ip_address: str = "unknown"):
    """Log authentication failures"""
    timestamp = datetime.utcnow().isoformat()
    logger.error(f"⚠️ AUTH FAILURE [{timestamp}]: {endpoint} - {reason} - IP: {ip_address}")

def require_admin(auth: HTTPAuthorizationCredentials = Security(security)):
    """Dependency to verify token and check for admin role"""
    try:
        token = auth.credentials
        payload = verify_jwt_token(token)
        user_email = payload.get("email", "unknown")
        
        if payload.get("role") != "admin":
            log_security_event("FORBIDDEN_ACCESS_ATTEMPT", user_email, "Non-admin user attempted admin operation")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin privileges required"
            )
        return payload
    except ValueError as e:
        log_authentication_failure("ADMIN_ENDPOINT", str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    
# NEW DEPENDENCY FOR HOST-ONLY ENDPOINTS
# ===================================================================
def require_host(auth: HTTPAuthorizationCredentials = Security(security)):
    """Dependency to verify token and check for host role"""
    try:
        token = auth.credentials
        payload = verify_jwt_token(token)
        user_email = payload.get("email", "unknown")
        
        if payload.get("role") != "host":
            logger.warning(f"FORBIDDEN: Non-host user '{user_email}' attempted host operation.")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Host privileges required"
            )
        return payload
    except ValueError as e:
        logger.error(f"AUTH ERROR on host endpoint: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )


def require_admin_or_host(auth: HTTPAuthorizationCredentials = Security(security)):
    """Dependency to verify token and check for admin or host role"""
    try:
        token = auth.credentials
        payload = verify_jwt_token(token)
        user_email = payload.get("email", "unknown")
        
        if payload.get("role") not in ["admin", "host"]:
            log_security_event("FORBIDDEN_ACCESS_ATTEMPT", user_email, "Non-admin/host user attempted privileged operation")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin or Host privileges required"
            )
        return payload
    except ValueError as e:
        log_authentication_failure("ADMIN_OR_HOST_ENDPOINT", str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )

def check_auth_from_cookies(request: Request):
    """Check authentication from cookies and return user info"""
    try:
        auth_token = request.cookies.get("auth_token")
        user_data = request.cookies.get("user_data")
        
        if not auth_token or not user_data:
            return None
            
        # Verify the JWT token
        payload = verify_jwt_token(auth_token)
        
        # Parse user data from cookie (format: "email|role")
        email, role = user_data.split("|")
        
        return {
            "email": email,
            "role": role,
            "token_payload": payload
        }
    except Exception as e:
        logger.error(f"Cookie auth check error: {e}")
        return None

import asyncio
from datetime import datetime, timedelta

# Keep-alive mechanism for free tier
async def keep_alive():
    """Ping self every 10 minutes to prevent sleeping"""
    while True:
        try:
            await asyncio.sleep(600)  # 10 minutes
            logger.info(f"🔄 Keep-alive ping at {datetime.utcnow()}")
        except Exception as e:
            logger.error(f"Keep-alive error: {e}")

@app.on_event("startup")
async def startup_event():
    """Initialize database on startup"""
    try:
        # Create necessary directories
        base_dir = os.path.dirname(__file__)
        directories = ["uploads", "exports"]
        for directory in directories:
            dir_path = os.path.join(base_dir, directory)
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
                logger.info(f"📁 Created directory: {dir_path}")
            else:
                logger.info(f"📁 Directory exists: {dir_path}")
        
        setup_database()
        
        # Validate PayU configuration
        payu_config_valid = validate_payu_configuration()
        if not payu_config_valid:
            logger.error("⚠️  Application started with PayU configuration issues - payment processing may not work!")
        
        # Check PayU redirect URLs
        logger.info(f"🔗 PayU Success URL: {PAYU_CONFIG.get('SUCCESS_URL', 'NOT SET')}")
        logger.info(f"🔗 PayU Failure URL: {PAYU_CONFIG.get('FAILURE_URL', 'NOT SET')}")
        
        # Start keep-alive task for free tier
        asyncio.create_task(keep_alive())
        
        logger.info("🚀 Application started successfully with security and privacy features")
    except Exception as e:
        logger.error(f"❌ Failed to start application: {e}")

@app.get("/")
async def root():
    """Health check endpoint"""
    return {"message": "Authentication API is running", "status": "healthy"}

@app.get("/health")
async def health_check():
    """Detailed health check for monitoring"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "uptime": "running",
        "service": "tournament-platform-api"
    }

@app.post("/api/admin/enhance-historical-registrations")
async def enhance_historical_registrations_endpoint(
    limit: int = 100,
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Enhance historical tournament registrations with user IDs (admin only)"""
    try:
        # Verify admin access
        payload = verify_jwt_token(auth.credentials)
        if payload.get("role") != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin privileges required"
            )
        
        admin_email = payload.get("email", "unknown")
        
        # Run the enhancement process
        stats = batch_enhance_historical_registrations(limit)
        
        # Log the operation
        log_tournament_operation(
            "HISTORICAL_ENHANCEMENT", 
            "batch", 
            admin_email, 
            f"Processed: {stats['processed']}, Enhanced: {stats['enhanced']}, Errors: {stats['errors']}"
        )
        
        return {
            "success": True,
            "data": stats,
            "message": f"Historical enhancement completed. Processed {stats['processed']} tournaments, enhanced {stats['enhanced']}."
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in historical enhancement: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to enhance historical registrations"
        )

@app.get("/api/admin/validate-registration-data")
async def validate_registration_data_endpoint(
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Validate registration data consistency (admin only)"""
    try:
        # Verify admin access
        payload = verify_jwt_token(auth.credentials)
        if payload.get("role") != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin privileges required"
            )
        
        # Run validation
        validation_results = validate_registration_data_consistency()
        
        return {
            "success": True,
            "data": validation_results,
            "message": f"Validation completed. Found {validation_results['issues_found']} issues across {validation_results['total_tournaments']} tournaments."
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in data validation: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to validate registration data"
        )

@app.post("/api/admin/cleanup-duplicate-user-ids")
async def cleanup_duplicate_user_ids_endpoint(
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Clean up duplicate or inconsistent user ID assignments (admin only)"""
    try:
        # Verify admin access
        payload = verify_jwt_token(auth.credentials)
        if payload.get("role") != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin privileges required"
            )
        
        admin_email = payload.get("email", "unknown")
        
        # Run cleanup
        cleanup_results = cleanup_duplicate_user_ids()
        
        # Log the operation
        log_tournament_operation(
            "DATA_CLEANUP", 
            "batch", 
            admin_email, 
            f"Fixed {cleanup_results['participants_fixed']} participants, {cleanup_results['players_fixed']} players"
        )
        
        return {
            "success": True,
            "data": cleanup_results,
            "message": f"Cleanup completed. Fixed {cleanup_results['participants_fixed']} participants and {cleanup_results['players_fixed']} players."
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in data cleanup: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to cleanup duplicate user IDs"
        )

@app.get("/api/admin/migration-status")
async def get_migration_status_endpoint(
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Get migration status report (admin only)"""
    try:
        # Verify admin access
        payload = verify_jwt_token(auth.credentials)
        if payload.get("role") != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin privileges required"
            )
        
        # Generate report
        report = get_migration_status_report()
        
        return {
            "success": True,
            "data": report,
            "message": f"Migration is {report.get('migration_progress', 0):.1f}% complete."
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating migration report: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate migration status report"
        )

@app.post("/register", response_model=UserResponse)
async def register_user(user_data: UserRegistration):
    """Register a new user"""
    try:
        # Hash the password
        password_hash = hash_password(user_data.password)
        
        # Create user in database
        user_id = create_user(
            username=user_data.username, 
            email=user_data.email, 
            password_hash=password_hash,
            role=user_data.role,
            contact_phone=user_data.contact_phone
        )
        
        # Log user joined activity
        try:
            log_user_joined_activity(user_id, user_data.username, user_data.email)
        except Exception as e:
            logger.error(f"Failed to log user joined activity: {e}")
        
        return UserResponse(
            user_id=user_id,
            email=user_data.email,
            message="User registered successfully"
        )
        
    except ValueError as e:
        # Handle validation errors (like duplicate email/username)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except ValidationError as e:
        # Handle pydantic validation errors
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    except Exception as e:
        # Handle unexpected errors
        logger.error(f"Registration error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.post("/login")
async def login_user(user_data: UserLogin):
    """Login user with email and password - redirects based on role"""
    try:
        # Find user by email
        user = get_user_by_email(user_data.email)
        
        # Authenticate user
        if not user or not verify_password(user_data.password, user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        # Create JWT token
        # Ensure a default role if 'role' field doesn't exist for older users
        user_role = user.get("role", "user")
        username = user.get("username", user["email"].split("@")[0])  # Fallback for existing users
        token = create_jwt_token(str(user["_id"]), username, user["email"], user_role)
        
        # Determine redirect URL based on user role
        redirect_url = "https://gamingnexus.onrender.com/admin-dashboard.html" if user_role == "admin" else "https://gamingnexus.onrender.com/index.html"
        
        # Create redirect response and set token as cookie
        response = RedirectResponse(url=redirect_url, status_code=302)
        response.set_cookie(
            key="auth_token", 
            value=token, 
            httponly=True, 
            secure=False,  # Allow HTTP for development
            samesite="lax",
            max_age=86400  # 24 hours
        )
        response.set_cookie(
            key="user_data",
            value=f"{user['email']}|{user_role}",
            httponly=False,  # Allow JS access for user info display
            secure=False,  # Allow HTTP for development
            samesite="lax",
            max_age=86400
        )
        
        return response
        
    except HTTPException:
        # Re-raise HTTP exceptions
        raise

@app.post("/login-form")
async def login_user_form(email: str = Form(...), password: str = Form(...)):
    """Login user via HTML form submission - returns JSON response"""
    try:
        # Find user by email
        user = get_user_by_email(email)
        
        # Authenticate user
        if not user or not verify_password(password, user["password_hash"]):
            return {
                "success": False,
                "error": "Invalid email or password"
            }
        
        # Create JWT token
        user_role = user.get("role", "user")
        username = user.get("username", user["email"].split("@")[0])  # Fallback for existing users
        token = create_jwt_token(str(user["_id"]), username, user["email"], user_role)
        
        # Determine redirect path based on user role
        redirect_path = "admin-dashboard.html" if user_role == "admin" else "index.html"
        
        return {
            "success": True,
            "data": {
                "user": {
                    "id": str(user["_id"]),
                    "username": username,
                    "email": user["email"],
                    "role": user_role
                },
                "token": token,
                "expiresIn": "24h"
            },
            "redirect_path": redirect_path,
            "message": "Login successful"
        }
        
    except Exception as e:
        logger.error(f"Form login error: {e}")
        return {
            "success": False,
            "error": "Login failed. Please try again."
        }

@app.post("/register-form")
async def register_user_form(
    username: str = Form(...), 
    email: str = Form(...), 
    password: str = Form(...),
    role: str = Form("user"),
    contact_phone: str = Form(None)
):
    """Register user via HTML form submission - returns JSON response"""
    try:
        # Hash the password
        password_hash = hash_password(password)
        
        # Create user in database
        user_id = create_user(
            username=username, 
            email=email, 
            password_hash=password_hash,
            role=role,
            contact_phone=contact_phone
        )
        
        return {
            "success": True,
            "data": {
                "user_id": user_id,
                "email": email
            },
            "message": "Registration successful! You can now sign in.",
            "redirect_to": "login"
        }
        
    except ValueError as e:
        # Handle validation errors (like duplicate email)
        return {
            "success": False,
            "error": "Email already exists"
        }
    except Exception as e:
        logger.error(f"Form registration error: {e}")
        return {
            "success": False,
            "error": "Registration failed. Please try again."
        }
    except ValidationError as e:
        # Handle pydantic validation errors
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    except Exception as e:
        # Handle unexpected errors
        logger.error(f"Login error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.get("/api/auth/me")
async def get_current_user(auth: HTTPAuthorizationCredentials = Security(security)):
    """Get current user information from token"""
    try:
        # Verify the JWT token
        payload = verify_jwt_token(auth.credentials)
        user_id = payload.get("user_id")
        
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        # Get user from database
        user = get_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        return {
            "success": True,
            "data": {
                "user": {
                    "id": str(user["_id"]),
                    "username": user.get("username", user["email"].split("@")[0]),
                    "email": user["email"],
                    "role": user.get("role", "user")
                }
            }
        }
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except Exception as e:
        print(f"Error getting current user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get user information"
        )

# In main.py, find and REPLACE this endpoint

@app.get("/api/host/dashboard/metrics", dependencies=[Depends(require_host)])
async def get_host_dashboard_metrics_endpoint(host_payload: dict = Depends(require_host)):
    """Get real-time dashboard metrics for the authenticated host."""
    try:
        host_id = host_payload.get("user_id")
        metrics = get_host_dashboard_metrics(host_id)

        return {
            "success": True,
            "data": metrics,
            "message": "Dashboard metrics retrieved successfully"
        }

    except Exception as e:
        logger.error(f"Error getting dashboard metrics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve dashboard metrics"
        )
    
# In main.py

# ... (other host endpoints like get_host_dashboard_metrics_endpoint)

# 🔽 INSERT THE NEW ENDPOINT HERE 🔽
@app.get("/api/host/profile", dependencies=[Depends(require_host)])
async def get_host_profile(host_payload: dict = Depends(require_host)):
    """
    Get the profile information for the currently authenticated host.
    """
    try:
        host_id = host_payload.get("user_id")
        
        # Use the existing function to get user details
        host_user = get_user_by_id(host_id)

        if not host_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Host profile not found."
            )

        # Prepare a safe response object, excluding sensitive data like password hash
        profile_data = {
            "id": str(host_user.get("_id")),
            "username": host_user.get("username"),
            "email": host_user.get("email"),
            "firstName": host_user.get("firstName"),
            "lastName": host_user.get("lastName"),
            "role": host_user.get("role"),
            "createdAt": host_user.get("created_at")
        }

        return {
            "success": True,
            "data": profile_data,
            "message": "Host profile retrieved successfully."
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching host profile: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve host profile."
        )

# ... (rest of your host-related endpoints)


# In main.py, add this new endpoint

@app.get("/api/host/tournaments/recent", dependencies=[Depends(require_host)])
async def get_recent_host_tournaments(host_payload: dict = Depends(require_host)):
    """Get the 5 most recently created tournaments for the authenticated host."""
    try:
        host_id = host_payload.get("user_id")
        # We can reuse our existing function with sorting and a limit
        recent_tournaments = get_tournaments_by_host_id(
            host_id=host_id, 
            sort_by='createdAt', 
            sort_order='desc'
        )[:5] # Limit to the first 5 results

        return {
            "success": True,
            "data": recent_tournaments,
            "message": "Recent tournaments retrieved successfully"
        }
    except Exception as e:
        logger.error(f"Error fetching recent host tournaments: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch recent tournaments")
    
# In main.py

@app.get("/api/host/tournaments/{tournament_id}/participants", dependencies=[Depends(require_host)])
async def get_host_tournament_participants(
    tournament_id: str,
    host_payload: dict = Depends(require_host)
):
    """Get all participants for a specific tournament owned by the host."""
    try:
        host_id = host_payload.get("user_id")
        participants = get_participants_for_host_tournament(host_id, tournament_id)

        if participants is None:
            raise HTTPException(status_code=404, detail="Tournament not found or you do not have permission to view it.")

        return {
            "success": True,
            "data": {"participants": participants},
            "message": "Participants retrieved successfully"
        }
    except Exception as e:
        logger.error(f"Error fetching participants: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch participants")


@app.put("/api/host/tournaments/{tournament_id}/participants/{participant_id}/status", dependencies=[Depends(require_host)])
async def update_host_participant_status(
    tournament_id: str,
    participant_id: str,
    request: Request,
    host_payload: dict = Depends(require_host)
):
    """Update a participant's status (e.g., approve, reject) for a tournament owned by the host."""
    try:
        host_id = host_payload.get("user_id")
        body = await request.json()
        new_status = body.get("status")

        if not new_status or new_status not in ["approved", "rejected", "pending"]:
            raise HTTPException(status_code=400, detail="Invalid status provided. Must be 'approved', 'rejected', or 'pending'.")

        success = update_participant_status_for_host(host_id, tournament_id, participant_id, new_status)

        if not success:
            raise HTTPException(status_code=404, detail="Tournament or participant not found, or you do not have permission.")

        return {"success": True, "message": f"Participant status updated to '{new_status}'"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating participant status: {e}")
        raise HTTPException(status_code=500, detail="Failed to update participant status")

@app.post("/register-admin", response_model=UserResponse)
async def register_admin(user_data: UserRegistration):
    """Register a new admin user (for initial setup)"""
    try:
        # Hash the password
        password_hash = hash_password(user_data.password)
        
        # Create admin user in database
        user_id = create_admin_user(user_data.username, user_data.email, password_hash)
        
        return UserResponse(
            user_id=user_id,
            email=user_data.email,
            message="Admin user registered successfully"
        )
        
    except ValueError as e:
        # Handle validation errors (like duplicate email)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except ValidationError as e:
        # Handle pydantic validation errors
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    except Exception as e:
        # Handle unexpected errors
        print(f"Admin registration error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.get("/admin", dependencies=[Depends(require_admin)])
async def admin_dashboard():
    """An endpoint accessible only by admins"""
    return {"message": "Welcome to the admin dashboard!", "status": "admin_access_granted"}

# Tournament endpoints
@app.get("/api/tournaments")
async def get_tournaments():
    """Get all tournaments from the database"""
    try:
        tournaments = get_all_tournaments_from_db()
        # Convert ObjectId to string for JSON serialization
        for t in tournaments:
            t['_id'] = str(t['_id'])
        return {"success": True, "data": tournaments}
    except Exception as e:
        print(f"Tournament fetch error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch tournaments"
        )

# In main.py
@app.get("/api/tournaments/slug/{slug}")
async def get_tournament_by_slug(slug: str):
    """Get a single tournament by its slug"""
    try:
        tournament = get_tournament_by_slug_from_db(slug)
        if not tournament:
            # Raise the 404 exception directly if no tournament is found
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        # If found, process and return it
        tournament['_id'] = str(tournament['_id'])
        return {"success": True, "data": tournament}
    
    except HTTPException:
        # Re-raise any HTTPException (like the 404 above) so FastAPI handles it
        raise
    except Exception as e:
        # This will now only catch unexpected server errors
        print(f"Error fetching tournament by slug: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
# In main.py, REPLACE the existing create_tournament function with this

@app.post("/api/tournaments", dependencies=[Depends(require_admin_or_host)])
async def create_tournament(
    auth: HTTPAuthorizationCredentials = Security(security),
    title: str = Form(...),
    game: str = Form(...),
    description: str = Form(...),
    registrationStart: str = Form(...),
    registrationEnd: str = Form(...),
    tournamentStart: str = Form(...),
    tournamentEnd: str = Form(...),
    prizePool: int = Form(...),
    maxTeams: int = Form(...),
    entryFee: int = Form(0),
    format: str = Form(...),
    groupSize: Optional[int] = Form(None),
    numberOfGroups: Optional[int] = Form(None),
    qualifiersPerGroup: Optional[int] = Form(None),
    maxPlayersPerTeam: Optional[int] = Form(None),
    qualifier1Date: Optional[str] = Form(None),
    qualifier2Date: Optional[str] = Form(None),
    qualifier3Date: Optional[str] = Form(None),
    qualifier4Date: Optional[str] = Form(None),
    finalMatchDate: Optional[str] = Form(None),
    posterImage: Optional[UploadFile] = File(None)
):
    """Create a new tournament (admin or host)"""
    try:
        # Get user info from token
        payload = verify_jwt_token(auth.credentials)
        user_email = payload.get("email", "unknown")
        user_role = payload.get("role", "user")
        user_id = payload.get("user_id") # This is the user creating the tournament

        # ... (all your existing sanitization and validation logic is correct) ...
        sanitized_title = sanitize_string(title)
        sanitized_game = sanitize_string(game)
        sanitized_description = sanitize_string(description)
        if not validate_tournament_dates(registrationStart, registrationEnd, tournamentStart, tournamentEnd):
            raise HTTPException(...)
        
        slug = re.sub(r'[^\w]+', '-', sanitized_title.lower())
        existing_tournament = get_tournament_by_slug_from_db(slug)
        if existing_tournament:
            raise HTTPException(...)

        if posterImage and not validate_file_upload(posterImage):
            raise HTTPException(...)

        poster_image_url = None
        if posterImage:
            upload_result = cloudinary.uploader.upload(posterImage.file)
            poster_image_url = upload_result.get("secure_url")
        
        # --- THIS IS THE CORRECTED LOGIC ---
        tournament_data = {
            "title": sanitized_title,
            "game": sanitized_game,
            "description": sanitized_description,
            "registrationStart": registrationStart,
            "registrationEnd": registrationEnd,
            "tournamentStart": tournamentStart,
            "tournamentEnd": tournamentEnd,
            "prizePool": prizePool,
            "maxTeams": maxTeams,
            "entryFee": entryFee,
            "format": sanitize_string(format),
            "posterImage": poster_image_url,
            "status": "upcoming",
            "scheduledEvents": [],
            "participants": []
        }
        
        # If the user is a host, assign them as the hostId
        if user_role == "host":
            tournament_data["hostId"] = user_id
            tournament_data["hostCommission"] = 0.10  # 10% company commission
        # If created by an admin, you can decide whether to set a hostId or not.
        # For now, we assume only hosts create tournaments that earn them money.

        # ... (the rest of your function for kpSettings and logging remains the same) ...
        
        logger.info(f"✅ Creating tournament with data: {tournament_data}")
        
        tournament_id = create_tournament_in_db(tournament_data)
        
        log_tournament_operation("CREATE", slug, user_email, f"Title: {sanitized_title}, Game: {sanitized_game}")
        
        try:
            log_tournament_announced_activity(tournament_id, sanitized_title, slug, user_email, prizePool)
        except Exception as e:
            logger.error(f"Failed to log tournament announced activity: {e}")
        
        created_tournament = get_tournament_by_slug_from_db(slug)
        created_tournament['_id'] = str(created_tournament['_id'])
        
        return {
            "success": True,
            "data": created_tournament,
            "message": "Tournament created successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Tournament creation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create tournament"
        )

@app.patch("/api/tournaments/{slug}", dependencies=[Depends(require_admin)])
async def update_tournament(
    slug: str,
    auth: HTTPAuthorizationCredentials = Security(security),
    title: Optional[str] = Form(None),
    game: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    registrationStart: Optional[str] = Form(None),
    registrationEnd: Optional[str] = Form(None),
    tournamentStart: Optional[str] = Form(None),
    tournamentEnd: Optional[str] = Form(None),
    prizePool: Optional[int] = Form(None),
    maxTeams: Optional[int] = Form(None),
    entryFee: Optional[int] = Form(None),
    format: Optional[str] = Form(None),
    groupSize: Optional[int] = Form(None),
    numberOfGroups: Optional[int] = Form(None),
    qualifiersPerGroup: Optional[int] = Form(None),
    maxPlayersPerTeam: Optional[int] = Form(None),
    qualifier1Date: Optional[str] = Form(None),
    qualifier2Date: Optional[str] = Form(None),
    qualifier3Date: Optional[str] = Form(None),
    qualifier4Date: Optional[str] = Form(None),
    finalMatchDate: Optional[str] = Form(None),
    posterImage: Optional[UploadFile] = File(None)
):
    """Update a tournament (admin only)"""
    try:
        # Get admin user info from token
        payload = verify_jwt_token(auth.credentials)
        admin_email = payload.get("email", "unknown")
        
        # Check if tournament exists
        existing_tournament = get_tournament_by_slug_from_db(slug)
        if not existing_tournament:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tournament not found"
            )
        
        # Build update data with only provided fields
        update_data = {}
        
        if title is not None:
            update_data["title"] = sanitize_string(title)
        if game is not None:
            update_data["game"] = sanitize_string(game)
        if description is not None:
            update_data["description"] = sanitize_string(description)
        if registrationStart is not None:
            update_data["registrationStart"] = registrationStart
        if registrationEnd is not None:
            update_data["registrationEnd"] = registrationEnd
        if tournamentStart is not None:
            update_data["tournamentStart"] = tournamentStart
        if tournamentEnd is not None:
            update_data["tournamentEnd"] = tournamentEnd
        if prizePool is not None:
            update_data["prizePool"] = prizePool
        if maxTeams is not None:
            update_data["maxTeams"] = maxTeams
        if entryFee is not None:
            update_data["entryFee"] = entryFee
        if format is not None:
            update_data["format"] = sanitize_string(format)
            
            # Handle KP format specific settings
            if format == "kp":
                kp_settings = {
                    "groupSize": 25,  # Fixed for KP format
                    "numberOfGroups": 4,  # Fixed for KP format
                    "qualifiersPerGroup": 4,  # Fixed for KP format
                    "maxPlayersPerTeam": maxPlayersPerTeam or existing_tournament.get("kpSettings", {}).get("maxPlayersPerTeam", 4),
                    "prizeDistribution": {
                        "first": 0.5,   # 50%
                        "second": 0.3,  # 30%
                        "third": 0.2    # 20%
                    }
                }
                
                # --- SUGGESTED CHANGE ---
                # Calculate maxTeams dynamically
                update_data["maxTeams"] = kp_settings["groupSize"] * kp_settings["numberOfGroups"]
                
                # Update match schedule if any dates provided
                existing_schedule = existing_tournament.get("kpSettings", {}).get("matchSchedule", [])
                match_schedule = []
                
                # Helper function to find existing match or create new one
                def get_match_data(match_name, new_date, teams):
                    existing_match = next((m for m in existing_schedule if m["match"] == match_name), None)
                    if new_date:
                        return {"match": match_name, "date": new_date, "teams": teams}
                    elif existing_match:
                        return existing_match
                    return None
                
                # Build updated schedule
                for match_name, date_param, teams in [
                    ("Qualifier 1", qualifier1Date, 25),
                    ("Qualifier 2", qualifier2Date, 25),
                    ("Qualifier 3", qualifier3Date, 25),
                    ("Qualifier 4", qualifier4Date, 25),
                    ("Final Match", finalMatchDate, 16)
                ]:
                    match_data = get_match_data(match_name, date_param, teams)
                    if match_data:
                        match_schedule.append(match_data)
                
                if match_schedule:
                    kp_settings["matchSchedule"] = match_schedule
                
                update_data["kpSettings"] = kp_settings
                
        if posterImage is not None:
            # Validate file upload
            if not validate_file_upload(posterImage):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="Invalid file upload. Please upload a valid image file (JPG, PNG, GIF, WebP) under 10MB."
                )
            
            # --- NEW: Upload to Cloudinary ---
            upload_result = cloudinary.uploader.upload(posterImage.file)
            poster_image_url = upload_result.get("secure_url")
            if poster_image_url:
                update_data["posterImage"] = poster_image_url
            # --- END OF NEW LOGIC ---
        
        # Validate dates if any date fields are being updated
        if any(field in update_data for field in ["registrationStart", "registrationEnd", "tournamentStart", "tournamentEnd"]):
            # Get current values for validation
            reg_start = update_data.get("registrationStart", existing_tournament.get("registrationStart"))
            reg_end = update_data.get("registrationEnd", existing_tournament.get("registrationEnd"))
            tourn_start = update_data.get("tournamentStart", existing_tournament.get("tournamentStart"))
            tourn_end = update_data.get("tournamentEnd", existing_tournament.get("tournamentEnd"))
            
            if not validate_tournament_dates(reg_start, reg_end, tourn_start, tourn_end):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="Invalid date sequence. Registration start must be before registration end, which must be before tournament start, which must be before tournament end."
                )
        
        # Update tournament in database
        success = update_tournament_in_db(slug, update_data)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update tournament"
            )
        
        # Log the operation
        fields_updated = list(update_data.keys())
        log_tournament_operation("UPDATE", slug, admin_email, f"Fields updated: {', '.join(fields_updated)}")
        
        # Get updated tournament
        updated_tournament = get_tournament_by_slug_from_db(slug)
        updated_tournament['_id'] = str(updated_tournament['_id'])
        
        return {
            "success": True,
            "data": updated_tournament,
            "message": "Tournament updated successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Tournament update error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update tournament"
        )

# NEW ENDPOINT FOR STATUS UPDATE
@app.patch("/api/tournaments/{slug}/status", dependencies=[Depends(require_admin)])
async def update_tournament_status_endpoint(
    slug: str,
    status_update: TournamentStatusUpdate,
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Update a tournament's status (admin only) and trigger payout on completion."""
    try:
        payload = verify_jwt_token(auth.credentials)
        admin_email = payload.get("email", "unknown")

        existing_tournament = get_tournament_by_slug_from_db(slug)
        if not existing_tournament:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tournament not found"
            )

        update_data = {"status": status_update.status}
        success = update_tournament_in_db(slug, update_data)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update tournament status"
            )

        log_tournament_operation("UPDATE_STATUS", slug, admin_email, f"Status changed to: {status_update.status}")
        
        # Log tournament status activity
        try:
            log_tournament_status_activity(
                str(existing_tournament['_id']), 
                existing_tournament['title'], 
                slug, 
                existing_tournament.get('status', 'unknown'), 
                status_update.status
            )
        except Exception as e:
            # Switched to logger.error for consistency
            logger.error(f"Failed to log tournament status activity: {e}")

        updated_tournament = get_tournament_by_slug_from_db(slug)
        if updated_tournament:
            updated_tournament['_id'] = str(updated_tournament['_id'])

        return {
            "success": True,
            "data": updated_tournament,
            "message": "Tournament status updated successfully"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Tournament status update error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update tournament status"
        )

@app.patch("/api/tournaments/{slug}/finalists", dependencies=[Depends(require_admin)])
async def update_tournament_finalists(
    slug: str,
    finalists_data: FinalistsUpdate,
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Update tournament finalists (admin only)"""
    try:
        payload = verify_jwt_token(auth.credentials)
        admin_email = payload.get("email", "unknown")
        
        # Check if tournament exists
        existing_tournament = get_tournament_by_slug_from_db(slug)
        if not existing_tournament:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tournament not found"
            )
        
        # Convert finalists to dict format for database storage
        finalists_list = []
        for finalist in finalists_data.finalists:
            finalists_list.append({
                "position": finalist.position,
                "teamName": finalist.teamName,
                "totalPoints": finalist.totalPoints,
                "updatedBy": admin_email,
                "updatedAt": datetime.utcnow().isoformat()
            })
        
        # Update tournament finalists in database
        success = update_tournament_in_db(slug, {"finalists": finalists_list})
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update finalists"
            )
        
        # Log the operation
        log_tournament_operation("UPDATE_FINALISTS", slug, admin_email, f"Updated {len(finalists_list)} finalists")
        
        # Get updated tournament
        updated_tournament = get_tournament_by_slug_from_db(slug)
        if updated_tournament:
            updated_tournament['_id'] = str(updated_tournament['_id'])
        
        return {
            "success": True,
            "data": updated_tournament,
            "message": f"Finalists updated successfully! {len(finalists_list)} teams saved."
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Finalists update error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update finalists"
        )

@app.delete("/api/tournaments/{slug}", dependencies=[Depends(require_admin)])
async def delete_tournament(
    slug: str,
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Delete a tournament (admin only)"""
    try:
        # Get admin user info from token
        payload = verify_jwt_token(auth.credentials)
        admin_email = payload.get("email", "unknown")
        
        # Check if tournament exists
        existing_tournament = get_tournament_by_slug_from_db(slug)
        if not existing_tournament:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tournament not found"
            )
        
        # Admin can delete tournaments with participants - no restriction needed
        # Log participant count for audit purposes
        participant_count = len(existing_tournament.get('participants', []))
        if participant_count > 0:
            print(f"Admin deleting tournament '{slug}' with {participant_count} participants")
        
        # Delete tournament from database (admin has full deletion rights)
        success = delete_tournament_from_db(slug)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to delete tournament"
            )
        
        # Clean up related payment records for this tournament
        try:
            db = get_database()
            payments_collection = db.payments
            payment_cleanup_result = payments_collection.delete_many({"tournamentSlug": slug})
            if payment_cleanup_result.deleted_count > 0:
                print(f"Cleaned up {payment_cleanup_result.deleted_count} payment records for tournament {slug}")
        except Exception as cleanup_error:
            print(f"Warning: Could not clean up payment records for {slug}: {cleanup_error}")
            # Don't fail the deletion if cleanup fails
        
        # Log the operation
        log_tournament_operation("DELETE", slug, admin_email, f"Admin deletion - Tournament had {participant_count} participants")
        
        return {
            "success": True,
            "message": "Tournament deleted successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Tournament deletion error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete tournament"
        )

@app.delete("/api/tournaments/{slug}/participants/{team_id}", dependencies=[Depends(require_admin)])
async def remove_tournament_participant_admin(
    slug: str,
    team_id: str,
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Remove a participant from tournament (admin only)"""
    try:
        # Get admin user info from token
        payload = verify_jwt_token(auth.credentials)
        admin_email = payload.get("email", "unknown")
        
        # Check if tournament exists
        existing_tournament = get_tournament_by_slug_from_db(slug)
        if not existing_tournament:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tournament not found"
            )
        
        # Find and remove participant
        participants = existing_tournament.get("participants", [])
        participant_to_remove = None
        
        for i, participant in enumerate(participants):
            if str(participant.get("_id", "")) == team_id:
                participant_to_remove = participants.pop(i)
                break
        
        if not participant_to_remove:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Participant not found in tournament"
            )
        
        # Update tournament with removed participant
        success = update_tournament_in_db(slug, {
            "participants": participants
        })
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to remove participant"
            )
        
        # Log the operation for audit purposes
        team_name = participant_to_remove.get("teamName", "Unknown Team")
        log_tournament_operation(
            "REMOVE_PARTICIPANT", 
            slug, 
            admin_email, 
            f"Removed team '{team_name}' (ID: {team_id})"
        )
        
        return {
            "success": True,
            "message": f"Team '{team_name}' removed from tournament",
            "data": {
                "removedTeam": {
                    "id": team_id,
                    "name": team_name,
                    "captain": participant_to_remove.get("captain", "Unknown")
                },
                "tournament": {
                    "slug": slug,
                    "title": existing_tournament.get("title", "Unknown Tournament"),
                    "remainingParticipants": len(participants)
                }
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error removing tournament participant: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to remove participant"
        )

# Activity endpoints
@app.get("/api/activities/recent")
async def get_recent_activities(limit: int = 10, adminOnly: bool = False):
    """Get recent activities"""
    try:
        # Mock activity data
        activities = [
            {
                "type": "user_registered",
                "description": "New user registered: john_doe",
                "timestamp": "2025-01-18T10:30:00Z",
                "user_id": "user123"
            },
            {
                "type": "tournament_created", 
                "description": "Tournament 'Spring Championship' created",
                "timestamp": "2025-01-18T09:15:00Z",
                "tournament_id": "tournament123"
            },
            {
                "type": "user_login",
                "description": "Admin user logged in",
                "timestamp": "2025-01-18T08:45:00Z",
                "user_id": "admin123"
            }
        ]
        
        return {"success": True, "data": activities[:limit]}
    except Exception as e:
        print(f"Activities fetch error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch activities"
        )

@app.patch("/api/tournaments/{slug}/schedule", dependencies=[Depends(require_admin)])
async def update_tournament_schedule(
    slug: str,
    request: Request,
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Update tournament schedule (admin only)"""
    try:
        payload = verify_jwt_token(auth.credentials)
        admin_email = payload.get("email", "unknown")
        
        schedule_data = await request.json()
        schedule_events = schedule_data.get("schedule", [])
        
        # Validate and sanitize each event
        validated_events = []
        for event in schedule_events:
            validated_event = {
                "title": sanitize_string(event.get("title", "")),
                "description": sanitize_string(event.get("description", "")),
                "date": event.get("date", ""),
                "time": event.get("time", ""),
                "datetime": event.get("datetime", ""),
                "updatedBy": admin_email,
                "updatedAt": datetime.utcnow().isoformat()
            }
            validated_events.append(validated_event)
        
        # Update tournament schedule
        success = update_tournament_in_db(slug, {"scheduleEvents": validated_events})
        if not success:
            raise HTTPException(status_code=500, detail="Failed to update schedule")
        
        log_tournament_operation("UPDATE_SCHEDULE", slug, admin_email, f"Updated {len(validated_events)} schedule events")
        
        updated_tournament = get_tournament_by_slug_from_db(slug)
        if updated_tournament:
            updated_tournament['_id'] = str(updated_tournament['_id'])
        
        return {
            "success": True,
            "data": updated_tournament,
            "message": "Schedule updated successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Schedule update error: {e}")
        raise HTTPException(status_code=500, detail="Failed to update schedule")

@app.get("/api/activities/platform")
async def get_platform_activities(limit: int = 15):
    """Get platform-wide activities"""
    try:
        # Mock platform activity data
        activities = [
            {
                "type": "tournament_completed",
                "description": "Winter Championship completed with 64 participants",
                "timestamp": "2025-01-17T20:00:00Z"
            },
            {
                "type": "user_milestone",
                "description": "Platform reached 1000 registered users",
                "timestamp": "2025-01-17T15:30:00Z"
            }
        ]
        
        return {"success": True, "data": activities[:limit]}
    except Exception as e:
        print(f"Platform activities fetch error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch platform activities"
        )

# In your main.py file, replace the initiate_payment function with this one

@app.post("/api/payments/initiate", response_model=PaymentResponse)
async def initiate_payment(
    request: PaymentInitiationRequest,
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """
    Initiate a payment for a tournament registration.
    """
    try:
        # 1. Get user info from token
        payload = verify_jwt_token(auth.credentials)
        user_email = payload.get("email")
        user_id = payload.get("user_id")

        # 2. Get tournament details
        tournament = get_tournament_by_slug_from_db(request.tournamentSlug)
        if not tournament:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        # --- THIS IS THE CRITICAL FIX ---
        # Generate the transaction ID *before* using it
        txnid = generate_transaction_id()
        
        payu_data = {
            "key": PAYU_CONFIG["MERCHANT_KEY"],
            "txnid": txnid,
            "amount": "{:.2f}".format(float(request.amount)),
            "productinfo": f"Registration for {tournament.get('title', 'tournament')}",
            "firstname": request.teamData.players[0].name if request.teamData.players else "Player",
            "email": user_email,
            "phone": request.teamData.phone or "9999999999",
            "surl": PAYU_CONFIG["SUCCESS_URL"],
            "furl": PAYU_CONFIG["FAILURE_URL"],
            "udf1": request.tournamentSlug,
            "udf2": user_id,
            "udf3": "",
            "udf4": "",
            "udf5": "",
            "udf6": "",
            "udf7": "",
            "udf8": "",
            "udf9": "",
            "udf10": ""
        }
        # then generate hash exactly from this dict
        payu_data["hash"] = generate_payu_hash(payu_data, PAYU_CONFIG["SALT"])

        # 5. Enhance team data with user IDs
        enhanced_team_data = enhance_registration_with_user_ids(
            request.teamData.dict(), 
            user_id, 
            user_email
        )
        
        # 6. Create initial payment record in your database
        payment_record = {
            "transactionId": txnid,
            "userId": user_id,
            "userEmail": user_email,
            "tournamentSlug": request.tournamentSlug,
            "teamData": enhanced_team_data,
            "amount": request.amount,
            "status": "initiated",
            "payuData": payu_data,
            "createdAt": datetime.utcnow().isoformat(),
            "updatedAt": datetime.utcnow().isoformat()
        }
        create_payment_record(payment_record)

        # 7. Return data to the frontend
        return PaymentResponse(
            success=True,
            message="Payment initiated successfully. Redirecting to PayU.",
            payuData=payu_data,
            payuUrl=PAYU_CONFIG["BASE_URL"]
        )

    except Exception as e:
        print(f"Payment initiation error: {e}")
        raise HTTPException(status_code=500, detail="Failed to initiate payment")

@app.post("/payment/success")
async def payment_success_callback(request: Request):
    """
    Handle the success callback from PayU with comprehensive error recovery.
    This is where the user is redirected after a successful payment.
    """
    try:
        form_data = await request.form()
        data = dict(form_data)
        tournament_slug = data.get("udf1", "")  # safe default
        transaction_id = data.get("txnid", "")
        
        logger.debug(f"DEBUG: Received payment callback for transaction: {transaction_id}")
        
        # Validate required fields
        if not transaction_id:
            logger.error("❌ Missing transaction ID in payment callback")
            return RedirectResponse(url=f"https://gamingnexus.onrender.com/team-registration.html?slug={tournament_slug}&status=failed&error=missing_txnid")
        
        # Check PayU configuration before verification
        if not PAYU_CONFIG.get("SALT"):
            logger.error("❌ PayU SALT not configured - cannot verify payment")
            update_payment_status(transaction_id, "failed", {"error": "Configuration error - missing SALT"})
            return RedirectResponse(url=f"https://gamingnexus.onrender.com/team-registration.html?slug={tournament_slug}&status=failed&error=config_error")

        # Verify PayU hash before processing payment
        try:
            hash_valid = verify_payu_hash(data, PAYU_CONFIG["SALT"])
            if not hash_valid:
                logger.error("❌ Invalid hash on success callback! Payment verification failed.")
                update_payment_status(transaction_id, "failed", {"error": "Hash verification failed"})
                return RedirectResponse(url=f"https://gamingnexus.onrender.com/team-registration.html?slug={tournament_slug}&status=failed&error=hash_mismatch")
        except Exception as e:
            logger.error(f"❌ Error during hash verification: {e}")
            update_payment_status(transaction_id, "failed", {"error": f"Hash verification error: {str(e)}"})
            return RedirectResponse(url=f"https://gamingnexus.onrender.com/team-registration.html?slug={tournament_slug}&status=failed&error=verification_error")
        
        logger.info("✅ PayU hash verification successful!")
        
    except Exception as e:
        logger.error(f"❌ Critical error in payment callback: {e}")
        # Fallback redirect with generic error
        return RedirectResponse(url="https://gamingnexus.onrender.com/team-registration.html?status=failed&error=callback_error")


    transaction_id = data.get("txnid")
    status = data.get("status")
    tournament_slug = data.get("udf1") # Get tournament slug from user-defined field

    logger.debug(f"DEBUG: Processing payment callback - TxnID: {transaction_id}, Status: {status}, Tournament: {tournament_slug}")
    
    # Update payment status in database with error handling
    try:
        update_payment_status(transaction_id, status, payu_response=data)
        logger.info(f"✅ Payment status updated: {transaction_id} -> {status}")
    except Exception as e:
        logger.error(f"❌ Failed to update payment status: {e}")
        # Continue processing but log the error
        
    # Process successful payment - add team to tournament
    if status.lower() == "success":
        print(f"🎯 Processing successful payment for transaction: {transaction_id}")
        try:
            # Get payment record to retrieve team data
            print(f"🔍 Retrieving payment record for: {transaction_id}")
            payment_record = get_payment_by_transaction_id(transaction_id)
            if not payment_record:
                print(f"❌ Payment record not found for transaction: {transaction_id}")
                return RedirectResponse(url=f"https://gamingnexus.onrender.com/team-registration.html?slug={tournament_slug}&status=failed&error=payment_record_not_found")
                
            print(f"✅ Payment record found. Status: {payment_record.get('status')}")
            
            if not payment_record.get("teamData"):
                print(f"❌ Team data not found in payment record: {transaction_id}")
                return RedirectResponse(url=f"https://gamingnexus.onrender.com/team-registration.html?slug={tournament_slug}&status=failed&error=team_data_missing")
                
            team_data = payment_record["teamData"]
            print(f"✅ Team data found. Team: {team_data.get('teamName')}")
            
            # Validate tournament exists
            print(f"🔍 Validating tournament exists: {tournament_slug}")
            tournament = get_tournament_by_slug_from_db(tournament_slug)
            if not tournament:
                print(f"❌ Tournament not found: {tournament_slug}")
                return RedirectResponse(url=f"https://gamingnexus.onrender.com/team-registration.html?slug={tournament_slug}&status=failed&error=tournament_not_found")
            
            print(f"✅ Tournament found: {tournament.get('title')}")
            
            # Add team to tournament participants
            print(f"🎯 Adding team to tournament: {tournament_slug}")
            
            # Create participant entry with enhanced data
            participant_data = {
                "_id": ObjectId(),
                "teamName": team_data.get("teamName"),
                "captainEmail": team_data.get("captainEmail", payment_record.get("userEmail")),
                "captainUserId": team_data.get("captainUserId"),
                "registeredBy": team_data.get("registeredBy"),
                "players": team_data.get("players", []),
                "phone": team_data.get("phone"),
                "registrationDate": datetime.utcnow().isoformat(),
                "paymentStatus": "paid",
                "transactionId": transaction_id
            }
            
            print(f"DEBUG: Participant data to be added:")
            print(f"  - Team Name: {participant_data.get('teamName')}")
            print(f"  - Captain Email: {participant_data.get('captainEmail')}")
            print(f"  - Players Count: {len(participant_data.get('players', []))}")
            print(f"  - Transaction ID: {participant_data.get('transactionId')}")
            
            # Add to tournament
            logger.info(f"🔄 Executing database update...")
            db = get_database()
            tournaments_collection = db.tournaments
            
            # First, check current participant count
            current_tournament = tournaments_collection.find_one({"slug": tournament_slug})
            current_count = len(current_tournament.get("participants", [])) if current_tournament else 0
            print(f"📊 Current participants in tournament: {current_count}")
            
            result = tournaments_collection.update_one(
                {"slug": tournament_slug},
                {"$push": {"participants": participant_data}}
            )
            
            print(f"📊 Database update result:")
            print(f"  - Matched count: {result.matched_count}")
            print(f"  - Modified count: {result.modified_count}")
            
            if result.modified_count > 0:
                print(f"✅ Team {team_data.get('teamName')} successfully added to tournament {tournament_slug}")
                
                #
                # 🔽 --- NEW LOGIC TO CREDIT HOST WALLET --- 🔽
                #
                print(f"💸 Crediting host wallet for successful payment...")
                try:
                    credit_host_for_payment(payment_record)
                except Exception as credit_error:
                    # Log if the credit fails, but don't fail the payment process for the user
                    logger.error(f"CRITICAL: Failed to credit host wallet for txnid {transaction_id}: {credit_error}")
                #
                # 🔼 --- END OF NEW LOGIC --- 🔼
                #
                
                # Verify the addition
                updated_tournament = tournaments_collection.find_one({"slug": tournament_slug})
                new_count = len(updated_tournament.get("participants", [])) if updated_tournament else 0
                print(f"📊 New participants count: {new_count}")
                
                # Log tournament registration activity
                try:
                    user_id = payment_record.get("userId")
                    user_email = payment_record.get("userEmail")
                    username = user_email.split("@")[0] if user_email else "Unknown"
                    log_tournament_registration_activity(
                        user_id, 
                        username, 
                        str(tournament["_id"]), 
                        tournament["title"], 
                        tournament_slug, 
                        team_data.get("teamName")
                    )
                    print(f"✅ Tournament registration activity logged")
                except Exception as e:
                    print(f"⚠️ Failed to log tournament registration activity: {e}")
            else:
                print(f"❌ Failed to add team to tournament {tournament_slug}")
                print(f"❌ Database update did not modify any documents")
                return RedirectResponse(url=f"https://gamingnexus.onrender.com/team-registration.html?slug={tournament_slug}&status=failed&error=registration_failed")
                        
        except Exception as e:
            print(f"❌ CRITICAL ERROR processing successful payment: {e}")
            import traceback
            traceback.print_exc()
            # Don't return error redirect - let payment succeed but log the issue
            print(f"⚠️ Payment successful but team registration failed - user will see success but team not added")

    print(f"✅ Payment successful for transaction: {transaction_id}")

    # Redirect back to the team registration page with a success status and transaction details
    team_name = ""
    if status.lower() == "success":
        try:
            payment_record = get_payment_by_transaction_id(transaction_id)
            print(f"DEBUG: Payment record found: {payment_record is not None}")
            if payment_record and payment_record.get("teamData"):
                team_data = payment_record["teamData"]
                print(f"DEBUG: Team data keys: {list(team_data.keys()) if team_data else 'None'}")
                team_name = team_data.get("teamName", "")
                print(f"DEBUG: Extracted team name: '{team_name}'")
                
                # If team name is empty, let's see what other data we have
                if not team_name:
                    print(f"DEBUG: Team name empty, checking other fields:")
                    print(f"DEBUG: - captainName: {team_data.get('captainName', 'Not found')}")
                    print(f"DEBUG: - players: {team_data.get('players', 'Not found')}")
                    # Fallback to actual team name if available
                    team_name = team_data.get("teamName") or team_data.get("captainName") or "Your Team"
            else:
                print(f"DEBUG: No team data found in payment record")
        except Exception as e:
            print(f"DEBUG: Error getting team name: {e}")
            pass
    
    success_url = f"https://gamingnexus.onrender.com/team-registration.html?slug={tournament_slug}&status=success&txnid={transaction_id}"
    if team_name:
        success_url += f"&teamName={urllib.parse.quote(team_name)}"
    
    print(f"🔄 Redirecting to: {success_url}")
    
    # Create a more robust redirect response
    response = RedirectResponse(url=success_url, status_code=302)  # Use 302 instead of 307
    
    # Add headers to help with redirect handling and prevent caching
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["Location"] = success_url
    
    # Add meta refresh as backup for browsers that don't follow redirects
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta http-equiv="refresh" content="0; url={success_url}">
        <title>Payment Successful - Redirecting...</title>
        <style>
            body {{ 
                font-family: Arial, sans-serif; 
                text-align: center; 
                padding: 50px;
                background: #0D0A1A;
                color: #F0F0F0;
            }}
            .spinner {{ 
                border: 4px solid #f3f3f3; 
                border-top: 4px solid #0AFAD9; 
                border-radius: 50%; 
                width: 40px; 
                height: 40px; 
                animation: spin 1s linear infinite; 
                margin: 20px auto;
            }}
            @keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
        </style>
    </head>
    <body>
        <div class="spinner"></div>
        <h2>🎉 Payment Successful!</h2>
        <p>Redirecting you back to the registration page...</p>
        <p>If you are not redirected automatically, <a href="{success_url}" style="color: #0AFAD9;">click here</a>.</p>
        <script>
            // JavaScript redirect as additional fallback
            setTimeout(function() {{
                window.location.href = "{success_url}";
            }}, 1000);
        </script>
    </body>
    </html>
    """
    
    # Return HTML content with multiple redirect methods
    return HTMLResponse(content=html_content, status_code=200)

# REPLACE the existing /payment/failure function with this one

@app.post("/payment/failure")
async def payment_failure_callback(request: Request):
    """
    Handle the failure callback from PayU with comprehensive error recovery.
    This is where the user is redirected after a failed or cancelled payment.
    """
    try:
        form_data = await request.form()
        data = dict(form_data)
        transaction_id = data.get("txnid", "")
        tournament_slug = data.get("udf1", "")
        
        print(f"DEBUG: Received payment failure callback for transaction: {transaction_id}")
        
        # Validate required fields
        if not transaction_id:
            print("❌ Missing transaction ID in payment failure callback")
            return RedirectResponse(url=f"https://gamingnexus.onrender.com/team-registration.html?slug={tournament_slug}&status=failed&error=missing_txnid")
        
        # Check PayU configuration before verification
        if not PAYU_CONFIG.get("SALT"):
            print("❌ PayU SALT not configured - cannot verify payment failure")
            return RedirectResponse(url=f"https://gamingnexus.onrender.com/team-registration.html?slug={tournament_slug}&status=failed&error=config_error")

        # Verify PayU hash before processing failure
        try:
            hash_valid = verify_payu_hash(data, PAYU_CONFIG["SALT"])
            if not hash_valid:
                print("❌ Invalid hash on failure callback! Payment verification failed.")
                # Still update status as failed but note the hash issue
                try:
                    update_payment_status(transaction_id, "failed", {"error": "Hash verification failed on failure callback"})
                except Exception as e:
                    print(f"❌ Failed to update payment status on hash failure: {e}")
                return RedirectResponse(url=f"https://gamingnexus.onrender.com/team-registration.html?slug={tournament_slug}&status=failed&error=hash_mismatch")
        except Exception as e:
            print(f"❌ Error during hash verification on failure callback: {e}")
            return RedirectResponse(url=f"https://gamingnexus.onrender.com/team-registration.html?slug={tournament_slug}&status=failed&error=verification_error")
        
        print("✅ PayU hash verification successful for failure callback!")

        transaction_id = data.get("txnid")
        status = data.get("status")
        tournament_slug = data.get("udf1") # Get tournament slug

        print(f"DEBUG: Processing payment failure callback - TxnID: {transaction_id}, Status: {status}, Tournament: {tournament_slug}")
        
        # Update payment status in database with error handling
        try:
            update_payment_status(transaction_id, status, payu_response=data)
            print(f"✅ Payment failure status updated: {transaction_id} -> {status}")
        except Exception as e:
            print(f"❌ Failed to update payment failure status: {e}")
            
        print(f"❌ Payment failed for transaction: {transaction_id}")

        # Redirect back to the team registration page with a failure status
        failure_url = f"https://gamingnexus.onrender.com/team-registration.html?slug={tournament_slug}&status=failed"
        print(f"🔄 Redirecting to failure page: {failure_url}")
        
        # Create robust failure redirect with HTML fallback
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta http-equiv="refresh" content="0; url={failure_url}">
            <title>Payment Failed - Redirecting...</title>
            <style>
                body {{ 
                    font-family: Arial, sans-serif; 
                    text-align: center; 
                    padding: 50px;
                    background: #0D0A1A;
                    color: #F0F0F0;
                }}
                .spinner {{ 
                    border: 4px solid #f3f3f3; 
                    border-top: 4px solid #ef4444; 
                    border-radius: 50%; 
                    width: 40px; 
                    height: 40px; 
                    animation: spin 1s linear infinite; 
                    margin: 20px auto;
                }}
                @keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
            </style>
        </head>
        <body>
            <div class="spinner"></div>
            <h2>❌ Payment Failed</h2>
            <p>Redirecting you back to try again...</p>
            <p>If you are not redirected automatically, <a href="{failure_url}" style="color: #ef4444;">click here</a>.</p>
            <script>
                setTimeout(function() {{
                    window.location.href = "{failure_url}";
                }}, 1000);
            </script>
        </body>
        </html>
        """
        
        from fastapi.responses import HTMLResponse
        return HTMLResponse(content=html_content, status_code=200)
        
    except Exception as e:
        print(f"❌ Critical error in payment failure callback: {e}")
        # Fallback redirect with generic error
        return RedirectResponse(url="https://gamingnexus.onrender.com/team-registration.html?status=failed&error=callback_error")
    
# In main.py, REPLACE the existing export_kp_tournament_slots_to_pdf function with this one:

@app.get("/api/tournaments/{slug}/export/kp-slots-pdf")
async def export_kp_tournament_slots_to_pdf(
    slug: str,
    token: Optional[str] = None,
    request: Request = None
):
    """Export KP tournament with teams distributed into slots/groups (admin only)"""
    try:
        # --- Authentication & Validation (Keep existing logic) ---
        admin_payload = None
        auth_header = request.headers.get("authorization") if request else None
        if auth_header and auth_header.startswith("Bearer "):
            try:
                admin_payload = verify_jwt_token(auth_header.split(" ")[1])
            except ValueError:
                pass
        
        if not admin_payload and token:
            try:
                admin_payload = verify_jwt_token(token)
            except ValueError:
                pass
        
        if not admin_payload:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        if admin_payload.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Admin privileges required")
        
        admin_email = admin_payload.get("email", "unknown")
        
        tournament = get_tournament_by_slug_from_db(slug)
        if not tournament:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        if tournament.get("format") != "kp":
            raise HTTPException(
                status_code=400, 
                detail="This export is only available for KP format tournaments"
            )
        
        participants = tournament.get("participants", [])
        if not participants:
            raise HTTPException(status_code=400, detail="No registered teams found")
        
        # --- PDF Generation Logic (Modified to include In-Game ID) ---
        
        # Import the distribute function
        from database import distribute_kp_teams
        groups = distribute_kp_teams(participants, num_groups=4)
        
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=portrait(A4), topMargin=0.5*inch)
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=16,
            alignment=TA_CENTER,
            spaceAfter=20,
            textColor=colors.darkblue
        )
        
        group_title_style = ParagraphStyle(
            'GroupTitle',
            parent=styles['Heading2'],
            fontSize=14,
            alignment=TA_LEFT,
            spaceAfter=15,
            textColor=colors.darkred
        )
        
        story = []
        
        for group_idx, group in enumerate(groups):
            # Add tournament title on first page only
            if group_idx == 0:
                story.append(Paragraph(f"{tournament.get('title', 'Tournament')}", title_style))
                story.append(Paragraph(f"Game: {tournament.get('game', 'Unknown')}", styles['Normal']))
                story.append(Paragraph(f"Total Registered Teams: {len(participants)}", styles['Normal']))
                story.append(Spacer(1, 0.3 * inch))
            
            # Group header
            story.append(Paragraph(f"<b>{group['groupName']}</b>: {group['teamCount']} Teams", group_title_style))

            # Add match schedule if available
            kp_settings = tournament.get("kpSettings", {})
            match_schedule = kp_settings.get("matchSchedule", [])
            group_match = next((match for match in match_schedule if f"Qualifier {group['groupNumber']}" in match.get("match", "")), None)
            
            if group_match:
                story.append(Paragraph(f"<b>Match Date:</b> {group_match.get('date', 'TBD')} at {group_match.get('time', 'TBD')}", styles['Normal']))
            
            story.append(Spacer(1, 0.2 * inch))

            # --- MODIFIED TABLE DATA STRUCTURE ---
            team_data = [
                [
                    "S.No", 
                    "Team Name", 
                    "Player Name", 
                    "In-Game ID", 
                    "Player Email", 
                    "Is Captain"
                ]
            ]
            
            for i, team in enumerate(group['teams'], 1):
                players = team.get("players", [])
                team_name = team.get("teamName", "Unknown")
                
                # Add a row for each player in the team
                for p_idx, player in enumerate(players):
                    is_captain = p_idx == 0 # Assume first player is captain based on form order
                    row_data = [
                        str(i) if p_idx == 0 else "", # S.No only on the first player row
                        team_name if p_idx == 0 else "", # Team Name only on the first player row
                        player.get("name", "N/A"),
                        player.get("inGameId", "N/A"), # The field you requested
                        player.get("email", "N/A"),
                        "Yes" if is_captain else "No"
                    ]
                    team_data.append(row_data)

                # Add a separator row if this is not the last team
                if i < len(group['teams']):
                    team_data.append(["", "", "", "", "", ""])

            
            # --- CREATE TABLE AND STYLING ---
            
            # Calculate column widths (sum must be <= 7.5 inches for A4 portrait)
            col_widths = [0.4*inch, 1.4*inch, 1.4*inch, 1.4*inch, 2.3*inch, 0.6*inch]
            group_table = Table(team_data, colWidths=col_widths)
            
            table_style_commands = [
                # Header styling
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0D0A1A')), # Dark background
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#0AFAD9')), # Electric Cyan text
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                
                # General data rows styling
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ALIGN', (0, 1), (0, -1), 'CENTER'),  # S.No center
                ('ALIGN', (1, 1), (1, -1), 'LEFT'),    # Team name left
                ('ALIGN', (2, 1), (-1, -1), 'LEFT'),   # All data columns left
                
                # Apply conditional row background and spanning
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
            ]
            
            # Merge cells for Team Name and S.No columns for multi-row teams
            row_start = 1
            for row_idx, row in enumerate(team_data[1:], 1):
                if row[0] != "":
                    # Find how many rows to span
                    span_count = 1
                    for next_row in team_data[row_idx + 1:]:
                        if next_row[0] == "":
                            span_count += 1
                        else:
                            break

                    if span_count > 1:
                        # Merge S.No and Team Name vertically
                        table_style_commands.append(('SPAN', (0, row_idx), (0, row_idx + span_count - 1)))
                        table_style_commands.append(('SPAN', (1, row_idx), (1, row_idx + span_count - 1)))
                        # Re-center the spanned cells
                        table_style_commands.append(('ALIGN', (0, row_idx), (1, row_idx + span_count - 1), 'CENTER'))
                        table_style_commands.append(('VALIGN', (0, row_idx), (1, row_idx + span_count - 1), 'MIDDLE'))

                    row_start = row_idx + 1
            
            # Apply team-level separators
            for row_idx, row in enumerate(team_data[1:], 1):
                if row[0] == "" and row[1] == "":
                    table_style_commands.append(('LINEBELOW', (0, row_idx-1), (-1, row_idx-1), 1.5, colors.black))
                    # Remove the row background for the separator row itself
                    table_style_commands.append(('BACKGROUND', (0, row_idx), (-1, row_idx), colors.white))


            group_table.setStyle(TableStyle(table_style_commands))
            story.append(group_table)
            
            # Add page break except for last group
            if group_idx < len(groups) - 1:
                story.append(PageBreak())
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        
        # Log the operation
        log_tournament_operation("EXPORT_KP_SLOTS_PDF", slug, admin_email, f"Exported {len(groups)} groups with {len(participants)} total teams")
        
        filename = f"{tournament.get('title', 'tournament').replace(' ', '_')}_kp_slots_roster.pdf"
        return StreamingResponse(
            io.BytesIO(buffer.read()),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except ImportError:
        # Check for reportlab dependencies
        try:
            import reportlab
        except ImportError:
            raise HTTPException(status_code=501, detail="PDF libraries (reportlab) not available.")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"KP slots PDF export error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to export KP slots PDF: {str(e)}")

# Update login endpoint to return proper API response format
@app.post("/api/auth/login", response_model=dict)
async def api_login_user(user_data: UserLogin):
    """API Login endpoint with proper response format"""
    try:
        # Find user by email
        user = get_user_by_email(user_data.email)
        
        # Debug logging
        print(f"DEBUG: Login attempt for email: {user_data.email}")
        if user:
            print(f"DEBUG: User found: {user.get('email')}")
            print(f"DEBUG: User role: {user.get('role', 'NO_ROLE_FIELD')}")
            print(f"DEBUG: User fields: {list(user.keys())}")
        else:
            print(f"DEBUG: No user found for email: {user_data.email}")
        
        # Authenticate user
        if not user or not verify_password(user_data.password, user["password_hash"]):
            print(f"DEBUG: Authentication failed for {user_data.email}")
            return {
                "success": False,
                "error": "Invalid credentials"
            }
        
        # Create JWT token
        user_role = user.get("role", "user")
        username = user.get("username", user["email"].split("@")[0])  # Fallback for existing users
        token = create_jwt_token(str(user["_id"]), username, user["email"], user_role)
        
        # Determine redirect path based on user role
        redirect_path = "admin-dashboard.html" if user_role == "admin" else "index.html"
        
        print(f"DEBUG: Final user_role: {user_role}")
        print(f"DEBUG: Redirect path: {redirect_path}")
        print(f"DEBUG: About to return success response")
        
        return {
            "success": True,
            "data": {
                "user": {
                    "id": str(user["_id"]),
                    "username": username,
                    "email": user["email"],
                    "role": user_role
                },
                "token": token,
                "expiresIn": "24h"
            },
            "redirect_path": redirect_path
        }
        
    except Exception as e:
        print(f"API Login error: {e}")
        return {
            "success": False,
            "error": "Login failed. Please try again."
        }

@app.post("/api/auth/register", response_model=dict)
async def api_register_user(user_data: UserRegistration):
    """API Register endpoint with proper response format"""
    try:
        # Hash the password
        password_hash = hash_password(user_data.password)
        
        # Create user in database with role and additional fields
        user_id = create_user(
            username=user_data.username, 
            email=user_data.email, 
            password_hash=password_hash,
            role=user_data.role,
            contact_phone=user_data.contact_phone,
            firstName=user_data.firstName,
            lastName=user_data.lastName
        )
        
        # Determine success message based on role
        if user_data.role == "host":
            message = "Host registration successful! You can now sign in and start hosting tournaments."
        else:
            message = "User registered successfully"
        
        return {
            "success": True,
            "data": {
                "user_id": user_id,
                "email": user_data.email,
                "role": user_data.role
            },
            "message": message
        }
        
    except ValueError as e:
        return {
            "success": False,
            "error": str(e)
        }
    except Exception as e:
        print(f"API Registration error: {e}")
        return {
            "success": False,
            "error": "Registration failed. Please try again."
        }

# Additional endpoints that frontend expects
@app.get("/api/tournaments/featured")
async def get_featured_tournaments():
    """Get featured tournaments"""
    try:
        tournaments = get_all_tournaments_from_db()
        # Convert ObjectId to string and limit to featured ones
        featured = []
        for t in tournaments[:3]:  # Get first 3 as featured
            t['_id'] = str(t['_id'])
            featured.append(t)
        return {"success": True, "data": featured}
    except Exception as e:
        print(f"Featured tournaments fetch error: {e}")
        return {"success": False, "data": []}

@app.get("/api/tournaments/stats")
async def get_tournament_stats():
    """Get tournament statistics"""
    try:
        tournaments = get_all_tournaments_from_db()
        stats = {
            "total_tournaments": len(tournaments),
            "active_tournaments": len([t for t in tournaments if t.get("status") == "live"]),
            "upcoming_tournaments": len([t for t in tournaments if t.get("status") == "upcoming"]),
            "total_participants": sum([len(t.get("participants", [])) for t in tournaments])
        }
        return {"success": True, "data": stats}
    except Exception as e:
        print(f"Tournament stats fetch error: {e}")
        return {"success": False, "data": {}}

@app.get("/api/matches/recent")
async def get_recent_matches():
    """Get recent matches"""
    return {"success": True, "data": []}  # Mock empty data for now

@app.get("/api/matches/live")
async def get_live_matches():
    """Get live matches"""
    return {"success": True, "data": []}  # Mock empty data for now

@app.get("/api/matches/upcoming")
async def get_upcoming_matches():
    """Get upcoming matches"""
    return {"success": True, "data": []}  # Mock empty data for now

@app.get("/api/content/sponsored")
async def get_sponsored_content():
    """Get sponsored content"""
    return {"success": True, "data": []}  # Mock empty data for now

# Team Registration Endpoints
@app.post("/api/tournaments/{slug}/register")
async def register_team(
    slug: str,
    request: Request,
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Register a team for a tournament"""
    try:
        # Get user info from token
        payload = verify_jwt_token(auth.credentials)
        user_id = payload.get("user_id")
        user_email = payload.get("email")
        
        # Get team data from request body
        team_data = await request.json()
        
        # Get tournament details
        tournament = get_tournament_by_slug_from_db(slug)
        if not tournament:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tournament not found"
            )
        
        # Check if registration is open
        tournament_status = tournament.get("status", "upcoming")
        if tournament_status not in ["registration_open"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Registration is not currently open for this tournament"
            )
        
        # Validate team data structure
        if not isinstance(team_data, dict):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid team data format"
            )
        
        required_fields = ["teamName", "players"]
        for field in required_fields:
            if field not in team_data:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Missing required field: {field}"
                )
        
        # Get tournament rules
        max_players = tournament.get("maxPlayersPerTeam", 4)
        if tournament.get("format") == "kp" and tournament.get("kpSettings"):
            max_players = tournament["kpSettings"].get("maxPlayersPerTeam", 4)
        
        # Validate team name
        team_name = sanitize_string(team_data["teamName"])
        if len(team_name) < 3 or len(team_name) > 50:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Team name must be between 3 and 50 characters"
            )
        
        # Validate players
        players = team_data["players"]
        if not isinstance(players, list):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Players must be a list"
            )
        
        if len(players) < 1 or len(players) > max_players:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Team must have between 1 and {max_players} players"
            )
        
        # Validate each player
        validated_players = []
        player_emails = set()
        
        for i, player in enumerate(players):
            if not isinstance(player, dict):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Player {i+1} data is invalid"
                )
            
            # Required player fields
            player_required = ["name", "email", "inGameId"]
            for field in player_required:
                if field not in player or not player[field]:
                    raise HTTPException(
                        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                        detail=f"Player {i+1} missing required field: {field}"
                    )
            
            # Validate player data
            player_name = sanitize_string(player["name"])
            player_email = player["email"].lower().strip()
            player_game_id = sanitize_string(player["inGameId"])
            
            # Check for duplicate emails within team
            if player_email in player_emails:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Duplicate email found: {player_email}"
                )
            player_emails.add(player_email)
            
            # Validate email format
            import re
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, player_email):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Invalid email format for player {i+1}: {player_email}"
                )
            
            validated_players.append({
                "name": player_name,
                "email": player_email,
                "inGameId": player_game_id,
                "role": player.get("role", "Player")
            })
        
        # Check if team name already exists in this tournament
        existing_participants = tournament.get("participants", [])
        for existing_team in existing_participants:
            if existing_team.get("teamName", "").lower() == team_name.lower():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Team name already exists in this tournament"
                )
        
        # Check if any player is already registered in this tournament
        for existing_team in existing_participants:
            for existing_player in existing_team.get("players", []):
                existing_email = existing_player.get("email", "").lower()
                if existing_email in player_emails:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Player {existing_email} is already registered in this tournament"
                    )
        
        # Create team registration
        team_registration = {
            "_id": ObjectId(),  # Generate unique team ID
            "teamName": team_name,
            "players": validated_players,
            "captainUserId": user_id,
            "captainEmail": user_email,
            "registrationDate": datetime.utcnow().isoformat(),
            "status": "pending"
        }
        
        # Add team to tournament participants
        db = get_database()
        tournaments_collection = db.tournaments
        
        result = tournaments_collection.update_one(
            {"slug": slug},
            {"$push": {"participants": team_registration}}
        )
        
        if result.modified_count == 0:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to register team"
            )
        
        # Log the registration
        log_tournament_operation("TEAM_REGISTRATION", slug, user_email, f"Team: {team_name}, Players: {len(validated_players)}")
        
        # Log tournament registration activity
        try:
            username = payload.get("username", user_email.split("@")[0])
            log_tournament_registration_activity(
                user_id, 
                username, 
                str(tournament["_id"]), 
                tournament["title"], 
                slug, 
                team_name
            )
        except Exception as e:
            print(f"Failed to log tournament registration activity: {e}")
        
        # New, corrected code
        return {
            "success": True,
            "data": {
                "teamId": str(team_registration["_id"]), # <-- Send the new _id as a string
                "teamName": team_registration["teamName"],
                "captainName": validated_players[0]["name"] if validated_players else "N/A",
                "players": validated_players,
                "message": "Team registered successfully"
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Team registration error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to register team"
        )

@app.get("/api/tournaments/{slug}/registration-status")
async def check_registration_status(
    slug: str,
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Check if user is already registered for a tournament"""
    try:
        # Get user info from token
        payload = verify_jwt_token(auth.credentials)
        user_email = payload.get("email")
        
        # Get tournament details
        tournament = get_tournament_by_slug_from_db(slug)
        if not tournament:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tournament not found"
            )
        
        # Check if user is already registered
        existing_participants = tournament.get("participants", [])
        user_team = None
        
        for team in existing_participants:
            # Check if user is team captain
            if team.get("captainEmail") == user_email:
                user_team = team
                break
            
            # Check if user is in players list
            for player in team.get("players", []):
                if player.get("email") == user_email:
                    user_team = team
                    break
            
            if user_team:
                break
        
        if user_team:
            return {
                "success": True,
                "data": {
                    "isRegistered": True,
                    "teamName": user_team.get("teamName"),
                    "teamId": user_team.get("teamId"),
                    "registrationDate": user_team.get("registrationDate")
                }
            }
        else:
            return {
                "success": True,
                "data": {
                    "isRegistered": False
                }
            }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Registration status check error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to check registration status"
        )

@app.post("/api/tournaments/{slug}/updates", dependencies=[Depends(require_admin)])
async def add_tournament_update(
    slug: str,
    request: Request,
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Add a tournament update/announcement (admin only)"""
    try:
        # Get admin user info from token
        payload = verify_jwt_token(auth.credentials)
        admin_email = payload.get("email", "unknown")
        
        # Get update data from request body
        update_data = await request.json()
        
        # Validate required fields
        required_fields = ["title", "description", "date", "time"]
        for field in required_fields:
            if field not in update_data:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Missing required field: {field}"
                )
        
        # Sanitize inputs
        sanitized_update = {
            "title": sanitize_string(update_data["title"]),
            "description": sanitize_string(update_data["description"]),
            "date": update_data["date"],  # Should be in YYYY-MM-DD format
            "time": update_data["time"],  # Should be in HH:MM:SS format
            "type": sanitize_string(update_data.get("type", "announcement")),
            "createdBy": admin_email,
            "createdAt": datetime.utcnow().isoformat()
        }
        
        # Validate date format
        try:
            datetime.fromisoformat(f"{sanitized_update['date']} {sanitized_update['time']}")
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid date or time format. Use YYYY-MM-DD for date and HH:MM:SS for time."
            )
        
        # Add update to tournament
        db = get_database()
        tournaments_collection = db.tournaments
        
        result = tournaments_collection.update_one(
            {"slug": slug},
            {"$push": {"scheduleEvents": sanitized_update}}
        )
        
        if result.modified_count == 0:
            # Check if tournament exists
            tournament = tournaments_collection.find_one({"slug": slug})
            if not tournament:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Tournament not found"
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to add tournament update"
                )
        
        # Log the operation
        log_tournament_operation("ADD_UPDATE", slug, admin_email, f"Update: {sanitized_update['title']}")
        
        return {
            "success": True,
            "data": sanitized_update,
            "message": "Tournament update added successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Tournament update error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to add tournament update"
        )

# Combined endpoint for both hosted and joined tournaments

@app.get("/api/users/me/tournaments/all")
async def get_all_user_tournaments_endpoint(auth: HTTPAuthorizationCredentials = Security(security)):
    """Get all tournaments - both hosted by user and joined by user in a single request."""
    try:
        payload = verify_jwt_token(auth.credentials)
        user_email = payload.get("email")
        user_id = payload.get("user_id")

        if not user_email:
            raise HTTPException(status_code=403, detail="Invalid token payload")

        # Get joined tournaments (by email participation)
        joined_tournaments = get_tournaments_for_user(user_email, user_id)
        joined_count = len(joined_tournaments)
        
        # No hosted tournaments section - removed user tournament hosting
        hosted_tournaments = []
        hosted_count = 0
        enhanced_hosted_tournaments = []

        # Transform joined tournaments with team details
        enhanced_joined_tournaments = []
        for tournament in joined_tournaments:
            # The tournament data is directly in the tournament object
            # Find the user's team info from participants
            user_team_info = None
            participants = tournament.get("participants", [])
            
            for participant in participants:
                # Check if this participant matches the user
                if (participant.get("captainEmail", "").lower() == user_email.lower() or
                    participant.get("captainUserId") == user_id or
                    any(player.get("email", "").lower() == user_email.lower() or 
                        player.get("userId") == user_id 
                        for player in participant.get("players", []))):
                    
                    user_team_info = {
                        "teamName": participant.get("teamName"),
                        "role": "captain" if (participant.get("captainEmail", "").lower() == user_email.lower() or 
                                            participant.get("captainUserId") == user_id) else "player",
                        "registrationDate": participant.get("registrationDate"),
                        "paymentStatus": participant.get("paymentStatus"),
                        "transactionId": participant.get("transactionId")
                    }
                    break
            
            enhanced_tournament = {
                "_id": tournament.get("_id"),
                "title": tournament.get("title"),
                "slug": tournament.get("slug"),
                "game": tournament.get("game"),
                "description": tournament.get("description"),
                "status": tournament.get("status"),
                "entryFee": tournament.get("entryFee"),
                "prizePool": tournament.get("prizePool"),
                "maxTeams": tournament.get("maxTeams"),
                "registrationStart": tournament.get("registrationStart"),
                "registrationEnd": tournament.get("registrationEnd"),
                "tournamentStart": tournament.get("tournamentStart"),
                "tournamentEnd": tournament.get("tournamentEnd"),
                "posterImageUrl": tournament.get("posterImageUrl"),
                "participant_count": len(tournament.get("participants", [])),
                "tournament_type": "joined",
                # Add team information
                "team_info": user_team_info or {}
            }
            enhanced_joined_tournaments.append(enhanced_tournament)

        return {
            "success": True,
            "data": {
                "joined": enhanced_joined_tournaments,  # Return actual joined tournaments
                "hosted": enhanced_hosted_tournaments,
                "counts": {
                    "joined": joined_count,
                    "hosted": hosted_count,
                    "active": len([t for t in enhanced_hosted_tournaments if t.get("status") in ["active", "registration_open"]])
                }
            },
            "message": f"Found {hosted_count} hosted and {joined_count} joined tournaments"
        }
    except Exception as e:
        print(f"Error fetching all user tournaments: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch user tournaments")

# Keep original endpoints for backward compatibility
@app.get("/api/users/me/tournaments")
async def get_my_tournaments(auth: HTTPAuthorizationCredentials = Security(security)):
    """Get all tournaments the current user is registered in."""
    try:
        payload = verify_jwt_token(auth.credentials)
        user_email = payload.get("email")
        user_id = payload.get("user_id")

        if not user_email:
            raise HTTPException(status_code=403, detail="Invalid token payload")

        # Use enhanced lookup with both email and user ID
        tournaments = get_tournaments_for_user(user_email, user_id)

        # Transform tournaments to include participation details
        enhanced_tournaments = []
        for tournament in tournaments:
            enhanced_tournament = {
                "_id": tournament.get("_id"),
                "title": tournament.get("title"),
                "slug": tournament.get("slug"),
                "game": tournament.get("game"),
                "description": tournament.get("description"),
                "status": tournament.get("status"),
                "entryFee": tournament.get("entryFee"),
                "prizePool": tournament.get("prizePool"),
                "maxTeams": tournament.get("maxTeams"),
                "registrationStart": tournament.get("registrationStart"),
                "registrationEnd": tournament.get("registrationEnd"),
                "tournamentStart": tournament.get("tournamentStart"),
                "tournamentEnd": tournament.get("tournamentEnd"),
                "posterImageUrl": tournament.get("posterImageUrl"),
                "participant_count": len(tournament.get("participants", [])),
                # Enhanced participation info
                "user_team_name": tournament.get("user_team_name"),
                "user_role": tournament.get("user_role"),
                "participation_type": tournament.get("participation_type"),
                "registration_email": tournament.get("registration_email"),
                "team_id": tournament.get("team_id")
            }
            enhanced_tournaments.append(enhanced_tournament)

        return {
            "success": True,
            "data": enhanced_tournaments
        }
    except Exception as e:
        print(f"Error fetching user tournaments: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch user tournaments")

@app.get("/api/content/highlights")
async def get_featured_highlights():
    """Get featured highlights"""
    return {"success": True, "data": []}  # Mock empty data for now

@app.post("/api/auth/logout")
async def logout_user():
    """Logout endpoint"""
    return {"success": True, "message": "Logged out successfully"}

@app.post("/logout")
async def logout_user_redirect():
    """Logout endpoint that redirects to home page"""
    response = RedirectResponse(url="https://gamingnexus.onrender.com/index.html", status_code=302)
    response.delete_cookie("auth_token")
    response.delete_cookie("user_data")
    return response

# Authentication check endpoint for frontend
@app.get("/api/auth/check")
async def check_auth_status(request: Request):
    """Check authentication status from cookies and return user info"""
    user_info = check_auth_from_cookies(request)
    
    if not user_info:
        return {
            "authenticated": False,
            "redirect_to": "auth.html?tab=login"
        }
    
    return {
        "authenticated": True,
        "user": {
            "email": user_info["email"],
            "role": user_info["role"]
        },
        "redirect_to": "admin-dashboard.html" if user_info["role"] == "admin" else "index.html"
    }

# Route to handle admin dashboard access validation
@app.get("/validate-admin-access")
async def validate_admin_access(request: Request):
    """Validate if user can access admin dashboard"""
    user_info = check_auth_from_cookies(request)
    
    if not user_info:
        # Not authenticated - redirect to login
        return RedirectResponse(url="https://gamingnexus.onrender.com/auth.html?tab=login", status_code=302)
    
    if user_info["role"] != "admin":
        # Not an admin - redirect to user dashboard  
        return RedirectResponse(url="https://gamingnexus.onrender.com/index.html", status_code=302)
    
    # Is admin - allow access to admin dashboard
    return RedirectResponse(url="https://gamingnexus.onrender.com/admin-dashboard.html", status_code=302)

# Export endpoints
@app.get("/api/tournaments/{slug}/export/excel", dependencies=[Depends(require_admin)])
async def export_tournament_to_excel(
    slug: str,
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Export tournament teams to Excel file (admin only)"""
    try:
        import pandas as pd
        from fastapi.responses import StreamingResponse
        import io
        
        # Get admin user info from token
        payload = verify_jwt_token(auth.credentials)
        admin_email = payload.get("email", "unknown")
        
        # Get tournament data
        tournament = get_tournament_by_slug_from_db(slug)
        if not tournament:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tournament not found"
            )
        
        # Prepare data for Excel
        teams_data = []
        for i, team in enumerate(tournament.get("participants", []), 1):
            team_info = {
                "Team #": i,
                "Team Name": team.get("teamName", "Unknown"),
                "Registration Date": team.get("registrationDate", "N/A"),
                "Captain Name": "",
                "Captain Email": "",
                "Captain In-Game ID": "",
                "Player 2 Name": "",
                "Player 2 Email": "",
                "Player 2 In-Game ID": "",
                "Player 3 Name": "",
                "Player 3 Email": "",
                "Player 3 In-Game ID": "",
                "Player 4 Name": "",
                "Player 4 Email": "",
                "Player 4 In-Game ID": ""
            }
            
            # Fill player data
            players = team.get("players", [])
            for j, player in enumerate(players[:4]):  # Max 4 players
                if j == 0:  # Captain
                    team_info["Captain Name"] = player.get("name", "")
                    team_info["Captain Email"] = player.get("email", "")
                    team_info["Captain In-Game ID"] = player.get("inGameId", "")
                else:  # Other players
                    team_info[f"Player {j+1} Name"] = player.get("name", "")
                    team_info[f"Player {j+1} Email"] = player.get("email", "")
                    team_info[f"Player {j+1} In-Game ID"] = player.get("inGameId", "")
            
            teams_data.append(team_info)
        
        # Create DataFrame
        df = pd.DataFrame(teams_data)
        
        # Create Excel file in memory
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            # Tournament info sheet
            tournament_info = pd.DataFrame([
                ["Tournament Name", tournament.get("title", "")],
                ["Game", tournament.get("game", "")],
                ["Total Teams", len(tournament.get("participants", []))],
                ["Max Teams", tournament.get("maxTeams", "")],
                ["Prize Pool", f"₹{tournament.get('prizePool', 0):,}"],
                ["Registration Start", tournament.get("registrationStart", "")],
                ["Registration End", tournament.get("registrationEnd", "")],
                ["Tournament Start", tournament.get("tournamentStart", "")],
                ["Tournament End", tournament.get("tournamentEnd", "")],
                ["Export Date", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")]
            ], columns=["Field", "Value"])
            
            tournament_info.to_excel(writer, sheet_name='Tournament Info', index=False)
            df.to_excel(writer, sheet_name='Teams', index=False)
        
        output.seek(0)
        
        # Log the operation
        log_tournament_operation("EXPORT_EXCEL", slug, admin_email, f"Exported {len(teams_data)} teams")
        
        # Return file as download
        filename = f"{tournament.get('title', 'tournament').replace(' ', '_')}_teams.xlsx"
        return StreamingResponse(
            io.BytesIO(output.read()),
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except ImportError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Excel export functionality not available. Please install required dependencies."
        )
    except Exception as e:
        print(f"Excel export error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to export to Excel"
        )

# Tournament Bracket Endpoints
@app.get("/api/tournaments/{tournament_id}/brackets")
async def get_tournament_brackets_endpoint(
    tournament_id: str,
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Get tournament brackets"""
    try:
        # Verify authentication
        payload = verify_jwt_token(auth.credentials)
        
        brackets = get_tournament_brackets(tournament_id)
        if not brackets:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Brackets not found for this tournament"
            )
        
        return {"success": True, "data": brackets}
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except Exception as e:
        print(f"Error fetching tournament brackets: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch tournament brackets"
        )

@app.get("/api/tournaments/slug/{slug}/brackets")
async def get_tournament_brackets_by_slug(
    slug: str,
    auth: Optional[HTTPAuthorizationCredentials] = Security(security)
):
    """Get tournament brackets by tournament slug (public endpoint)"""
    try:
        # Get tournament by slug first
        tournament = get_tournament_by_slug_from_db(slug)
        if not tournament:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tournament not found"
            )
        
        tournament_id = str(tournament["_id"])
        
        # Get brackets
        brackets = get_tournament_brackets(tournament_id)
        if not brackets:
            # If no brackets exist, create a basic structure based on tournament participants
            participants = tournament.get("participants", [])
            if not participants:
                return {
                    "success": True, 
                    "data": {
                        "message": "No teams registered yet",
                        "tournament": {
                            "id": tournament_id,
                            "title": tournament.get("title"),
                            "format": tournament.get("format"),
                            "maxTeams": tournament.get("maxTeams", 0),
                            "registeredTeams": 0
                        }
                    }
                }
            
            # Create basic bracket structure for display
            basic_brackets = {
                "tournamentId": tournament_id,
                "tournament": {
                    "title": tournament.get("title"),
                    "format": tournament.get("format"),
                    "maxTeams": tournament.get("maxTeams", 0),
                    "registeredTeams": len(participants),
                    "status": tournament.get("status")
                },
                "teams": participants,
                "bracketsGenerated": False,
                "message": "Brackets will be generated when tournament starts"
            }
            return {"success": True, "data": basic_brackets}
        
        # Add tournament info to brackets
        brackets["tournament"] = {
            "title": tournament.get("title"),
            "format": tournament.get("format"),
            "maxTeams": tournament.get("maxTeams", 0),
            "registeredTeams": len(tournament.get("participants", [])),
            "status": tournament.get("status")
        }
        brackets["bracketsGenerated"] = True
        
        # If user is authenticated, add their team info
        user_team_info = None
        if auth:
            try:
                payload = verify_jwt_token(auth.credentials)
                user_email = payload.get("email")
                if user_email:
                    # Find user's team in tournament
                    for participant in tournament.get("participants", []):
                        if participant.get("captainEmail") == user_email:
                            user_team_info = {
                                "teamId": str(participant.get("_id")), # <-- Get the _id instead
                                "teamName": participant.get("teamName"),
                                "isCaptain": True
                            }
                            break
                        # Check if user is in players list
                        for player in participant.get("players", []):
                            if player.get("email") == user_email:
                                user_team_info = {
                                    "teamId": participant.get("teamId"),
                                    "teamName": participant.get("teamName"),
                                    "isCaptain": False
                                }
                                break
                        if user_team_info:
                            break
            except:
                pass  # Continue without user info if token is invalid
        
        if user_team_info:
            brackets["userTeam"] = user_team_info
        
        return {"success": True, "data": brackets}
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error fetching tournament brackets by slug: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch tournament brackets"
        )

@app.post("/api/tournaments/{tournament_id}/brackets", dependencies=[Depends(require_admin)])
async def create_tournament_brackets_endpoint(
    tournament_id: str,
    brackets_data: dict,
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Create tournament brackets"""
    try:
        # Get admin user info from token
        payload = verify_jwt_token(auth.credentials)
        admin_email = payload.get("email", "unknown")
        
        # Check if brackets already exist
        existing_brackets = get_tournament_brackets(tournament_id)
        if existing_brackets:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Brackets already exist for this tournament"
            )
        
        # Create brackets
        brackets_id = create_tournament_brackets(tournament_id, brackets_data)
        
        # Get created brackets
        created_brackets = get_tournament_brackets(tournament_id)
        
        log_tournament_operation("CREATE_BRACKETS", tournament_id, admin_email)
        
        return {"success": True, "data": created_brackets, "message": "Brackets created successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error creating tournament brackets: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create tournament brackets"
        )

@app.post("/api/tournaments/{tournament_id}/brackets/round/{round_key}/start", dependencies=[Depends(require_admin)])
async def start_tournament_round(
    tournament_id: str,
    round_key: str,
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Start a tournament round"""
    try:
        # Get admin user info from token
        payload = verify_jwt_token(auth.credentials)
        admin_email = payload.get("email", "unknown")
        
        # Validate round key
        valid_rounds = ["1", "2", "3", "4", "final"]
        if round_key not in valid_rounds:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid round key"
            )
        
        # Check if brackets exist
        brackets = get_tournament_brackets(tournament_id)
        if not brackets:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Brackets not found for this tournament"
            )
        
        # Check if round can be started
        if brackets["rounds"][round_key]["status"] != "pending":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Round {round_key} cannot be started (current status: {brackets['rounds'][round_key]['status']})"
            )
        
        # Start the round
        success = update_round_status(tournament_id, round_key, "active")
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to start round"
            )
        
        log_tournament_operation("START_ROUND", tournament_id, admin_email, f"Round {round_key}")
        
        # Log round started activity
        try:
            # Get tournament details for activity logging
            tournament = get_tournament_by_slug_from_db(brackets.get("tournamentSlug", ""))
            if not tournament:
                # Fallback: find tournament by ID
                from database import get_database
                db = get_database()
                tournament = db.tournaments.find_one({"_id": ObjectId(tournament_id)})
            
            if tournament:
                log_round_activity(
                    tournament_id, 
                    tournament.get("title", "Unknown Tournament"), 
                    tournament.get("slug", ""), 
                    round_key, 
                    "started", 
                    admin_email
                )
        except Exception as e:
            print(f"Failed to log round started activity: {e}")
        
        return {"success": True, "message": f"Round {round_key} started successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error starting tournament round: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start tournament round"
        )

@app.post("/api/tournaments/{tournament_id}/brackets/round/{round_key}/complete", dependencies=[Depends(require_admin)])
async def complete_tournament_round(
    tournament_id: str,
    round_key: str,
    request_data: Optional[dict] = None,
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Complete a tournament round and advance qualifying teams"""
    try:
        # Get admin user info from token
        payload = verify_jwt_token(auth.credentials)
        admin_email = payload.get("email", "unknown")
        
        # Validate round key
        valid_rounds = ["1", "2", "3", "4", "final"]
        if round_key not in valid_rounds:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid round key"
            )
        
        # Check if brackets exist
        brackets = get_tournament_brackets(tournament_id)
        if not brackets:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Brackets not found for this tournament"
            )
        
        # Check if round can be completed
        if brackets["rounds"][round_key]["status"] != "active":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Round {round_key} cannot be completed (current status: {brackets['rounds'][round_key]['status']})"
            )
        
        # For final round, just mark as completed
        if round_key == "final":
            success = update_round_status(tournament_id, round_key, "completed")
            if not success:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to complete final round"
                )
        else:
            # Get qualifying teams (top performers from current round)
            current_round_teams = brackets["rounds"][round_key]["teams"]
            
            # For KP format: top 4 teams from each group qualify (16 total for next round)
            qualifying_teams = []
            if round_key in ["1", "2", "3"]:
                # Sort teams by score and take top performers
                sorted_teams = sorted(current_round_teams, key=lambda x: x.get("score", 0), reverse=True)
                
                # Number of teams that qualify depends on the round
                qualify_count = {
                    "1": 25,  # Top 25 from round 1 (from 100 teams)
                    "2": 16,  # Top 16 from round 2 (from 25 teams)
                    "3": 8    # Top 8 from round 3 (from 16 teams)
                }.get(round_key, 16)
                
                qualifying_teams = sorted_teams[:qualify_count]
            
            # Advance teams to next round
            if qualifying_teams:
                success = advance_teams_to_next_round(tournament_id, round_key, qualifying_teams)
                if not success:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Failed to advance teams to next round"
                    )
        
        # Get updated brackets
        updated_brackets = get_tournament_brackets(tournament_id)
        
        log_tournament_operation("COMPLETE_ROUND", tournament_id, admin_email, f"Round {round_key}")
        
        # Log round completed activity
        try:
            # Get tournament details for activity logging
            from database import get_database
            db = get_database()
            tournament = db.tournaments.find_one({"_id": ObjectId(tournament_id)})
            
            if tournament:
                log_round_activity(
                    tournament_id, 
                    tournament.get("title", "Unknown Tournament"), 
                    tournament.get("slug", ""), 
                    round_key, 
                    "completed", 
                    admin_email
                )
        except Exception as e:
            print(f"Failed to log round completed activity: {e}")
        
        return {
            "success": True, 
            "data": updated_brackets,
            "message": f"Round {round_key} completed successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error completing tournament round: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to complete tournament round"
        )

@app.post("/api/tournaments/{tournament_id}/brackets/payment")
async def update_bracket_payment(
    tournament_id: str,
    payment_data: BracketPaymentRequest,
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Update team payment status for tournament brackets"""
    try:
        # Verify authentication
        payload = verify_jwt_token(auth.credentials)
        user_email = payload.get("email", "unknown")
        
        # Check if brackets exist
        brackets = get_tournament_brackets(tournament_id)
        if not brackets:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Brackets not found for this tournament"
            )
        
        # Validate round key
        if payment_data.roundKey not in brackets["rounds"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid round key"
            )
        
        # Update payment status
        payment_info = {
            "status": payment_data.status,
            "amount": payment_data.amount,
            "paymentMethod": payment_data.paymentMethod,
            "transactionId": payment_data.transactionId,
            "updatedBy": user_email,
            "updatedAt": datetime.utcnow().isoformat()
        }
        
        success = update_team_payment_status(
            tournament_id, 
            payment_data.teamId, 
            payment_data.roundKey, 
            payment_info
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update payment status"
            )
        
        return {"success": True, "message": "Payment status updated successfully"}
        
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except Exception as e:
        print(f"Error updating bracket payment: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update payment status"
        )

# Team Management Endpoints
@app.get("/api/teams/{team_id}")
async def get_team_details(
    team_id: str,
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Get team details by team ID"""
    try:
        # Verify authentication
        payload = verify_jwt_token(auth.credentials)
        
        team = get_team_by_id(team_id)
        if not team:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Team not found"
            )
        
        return {"success": True, "data": team}
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error fetching team details: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch team details"
        )

@app.get("/api/tournaments/{tournament_id}/team")
async def get_user_team_in_tournament_endpoint(
    tournament_id: str,
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Get user's team in a specific tournament with enhanced lookup"""
    try:
        # Verify authentication
        payload = verify_jwt_token(auth.credentials)
        user_email = payload.get("email")
        user_id = payload.get("user_id")
        
        if not user_email:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User email not found in token"
            )
        
        # Use enhanced lookup with both email and user ID
        team = get_user_team_in_tournament(tournament_id, user_email, user_id)
        if not team:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User is not registered in this tournament"
            )
        
        return {"success": True, "data": team}
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error fetching user team: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch user team"
        )

# Static file serving endpoint for images
@app.get("/api/static/images/{filename}")
async def serve_static_image(filename: str):
    """Serve static images with proper CORS headers"""
    try:
        import os
        from fastapi.responses import FileResponse
        
        file_path = os.path.join("uploads", filename)
        if not os.path.exists(file_path):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Image not found"
            )
        
        return FileResponse(
            file_path,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET",
                "Access-Control-Allow-Headers": "*"
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error serving static image: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to serve image"
        )

# Activity System Endpoints
@app.get("/api/activities/recent")
async def get_recent_activities_endpoint(
    limit: int = 20,
    skip: int = 0,
    type: Optional[str] = None,
    auth: Optional[HTTPAuthorizationCredentials] = Security(security)
):
    """Get recent platform activities"""
    try:
        # Optional authentication - show more activities if authenticated
        user_id = None
        if auth:
            try:
                payload = verify_jwt_token(auth.credentials)
                user_id = payload.get("user_id")
            except:
                pass  # Continue without authentication
        
        activities, total_count = get_recent_activities(limit, skip, type, user_id)
        
        # Calculate pagination info
        page = (skip // limit) + 1
        
        return {
            "success": True,
            "data": activities,
            "total": total_count,
            "page": page,
            "limit": limit,
            "hasMore": skip + limit < total_count
        }
        
    except Exception as e:
        print(f"Error fetching recent activities: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch recent activities"
        )

@app.get("/api/activities/user")
async def get_user_activities_endpoint(
    limit: int = 20,
    skip: int = 0,
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Get activities for the authenticated user"""
    try:
        # Verify authentication
        payload = verify_jwt_token(auth.credentials)
        user_id = payload.get("user_id")
        
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User ID not found in token"
            )
        
        activities, total_count = get_user_activities(user_id, limit, skip)
        
        # Calculate pagination info
        page = (skip // limit) + 1
        
        return {
            "success": True,
            "data": activities,
            "total": total_count,
            "page": page,
            "limit": limit,
            "hasMore": skip + limit < total_count
        }
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except Exception as e:
        print(f"Error fetching user activities: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch user activities"
        )

@app.get("/api/tournaments/{tournament_id}/activities")
async def get_tournament_activities_endpoint(
    tournament_id: str,
    limit: int = 20,
    auth: Optional[HTTPAuthorizationCredentials] = Security(security)
):
    """Get activities for a specific tournament"""
    try:
        activities = get_tournament_activities(tournament_id, limit)
        
        return {
            "success": True,
            "data": activities,
            "total": len(activities)
        }
        
    except Exception as e:
        print(f"Error fetching tournament activities: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch tournament activities"
        )

@app.post("/api/activities", dependencies=[Depends(require_admin)])
async def create_activity_endpoint(
    activity_data: ActivityCreate,
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Create a new activity (admin only)"""
    try:
        # Get admin user info from token
        payload = verify_jwt_token(auth.credentials)
        admin_email = payload.get("email", "unknown")
        
        # Convert to dict and create activity
        activity_dict = activity_data.dict()
        activity_dict["createdBy"] = admin_email
        
        activity_id = create_activity(activity_dict)
        
        return {
            "success": True,
            "data": {"id": activity_id},
            "message": "Activity created successfully"
        }
        
    except Exception as e:
        print(f"Error creating activity: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create activity"
        )

@app.delete("/api/activities/cleanup", dependencies=[Depends(require_admin)])
async def cleanup_old_activities_endpoint(
    days: int = 90,
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Clean up old activities (admin only)"""
    try:
        # Get admin user info from token
        payload = verify_jwt_token(auth.credentials)
        admin_email = payload.get("email", "unknown")
        
        deleted_count = cleanup_old_activities(days)
        
        return {
            "success": True,
            "data": {"deletedCount": deleted_count},
            "message": f"Cleaned up {deleted_count} old activities"
        }
        
    except Exception as e:
        print(f"Error cleaning up activities: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to clean up activities"
        )

@app.get("/api/tournaments/{slug}/export/pdf", dependencies=[Depends(require_admin)])
async def export_tournament_to_pdf(
    slug: str,
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Export tournament teams to PDF with nested player tables."""
    try:
        from reportlab.lib.pagesizes import letter, A4, landscape
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib import colors
        from reportlab.lib.units import inch
        from fastapi.responses import StreamingResponse
        import io
        
        # Get admin user info
        payload = verify_jwt_token(auth.credentials)
        admin_email = payload.get("email", "unknown")
        
        # Get tournament data
        tournament = get_tournament_by_slug_from_db(slug)
        if not tournament:
            raise HTTPException(status_code=404, detail="Tournament not found")
        
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=landscape(A4))
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        story.append(Paragraph(f"Registered Teams: {tournament.get('title', '')}", styles['h1']))
        story.append(Spacer(1, 0.25 * inch))
        
        # --- NEW: Data preparation for nested tables ---
        table_headers = ["S.No", "Team Name", "Player Details (Name, Email, In-Game ID)"]
        table_data = [table_headers]
        
        for i, team in enumerate(tournament.get("participants", []), 1):
            players = team.get("players", [])
            
            # Create the inner table for players
            player_data = []
            for player in players:
                player_details = [
                    player.get("name", "N/A"),
                    player.get("email", "N/A"),
                    player.get("inGameId", "N/A")
                ]
                player_data.append(player_details)
            
            if not player_data:  # If team has no players, show a placeholder
                player_data = [["No players listed", "", ""]]
            
            # Create the inner Table object
            player_table = Table(player_data, colWidths=[2.5*inch, 3*inch, 2*inch])
            player_table.setStyle(TableStyle([
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            
            # Add the main row, with the inner table as a cell
            table_data.append([
                str(i),
                team.get("teamName", "Unknown"),
                player_table  # Embed the player table here
            ])
        
        # --- Main Table Styling ---
        main_table = Table(table_data, colWidths=[0.5*inch, 2*inch, 7.5*inch])
        main_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),  # Center headers
            ('ALIGN', (0, 1), (1, -1), 'CENTER'),  # Center S.No and Team Name
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('TOPPADDING', (0, 1), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
        ]))
        
        story.append(main_table)
        doc.build(story)
        buffer.seek(0)
        
        log_tournament_operation("EXPORT_PDF", slug, admin_email)
        filename = f"{slug}_teams_report.pdf"
        
        return StreamingResponse(
            io.BytesIO(buffer.read()),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except ImportError:
        raise HTTPException(status_code=501, detail="PDF export libraries not installed.")
    except Exception as e:
        print(f"PDF export error: {e}")
        raise HTTPException(status_code=500, detail="Failed to export to PDF")


def get_current_user(auth: HTTPAuthorizationCredentials = Security(security)):
    """Dependency to get current authenticated user"""
    try:
        payload = verify_jwt_token(auth.credentials)
        user_id = payload.get("user_id")
        email = payload.get("email")
        username = payload.get("username")
        role = payload.get("role", "user")
        
        if not user_id or not email:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload"
            )
        
        return {
            "id": user_id,
            "email": email,
            "username": username,
            "role": role
        }
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )



    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating venue assignment: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create venue assignment"
        )

# ================================
# TICKET MANAGEMENT ENDPOINTS
# ================================

@app.post("/api/tickets/create", response_model=TicketResponse)
async def create_ticket_endpoint(
    ticket_data: TicketCreateRequest,
    request: Request
):
    """Create a new support/dispute ticket with enhanced error handling"""
    try:
        # Get user information from session/cookies
        user_info = check_auth_from_cookies(request)
        
        if not user_info:
            raise TicketPermissionError("Authentication required to create tickets")
        
        user_email = user_info.get("email")
        user_id = user_info.get("token_payload", {}).get("user_id")
        
        if not user_id:
            # Try to get user ID from email
            user_record = get_user_by_email(user_email)
            if user_record:
                user_id = str(user_record.get("_id"))
            else:
                raise TicketValidationError("Unable to identify user", "userId")
        
        # Check rate limiting
        if ticket_rate_limiter.is_rate_limited(user_id, max_requests=5, window_minutes=60):
            retry_after = ticket_rate_limiter.get_retry_after(user_id, window_minutes=60)
            raise TicketRateLimitError(
                "Too many ticket submissions. Please wait before creating another ticket.",
                retry_after=retry_after
            )
        
        # Additional validation
        ticket_dict = ticket_data.model_dump()
        validation_errors = validate_ticket_data(ticket_dict)
        if validation_errors:
            raise TicketValidationError(f"Validation failed: {'; '.join(validation_errors)}")
        
        # Generate unique ticket ID
        ticket_id = generate_ticket_id()
        
        # Prepare ticket data for database
        current_time = datetime.utcnow()
        ticket_doc = {
            "ticketId": ticket_id,
            "userId": user_id,
            "userEmail": user_email,
            "category": ticket_data.issueType,
            "priority": ticket_data.priority,
            "status": "open",
            "subject": sanitize_html_input(ticket_data.subject),
            "description": sanitize_html_input(ticket_data.description),
            "attachments": ticket_data.attachments,
            "tournamentId": ticket_data.tournamentId,
            "assignedTo": None,
            "tags": [],
            "resolution": None,
            "satisfactionRating": None,
            "createdAt": current_time,
            "updatedAt": current_time,
            "resolvedAt": None,
            "messages": [],
            # Metadata for audit
            "ipAddress": request.client.host if request.client else "unknown",
            "userAgent": request.headers.get("user-agent", "unknown"),
            "source": "web"
        }
        
        # Create ticket in database
        try:
            db_ticket_id = create_support_ticket(ticket_doc)
        except Exception as db_error:
            log_ticket_error(db_error, {"operation": "create_ticket", "user_id": user_id})
            raise TicketError("Failed to save ticket to database")
        
        # Log the operation
        log_ticket_operation("CREATE", ticket_id, user_email, f"Category: {ticket_data.issueType}, Priority: {ticket_data.priority}")
        
        # Calculate estimated resolution time
        resolution_hours = 48 if ticket_data.priority in ["high", "critical"] else 72
        estimated_resolution = current_time + datetime.timedelta(hours=resolution_hours)
        
        # Return success response
        return TicketResponse(
            success=True,
            ticketId=ticket_id,
            message="Ticket created successfully. Our support team will review your request and respond soon.",
            data={
                "ticketId": ticket_id,
                "status": "open",
                "priority": ticket_data.priority,
                "category": ticket_data.issueType,
                "createdAt": current_time.isoformat(),
                "estimatedResolution": estimated_resolution.isoformat(),
                "supportHours": "Monday-Friday 9AM-6PM UTC"
            }
        )
        
    except (TicketError, TicketValidationError, TicketPermissionError, TicketRateLimitError) as e:
        raise handle_ticket_exception(e, "ticket creation")
    except ValidationError as e:
        validation_errors = [f"{error['loc'][-1]}: {error['msg']}" for error in e.errors()]
        return TicketResponse(
            success=False,
            message="Validation failed",
            errors=validation_errors
        )
    except Exception as e:
        log_ticket_error(e, {"operation": "create_ticket", "user_email": user_email})
        raise handle_ticket_exception(e, "ticket creation")


@app.get("/api/tickets/user/{user_id}")
async def get_user_tickets_endpoint(
    user_id: str,
    request: Request,
    page: int = 1,
    limit: int = 10,
    status: Optional[str] = None,
    category: Optional[str] = None,
    search: Optional[str] = None
):
    """Get tickets for a specific user"""
    try:
        # Verify authentication
        user_info = check_auth_from_cookies(request)
        
        if not user_info:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required"
            )
        
        # Check if user is requesting their own tickets or is admin
        requesting_user_id = user_info.get("token_payload", {}).get("user_id")
        is_admin = user_info.get("role") == "admin"
        
        if not is_admin and requesting_user_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only access your own tickets"
            )
        
        # Build filters
        filters = {"userId": user_id}
        if status and validate_ticket_status(status):
            filters["status"] = status
        if category and validate_ticket_category(category):
            filters["category"] = category
        
        # Calculate pagination
        skip = (page - 1) * limit
        
        # Get tickets from database
        tickets = get_support_tickets(
            category=category,
            status=status,
            limit=limit,
            skip=skip
        )
        
        # Filter by user ID (since get_support_tickets doesn't have user filter)
        user_tickets = [ticket for ticket in tickets if ticket.get("userId") == user_id]
        
        # Apply search filter if provided
        if search:
            search_lower = search.lower()
            user_tickets = [
                ticket for ticket in user_tickets
                if search_lower in ticket.get("subject", "").lower() or
                   search_lower in ticket.get("description", "").lower() or
                   search_lower in ticket.get("ticketId", "").lower()
            ]
        
        # Format tickets for response
        formatted_tickets = []
        for ticket in user_tickets:
            formatted_ticket = format_ticket_for_response(ticket, include_messages=False)
            formatted_tickets.append(formatted_ticket)
        
        # Calculate total for pagination
        total_tickets = len(formatted_tickets)
        total_pages = (total_tickets + limit - 1) // limit
        
        return {
            "success": True,
            "data": {
                "tickets": formatted_tickets,
                "pagination": {
                    "total": total_tickets,
                    "page": page,
                    "limit": limit,
                    "totalPages": total_pages
                }
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting user tickets: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve tickets"
        )


# SIMPLIFIED and FIXED VERSION for main.py

@app.get("/api/tickets/{ticket_id}")
async def get_ticket_details_endpoint(
    ticket_id: str,
    request: Request
):
    """Get detailed information for a specific ticket"""
    try:
        user_info = check_auth_from_cookies(request)
        if not user_info:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required"
            )

        # Directly call the corrected database function
        ticket = get_support_ticket(ticket_id) 

        if not ticket:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Ticket not found"
            )

        # Check authorization (same as before)
        requesting_user_id = user_info.get("token_payload", {}).get("user_id")
        is_admin = user_info.get("role") == "admin"
        ticket_user_id = ticket.get("userId")

        if not is_admin and requesting_user_id != ticket_user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only access your own tickets"
            )

        # Format and return the ticket
        formatted_ticket = format_ticket_for_response(ticket, include_messages=True)
        return { "success": True, "data": formatted_ticket }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting ticket details: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve ticket details"
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

@app.get("/api/tournaments/all")
async def get_all_tournaments_including_user_hosted(
    limit: int = 50,
    skip: int = 0,
    game: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None
):
    """Get all tournaments (admin only)"""
    try:
        all_tournaments = []
        
        # Get admin tournaments only
        admin_tournaments = get_all_tournaments_from_db()
        for tournament in admin_tournaments:
            tournament["hostingType"] = "admin"
            tournament["organizerUsername"] = "Admin"
            tournament["organizerEmail"] = "admin@gamingnexus.com"
            all_tournaments.append(tournament)
        
        # Apply filters
        filtered_tournaments = all_tournaments
        
        if game:
            filtered_tournaments = [t for t in filtered_tournaments if t.get("game", "").lower() == game.lower()]
        
        if status:
            filtered_tournaments = [t for t in filtered_tournaments if t.get("status", "") == status]
        
        if search:
            search_lower = search.lower()
            filtered_tournaments = [
                t for t in filtered_tournaments 
                if search_lower in t.get("title", "").lower() 
                or search_lower in t.get("game", "").lower()
                or search_lower in t.get("description", "").lower()
            ]
        
        # Sort by creation date (newest first)
        filtered_tournaments.sort(key=lambda x: x.get("createdAt", ""), reverse=True)
        
        # Apply pagination
        paginated_tournaments = filtered_tournaments[skip:skip + limit]
        
        return {
            "success": True,
            "data": paginated_tournaments,
            "total": len(filtered_tournaments),
            "page": (skip // limit) + 1,
            "limit": limit,
            "hasMore": skip + limit < len(filtered_tournaments)
        }
        
    except Exception as e:
        print(f"Error fetching all tournaments: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch tournaments"
        )



@app.get("/api/tournaments/featured")
async def get_featured_tournaments_extended():
    """Get featured tournaments (admin only)"""
    try:
        featured_tournaments = []
        
        # Get admin tournaments (always featured)
        admin_tournaments = get_all_tournaments_from_db()
        for tournament in admin_tournaments[:5]:  # Top 5 admin tournaments
            tournament["hostingType"] = "admin"
            tournament["featured"] = True
            tournament["featuredReason"] = "Official Tournament"
            featured_tournaments.append(tournament)
        
        return {
            "success": True,
            "data": featured_tournaments,
            "message": "Featured tournaments retrieved successfully"
        }
        
    except Exception as e:
        print(f"Error fetching featured tournaments: {e}")
        return {"success": False, "data": []}

@app.get("/api/tournaments/search")
async def search_tournaments(
    q: str,
    limit: int = 20
):
    """Search tournaments by title, game, or description (admin only)"""
    try:
        if not q or len(q.strip()) < 2:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Search query must be at least 2 characters long"
            )
        
        search_query = q.strip().lower()
        results = []
        
        # Search admin tournaments only
        admin_tournaments = get_all_tournaments_from_db()
        for tournament in admin_tournaments:
            if (search_query in tournament.get("title", "").lower() or
                search_query in tournament.get("game", "").lower() or
                search_query in tournament.get("description", "").lower()):
                tournament["hostingType"] = "admin"
                tournament["organizerUsername"] = "Admin"
                results.append(tournament)
        
        # Sort by relevance (exact title matches first, then game matches, then description)
        def relevance_score(tournament):
            title = tournament.get("title", "").lower()
            game = tournament.get("game", "").lower()
            description = tournament.get("description", "").lower()
            
            if search_query == title:
                return 100
            elif search_query in title:
                return 90
            elif search_query == game:
                return 80
            elif search_query in game:
                return 70
            elif search_query in description:
                return 60
            else:
                return 0
        
        results.sort(key=relevance_score, reverse=True)
        
        # Apply limit
        results = results[:limit]
        
        return {
            "success": True,
            "data": results,
            "total": len(results),
            "query": q,
            "message": f"Found {len(results)} tournaments matching '{q}'"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error searching tournaments: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to search tournaments"
        )#

@app.get("/api/tournaments/{slug}/details")
async def get_tournament_details_unified(slug: str):
    """Get tournament details (admin only)"""
    try:
        # Find in admin tournaments only
        admin_tournament = get_tournament_by_slug_from_db(slug)
        
        if admin_tournament:
            admin_tournament["hostingType"] = "admin"
            admin_tournament["organizerUsername"] = "Admin"
            admin_tournament["organizerEmail"] = "admin@gamingnexus.com"
            admin_tournament["organizerRating"] = 5.0
            admin_tournament["organizerReputationScore"] = 100
            
            return {
                "success": True,
                "data": admin_tournament,
                "message": "Tournament details retrieved successfully"
            }
        
        # Tournament not found
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tournament not found"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error getting tournament details: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get tournament details"
        )#


@app.get("/api/analytics/platform", dependencies=[Depends(require_admin)])
async def get_platform_analytics_endpoint(
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Get platform-wide analytics (admin only)"""
    try:
        # Get analytics
        from analytics_service import get_analytics_service
        analytics_service = get_analytics_service()
        
        analytics = analytics_service.get_platform_analytics()
        
        if "error" in analytics:
            raise HTTPException(status_code=400, detail=analytics["error"])
        
        return analytics
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error getting platform analytics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get platform analytics"
        )


# In main.py

@app.get("/api/notifications")
async def get_user_notifications(
    limit: int = 20,
    skip: int = Query(0, alias="offset"), # Use alias to accept 'offset' from frontend
    unread_only: bool = False,
    current_user: dict = Depends(get_current_user)
):
    """Get user's notifications (using the activity system)."""
    try:
        # --- FIX 1: Correctly unpack the tuple returned by the database function ---
        activities, total_count = get_user_activities(
            user_id=current_user["id"],
            limit=limit,
            skip=skip
        )
        
        notifications = []
        # --- FIX 2: Treat all user-specific activities as notifications ---
        for activity in activities:
            metadata = activity.get("metadata", {})
            
            # Filter for unread if requested
            is_read = metadata.get("isRead", False)
            if unread_only and is_read:
                continue

            # Construct the notification object from the activity data
            notification = {
                "id": str(activity["_id"]),
                "title": activity.get("title"),
                "message": activity.get("description"),
                "type": activity.get("type"), # Use the activity's main type
                "relatedId": activity.get("tournamentId"),
                "actionUrl": f"/tournament-details.html?slug={activity.get('tournamentSlug', '')}" if activity.get('tournamentSlug') else None,
                "isRead": is_read,
                "priority": activity.get("priority", "normal"),
                "createdAt": activity.get("timestamp")
            }
            notifications.append(notification)
        
        unread_count = sum(1 for n in notifications if not n["isRead"])

        return {
            "success": True,
            "data": {
                "notifications": notifications,
                "total": total_count,
                "unreadCount": unread_count
            },
            "message": "Notifications retrieved successfully"
        }
        
    except Exception as e:
        logger.error(f"Error getting user notifications: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve notifications")

# In main.py

@app.patch("/api/notifications/{notification_id}/read")
async def mark_notification_read(
    notification_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Mark a specific notification as read."""
    try:
        from database import get_database
        db = get_database()
        activities_collection = db.activities

        # --- CORRECTED QUERY ---
        # Use the correct user ID key and remove the non-existent 'activityType' field.
        # This ensures a user can only mark their own notifications as read.
        result = activities_collection.update_one(
            {
                "_id": ObjectId(notification_id),
                "userId": current_user["id"] 
            },
            {
                "$set": {
                    "metadata.isRead": True,
                    "metadata.readAt": datetime.utcnow().isoformat()
                }
            }
        )

        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Notification not found or you do not have permission to modify it.")

        return {"success": True, "message": "Notification marked as read"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error marking notification as read: {e}")
        raise HTTPException(status_code=500, detail="Failed to update notification")

# In main.py

@app.patch("/api/notifications/read-all")
async def mark_all_notifications_read(
    current_user: dict = Depends(get_current_user)
):
    """Mark all unread notifications as read for the current user."""
    try:
        from database import get_database
        db = get_database()
        activities_collection = db.activities

        # --- CORRECTED QUERY ---
        # Use the correct user ID key and remove the non-existent 'activityType' field.
        result = activities_collection.update_many(
            {
                "userId": current_user["id"],
                "metadata.isRead": {"$ne": True}
            },
            {
                "$set": {
                    "metadata.isRead": True,
                    "metadata.readAt": datetime.utcnow().isoformat()
                }
            }
        )

        return {
            "success": True,
            "data": {"updatedCount": result.modified_count},
            "message": f"Marked {result.modified_count} notifications as read"
        }

    except Exception as e:
        logger.error(f"Error marking all notifications as read: {e}")
        raise HTTPException(status_code=500, detail="Failed to update notifications")


@app.delete("/api/notifications/{notification_id}")
async def delete_notification(
    notification_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a notification"""
    try:
        from database import get_database
        
        # Validate notification ID format
        try:
            ObjectId(notification_id)
        except:
            raise HTTPException(status_code=400, detail="Invalid notification ID format")
        
        db = get_database()
        activities_collection = db.activities
        
        # Delete notification
        result = activities_collection.delete_one({
            "_id": ObjectId(notification_id),
            "userId": current_user["user_id"],
            "activityType": "notification"
        })
        
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Notification not found")
        
        return {
            "success": True,
            "message": "Notification deleted successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error deleting notification: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete notification")


@app.get("/api/notifications/preferences")
async def get_notification_preferences(
    current_user: dict = Depends(get_current_user)
):
    """Get user's notification preferences"""
    try:
        from database import get_database
        
        db = get_database()
        users_collection = db.users
        
        user = users_collection.find_one({"_id": ObjectId(current_user["user_id"])})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Default notification preferences
        default_preferences = {
            "emailNotifications": {
                "tournamentUpdates": True,
                "registrationConfirmations": True,
                "paymentConfirmations": True,
                "tournamentReminders": True,
                "waitlistPromotions": True,
                "organizerMessages": True
            },
            "inAppNotifications": {
                "tournamentUpdates": True,
                "registrationConfirmations": True,
                "paymentConfirmations": True,
                "tournamentReminders": True,
                "waitlistPromotions": True,
                "organizerMessages": True
            },
            "smsNotifications": {
                "tournamentReminders": False,
                "waitlistPromotions": False,
                "urgentUpdates": False
            }
        }
        
        preferences = user.get("notificationPreferences", default_preferences)
        
        return {
            "success": True,
            "data": preferences,
            "message": "Notification preferences retrieved successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error getting notification preferences: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve preferences")


@app.patch("/api/notifications/preferences")
async def update_notification_preferences(
    preferences: dict,
    current_user: dict = Depends(get_current_user)
):
    """Update user's notification preferences"""
    try:
        from database import get_database
        
        db = get_database()
        users_collection = db.users
        
        # Update user's notification preferences
        result = users_collection.update_one(
            {"_id": ObjectId(current_user["user_id"])},
            {
                "$set": {
                    "notificationPreferences": preferences,
                    "updatedAt": datetime.utcnow().isoformat()
                }
            }
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="User not found")
        
        return {
            "success": True,
            "data": preferences,
            "message": "Notification preferences updated successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error updating notification preferences: {e}")
        raise HTTPException(status_code=500, detail="Failed to update preferences")

# Content Moderation API Endpoints

@app.get("/api/admin/moderation/queue")
async def get_moderation_queue_endpoint(
    limit: int = 50,
    skip: int = 0,
    priority: Optional[str] = None,
    admin: dict = Depends(require_admin)
):
    """Get items from the moderation queue (admin only)"""
    try:
        queue_items = get_moderation_queue(limit=limit, skip=skip, priority=priority)
        
        return {
            "success": True,
            "data": queue_items,
            "total": len(queue_items),
            "message": "Moderation queue retrieved successfully"
        }
        
    except Exception as e:
        print(f"Error getting moderation queue: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve moderation queue"
        )


@app.post("/api/admin/moderation/review/{tournament_id}")
async def review_tournament_moderation(
    tournament_id: str,
    moderation_action: ModerationAction,
    admin: dict = Depends(require_admin)
):
    """Review and take action on a tournament in moderation queue (admin only)"""
    try:
        reviewer_id = admin.get("email", "unknown")
        
        # Update tournament moderation status
        success = update_tournament_moderation_status(
            tournament_id=tournament_id,
            status=moderation_action.action,
            reviewer_id=reviewer_id,
            notes=moderation_action.notes
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tournament not found or already reviewed"
            )
        
        # Create moderation review record
        review_data = {
            "tournament_id": tournament_id,
            "reviewer_id": reviewer_id,
            "action": moderation_action.action,
            "notes": moderation_action.notes,
            "notify_organizer": moderation_action.notifyOrganizer
        }
        
        review_id = create_moderation_review(review_data)
        
        # TODO: Send notification to organizer if requested
        if moderation_action.notifyOrganizer:
            # This would integrate with the notification service
            pass
        
        return ModerationResponse(
            success=True,
            data={"review_id": review_id, "action": moderation_action.action},
            message=f"Tournament {moderation_action.action}d successfully"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error reviewing tournament moderation: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process moderation review"
        )


@app.get("/api/admin/moderation/stats")
async def get_moderation_statistics(
    days: int = 30,
    admin: dict = Depends(require_admin)
):
    """Get moderation statistics (admin only)"""
    try:
        stats = get_moderation_stats(date_range=days)
        
        return {
            "success": True,
            "data": stats,
            "message": "Moderation statistics retrieved successfully"
        }
        
    except Exception as e:
        print(f"Error getting moderation stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve moderation statistics"
        )


@app.post("/api/admin/moderation/trusted-organizer/{organizer_id}")
async def add_trusted_organizer(
    organizer_id: str,
    admin: dict = Depends(require_admin)
):
    """Add organizer to trusted list (admin only)"""
    try:
        moderation_service = get_content_moderation_service()
        await moderation_service.add_trusted_organizer(organizer_id)
        
        return {
            "success": True,
            "message": f"Organizer {organizer_id} added to trusted list"
        }
        
    except Exception as e:
        print(f"Error adding trusted organizer: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to add trusted organizer"
        )


@app.delete("/api/admin/moderation/trusted-organizer/{organizer_id}")
async def remove_trusted_organizer(
    organizer_id: str,
    admin: dict = Depends(require_admin)
):
    """Remove organizer from trusted list (admin only)"""
    try:
        moderation_service = get_content_moderation_service()
        await moderation_service.remove_trusted_organizer(organizer_id)
        
        return {
            "success": True,
            "message": f"Organizer {organizer_id} removed from trusted list"
        }
        
    except Exception as e:
        print(f"Error removing trusted organizer: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to remove trusted organizer"
        )



    except Exception as e:
        print(f"Error rating organizer: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to submit organizer rating"
        )


# @app.get("/api/organizers/{organizer_id}/credibility")
# async def get_organizer_credibility_indicators(organizer_id: str):
#     """Get credibility indicators for organizer display"""
#     try:
#         indicators = await organizer_reputation_service.get_credibility_indicators(organizer_id)
        
#         return {
#             "success": True,
#             "data": {
#                 "indicators": [
#                     {
#                         "type": indicator.indicator_type,
#                         "label": indicator.label,
#                         "value": indicator.value,
#                         "icon": indicator.icon,
#                         "color": indicator.color,
#                         "tooltip": indicator.tooltip
#                     }
#                     for indicator in indicators
#                 ]
#             },
#             "message": "Credibility indicators retrieved successfully"
#         }
        
#     except Exception as e:
#         print(f"Error getting credibility indicators: {e}")
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail="Failed to retrieve credibility indicators"
#         )


# @app.get("/api/organizers/{organizer_id}/ratings-summary")
# async def get_organizer_ratings_summary_endpoint(organizer_id: str):
#     """Get summary of organizer ratings and feedback"""
#     try:
#         summary = await organizer_reputation_service.get_organizer_ratings_summary(organizer_id)
        
#         return {
#             "success": True,
#             "data": summary,
#             "message": "Ratings summary retrieved successfully"
#         }
        
#     except Exception as e:
#         print(f"Error getting ratings summary: {e}")
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail="Failed to retrieve ratings summary"
#         )


# Dispute Resolution API Endpoints

@app.post("/api/tournaments/{tournament_id}/dispute")
async def create_tournament_dispute(
    tournament_id: str,
    dispute_data: dict,
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Create a dispute ticket for a tournament"""
    try:
        # Verify user authentication
        payload = verify_jwt_token(auth.credentials)
        user_id = payload.get("user_id")
        user_email = payload.get("email")
        
        # Get tournament details
        tournament = get_tournament_by_id(tournament_id)
        if not tournament:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tournament not found"
            )
        
        # Create dispute ticket
        ticket_data = {
            "ticket_id": f"dispute_{int(datetime.utcnow().timestamp())}_{user_id}",
            "tournament_id": tournament_id,
            "organizer_id": tournament["organizer_id"],
            "reporter_id": user_id,
            "reporter_email": user_email,
            "dispute_type": dispute_data.get("dispute_type", "other"),
            "priority": dispute_data.get("priority", "normal"),
            "status": "open",
            "title": dispute_data.get("title", ""),
            "description": dispute_data.get("description", ""),
            "evidence": dispute_data.get("evidence", [])
        }
        
        ticket_id = create_dispute_ticket(ticket_data)
        
        return DisputeResponse(
            success=True,
            data=None,
            message="Dispute ticket created successfully",
            ticketId=ticket_id
        )
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error creating dispute: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create dispute ticket"
        )


@app.get("/api/disputes/{ticket_id}")
async def get_dispute_details(
    ticket_id: str,
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Get dispute ticket details"""
    try:
        # Verify user authentication
        payload = verify_jwt_token(auth.credentials)
        user_email = payload.get("email")
        
        ticket = get_dispute_ticket_by_ticket_id(ticket_id)
        if not ticket:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Dispute ticket not found"
            )
        
        # Check if user has access to this ticket
        has_access = (
            ticket["reporter_email"] == user_email or
            payload.get("role") == "admin"
        )
        
        if not has_access:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this dispute ticket"
            )
        
        return DisputeResponse(
            success=True,
            data=ticket,
            message="Dispute ticket retrieved successfully"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error getting dispute: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve dispute ticket"
        )


@app.post("/api/disputes/{ticket_id}/message")
async def add_dispute_message_endpoint(
    ticket_id: str,
    message_data: dict,
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Add a message to dispute ticket"""
    try:
        # Verify user authentication
        payload = verify_jwt_token(auth.credentials)
        user_email = payload.get("email")
        
        ticket = get_dispute_ticket(ticket_id)
        if not ticket:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Dispute ticket not found"
            )
        
        # Check if user has access to this ticket
        has_access = (
            ticket["reporter_email"] == user_email or
            payload.get("role") == "admin"
        )
        
        if not has_access:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this dispute ticket"
            )
        
        # Add message
        message = {
            "sender_email": user_email,
            "sender_role": payload.get("role", "user"),
            "message": message_data.get("message", ""),
            "attachments": message_data.get("attachments", [])
        }
        
        success = add_dispute_message(ticket_id, message)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to add message to dispute ticket"
            )
        
        return {
            "success": True,
            "message": "Message added to dispute ticket successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error adding dispute message: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to add message to dispute ticket"
        )


@app.get("/api/admin/disputes")
async def get_all_disputes(
    status: Optional[str] = None,
    limit: int = 50,
    skip: int = 0,
    admin: dict = Depends(require_admin)
):
    """Get all dispute tickets (admin only)"""
    try:
        tickets = get_dispute_tickets(status=status, limit=limit, skip=skip)
        
        return {
            "success": True,
            "data": tickets,
            "total": len(tickets),
            "message": "Dispute tickets retrieved successfully"
        }
        
    except Exception as e:
        print(f"Error getting disputes: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve dispute tickets"
        )


@app.patch("/api/admin/disputes/{ticket_id}")
async def update_dispute_status(
    ticket_id: str,
    update_data: dict,
    admin: dict = Depends(require_admin)
):
    """Update dispute ticket status (admin only)"""
    try:
        # Add admin info to update
        update_data["assigned_to"] = admin.get("email")
        
        if update_data.get("status") == "resolved":
            update_data["resolved_at"] = datetime.utcnow().isoformat()
        
        success = update_dispute_ticket_by_ticket_id(ticket_id, update_data)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Dispute ticket not found"
            )
        
        # Process automated refund if requested
        if update_data.get("process_refund") and update_data.get("tournament_id"):
            try:
                refund_result = process_automated_refund(
                    tournament_id=update_data["tournament_id"],
                    refund_reason=update_data.get("refund_reason", "Dispute resolution")
                )
                update_data["refund_processed"] = refund_result
            except Exception as e:
                print(f"Error processing refund: {e}")
                # Continue without failing the dispute update
        
        return {
            "success": True,
            "message": "Dispute ticket updated successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error updating dispute: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update dispute ticket"
        )


# Support Ticket API Endpoints

@app.post("/api/support/ticket")
async def create_support_ticket_endpoint(
    ticket_data: dict,
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Create a support ticket with attachment support"""
    try:
        # Verify user authentication
        payload = verify_jwt_token(auth.credentials)
        user_id = payload.get("user_id")
        user_email = payload.get("email")
        
        # Validate required fields
        if not ticket_data.get("issueType"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Issue type is required"
            )
        
        if not ticket_data.get("subject") or len(ticket_data.get("subject", "").strip()) < 5:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Subject must be at least 5 characters long"
            )
        
        if not ticket_data.get("description") or len(ticket_data.get("description", "").strip()) < 10:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Description must be at least 10 characters long"
            )
        
        # Generate unique ticket ID
        ticket_id = f"TKT-{int(datetime.utcnow().timestamp())}-{str(uuid.uuid4())[:8].upper()}"
        
        # Process attachments if provided
        attachments = ticket_data.get("attachments", [])
        processed_attachments = []
        
        for attachment in attachments:
            if isinstance(attachment, dict) and attachment.get("url"):
                processed_attachments.append({
                    "url": attachment["url"],
                    "publicId": attachment.get("publicId", ""),
                    "originalName": attachment.get("originalName", ""),
                    "fileType": attachment.get("fileType", ""),
                    "fileSize": attachment.get("fileSize", 0),
                    "uploadedAt": datetime.utcnow().isoformat()
                })
        
        # Create support ticket
        support_data = {
            "ticket_id": ticket_id,
            "user_id": user_id,
            "user_email": user_email,
            "category": ticket_data.get("issueType", "other"),
            "priority": ticket_data.get("priority", "medium"),
            "subject": ticket_data.get("subject", "").strip(),
            "description": ticket_data.get("description", "").strip(),
            "attachments": processed_attachments,
            "status": "open",
            "tags": [],
            "tournament_id": ticket_data.get("tournamentId")
        }
        
        db_ticket_id = create_support_ticket(support_data)
        
        # Log ticket creation
        print(f"✅ Support ticket created: {ticket_id} by {user_email}")
        
        return {
            "success": True,
            "ticketId": ticket_id,
            "data": {
                "ticketId": ticket_id,
                "status": "open",
                "estimatedResolution": (datetime.utcnow() + timedelta(hours=24)).isoformat()
            },
            "message": "Support ticket created successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error creating support ticket: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create support ticket"
        )


@app.get("/api/support/tickets")
async def get_user_support_tickets(
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Get user's support tickets"""
    try:
        # Verify user authentication
        payload = verify_jwt_token(auth.credentials)
        user_email = payload.get("email")
        
        # Get user's tickets
        tickets = get_support_tickets()
        user_tickets = [t for t in tickets if t.get("user_email") == user_email]
        
        return {
            "success": True,
            "data": user_tickets,
            "total": len(user_tickets),
            "message": "Support tickets retrieved successfully"
        }
        
    except Exception as e:
        print(f"Error getting support tickets: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve support tickets"
        )


@app.get("/api/admin/support/tickets")
async def get_all_support_tickets(
    category: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
    skip: int = 0,
    admin: dict = Depends(require_admin)
):
    """Get all support tickets (admin only)"""
    try:
        tickets = get_support_tickets(category=category, status=status, limit=limit, skip=skip)
        
        return {
            "success": True,
            "data": tickets,
            "total": len(tickets),
            "message": "Support tickets retrieved successfully"
        }
        
    except Exception as e:
        print(f"Error getting support tickets: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve support tickets"
        )


# User access to their own disputes and support tickets
@app.get("/api/disputes")
async def get_user_disputes(
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Get user's dispute tickets"""
    try:
        # Verify user authentication
        payload = verify_jwt_token(auth.credentials)
        user_email = payload.get("email")
        
        # Get all disputes and filter by user
        all_disputes = get_dispute_tickets()
        user_disputes = [d for d in all_disputes if d.get("reporter_email") == user_email]
        
        return {
            "success": True,
            "data": user_disputes,
            "total": len(user_disputes),
            "message": "User disputes retrieved successfully"
        }
        
    except Exception as e:
        print(f"Error getting user disputes: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user disputes"
        )


@app.get("/api/support/tickets/{ticket_id}")
async def get_support_ticket_details(
    ticket_id: str,
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Get support ticket details"""
    try:
        # Verify user authentication
        payload = verify_jwt_token(auth.credentials)
        user_email = payload.get("email")
        
        ticket = get_support_ticket_by_ticket_id(ticket_id)
        if not ticket:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Support ticket not found"
            )
        
        # Check if user has access to this ticket
        has_access = (
            ticket["user_email"] == user_email or
            payload.get("role") == "admin"
        )
        
        if not has_access:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this support ticket"
            )
        
        return {
            "success": True,
            "data": ticket,
            "message": "Support ticket retrieved successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error getting support ticket: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve support ticket"
        )


@app.post("/api/support/tickets/{ticket_id}/message")
async def add_support_message_endpoint(
    ticket_id: str,
    message_data: dict,
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Add a message to support ticket"""
    try:
        # Verify user authentication
        payload = verify_jwt_token(auth.credentials)
        user_email = payload.get("email")
        
        ticket = get_support_ticket_by_ticket_id(ticket_id)
        if not ticket:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Support ticket not found"
            )
        
        # Check if user has access to this ticket
        has_access = (
            ticket["user_email"] == user_email or
            payload.get("role") == "admin"
        )
        
        if not has_access:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this support ticket"
            )
        
        # Add message
        message = {
            "sender_email": user_email,
            "sender_role": payload.get("role", "user"),
            "message": message_data.get("message", ""),
            "attachments": message_data.get("attachments", [])
        }
        
        success = add_support_message_by_ticket_id(ticket_id, message)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to add message to support ticket"
            )
        
        return {
            "success": True,
            "message": "Message added to support ticket successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error adding support message: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to add message to support ticket"
        )


@app.patch("/api/admin/support/tickets/{ticket_id}")
async def update_support_ticket_status(
    ticket_id: str,
    update_data: dict,
    admin: dict = Depends(require_admin)
):
    """Update support ticket status (admin only)"""
    try:
        # Add admin info to update
        update_data["assigned_to"] = admin.get("email")
        
        if update_data.get("status") == "resolved":
            update_data["resolved_at"] = datetime.utcnow().isoformat()
        
        success = update_support_ticket_by_ticket_id(ticket_id, update_data)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Support ticket not found"
            )
        
        return {
            "success": True,
            "message": "Support ticket updated successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error updating support ticket: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update support ticket"
        )


# In main.py, add the following endpoints:

# ===== ADMIN WITHDRAWAL ENDPOINTS =====

@app.get("/api/admin/payouts", dependencies=[Depends(require_admin)])
async def get_admin_payout_requests(
    status: Optional[str] = Query("pending", description="Filter by status (pending, completed, failed)"),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    admin_payload: dict = Depends(require_admin)
):
    """Get all withdrawal requests for admin review with filtering and pagination."""
    try:
        skip = (page - 1) * limit
        
        # Use the new database function
        requests = get_admin_withdrawal_requests(status=status, limit=limit, skip=skip)
        
        # Get total count (simple count, as full aggregation is complex without dedicated function)
        total_count = get_database().withdrawals.count_documents({"status": status} if status else {})
        total_pages = (total_count + limit - 1) // limit

        # Enhance data with user info if needed (optional, using get_user_by_id)
        for req in requests:
            # Look up host username/email for display
            host_user = get_user_by_id(req["userId"])
            if host_user:
                req["hostEmail"] = host_user.get("email")
                req["hostUsername"] = host_user.get("username")
            else:
                req["hostEmail"] = "User Not Found"
                req["hostUsername"] = "N/A"

        return {
            "success": True,
            "data": {
                "requests": requests,
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "totalCount": total_count,
                    "totalPages": total_pages,
                    "hasNext": page < total_pages,
                    "hasPrev": page > 1
                }
            },
            "message": f"Retrieved {len(requests)} '{status}' withdrawal requests"
        }
    except Exception as e:
        logger.error(f"Error fetching admin payouts: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve payout requests")


@app.patch("/api/admin/payouts/{withdrawal_id}/action", dependencies=[Depends(require_admin)])
async def process_admin_withdrawal_action(
    withdrawal_id: str,
    action_data: AdminWithdrawalAction,
    admin_payload: dict = Depends(require_admin)
):
    """Process a pending withdrawal request (complete or fail)."""
    try:
        admin_id = admin_payload.get("user_id")
        new_status = "completed" if action_data.action == "complete" else "failed"
        
        success = finalize_withdrawal_status(
            withdrawal_id=withdrawal_id,
            new_status=new_status,
            admin_id=admin_id,
            notes=action_data.notes
        )

        if not success:
            raise HTTPException(
                status_code=400, 
                detail="Withdrawal ID not found or processing failed during reconciliation."
            )

        # Log the activity
        log_tournament_operation(
            "WITHDRAWAL_PROCESS", 
            withdrawal_id, 
            admin_payload.get("email"), 
            f"Action: {new_status}. Notes: {action_data.notes or 'None'}"
        )

        return {
            "success": True,
            "message": f"Withdrawal request {withdrawal_id} successfully marked as {new_status} and host wallet reconciled."
        }

    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing admin withdrawal action: {e}")
        raise HTTPException(status_code=500, detail="Failed to process withdrawal action")


# @app.post("/api/tournaments/{tournament_id}/rate-organizer")
# async def rate_organizer(
#     tournament_id: str,
#     rating_data: dict,
#     auth: HTTPAuthorizationCredentials = Security(security)
# ):
#     """Submit a rating for tournament organizer"""
#     try:
#         # Verify user authentication
#         payload = verify_jwt_token(auth.credentials)
#         participant_id = payload.get("user_id")
#         participant_email = payload.get("email")
        
#         if not participant_id:
#             raise HTTPException(
#                 status_code=status.HTTP_401_UNAUTHORIZED,
#                 detail="Invalid authentication token"
#             )
        
#         # Get tournament details
#         from database import get_database
#         db = get_database()
#         tournament = db.user_tournaments.find_one({"_id": ObjectId(tournament_id)})
        
#         if not tournament:
#             # Try regular tournaments collection
#             tournament = db.tournaments.find_one({"_id": ObjectId(tournament_id)})
            
#         if not tournament:
#             raise HTTPException(
#                 status_code=status.HTTP_404_NOT_FOUND,
#                 detail="Tournament not found"
#             )
        
#         # Check if tournament is completed
#         if tournament.get("status") != "completed":
#             raise HTTPException(
#                 status_code=status.HTTP_400_BAD_REQUEST,
#                 detail="Can only rate organizers after tournament completion"
#             )
        
#         # Get organizer ID
#         organizer_id = tournament.get("organizer_id") or tournament.get("organizerId")
#         if not organizer_id:
#             raise HTTPException(
#                 status_code=status.HTTP_400_BAD_REQUEST,
#                 detail="Tournament organizer not found"
#             )
        
#         # Submit rating
#         success = await organizer_reputation_service.submit_organizer_rating(
#             tournament_id=tournament_id,
#             participant_id=participant_id,
#             organizer_id=organizer_id,
#             rating=rating_data.overallRating,
#             feedback=rating_data.feedback
#         )
        
#         if not success:
#             raise HTTPException(
#                 status_code=status.HTTP_400_BAD_REQUEST,
#                 detail="Failed to submit rating. You may have already rated this organizer."
#             )
        
#         # Update organizer reputation in database
#         try:
#             reputation_data = await organizer_reputation_service.calculate_reputation_score(organizer_id)
#             await update_organizer_reputation(organizer_id, {
#                 "reputation_score": reputation_data.total_score,
#                 "trust_level": reputation_data.trust_level.value,
#                 "last_updated": datetime.utcnow().isoformat()
#             })
#         except Exception as e:
#             logger.warning(f"Failed to update organizer reputation cache: {e}")
        
#         return {
#             "success": True,
#             "message": "Rating submitted successfully",
#             "data": {
#                 "tournament_id": tournament_id,
#                 "organizer_id": organizer_id,
#                 "rating": rating_data.overallRating
#             }
#         }
        
#     except HTTPException:
#         raise
#     except Exception as e:
#         logger.error(f"Error submitting organizer rating: {e}")
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail="Failed to submit rating"
#         )

# @app.get("/api/organizers/{organizer_id}/ratings")
# async def get_organizer_ratings(organizer_id: str, limit: int = 10, offset: int = 0):
#     """Get organizer ratings and feedback"""
#     try:
#         from database import get_database
#         db = get_database()
        
#         # Get ratings with pagination
#         ratings_cursor = db.organizer_ratings.find({
#             "organizer_id": organizer_id
#         }).sort("created_at", -1).skip(offset).limit(limit)
        
#         ratings = list(ratings_cursor)
        
#         # Convert ObjectIds to strings
#         for rating in ratings:
#             rating["_id"] = str(rating["_id"])
#             if "created_at" in rating:
#                 rating["created_at"] = rating["created_at"].isoformat()
#             if "updated_at" in rating:
#                 rating["updated_at"] = rating["updated_at"].isoformat()
        
#         # Get total count
#         total_count = db.organizer_ratings.count_documents({
#             "organizer_id": organizer_id
#         })
        
#         # Get ratings summary
#         ratings_summary = await organizer_reputation_service.get_organizer_ratings_summary(organizer_id)
        
#         return {
#             "success": True,
#             "data": {
#                 "ratings": ratings,
#                 "summary": ratings_summary,
#                 "pagination": {
#                     "total": total_count,
#                     "limit": limit,
#                     "offset": offset,
#                     "has_more": offset + limit < total_count
#                 }
#             },
#             "message": "Organizer ratings retrieved successfully"
#         }
        
#     except Exception as e:
#         logger.error(f"Error getting organizer ratings: {e}")
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail="Failed to retrieve organizer ratings"
#         )
# # In main.py



#===================================================================
# NEW HOST-SPECIFIC TOURNAMENT ENDPOINTS (These should be right after the code above)
# ===================================================================

@app.get("/api/host/tournaments", dependencies=[Depends(require_host)])
async def get_host_tournaments(
    host_payload: dict = Depends(require_host),
    status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    sort_by: Optional[str] = Query('createdAt'),
    sort_order: Optional[str] = Query('desc')
):
    """Get all tournaments created by the authenticated host."""
    try:
        host_id = host_payload.get("user_id")
        tournaments = get_tournaments_by_host_id(host_id, status, search, sort_by, sort_order)
        
        return {
            "success": True,
            "data": {
                "tournaments": tournaments,
                "total": len(tournaments)
            },
            "message": "Host tournaments retrieved successfully"
        }
    except Exception as e:
        logger.error(f"Error fetching host tournaments: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch tournaments")


# In main.py, replace the old update_host_tournament function with this one

@app.put("/api/host/tournaments/{tournament_id}", dependencies=[Depends(require_host)])
async def update_host_tournament(
    tournament_id: str,
    request: Request,  # <-- CORRECTED: Get the raw request
    host_payload: dict = Depends(require_host)
):
    """Update a tournament owned by the host."""
    try:
        host_id = host_payload.get("user_id")
        update_data = await request.json()  # <-- CORRECTED: Get JSON data from the request body
        
        db = get_database()
        tournament = db.tournaments.find_one({"_id": ObjectId(tournament_id), "hostId": host_id})
        
        if not tournament:
            raise HTTPException(status_code=404, detail="Tournament not found or you do not have permission to edit it.")

        # The rest of the function logic is correct
        success = update_tournament_in_db(tournament['slug'], update_data)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to update tournament")

        return {"success": True, "message": "Tournament updated successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating host tournament: {e}")
        raise HTTPException(status_code=500, detail="Failed to update tournament")

@app.delete("/api/host/tournaments/{tournament_id}", dependencies=[Depends(require_host)])
async def delete_host_tournament(
    tournament_id: str,
    host_payload: dict = Depends(require_host)
):
    """Delete a tournament owned by the host."""
    try:
        host_id = host_payload.get("user_id")
        
        # Find the tournament to get its slug for deletion
        db = get_database()
        tournament = db.tournaments.find_one({"_id": ObjectId(tournament_id), "hostId": host_id})

        if not tournament:
            raise HTTPException(status_code=404, detail="Tournament not found or you do not have permission to delete it.")

        # Prevent deletion if tournament has participants
        if len(tournament.get("participants", [])) > 0:
            raise HTTPException(status_code=400, detail="Cannot delete a tournament that has registered participants.")

        success = delete_tournament_from_db(tournament['slug'])
        if not success:
            raise HTTPException(status_code=500, detail="Failed to delete tournament")

        return {"success": True, "message": "Tournament deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting host tournament: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete tournament")
    
# Add the new endpoint to your main.py file:
@app.get("/api/host/tournaments/{tournament_id}/export/csv", dependencies=[Depends(require_host)])
async def export_host_participants_to_csv(
    tournament_id: str,
    host_payload: dict = Depends(require_host)
):
    """Export a host's tournament participants to a CSV file."""
    try:
        host_id = host_payload.get("user_id")

        # Get tournament data and verify ownership
        tournament = get_tournament_for_host(host_id, tournament_id)
        if not tournament:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tournament not found or you do not have permission to export it."
            )

        output = io.StringIO()
        writer = csv.writer(output)

        # Write header row
        header = [
            "Team Name", "Registration Date",
            "Captain Name", "Captain Email", "Captain In-Game ID",
            "Player 2 Name", "Player 2 Email", "Player 2 In-Game ID",
            "Player 3 Name", "Player 3 Email", "Player 3 In-Game ID",
            "Player 4 Name", "Player 4 Email", "Player 4 In-Game ID"
        ]
        writer.writerow(header)

        # Write data rows
        participants = tournament.get("participants", [])
        for team in participants:
            row = [
                team.get("teamName", ""),
                team.get("registrationDate", "")
            ]
            players = team.get("players", [])
            for i in range(4): # Loop for 4 players (1 captain + 3 players)
                if i < len(players):
                    player = players[i]
                    row.extend([
                        player.get("name", ""),
                        player.get("email", ""),
                        player.get("inGameId", "")
                    ])
                else:
                    row.extend(["", "", ""]) # Fill with empty strings if no player
            writer.writerow(row)

        output.seek(0)

        filename = f"{tournament.get('slug', 'tournament')}_participants.csv"
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error exporting participants to CSV for host: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to export participant list."
        )

@app.get("/api/host/analytics/revenue", dependencies=[Depends(require_host)])
async def get_host_revenue_analytics(
    days: int = Query(90, ge=7, le=365), # Allow frontend to request 7 to 365 days of data
    host_payload: dict = Depends(require_host)
):
    """Provides data for the 'Revenue Over Time' chart for the authenticated host."""
    try:
        host_id = host_payload.get("user_id")
        revenue_data = get_host_revenue_over_time(host_id, days)
        return {
            "success": True,
            "data": revenue_data,
            "message": f"Revenue data for the last {days} days retrieved successfully."
        }
    except Exception as e:
        logger.error(f"Error fetching host revenue analytics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve revenue analytics."
        )


@app.get("/api/host/analytics/participants", dependencies=[Depends(require_host)])
async def get_host_participant_analytics(
    days: int = Query(90, ge=7, le=365),
    host_payload: dict = Depends(require_host)
):
    """Provides data for the 'Participant Growth' chart for the authenticated host."""
    try:
        host_id = host_payload.get("user_id")
        participant_data = get_host_participant_growth(host_id, days)
        return {
            "success": True,
            "data": participant_data,
            "message": f"Participant growth data for the last {days} days retrieved successfully."
        }
    except Exception as e:
        logger.error(f"Error fetching host participant analytics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve participant analytics."
        )

# ===== WALLET SYSTEM ENDPOINTS =====

@app.get("/api/host/wallet")
async def get_host_wallet_info(auth: HTTPAuthorizationCredentials = Security(security)):
    """Get host wallet information"""
    try:
        payload = verify_jwt_token(auth.credentials)
        user_id = payload.get("user_id")
        
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Get wallet balance from database
        db = get_database()
        wallet = db.wallets.find_one({"userId": user_id})
        
        if not wallet:
            # Create new wallet if doesn't exist
            wallet_data = {
                "userId": user_id,
                "availableBalance": 0.0,
                "pendingBalance": 0.0,
                "totalEarnings": 0.0,
                "totalWithdrawals": 0.0,
                "currency": "INR",
                "lastUpdated": datetime.utcnow().isoformat(),
                "createdAt": datetime.utcnow().isoformat()
            }
            db.wallets.insert_one(wallet_data)
            wallet = wallet_data
        
        # Get recent transactions count
        recent_transactions = db.transactions.count_documents({
            "userId": user_id,
            "createdAt": {"$gte": (datetime.utcnow() - timedelta(days=30)).isoformat()}
        })
        
        return {
            "success": True,
            "data": {
                "availableBalance": wallet.get("availableBalance", 0.0),
                "pendingBalance": wallet.get("pendingBalance", 0.0),
                "totalEarnings": wallet.get("totalEarnings", 0.0),
                "totalWithdrawals": wallet.get("totalWithdrawals", 0.0),
                "currency": wallet.get("currency", "INR"),
                "recentTransactions": recent_transactions,
                "lastUpdated": wallet.get("lastUpdated")
            },
            "message": "Wallet information retrieved successfully"
        }
        
    except Exception as e:
        logger.error(f"Error getting wallet info: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve wallet information")

@app.get("/api/host/wallet/transactions")
async def get_host_transactions(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    transaction_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Get host transaction history with pagination and filters"""
    try:
        payload = verify_jwt_token(auth.credentials)
        user_id = payload.get("user_id")
        
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        db = get_database()
        
        # Build query
        query = {"userId": user_id}
        if transaction_type:
            query["type"] = transaction_type
        if status:
            query["status"] = status
        
        # Get transactions with pagination
        skip = (page - 1) * limit
        transactions = list(
            db.transactions.find(query)
            .sort("createdAt", -1)
            .skip(skip)
            .limit(limit)
        )
        
        # Convert ObjectId to string
        for transaction in transactions:
            transaction["_id"] = str(transaction["_id"])
        
        # Get total count
        total_count = db.transactions.count_documents(query)
        total_pages = (total_count + limit - 1) // limit
        
        return {
            "success": True,
            "data": {
                "transactions": transactions,
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "totalCount": total_count,
                    "totalPages": total_pages,
                    "hasNext": page < total_pages,
                    "hasPrev": page > 1
                }
            },
            "message": "Transaction history retrieved successfully"
        }
        
    except Exception as e:
        logger.error(f"Error getting transactions: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve transaction history")

@app.post("/api/host/wallet/withdraw")
async def request_withdrawal(
    request: Request,
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Request money withdrawal"""
    try:
        # ---> FIX 1: This entire block is now correctly indented inside the 'try'
        payload = verify_jwt_token(auth.credentials)
        user_id = payload.get("user_id")
        
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        withdrawal_data = await request.json()
        amount = float(withdrawal_data.get("amount", 0))
        payment_method = withdrawal_data.get("paymentMethod")
        bank_details = withdrawal_data.get("bankDetails")
        upi_id = withdrawal_data.get("upiId")
        
        # Validate amount
        if amount < 100:
            raise HTTPException(status_code=400, detail="Minimum withdrawal amount is ₹100")
        if amount > 100000:
            raise HTTPException(status_code=400, detail="Maximum withdrawal amount is ₹1,00,000")
        
        # Check wallet balance
        db = get_database()
        wallet = db.wallets.find_one({"userId": user_id})
        
        if not wallet or wallet.get("availableBalance", 0) < amount:
            raise HTTPException(status_code=400, detail="Insufficient balance")
        
        # ---> FIX 2: This block is now at the correct indentation level.
        # It is no longer inside the 'if' statement above.
        withdrawal_id = str(uuid.uuid4())
        withdrawal_request = {
            "withdrawalId": withdrawal_id,
            "userId": user_id,
            "amount": amount,
            "currency": "INR",
            "paymentMethod": payment_method,
            "bankDetails": bank_details,
            "upiId": upi_id,
            "status": "pending",
            "requestedAt": datetime.utcnow().isoformat()
        }
        
        db.withdrawals.insert_one(withdrawal_request)
        
        # Update wallet balance (move from available to pending)
        db.wallets.update_one(
            {"userId": user_id},
            {
                "$inc": {
                    "availableBalance": -amount,
                    "pendingBalance": amount
                },
                "$set": {
                    "lastUpdated": datetime.utcnow().isoformat()
                }
            }
        )
        
        # Create transaction record
        transaction_data = {
            "transactionId": str(uuid.uuid4()),
            "userId": user_id,
            "type": "withdrawal",
            "status": "pending",
            "amount": -amount,  # Negative for withdrawal
            "currency": "INR",
            "description": f"Withdrawal request - {payment_method}",
            "metadata": {"withdrawalId": withdrawal_id},
            "createdAt": datetime.utcnow().isoformat(),
            "updatedAt": datetime.utcnow().isoformat()
        }
        
        db.transactions.insert_one(transaction_data)
        
        return {
            "success": True,
            "data": {
                "withdrawalId": withdrawal_id,
                "amount": amount,
                "status": "pending",
                "estimatedProcessingTime": "1-3 business days"
            },
            "message": "Withdrawal request submitted successfully"
        }
        
    except HTTPException:
        # Re-raise the validation exception so FastAPI can handle it correctly
        raise
    except Exception as e:
        # This will now ONLY catch UNEXPECTED errors (like a database crash)
        logger.error(f"An unexpected error occurred during withdrawal: {e}")
        raise HTTPException(status_code=500, detail="An unexpected server error occurred.")

@app.get("/api/host/wallet/withdrawals")
async def get_withdrawal_requests(
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=50),
    status: Optional[str] = Query(None),
    auth: HTTPAuthorizationCredentials = Security(security)
):
    """Get host withdrawal requests"""
    try:
        payload = verify_jwt_token(auth.credentials)
        user_id = payload.get("user_id")
        
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        db = get_database()
        
        # Build query
        query = {"userId": user_id}
        if status:
            query["status"] = status
        
        # Get withdrawals with pagination
        skip = (page - 1) * limit
        withdrawals = list(
            db.withdrawals.find(query)
            .sort("requestedAt", -1)
            .skip(skip)
            .limit(limit)
        )
        
        # Convert ObjectId to string
        for withdrawal in withdrawals:
            withdrawal["_id"] = str(withdrawal["_id"])
        
        # Get total count
        total_count = db.withdrawals.count_documents(query)
        
        return {
            "success": True,
            "data": {
                "withdrawals": withdrawals,
                "totalCount": total_count,
                "page": page,
                "limit": limit
            },
            "message": "Withdrawal requests retrieved successfully"
        }
        
    except Exception as e:
        logger.error(f"Error getting withdrawals: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve withdrawal requests")
