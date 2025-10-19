import os
import jwt
import bcrypt
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# JWT Configuration
JWT_SECRET = os.getenv("JWT_SECRET", "fallback-secret-key")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    try:
        # Generate salt and hash password
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    except Exception as e:
        print(f"Error hashing password: {e}")
        raise e

def verify_password(password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception as e:
        print(f"Error verifying password: {e}")
        return False

def create_jwt_token(user_id: str, username: str, email: str, role: str) -> str:
    """Create a JWT token for authenticated user"""
    try:
        # Token payload
        payload = {
            "user_id": user_id,
            "username": username,
            "email": email,
            "role": role,
            "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),
            "iat": datetime.utcnow()
        }
        
        # Create token
        token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
        return token
        
    except Exception as e:
        print(f"Error creating JWT token: {e}")
        raise e

def verify_jwt_token(token: str) -> dict:
    """Verify and decode a JWT token"""
    try:
        # Decode token
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
        
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")
    except Exception as e:
        print(f"Error verifying JWT token: {e}")
        raise ValueError("Token verification failed")

def extract_token_from_header(authorization_header: str) -> str:
    """Extract JWT token from Authorization header"""
    try:
        if not authorization_header:
            raise ValueError("Authorization header is missing")
        
        # Expected format: "Bearer <token>"
        parts = authorization_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise ValueError("Invalid authorization header format")
        
        return parts[1]
        
    except Exception as e:
        print(f"Error extracting token: {e}")
        raise ValueError("Invalid authorization header")

def require_admin_role(payload: dict) -> bool:
    """Check if user has admin role"""
    return payload.get("role") == "admin"

def require_host_role(payload: dict) -> bool:
    """Check if user has host role"""
    return payload.get("role") == "host"

def require_admin_or_host_role(payload: dict) -> bool:
    """Check if user has admin or host role"""
    return payload.get("role") in ["admin", "host"]