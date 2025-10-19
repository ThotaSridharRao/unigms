"""
Security Middleware for Tournament Platform

This module provides security middleware including rate limiting,
request validation, and security headers.
"""

import time
import logging
from typing import Optional
from fastapi import Request, Response, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from rate_limiting_service import get_rate_limiting_service
from auth import verify_jwt_token

logger = logging.getLogger(__name__)

class SecurityMiddleware(BaseHTTPMiddleware):
    """Comprehensive security middleware"""
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.rate_limiter = get_rate_limiting_service()
        
        # Security headers to add to all responses
        self.security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; img-src 'self' data: https:; font-src 'self' https://cdnjs.cloudflare.com;",
        }
    
    async def dispatch(self, request: Request, call_next):
        """Process request through security checks"""
        start_time = time.time()
        
        # Get client IP address
        client_ip = self._get_client_ip(request)
        
        # Get user ID from token if available
        user_id = await self._extract_user_id(request)
        
        # Apply rate limiting
        rate_limit_result = await self._check_rate_limits(request, client_ip, user_id)
        if not rate_limit_result.allowed:
            return self._create_rate_limit_response(rate_limit_result)
        
        # Validate request size and content
        if not await self._validate_request(request):
            return JSONResponse(
                status_code=413,
                content={"error": "Request too large or invalid content"}
            )
        
        # Process the request
        try:
            response = await call_next(request)
        except Exception as e:
            logger.error(f"Request processing error: {e}")
            # Don't expose internal errors
            return JSONResponse(
                status_code=500,
                content={"error": "Internal server error"}
            )
        
        # Add security headers
        self._add_security_headers(response)
        
        # Add rate limit headers
        self._add_rate_limit_headers(response, rate_limit_result)
        
        # Log request for monitoring
        processing_time = time.time() - start_time
        await self._log_request(request, response, client_ip, user_id, processing_time)
        
        return response
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address from request"""
        # Check for forwarded headers (for reverse proxy setups)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP in the chain
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        # Fallback to direct client IP
        return request.client.host if request.client else "unknown"
    
    async def _extract_user_id(self, request: Request) -> Optional[str]:
        """Extract user ID from JWT token"""
        try:
            # Check Authorization header
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]
                payload = verify_jwt_token(token)
                return payload.get("user_id")
            
            # Check cookies
            auth_token = request.cookies.get("auth_token")
            if auth_token:
                payload = verify_jwt_token(auth_token)
                return payload.get("user_id")
        
        except Exception:
            # Invalid token, continue without user ID
            pass
        
        return None
    
    async def _check_rate_limits(self, request: Request, client_ip: str, user_id: Optional[str]):
        """Check rate limits for the request"""
        endpoint = request.url.path
        method = request.method
        
        # Only apply rate limiting to specific methods and endpoints
        if method in ["POST", "PUT", "PATCH", "DELETE"] or endpoint.startswith("/api/"):
            return await self.rate_limiter.check_rate_limit(endpoint, client_ip, user_id)
        
        # Allow GET requests to static content without rate limiting
        from rate_limiting_service import RateLimitResult
        return RateLimitResult(allowed=True, remaining=1000)
    
    async def _validate_request(self, request: Request) -> bool:
        """Validate request size and content"""
        # Check content length
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                size = int(content_length)
                # Limit request size to 50MB (for file uploads)
                if size > 50 * 1024 * 1024:
                    return False
            except ValueError:
                return False
        
        # Validate content type for POST/PUT requests
        if request.method in ["POST", "PUT", "PATCH"]:
            content_type = request.headers.get("content-type", "")
            allowed_types = [
                "application/json",
                "application/x-www-form-urlencoded",
                "multipart/form-data",
                "text/plain"
            ]
            
            # Check if content type is allowed (or starts with allowed type for multipart)
            if not any(content_type.startswith(allowed) for allowed in allowed_types):
                logger.warning(f"Rejected request with content-type: {content_type}")
                return False
        
        return True
    
    def _create_rate_limit_response(self, rate_limit_result) -> JSONResponse:
        """Create rate limit exceeded response"""
        return JSONResponse(
            status_code=429,
            content={
                "error": "Rate limit exceeded",
                "message": rate_limit_result.reason or "Too many requests",
                "retry_after": rate_limit_result.retry_after,
                "reset_time": rate_limit_result.reset_time.isoformat() if rate_limit_result.reset_time else None
            },
            headers={
                "Retry-After": str(rate_limit_result.retry_after),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(rate_limit_result.reset_time.timestamp())) if rate_limit_result.reset_time else "0"
            }
        )
    
    def _add_security_headers(self, response: Response):
        """Add security headers to response"""
        for header, value in self.security_headers.items():
            response.headers[header] = value
    
    def _add_rate_limit_headers(self, response: Response, rate_limit_result):
        """Add rate limit headers to response"""
        if rate_limit_result.remaining is not None:
            response.headers["X-RateLimit-Remaining"] = str(rate_limit_result.remaining)
        
        if rate_limit_result.reset_time:
            response.headers["X-RateLimit-Reset"] = str(int(rate_limit_result.reset_time.timestamp()))
    
    async def _log_request(self, request: Request, response: Response, 
                          client_ip: str, user_id: Optional[str], processing_time: float):
        """Log request for monitoring and security analysis"""
        # Log security-relevant requests
        if (response.status_code >= 400 or 
            request.url.path.startswith("/api/") or 
            request.method in ["POST", "PUT", "PATCH", "DELETE"]):
            
            log_data = {
                "timestamp": time.time(),
                "method": request.method,
                "path": request.url.path,
                "client_ip": client_ip,
                "user_id": user_id,
                "status_code": response.status_code,
                "processing_time": processing_time,
                "user_agent": request.headers.get("user-agent", "unknown")
            }
            
            # Log failed requests with higher priority
            if response.status_code >= 400:
                logger.warning(f"Failed request: {log_data}")
                
                # Record failed authentication attempts
                if (response.status_code == 401 and 
                    request.url.path in ["/login", "/login-form"]):
                    await self.rate_limiter.record_failed_authentication(client_ip, request.url.path)
            else:
                logger.info(f"Request: {request.method} {request.url.path} - {response.status_code} - {processing_time:.3f}s")

class InputValidationMiddleware(BaseHTTPMiddleware):
    """Middleware for input validation and sanitization"""
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        
        # Patterns that indicate potential attacks
        self.suspicious_patterns = [
            r"<script[^>]*>.*?</script>",  # XSS
            r"javascript:",  # XSS
            r"on\w+\s*=",  # Event handlers
            r"union\s+select",  # SQL injection
            r"drop\s+table",  # SQL injection
            r"insert\s+into",  # SQL injection
            r"delete\s+from",  # SQL injection
            r"\.\./",  # Path traversal
            r"\\x[0-9a-f]{2}",  # Hex encoding
            r"%[0-9a-f]{2}",  # URL encoding of suspicious chars
        ]
    
    async def dispatch(self, request: Request, call_next):
        """Validate and sanitize request input"""
        # Check URL path for suspicious patterns
        if self._contains_suspicious_content(request.url.path):
            logger.warning(f"Suspicious URL path detected: {request.url.path}")
            return JSONResponse(
                status_code=400,
                content={"error": "Invalid request"}
            )
        
        # Check query parameters
        for key, value in request.query_params.items():
            if self._contains_suspicious_content(f"{key}={value}"):
                logger.warning(f"Suspicious query parameter: {key}={value}")
                return JSONResponse(
                    status_code=400,
                    content={"error": "Invalid query parameters"}
                )
        
        return await call_next(request)
    
    def _contains_suspicious_content(self, content: str) -> bool:
        """Check if content contains suspicious patterns"""
        import re
        content_lower = content.lower()
        
        for pattern in self.suspicious_patterns:
            if re.search(pattern, content_lower, re.IGNORECASE):
                return True
        
        return False

# Utility functions for manual rate limit checks
async def check_rate_limit_for_endpoint(endpoint: str, client_ip: str, user_id: Optional[str] = None):
    """Manually check rate limit for specific endpoint"""
    rate_limiter = get_rate_limiting_service()
    return await rate_limiter.check_rate_limit(endpoint, client_ip, user_id)

async def record_failed_auth_attempt(client_ip: str, endpoint: str):
    """Record failed authentication attempt"""
    rate_limiter = get_rate_limiting_service()
    return await rate_limiter.record_failed_authentication(client_ip, endpoint)