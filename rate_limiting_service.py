"""
Rate Limiting and Abuse Protection Service

This module provides comprehensive rate limiting and abuse detection
for the tournament hosting platform.
"""

import time
import asyncio
from typing import Dict, Optional, List, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from collections import defaultdict, deque
import hashlib
import json
import logging

logger = logging.getLogger(__name__)

@dataclass
class RateLimitResult:
    """Result of rate limit check"""
    allowed: bool
    remaining: int = 0
    reset_time: Optional[datetime] = None
    retry_after: int = 0
    reason: Optional[str] = None

@dataclass
class RateLimitConfig:
    """Rate limit configuration"""
    requests: int
    window_seconds: int
    burst_requests: Optional[int] = None
    burst_window_seconds: Optional[int] = None

class InMemoryRateLimiter:
    """In-memory rate limiter using sliding window algorithm"""
    
    def __init__(self):
        self.requests: Dict[str, deque] = defaultdict(deque)
        self.lock = asyncio.Lock()
    
    async def is_allowed(self, key: str, config: RateLimitConfig) -> RateLimitResult:
        """Check if request is allowed based on rate limit configuration"""
        async with self.lock:
            now = time.time()
            window_start = now - config.window_seconds
            
            # Clean old requests outside the window
            request_times = self.requests[key]
            while request_times and request_times[0] < window_start:
                request_times.popleft()
            
            # Check if within rate limit
            current_count = len(request_times)
            
            if current_count >= config.requests:
                # Calculate retry after time
                oldest_request = request_times[0] if request_times else now
                retry_after = int(oldest_request + config.window_seconds - now) + 1
                reset_time = datetime.fromtimestamp(oldest_request + config.window_seconds)
                
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_time=reset_time,
                    retry_after=retry_after,
                    reason="Rate limit exceeded"
                )
            
            # Check burst limit if configured
            if config.burst_requests and config.burst_window_seconds:
                burst_window_start = now - config.burst_window_seconds
                burst_count = sum(1 for t in request_times if t >= burst_window_start)
                
                if burst_count >= config.burst_requests:
                    return RateLimitResult(
                        allowed=False,
                        remaining=0,
                        reset_time=datetime.fromtimestamp(now + config.burst_window_seconds),
                        retry_after=config.burst_window_seconds,
                        reason="Burst limit exceeded"
                    )
            
            # Allow request and record it
            request_times.append(now)
            remaining = config.requests - current_count - 1
            reset_time = datetime.fromtimestamp(now + config.window_seconds)
            
            return RateLimitResult(
                allowed=True,
                remaining=remaining,
                reset_time=reset_time,
                retry_after=0
            )

class AbuseDetectionService:
    """Service for detecting and preventing abuse patterns"""
    
    def __init__(self):
        self.suspicious_activities: Dict[str, List[float]] = defaultdict(list)
        self.blocked_ips: Dict[str, float] = {}  # IP -> block_until_timestamp
        self.blocked_users: Dict[str, float] = {}  # user_id -> block_until_timestamp
        self.failed_attempts: Dict[str, List[float]] = defaultdict(list)
        
        # Abuse detection thresholds
        self.max_failed_attempts = 5
        self.failed_attempts_window = 300  # 5 minutes
        self.block_duration = 900  # 15 minutes
        
        # Suspicious pattern thresholds
        self.rapid_requests_threshold = 50
        self.rapid_requests_window = 60  # 1 minute
        
    async def record_failed_attempt(self, identifier: str, attempt_type: str = "login") -> bool:
        """Record a failed attempt and check if blocking is needed"""
        now = time.time()
        key = f"{identifier}:{attempt_type}"
        
        # Clean old attempts
        self.failed_attempts[key] = [
            t for t in self.failed_attempts[key] 
            if now - t < self.failed_attempts_window
        ]
        
        # Add new attempt
        self.failed_attempts[key].append(now)
        
        # Check if threshold exceeded
        if len(self.failed_attempts[key]) >= self.max_failed_attempts:
            self._block_identifier(identifier, now + self.block_duration)
            logger.warning(f"Blocked {identifier} due to {self.max_failed_attempts} failed {attempt_type} attempts")
            return True
        
        return False
    
    async def is_blocked(self, identifier: str, identifier_type: str = "ip") -> Tuple[bool, Optional[int]]:
        """Check if identifier is currently blocked"""
        now = time.time()
        
        if identifier_type == "ip":
            block_until = self.blocked_ips.get(identifier, 0)
        else:
            block_until = self.blocked_users.get(identifier, 0)
        
        if block_until > now:
            return True, int(block_until - now)
        
        # Clean expired blocks
        if identifier_type == "ip" and identifier in self.blocked_ips:
            del self.blocked_ips[identifier]
        elif identifier_type == "user" and identifier in self.blocked_users:
            del self.blocked_users[identifier]
        
        return False, None
    
    async def detect_suspicious_activity(self, identifier: str, activity_type: str) -> bool:
        """Detect suspicious activity patterns"""
        now = time.time()
        key = f"{identifier}:{activity_type}"
        
        # Clean old activities
        self.suspicious_activities[key] = [
            t for t in self.suspicious_activities[key]
            if now - t < self.rapid_requests_window
        ]
        
        # Add new activity
        self.suspicious_activities[key].append(now)
        
        # Check for rapid requests
        if len(self.suspicious_activities[key]) >= self.rapid_requests_threshold:
            logger.warning(f"Suspicious activity detected: {identifier} made {len(self.suspicious_activities[key])} {activity_type} requests in {self.rapid_requests_window} seconds")
            self._block_identifier(identifier, now + self.block_duration)
            return True
        
        return False
    
    def _block_identifier(self, identifier: str, block_until: float):
        """Block an identifier (IP or user)"""
        # Determine if it's an IP or user ID
        if self._is_ip_address(identifier):
            self.blocked_ips[identifier] = block_until
        else:
            self.blocked_users[identifier] = block_until
    
    def _is_ip_address(self, identifier: str) -> bool:
        """Check if identifier is an IP address"""
        import re
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(ip_pattern, identifier))

class RateLimitingService:
    """Main rate limiting service with configurable limits"""
    
    def __init__(self):
        self.limiter = InMemoryRateLimiter()
        self.abuse_detector = AbuseDetectionService()
        
        # Rate limit configurations for different endpoints
        self.limits = {
            # Authentication endpoints
            "/login": RateLimitConfig(requests=5, window_seconds=300),  # 5 per 5 minutes
            "/register": RateLimitConfig(requests=3, window_seconds=3600),  # 3 per hour
            "/login-form": RateLimitConfig(requests=5, window_seconds=300),
            "/register-form": RateLimitConfig(requests=3, window_seconds=3600),
            
            # Tournament creation (user tournaments)
            "/api/user-tournaments": RateLimitConfig(
                requests=5, 
                window_seconds=3600,  # 5 per hour
                burst_requests=2,
                burst_window_seconds=300  # Max 2 in 5 minutes
            ),
            
            # Tournament registration
            "/api/tournaments/.*/register": RateLimitConfig(
                requests=10, 
                window_seconds=300  # 10 per 5 minutes
            ),
            
            # Payment endpoints
            "/api/user-tournaments/.*/payment": RateLimitConfig(
                requests=3,
                window_seconds=300  # 3 payment attempts per 5 minutes
            ),
            
            # General API endpoints
            "/api/tournaments": RateLimitConfig(requests=100, window_seconds=60),  # 100 per minute
            "/api/user-tournaments/.*": RateLimitConfig(requests=50, window_seconds=60),  # 50 per minute
            
            # Waitlist operations
            "/api/tournaments/.*/waitlist": RateLimitConfig(
                requests=5,
                window_seconds=300  # 5 waitlist operations per 5 minutes
            ),
            
            # Co-organizer invitations
            "/api/user-tournaments/.*/co-organizers": RateLimitConfig(
                requests=10,
                window_seconds=3600  # 10 invitations per hour
            ),
            
            # Default for unspecified endpoints
            "default": RateLimitConfig(requests=60, window_seconds=60)  # 60 per minute
        }
    
    async def check_rate_limit(self, endpoint: str, identifier: str, user_id: Optional[str] = None) -> RateLimitResult:
        """Check if request is within rate limits"""
        # First check if identifier is blocked
        is_blocked, block_time = await self.abuse_detector.is_blocked(identifier, "ip")
        if is_blocked:
            return RateLimitResult(
                allowed=False,
                remaining=0,
                retry_after=block_time,
                reason=f"IP blocked due to suspicious activity. Try again in {block_time} seconds."
            )
        
        # Check user-specific blocks
        if user_id:
            is_user_blocked, user_block_time = await self.abuse_detector.is_blocked(user_id, "user")
            if is_user_blocked:
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    retry_after=user_block_time,
                    reason=f"User blocked due to suspicious activity. Try again in {user_block_time} seconds."
                )
        
        # Find matching rate limit configuration
        limit_config = self._get_limit_config(endpoint)
        
        # Create rate limit key (prefer user_id over IP for authenticated requests)
        rate_limit_key = f"{endpoint}:{user_id or identifier}"
        
        # Check rate limit
        result = await self.limiter.is_allowed(rate_limit_key, limit_config)
        
        # Record suspicious activity if rate limit exceeded
        if not result.allowed:
            await self.abuse_detector.detect_suspicious_activity(
                identifier, 
                f"rate_limit_exceeded:{endpoint}"
            )
        
        return result
    
    async def record_failed_authentication(self, identifier: str, endpoint: str) -> bool:
        """Record failed authentication attempt"""
        return await self.abuse_detector.record_failed_attempt(identifier, f"auth:{endpoint}")
    
    def _get_limit_config(self, endpoint: str) -> RateLimitConfig:
        """Get rate limit configuration for endpoint"""
        # Try exact match first
        if endpoint in self.limits:
            return self.limits[endpoint]
        
        # Try pattern matching for parameterized endpoints
        import re
        for pattern, config in self.limits.items():
            if re.match(pattern.replace(".*", ".*"), endpoint):
                return config
        
        # Return default configuration
        return self.limits["default"]
    
    async def get_rate_limit_status(self, endpoint: str, identifier: str, user_id: Optional[str] = None) -> Dict:
        """Get current rate limit status for debugging/monitoring"""
        limit_config = self._get_limit_config(endpoint)
        rate_limit_key = f"{endpoint}:{user_id or identifier}"
        
        # Get current status without consuming a request
        now = time.time()
        window_start = now - limit_config.window_seconds
        
        request_times = self.limiter.requests.get(rate_limit_key, deque())
        current_requests = [t for t in request_times if t >= window_start]
        
        return {
            "endpoint": endpoint,
            "identifier": identifier,
            "current_requests": len(current_requests),
            "limit": limit_config.requests,
            "window_seconds": limit_config.window_seconds,
            "remaining": max(0, limit_config.requests - len(current_requests)),
            "reset_time": datetime.fromtimestamp(now + limit_config.window_seconds).isoformat()
        }

# Global instance
rate_limiting_service = RateLimitingService()

def get_rate_limiting_service() -> RateLimitingService:
    """Get the global rate limiting service instance"""
    return rate_limiting_service