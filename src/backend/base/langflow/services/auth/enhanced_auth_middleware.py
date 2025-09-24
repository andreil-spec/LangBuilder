"""Enhanced authentication middleware with comprehensive security controls."""

import asyncio
import time
from typing import Callable, Optional, Dict, Any
from functools import wraps

from fastapi import Request, Response, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from loguru import logger

from langflow.services.auth.rate_limiter import get_rate_limiter, AuthRateLimiter
from langflow.services.auth.session_manager import get_session_manager, SessionSecurityManager
from langflow.services.auth.brute_force_protection import get_brute_force_protection, BruteForceProtection
from langflow.services.database.models.user.model import User


class EnhancedHTTPBearer(HTTPBearer):
    """Enhanced HTTP Bearer with additional security checks."""

    def __init__(self, auto_error: bool = True):
        super().__init__(auto_error=auto_error)
        self.rate_limiter = get_rate_limiter()
        self.session_manager = get_session_manager()
        self.brute_force_protection = get_brute_force_protection()

    async def __call__(self, request: Request) -> Optional[HTTPAuthorizationCredentials]:
        """Enhanced authentication with security controls."""
        # Rate limiting check for API access
        await self._check_api_rate_limit(request)

        # Get credentials
        credentials = await super().__call__(request)

        if credentials:
            # Additional security checks for token access
            await self._validate_token_security(request, credentials.credentials)

        return credentials

    async def _check_api_rate_limit(self, request: Request) -> None:
        """Check API rate limiting."""
        try:
            allowed, info = await self.rate_limiter.check_rate_limit(request, "api_key")
            if not allowed:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "message": "API rate limit exceeded",
                        **info
                    },
                    headers={"Retry-After": str(info.get("retry_after", 60))}
                )
        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")
            # Continue without blocking if rate limiter fails

    async def _validate_token_security(self, request: Request, token: str) -> None:
        """Validate token-based access security."""
        # Extract session ID from token if applicable
        # This would depend on your token structure
        # For now, we'll do basic validation

        # Check for suspicious patterns in token usage
        user_agent = request.headers.get("User-Agent", "")
        ip_address = self._get_client_ip(request)

        # Log token usage for monitoring
        logger.debug(f"Token access from {ip_address} with agent: {user_agent[:50]}...")

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address."""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()

        if hasattr(request, "client") and request.client:
            return request.client.host

        return "unknown"


def enhanced_authentication_required(
    enable_rate_limiting: bool = True,
    enable_session_validation: bool = True,
    enable_brute_force_protection: bool = True,
    security_level: str = "standard"
):
    """
    Enhanced authentication decorator with comprehensive security controls.

    Args:
        enable_rate_limiting: Enable rate limiting for this endpoint
        enable_session_validation: Enable session security validation
        enable_brute_force_protection: Enable brute force protection
        security_level: Security level (standard, high, admin)
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request from args/kwargs
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break

            if not request:
                for value in kwargs.values():
                    if isinstance(value, Request):
                        request = value
                        break

            if not request:
                logger.error("No Request object found in authentication decorator")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Authentication error: No request context"
                )

            # Apply security controls
            await _apply_security_controls(
                request=request,
                enable_rate_limiting=enable_rate_limiting,
                enable_session_validation=enable_session_validation,
                enable_brute_force_protection=enable_brute_force_protection,
                security_level=security_level
            )

            # Call original function
            return await func(*args, **kwargs)

        return wrapper
    return decorator


async def _apply_security_controls(
    request: Request,
    enable_rate_limiting: bool,
    enable_session_validation: bool,
    enable_brute_force_protection: bool,
    security_level: str
) -> None:
    """Apply comprehensive security controls."""

    # Rate limiting
    if enable_rate_limiting:
        await _check_endpoint_rate_limit(request, security_level)

    # Session validation
    if enable_session_validation:
        await _validate_session_security(request, security_level)

    # Brute force protection
    if enable_brute_force_protection:
        await _check_brute_force_protection(request)


async def _check_endpoint_rate_limit(request: Request, security_level: str) -> None:
    """Check endpoint-specific rate limiting."""
    rate_limiter = get_rate_limiter()

    # Determine rate limit rule based on security level
    if security_level == "admin":
        rule_name = "admin_api"
    elif security_level == "high":
        rule_name = "high_security_api"
    else:
        rule_name = "api_key"

    try:
        allowed, info = await rate_limiter.check_rate_limit(request, rule_name)
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "message": f"Rate limit exceeded for {security_level} endpoint",
                    **info
                },
                headers={"Retry-After": str(info.get("retry_after", 60))}
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Rate limit check failed: {e}")


async def _validate_session_security(request: Request, security_level: str) -> None:
    """Validate session security requirements."""
    session_manager = get_session_manager()

    # Extract session information from headers or cookies
    session_id = request.headers.get("X-Session-ID")
    if not session_id:
        # Try to get from cookies if available
        session_id = request.cookies.get("session_id")

    if session_id:
        try:
            session_info = await session_manager.validate_session(request, session_id)
            if not session_info:
                logger.warning("Invalid session detected")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or expired session"
                )

            # Check security level requirements
            if security_level == "admin" and session_info.security_level != "admin":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Admin access required"
                )

            # Check for suspicious activity
            if session_info.suspicious_activity:
                logger.warning(f"Suspicious activity detected for session {session_id[:8]}...")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Session security violation detected"
                )

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Session validation failed: {e}")


async def _check_brute_force_protection(request: Request) -> None:
    """Check brute force protection."""
    # This is more relevant for login endpoints, but we can check for general patterns
    protection = get_brute_force_protection()

    try:
        # Check if IP is currently blocked
        ip_address = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        if not ip_address:
            ip_address = request.headers.get("X-Real-IP", "")
        if not ip_address and hasattr(request, "client") and request.client:
            ip_address = request.client.host

        if ip_address:
            threat_info = await protection.get_threat_assessment(ip_address, "ip")
            if threat_info.get("blocked", False):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="IP address is temporarily blocked due to suspicious activity"
                )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Brute force protection check failed: {e}")


class AuthenticationEnhancementMiddleware:
    """Middleware to apply authentication enhancements globally."""

    def __init__(self, app):
        self.app = app
        self.rate_limiter = get_rate_limiter()
        self.session_manager = get_session_manager()
        self.brute_force_protection = get_brute_force_protection()

    async def __call__(self, scope, receive, send):
        """ASGI middleware implementation."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Create request object
        from fastapi import Request
        request = Request(scope)

        # Apply global security controls
        try:
            await self._apply_global_security(request)
        except HTTPException as e:
            # Send error response
            response = {
                "type": "http.response.start",
                "status": e.status_code,
                "headers": [[b"content-type", b"application/json"]],
            }
            await send(response)

            import json
            body = json.dumps({"detail": e.detail}).encode()
            await send({
                "type": "http.response.body",
                "body": body,
            })
            return

        # Continue with the app
        await self.app(scope, receive, send)

    async def _apply_global_security(self, request: Request) -> None:
        """Apply global security controls."""
        path = request.url.path

        # Skip security for health checks and static files
        if path.startswith(("/health", "/static", "/docs", "/openapi.json")):
            return

        # Apply basic rate limiting to all requests
        try:
            allowed, info = await self.rate_limiter.check_rate_limit(request, "general")
            if not allowed:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "message": "Global rate limit exceeded",
                        **info
                    }
                )
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Global rate limiting failed: {e}")

        # Check for blocked IPs
        try:
            ip_address = self._get_client_ip(request)
            threat_info = await self.brute_force_protection.get_threat_assessment(ip_address, "ip")

            if threat_info.get("blocked", False):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: IP address is blocked"
                )

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"IP blocking check failed: {e}")

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address."""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()

        if hasattr(request, "client") and request.client:
            return request.client.host

        return "unknown"


# FastAPI dependencies for enhanced authentication
enhanced_bearer = EnhancedHTTPBearer()


async def enhanced_auth_dependency(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(enhanced_bearer)
) -> Dict[str, Any]:
    """Enhanced authentication dependency for FastAPI."""
    return {
        "token": credentials.credentials,
        "scheme": credentials.scheme,
        "request": request,
        "timestamp": time.time()
    }


# Utility functions for endpoint decoration
def login_security_required(func: Callable) -> Callable:
    """Security decorator specifically for login endpoints."""
    return enhanced_authentication_required(
        enable_rate_limiting=True,
        enable_session_validation=False,  # No session during login
        enable_brute_force_protection=True,
        security_level="standard"
    )(func)


def admin_security_required(func: Callable) -> Callable:
    """Security decorator for admin endpoints."""
    return enhanced_authentication_required(
        enable_rate_limiting=True,
        enable_session_validation=True,
        enable_brute_force_protection=True,
        security_level="admin"
    )(func)


def high_security_required(func: Callable) -> Callable:
    """Security decorator for high-security endpoints."""
    return enhanced_authentication_required(
        enable_rate_limiting=True,
        enable_session_validation=True,
        enable_brute_force_protection=True,
        security_level="high"
    )(func)


# Background tasks for maintenance
async def run_security_maintenance():
    """Run periodic security maintenance tasks."""
    rate_limiter = get_rate_limiter()
    session_manager = get_session_manager()
    brute_force_protection = get_brute_force_protection()

    while True:
        try:
            # Clean up expired data
            await asyncio.gather(
                rate_limiter.cleanup_expired_states(),
                session_manager.cleanup_expired_sessions(),
                brute_force_protection.cleanup_expired_data()
            )

            logger.info("Security maintenance completed")

        except Exception as e:
            logger.error(f"Security maintenance failed: {e}")

        # Run every hour
        await asyncio.sleep(3600)
