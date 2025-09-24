"""Rate limiting service for authentication endpoints."""

import asyncio
import time
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict
import hashlib

from fastapi import HTTPException, Request, status
from loguru import logger


@dataclass
class RateLimitRule:
    """Rate limit rule configuration."""
    max_attempts: int
    window_seconds: int
    block_duration_seconds: int = 0  # 0 means no blocking, just limit
    name: str = "default"


@dataclass
class AttemptRecord:
    """Individual attempt record."""
    timestamp: float
    ip_address: str
    user_identifier: Optional[str] = None
    success: bool = False


@dataclass
class ClientState:
    """Client rate limit state."""
    attempts: list[AttemptRecord]
    blocked_until: Optional[float] = None
    first_attempt: float = 0
    last_attempt: float = 0
    total_attempts: int = 0
    failed_attempts: int = 0


class AuthRateLimiter:
    """Advanced rate limiter for authentication endpoints with brute force protection."""

    def __init__(self):
        # Different rate limits for different scenarios
        # DEVELOPMENT: Set to very large values to effectively disable rate limiting
        self.rules = {
            "login": RateLimitRule(
                max_attempts=999999,
                window_seconds=1,  # Very short window
                block_duration_seconds=0,  # No blocking for development
                name="login"
            ),
            "login_user": RateLimitRule(
                max_attempts=999999,
                window_seconds=1,  # Very short window
                block_duration_seconds=0,  # No blocking for development
                name="login_user"
            ),
            "refresh": RateLimitRule(
                max_attempts=999999,
                window_seconds=1,  # Very short window
                block_duration_seconds=0,  # No blocking for development
                name="refresh"
            ),
            "api_key": RateLimitRule(
                max_attempts=999999,
                window_seconds=1,  # Very short window
                block_duration_seconds=0,  # No blocking for development
                name="api_key"
            ),
            "password_reset": RateLimitRule(
                max_attempts=999999,
                window_seconds=1,  # Very short window
                block_duration_seconds=0,  # No blocking for development
                name="password_reset"
            )
        }

        # Client state storage (in-memory for now, could be Redis in production)
        self.client_states: Dict[str, ClientState] = {}
        self.lock = asyncio.Lock()

    def _get_client_key(self, ip_address: str, rule_name: str, user_identifier: Optional[str] = None) -> str:
        """Generate a unique key for rate limiting."""
        if user_identifier and rule_name in ["login_user", "password_reset"]:
            # User-specific rate limiting
            key_data = f"{rule_name}:user:{user_identifier}"
        else:
            # IP-based rate limiting
            key_data = f"{rule_name}:ip:{ip_address}"

        # Hash the key for consistent length and security
        return hashlib.sha256(key_data.encode()).hexdigest()

    def _cleanup_old_attempts(self, client_state: ClientState, window_seconds: int) -> None:
        """Remove attempts outside the current window."""
        current_time = time.time()
        cutoff_time = current_time - window_seconds

        client_state.attempts = [
            attempt for attempt in client_state.attempts
            if attempt.timestamp > cutoff_time
        ]

    def _is_blocked(self, client_state: ClientState) -> bool:
        """Check if client is currently blocked."""
        if client_state.blocked_until is None:
            return False

        current_time = time.time()
        if current_time >= client_state.blocked_until:
            # Block has expired
            client_state.blocked_until = None
            return False

        return True

    def _should_block(self, client_state: ClientState, rule: RateLimitRule) -> bool:
        """Determine if client should be blocked based on attempts."""
        if rule.block_duration_seconds == 0:
            return False  # No blocking for this rule

        # Count failed attempts in the window
        current_time = time.time()
        window_start = current_time - rule.window_seconds

        failed_in_window = sum(
            1 for attempt in client_state.attempts
            if attempt.timestamp > window_start and not attempt.success
        )

        return failed_in_window >= rule.max_attempts

    async def check_rate_limit(
        self,
        request: Request,
        rule_name: str,
        user_identifier: Optional[str] = None
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if request should be rate limited.

        Returns:
            Tuple of (allowed, info_dict)
        """
        if rule_name not in self.rules:
            logger.warning(f"Unknown rate limit rule: {rule_name}")
            return True, {}

        rule = self.rules[rule_name]
        ip_address = self._get_client_ip(request)
        client_key = self._get_client_key(ip_address, rule_name, user_identifier)

        async with self.lock:
            # Get or create client state
            if client_key not in self.client_states:
                self.client_states[client_key] = ClientState(attempts=[])

            client_state = self.client_states[client_key]
            current_time = time.time()

            # Check if currently blocked
            if self._is_blocked(client_state):
                block_remaining = (client_state.blocked_until or 0) - current_time
                logger.warning(f"Rate limit blocked: {rule_name} for {client_key[:8]}... (remaining: {block_remaining:.1f}s)")

                return False, {
                    "error": "rate_limit_exceeded",
                    "rule": rule_name,
                    "block_remaining_seconds": int(block_remaining),
                    "retry_after": int(block_remaining) + 1
                }

            # Clean up old attempts
            self._cleanup_old_attempts(client_state, rule.window_seconds)

            # Count current attempts in window
            attempts_in_window = len(client_state.attempts)

            # Check if limit exceeded
            if attempts_in_window >= rule.max_attempts:
                logger.warning(f"Rate limit exceeded: {rule_name} for {client_key[:8]}... ({attempts_in_window}/{rule.max_attempts})")

                # Set block if configured
                if rule.block_duration_seconds > 0:
                    client_state.blocked_until = current_time + rule.block_duration_seconds
                    logger.info(f"Client blocked for {rule.block_duration_seconds}s: {client_key[:8]}...")

                return False, {
                    "error": "rate_limit_exceeded",
                    "rule": rule_name,
                    "attempts": attempts_in_window,
                    "max_attempts": rule.max_attempts,
                    "window_seconds": rule.window_seconds,
                    "retry_after": rule.window_seconds // rule.max_attempts
                }

            return True, {
                "attempts_remaining": rule.max_attempts - attempts_in_window,
                "window_seconds": rule.window_seconds,
                "rule": rule_name
            }

    async def record_attempt(
        self,
        request: Request,
        rule_name: str,
        success: bool,
        user_identifier: Optional[str] = None
    ) -> None:
        """Record an authentication attempt."""
        if rule_name not in self.rules:
            return

        ip_address = self._get_client_ip(request)
        client_key = self._get_client_key(ip_address, rule_name, user_identifier)

        async with self.lock:
            if client_key not in self.client_states:
                self.client_states[client_key] = ClientState(attempts=[])

            client_state = self.client_states[client_key]
            current_time = time.time()

            # Add attempt record
            attempt = AttemptRecord(
                timestamp=current_time,
                ip_address=ip_address,
                user_identifier=user_identifier,
                success=success
            )
            client_state.attempts.append(attempt)

            # Update state
            client_state.total_attempts += 1
            if not success:
                client_state.failed_attempts += 1

            client_state.last_attempt = current_time
            if client_state.first_attempt == 0:
                client_state.first_attempt = current_time

            # Check if should block after failed attempt
            if not success and self._should_block(client_state, self.rules[rule_name]):
                rule = self.rules[rule_name]
                if rule.block_duration_seconds > 0:
                    client_state.blocked_until = current_time + rule.block_duration_seconds
                    logger.warning(f"Client blocked due to repeated failures: {client_key[:8]}... for {rule.block_duration_seconds}s")

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address from request."""
        # Check for forwarded headers first
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP (original client)
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()

        # Fallback to direct client IP
        if hasattr(request, "client") and request.client:
            return request.client.host

        return "unknown"

    async def get_client_stats(self, request: Request, rule_name: str, user_identifier: Optional[str] = None) -> Dict[str, Any]:
        """Get rate limiting statistics for a client."""
        if rule_name not in self.rules:
            return {}

        ip_address = self._get_client_ip(request)
        client_key = self._get_client_key(ip_address, rule_name, user_identifier)

        async with self.lock:
            if client_key not in self.client_states:
                return {"attempts": 0, "blocked": False}

            client_state = self.client_states[client_key]
            rule = self.rules[rule_name]

            # Clean up old attempts
            self._cleanup_old_attempts(client_state, rule.window_seconds)

            current_time = time.time()
            is_blocked = self._is_blocked(client_state)

            attempts_in_window = len(client_state.attempts)
            failed_in_window = sum(1 for attempt in client_state.attempts if not attempt.success)

            return {
                "total_attempts": client_state.total_attempts,
                "failed_attempts": client_state.failed_attempts,
                "attempts_in_window": attempts_in_window,
                "failed_in_window": failed_in_window,
                "max_attempts": rule.max_attempts,
                "blocked": is_blocked,
                "block_remaining": max(0, client_state.blocked_until - current_time) if client_state.blocked_until else 0,
                "first_attempt": datetime.fromtimestamp(client_state.first_attempt) if client_state.first_attempt else None,
                "last_attempt": datetime.fromtimestamp(client_state.last_attempt) if client_state.last_attempt else None
            }

    async def reset_client_limits(self, request: Request, rule_name: str, user_identifier: Optional[str] = None) -> bool:
        """Reset rate limits for a client (admin function)."""
        ip_address = self._get_client_ip(request)
        client_key = self._get_client_key(ip_address, rule_name, user_identifier)

        async with self.lock:
            if client_key in self.client_states:
                del self.client_states[client_key]
                logger.info(f"Reset rate limits for client: {client_key[:8]}...")
                return True
            return False

    async def cleanup_expired_states(self) -> int:
        """Clean up expired client states (maintenance function)."""
        current_time = time.time()
        expired_keys = []

        async with self.lock:
            for client_key, client_state in self.client_states.items():
                # Remove if no activity for 24 hours
                if client_state.last_attempt > 0 and current_time - client_state.last_attempt > 86400:
                    expired_keys.append(client_key)
                # Also remove if only old attempts remain
                elif client_state.attempts and all(
                    current_time - attempt.timestamp > 86400 for attempt in client_state.attempts
                ):
                    expired_keys.append(client_key)

            for key in expired_keys:
                del self.client_states[key]

        if expired_keys:
            logger.info(f"Cleaned up {len(expired_keys)} expired rate limit states")

        return len(expired_keys)


# Global rate limiter instance
_rate_limiter: Optional[AuthRateLimiter] = None


def get_rate_limiter() -> AuthRateLimiter:
    """Get the global rate limiter instance."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = AuthRateLimiter()
    return _rate_limiter


async def rate_limit_check(request: Request, rule_name: str, user_identifier: Optional[str] = None) -> None:
    """FastAPI dependency for rate limiting."""
    rate_limiter = get_rate_limiter()

    allowed, info = await rate_limiter.check_rate_limit(request, rule_name, user_identifier)

    if not allowed:
        error_detail = info.get("error", "rate_limit_exceeded")
        retry_after = info.get("retry_after", 60)

        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "message": f"Rate limit exceeded for {rule_name}",
                "error": error_detail,
                "retry_after_seconds": retry_after,
                **info
            },
            headers={"Retry-After": str(retry_after)}
        )
