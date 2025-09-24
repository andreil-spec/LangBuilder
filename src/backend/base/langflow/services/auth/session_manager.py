"""Advanced session security controls for authentication."""

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Dict, Optional, Set, List, Any
import hashlib
import secrets

from fastapi import Request, Response, HTTPException, status
from loguru import logger
from sqlmodel import Session

from langflow.services.database.models.user.model import User


@dataclass
class SessionInfo:
    """Session information and security metadata."""
    session_id: str
    user_id: str
    created_at: float
    last_activity: float
    ip_address: str
    user_agent: str
    device_fingerprint: str
    is_active: bool = True
    login_method: str = "password"  # password, api_key, oauth, etc.
    security_level: str = "standard"  # standard, high, admin
    suspicious_activity: bool = False
    concurrent_sessions: int = 1
    last_ip_change: Optional[float] = None
    last_location_change: Optional[float] = None
    failed_refresh_attempts: int = 0
    access_patterns: List[str] = None

    def __post_init__(self):
        if self.access_patterns is None:
            self.access_patterns = []


@dataclass
class SecurityThresholds:
    """Security thresholds for session management."""
    max_session_duration: int = 86400  # 24 hours
    max_idle_time: int = 7200  # 2 hours
    max_concurrent_sessions: int = 5
    ip_change_tolerance: int = 2  # Allow 2 IP changes per session
    location_change_tolerance: int = 1  # Allow 1 location change per session
    suspicious_activity_threshold: int = 3
    high_security_idle_time: int = 1800  # 30 minutes for high security
    admin_idle_time: int = 900  # 15 minutes for admin users


class SessionSecurityManager:
    """Advanced session security management with threat detection."""

    def __init__(self):
        self.sessions: Dict[str, SessionInfo] = {}
        self.user_sessions: Dict[str, Set[str]] = {}  # user_id -> session_ids
        self.thresholds = SecurityThresholds()
        self.lock = asyncio.Lock()

        # Tracking for suspicious activity
        self.ip_locations: Dict[str, str] = {}  # Simplified IP -> location mapping
        self.device_patterns: Dict[str, Set[str]] = {}  # user_id -> device fingerprints

    def _generate_session_id(self) -> str:
        """Generate a cryptographically secure session ID."""
        return secrets.token_urlsafe(32)

    def _generate_device_fingerprint(self, request: Request) -> str:
        """Generate a device fingerprint from request headers."""
        user_agent = request.headers.get("User-Agent", "")
        accept_language = request.headers.get("Accept-Language", "")
        accept_encoding = request.headers.get("Accept-Encoding", "")

        # Create a fingerprint from various headers
        fingerprint_data = f"{user_agent}:{accept_language}:{accept_encoding}"
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address with proper forwarded header handling."""
        # Check for forwarded headers
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()

        if hasattr(request, "client") and request.client:
            return request.client.host

        return "unknown"

    def _detect_ip_location_change(self, session_info: SessionInfo, new_ip: str) -> bool:
        """Detect significant IP location changes (simplified)."""
        if session_info.ip_address == new_ip:
            return False

        # Simplified location detection (in production, use GeoIP service)
        old_location = self._get_ip_location(session_info.ip_address)
        new_location = self._get_ip_location(new_ip)

        return old_location != new_location

    def _get_ip_location(self, ip: str) -> str:
        """Get location for IP address (simplified implementation)."""
        # In production, this would use a GeoIP service
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            return "private"
        elif ip.startswith("127."):
            return "localhost"
        else:
            # Simplified: use first two octets as "location"
            parts = ip.split(".")
            if len(parts) >= 2:
                return f"{parts[0]}.{parts[1]}.x.x"
            return "unknown"

    def _assess_security_level(self, user: User, login_method: str) -> str:
        """Assess required security level for user and login method."""
        if user.is_superuser:
            return "admin"
        elif login_method in ["api_key", "oauth"]:
            return "high"
        else:
            return "standard"

    def _get_idle_timeout(self, security_level: str) -> int:
        """Get idle timeout based on security level."""
        if security_level == "admin":
            return self.thresholds.admin_idle_time
        elif security_level == "high":
            return self.thresholds.high_security_idle_time
        else:
            return self.thresholds.max_idle_time

    async def create_session(
        self,
        request: Request,
        user: User,
        login_method: str = "password"
    ) -> SessionInfo:
        """Create a new secure session."""
        async with self.lock:
            session_id = self._generate_session_id()
            current_time = time.time()
            ip_address = self._get_client_ip(request)
            user_agent = request.headers.get("User-Agent", "")
            device_fingerprint = self._generate_device_fingerprint(request)
            security_level = self._assess_security_level(user, login_method)

            # Check concurrent session limits
            user_id = str(user.id)
            current_sessions = self.user_sessions.get(user_id, set())

            if len(current_sessions) >= self.thresholds.max_concurrent_sessions:
                # Remove oldest session
                await self._cleanup_oldest_session(user_id)

            # Create session info
            session_info = SessionInfo(
                session_id=session_id,
                user_id=user_id,
                created_at=current_time,
                last_activity=current_time,
                ip_address=ip_address,
                user_agent=user_agent,
                device_fingerprint=device_fingerprint,
                login_method=login_method,
                security_level=security_level,
                concurrent_sessions=len(current_sessions) + 1
            )

            # Store session
            self.sessions[session_id] = session_info

            # Update user sessions tracking
            if user_id not in self.user_sessions:
                self.user_sessions[user_id] = set()
            self.user_sessions[user_id].add(session_id)

            # Track device pattern
            if user_id not in self.device_patterns:
                self.device_patterns[user_id] = set()
            self.device_patterns[user_id].add(device_fingerprint)

            logger.info(f"Created session {session_id[:8]}... for user {user_id} (security: {security_level})")

            return session_info

    async def validate_session(
        self,
        request: Request,
        session_id: str,
        update_activity: bool = True
    ) -> Optional[SessionInfo]:
        """Validate and optionally update session activity."""
        async with self.lock:
            if session_id not in self.sessions:
                logger.warning(f"Session not found: {session_id[:8]}...")
                return None

            session_info = self.sessions[session_id]
            current_time = time.time()

            # Check if session is active
            if not session_info.is_active:
                logger.warning(f"Inactive session access attempt: {session_id[:8]}...")
                return None

            # Check session expiration
            session_age = current_time - session_info.created_at
            if session_age > self.thresholds.max_session_duration:
                logger.info(f"Session expired (age): {session_id[:8]}...")
                await self._invalidate_session(session_id)
                return None

            # Check idle timeout
            idle_time = current_time - session_info.last_activity
            max_idle = self._get_idle_timeout(session_info.security_level)

            if idle_time > max_idle:
                logger.info(f"Session expired (idle): {session_id[:8]}... (idle: {idle_time:.0f}s)")
                await self._invalidate_session(session_id)
                return None

            # Security checks
            current_ip = self._get_client_ip(request)
            current_fingerprint = self._generate_device_fingerprint(request)

            # Check for IP changes
            if current_ip != session_info.ip_address:
                if self._detect_ip_location_change(session_info, current_ip):
                    session_info.last_location_change = current_time
                    logger.warning(f"Location change detected for session {session_id[:8]}...")

                session_info.last_ip_change = current_time
                session_info.ip_address = current_ip

            # Check for device fingerprint changes
            if current_fingerprint != session_info.device_fingerprint:
                logger.warning(f"Device fingerprint change for session {session_id[:8]}...")
                session_info.suspicious_activity = True
                session_info.device_fingerprint = current_fingerprint

            # Update activity
            if update_activity:
                session_info.last_activity = current_time

            return session_info

    async def refresh_session(
        self,
        request: Request,
        session_id: str
    ) -> Optional[SessionInfo]:
        """Refresh session with additional security checks."""
        session_info = await self.validate_session(request, session_id, update_activity=True)

        if session_info is None:
            return None

        # Additional security checks for refresh
        current_time = time.time()

        # Check for too many refresh attempts
        if session_info.failed_refresh_attempts >= 5:
            logger.warning(f"Too many failed refresh attempts: {session_id[:8]}...")
            await self._invalidate_session(session_id)
            return None

        # Reset failed refresh attempts on successful refresh
        session_info.failed_refresh_attempts = 0

        # Track access pattern
        session_info.access_patterns.append(f"refresh:{current_time}")
        if len(session_info.access_patterns) > 10:
            session_info.access_patterns = session_info.access_patterns[-10:]

        logger.debug(f"Session refreshed: {session_id[:8]}...")
        return session_info

    async def record_failed_refresh(self, session_id: str) -> None:
        """Record a failed refresh attempt."""
        async with self.lock:
            if session_id in self.sessions:
                session_info = self.sessions[session_id]
                session_info.failed_refresh_attempts += 1

                if session_info.failed_refresh_attempts >= 5:
                    logger.warning(f"Invalidating session due to failed refreshes: {session_id[:8]}...")
                    await self._invalidate_session(session_id)

    async def invalidate_session(self, session_id: str) -> bool:
        """Invalidate a specific session."""
        async with self.lock:
            return await self._invalidate_session(session_id)

    async def _invalidate_session(self, session_id: str) -> bool:
        """Internal session invalidation."""
        if session_id not in self.sessions:
            return False

        session_info = self.sessions[session_id]
        user_id = session_info.user_id

        # Remove from sessions
        del self.sessions[session_id]

        # Remove from user sessions
        if user_id in self.user_sessions:
            self.user_sessions[user_id].discard(session_id)
            if not self.user_sessions[user_id]:
                del self.user_sessions[user_id]

        logger.info(f"Session invalidated: {session_id[:8]}...")
        return True

    async def invalidate_all_user_sessions(self, user_id: str) -> int:
        """Invalidate all sessions for a user."""
        async with self.lock:
            if user_id not in self.user_sessions:
                return 0

            session_ids = list(self.user_sessions[user_id])
            count = 0

            for session_id in session_ids:
                if await self._invalidate_session(session_id):
                    count += 1

            logger.info(f"Invalidated {count} sessions for user {user_id}")
            return count

    async def _cleanup_oldest_session(self, user_id: str) -> None:
        """Remove the oldest session for a user."""
        if user_id not in self.user_sessions:
            return

        session_ids = list(self.user_sessions[user_id])
        if not session_ids:
            return

        # Find oldest session
        oldest_session_id = min(
            session_ids,
            key=lambda sid: self.sessions[sid].created_at if sid in self.sessions else 0
        )

        await self._invalidate_session(oldest_session_id)
        logger.info(f"Removed oldest session for user {user_id}: {oldest_session_id[:8]}...")

    async def get_user_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """Get all active sessions for a user."""
        async with self.lock:
            if user_id not in self.user_sessions:
                return []

            sessions = []
            for session_id in self.user_sessions[user_id]:
                if session_id in self.sessions:
                    session_info = self.sessions[session_id]
                    sessions.append({
                        "session_id": session_id[:8] + "...",  # Truncated for security
                        "created_at": datetime.fromtimestamp(session_info.created_at).isoformat(),
                        "last_activity": datetime.fromtimestamp(session_info.last_activity).isoformat(),
                        "ip_address": session_info.ip_address,
                        "user_agent": session_info.user_agent,
                        "security_level": session_info.security_level,
                        "login_method": session_info.login_method,
                        "suspicious_activity": session_info.suspicious_activity
                    })

            return sorted(sessions, key=lambda s: s["last_activity"], reverse=True)

    async def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions."""
        async with self.lock:
            current_time = time.time()
            expired_sessions = []

            for session_id, session_info in self.sessions.items():
                session_age = current_time - session_info.created_at
                idle_time = current_time - session_info.last_activity
                max_idle = self._get_idle_timeout(session_info.security_level)

                if (session_age > self.thresholds.max_session_duration or
                    idle_time > max_idle or
                    not session_info.is_active):
                    expired_sessions.append(session_id)

            count = 0
            for session_id in expired_sessions:
                if await self._invalidate_session(session_id):
                    count += 1

            if count > 0:
                logger.info(f"Cleaned up {count} expired sessions")

            return count

    async def detect_suspicious_activity(self, user_id: str) -> Dict[str, Any]:
        """Detect suspicious activity patterns for a user."""
        async with self.lock:
            if user_id not in self.user_sessions:
                return {"suspicious": False, "reasons": []}

            reasons = []
            current_time = time.time()

            # Check for too many concurrent sessions
            session_count = len(self.user_sessions[user_id])
            if session_count > self.thresholds.max_concurrent_sessions - 1:
                reasons.append(f"High concurrent sessions: {session_count}")

            # Check for rapid session creation
            session_times = []
            for session_id in self.user_sessions[user_id]:
                if session_id in self.sessions:
                    session_times.append(self.sessions[session_id].created_at)

            if len(session_times) >= 3:
                session_times.sort()
                if session_times[-1] - session_times[-3] < 300:  # 3 sessions in 5 minutes
                    reasons.append("Rapid session creation detected")

            # Check for multiple device fingerprints
            if user_id in self.device_patterns:
                device_count = len(self.device_patterns[user_id])
                if device_count > 3:
                    reasons.append(f"Multiple devices: {device_count}")

            # Check individual session suspicious activity
            suspicious_sessions = 0
            for session_id in self.user_sessions[user_id]:
                if session_id in self.sessions:
                    session_info = self.sessions[session_id]
                    if session_info.suspicious_activity:
                        suspicious_sessions += 1

            if suspicious_sessions > 0:
                reasons.append(f"Suspicious session activity: {suspicious_sessions}")

            return {
                "suspicious": len(reasons) > 0,
                "reasons": reasons,
                "session_count": session_count,
                "device_count": len(self.device_patterns.get(user_id, set())),
                "suspicious_sessions": suspicious_sessions
            }

    def set_security_thresholds(self, **kwargs) -> None:
        """Update security thresholds."""
        for key, value in kwargs.items():
            if hasattr(self.thresholds, key):
                setattr(self.thresholds, key, value)
                logger.info(f"Updated security threshold {key} = {value}")


# Global session manager instance
_session_manager: Optional[SessionSecurityManager] = None


def get_session_manager() -> SessionSecurityManager:
    """Get the global session manager instance."""
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionSecurityManager()
    return _session_manager
