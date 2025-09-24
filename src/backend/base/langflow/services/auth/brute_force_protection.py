"""Advanced brute force protection system with intelligent threat detection."""

import asyncio
import time
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any
from enum import Enum
import secrets
import math

from fastapi import Request, HTTPException, status
from loguru import logger


class ThreatLevel(Enum):
    """Threat assessment levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackPattern(Enum):
    """Known attack patterns."""
    DICTIONARY = "dictionary"
    BRUTE_FORCE = "brute_force"
    CREDENTIAL_STUFFING = "credential_stuffing"
    DISTRIBUTED = "distributed"
    SLOW_ATTACK = "slow_attack"
    TARGETED = "targeted"


@dataclass
class LoginAttempt:
    """Individual login attempt record."""
    timestamp: float
    username: str
    ip_address: str
    user_agent: str
    success: bool
    password_length: int
    response_time: float
    geolocation: Optional[str] = None
    attack_indicators: List[str] = field(default_factory=list)


@dataclass
class ThreatProfile:
    """Threat profile for an IP or user."""
    identifier: str
    identifier_type: str  # 'ip' or 'user'
    threat_level: ThreatLevel
    first_seen: float
    last_seen: float
    total_attempts: int
    failed_attempts: int
    success_rate: float
    attack_patterns: Set[AttackPattern]
    blocked_until: Optional[float] = None
    escalation_count: int = 0
    geographical_spread: Set[str] = field(default_factory=set)
    user_agents: Set[str] = field(default_factory=set)
    targeted_users: Set[str] = field(default_factory=set)


@dataclass
class ProtectionConfig:
    """Brute force protection configuration."""
    # Basic thresholds - DEVELOPMENT: Set to very large values to effectively disable
    max_attempts_per_ip: int = 999999
    max_attempts_per_user: int = 999999
    time_window_seconds: int = 1  # Very short window

    # Progressive blocking - DEVELOPMENT: Disabled for dev
    initial_block_duration: int = 0  # No blocking
    max_block_duration: int = 0  # No blocking
    escalation_factor: float = 1.0

    # Advanced detection - DEVELOPMENT: Disabled for dev
    enable_pattern_detection: bool = False
    enable_distributed_detection: bool = False
    suspicious_user_agent_threshold: int = 999999
    geographical_spread_threshold: int = 999999

    # Threat response - DEVELOPMENT: Disabled for dev
    auto_block_critical_threats: bool = False
    notification_threshold: ThreatLevel = ThreatLevel.CRITICAL


class BruteForceProtection:
    """Advanced brute force protection with pattern recognition and adaptive blocking."""

    def __init__(self, config: Optional[ProtectionConfig] = None):
        self.config = config or ProtectionConfig()
        self.login_attempts: List[LoginAttempt] = []
        self.threat_profiles: Dict[str, ThreatProfile] = {}
        self.blocked_identifiers: Dict[str, float] = {}  # identifier -> block_until_timestamp
        self.lock = asyncio.Lock()

        # Pattern detection
        self.common_passwords = self._load_common_passwords()
        self.suspicious_user_agents: set[str] = set()

        # Statistics
        self.stats = {
            "total_attempts": 0,
            "blocked_attempts": 0,
            "patterns_detected": 0,
            "threats_identified": 0
        }

    def _load_common_passwords(self) -> Set[str]:
        """Load common passwords for pattern detection."""
        # In production, load from a file or database
        return {
            "password", "123456", "password123", "admin", "qwerty",
            "letmein", "welcome", "monkey", "dragon", "master",
            "654321", "111111", "123123", "1234567890"
        }

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

    def _get_geolocation(self, ip_address: str) -> str:
        """Get geolocation for IP (simplified implementation)."""
        # In production, use a proper GeoIP service
        if ip_address.startswith("192.168.") or ip_address.startswith("10."):
            return "private"
        elif ip_address.startswith("127."):
            return "localhost"
        else:
            # Simplified geolocation based on IP range
            parts = ip_address.split(".")
            if len(parts) >= 2:
                return f"region_{parts[0]}_{parts[1]}"
            return "unknown"

    def _calculate_block_duration(self, escalation_count: int) -> int:
        """Calculate progressive block duration."""
        duration = self.config.initial_block_duration * (self.config.escalation_factor ** escalation_count)
        return min(int(duration), self.config.max_block_duration)

    def _detect_attack_patterns(self, attempts: List[LoginAttempt]) -> Set[AttackPattern]:
        """Detect attack patterns from login attempts."""
        patterns: set[AttackPattern] = set()

        if len(attempts) < 3:
            return patterns

        # Sort by timestamp
        attempts = sorted(attempts, key=lambda a: a.timestamp)

        # Check for brute force (rapid attempts)
        time_diffs = [attempts[i].timestamp - attempts[i-1].timestamp for i in range(1, len(attempts))]
        avg_time_diff = sum(time_diffs) / len(time_diffs)

        if avg_time_diff < 2.0:  # Less than 2 seconds between attempts
            patterns.add(AttackPattern.BRUTE_FORCE)

        # Check for dictionary attack (common passwords)
        failed_attempts = [a for a in attempts if not a.success]
        if len(failed_attempts) >= 5:
            # Look for patterns in password lengths (dictionary attacks often use common lengths)
            password_lengths = [a.password_length for a in failed_attempts if a.password_length > 0]
            if password_lengths:
                common_lengths = {6, 8, 10, 12}  # Common password lengths
                common_count = sum(1 for length in password_lengths if length in common_lengths)
                if common_count / len(password_lengths) > 0.7:
                    patterns.add(AttackPattern.DICTIONARY)

        # Check for credential stuffing (multiple usernames from same IP)
        usernames = set(a.username for a in attempts)
        if len(usernames) > 5:
            patterns.add(AttackPattern.CREDENTIAL_STUFFING)

        # Check for slow attack (spread over time to avoid detection)
        if len(attempts) >= 10 and avg_time_diff > 60:  # More than 1 minute between attempts
            patterns.add(AttackPattern.SLOW_ATTACK)

        # Check for targeted attack (same username, multiple IPs)
        if len(set(a.ip_address for a in attempts)) > 3 and len(usernames) == 1:
            patterns.add(AttackPattern.TARGETED)

        return patterns

    def _assess_threat_level(self, profile: ThreatProfile) -> ThreatLevel:
        """Assess threat level based on profile."""
        score = 0

        # Base score from success rate
        if profile.success_rate == 0.0:
            score += 30
        elif profile.success_rate < 0.1:
            score += 20
        elif profile.success_rate < 0.3:
            score += 10

        # Score from attempt volume
        if profile.total_attempts > 100:
            score += 25
        elif profile.total_attempts > 50:
            score += 15
        elif profile.total_attempts > 20:
            score += 10

        # Score from attack patterns
        score += len(profile.attack_patterns) * 10

        # Score from geographical spread
        if len(profile.geographical_spread) > 5:
            score += 20
        elif len(profile.geographical_spread) > 3:
            score += 10

        # Score from user agent diversity
        if len(profile.user_agents) > 10:
            score += 15
        elif len(profile.user_agents) > 5:
            score += 10

        # Score from targeted users
        if len(profile.targeted_users) > 10:
            score += 20
        elif len(profile.targeted_users) > 5:
            score += 10

        # Determine threat level
        if score >= 80:
            return ThreatLevel.CRITICAL
        elif score >= 60:
            return ThreatLevel.HIGH
        elif score >= 40:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW

    def _update_threat_profile(self, identifier: str, identifier_type: str, attempt: LoginAttempt) -> ThreatProfile:
        """Update or create threat profile."""
        if identifier not in self.threat_profiles:
            self.threat_profiles[identifier] = ThreatProfile(
                identifier=identifier,
                identifier_type=identifier_type,
                threat_level=ThreatLevel.LOW,
                first_seen=attempt.timestamp,
                last_seen=attempt.timestamp,
                total_attempts=0,
                failed_attempts=0,
                success_rate=0.0,
                attack_patterns=set()
            )

        profile = self.threat_profiles[identifier]
        profile.last_seen = attempt.timestamp
        profile.total_attempts += 1

        if not attempt.success:
            profile.failed_attempts += 1

        # Update success rate
        if profile.total_attempts > 0:
            profile.success_rate = 1.0 - (profile.failed_attempts / profile.total_attempts)

        # Update sets
        if attempt.geolocation:
            profile.geographical_spread.add(attempt.geolocation)
        profile.user_agents.add(attempt.user_agent)
        profile.targeted_users.add(attempt.username)

        # Get relevant attempts for pattern detection
        relevant_attempts = [
            a for a in self.login_attempts[-50:]  # Last 50 attempts
            if (identifier_type == "ip" and a.ip_address == identifier) or
               (identifier_type == "user" and a.username == identifier)
        ]

        # Detect attack patterns
        if self.config.enable_pattern_detection:
            detected_patterns = self._detect_attack_patterns(relevant_attempts)
            profile.attack_patterns.update(detected_patterns)

        # Update threat level
        profile.threat_level = self._assess_threat_level(profile)

        return profile

    async def check_attempt_allowed(
        self,
        request: Request,
        username: str,
        password_length: int = 0
    ) -> Tuple[bool, Dict[str, Any]]:
        """Check if login attempt should be allowed."""
        async with self.lock:
            current_time = time.time()
            ip_address = self._get_client_ip(request)

            # Check if IP is blocked
            if ip_address in self.blocked_identifiers:
                if current_time < self.blocked_identifiers[ip_address]:
                    remaining = self.blocked_identifiers[ip_address] - current_time
                    logger.warning(f"Blocked IP attempted login: {ip_address} (remaining: {remaining:.0f}s)")
                    return False, {
                        "error": "ip_blocked",
                        "reason": "IP address is temporarily blocked due to suspicious activity",
                        "blocked_until": datetime.fromtimestamp(self.blocked_identifiers[ip_address]).isoformat(),
                        "retry_after": int(remaining) + 1
                    }
                else:
                    # Block expired
                    del self.blocked_identifiers[ip_address]

            # Check if user is blocked
            if username in self.blocked_identifiers:
                if current_time < self.blocked_identifiers[username]:
                    remaining = self.blocked_identifiers[username] - current_time
                    logger.warning(f"Blocked user attempted login: {username} (remaining: {remaining:.0f}s)")
                    return False, {
                        "error": "user_blocked",
                        "reason": "User account is temporarily blocked due to suspicious activity",
                        "blocked_until": datetime.fromtimestamp(self.blocked_identifiers[username]).isoformat(),
                        "retry_after": int(remaining) + 1
                    }
                else:
                    # Block expired
                    del self.blocked_identifiers[username]

            # Check rate limits
            window_start = current_time - self.config.time_window_seconds

            # IP-based rate limiting
            ip_attempts = [
                a for a in self.login_attempts
                if a.ip_address == ip_address and a.timestamp > window_start
            ]

            if len(ip_attempts) >= self.config.max_attempts_per_ip:
                logger.warning(f"IP rate limit exceeded: {ip_address} ({len(ip_attempts)} attempts)")
                return False, {
                    "error": "rate_limit_exceeded",
                    "reason": f"Too many login attempts from this IP address",
                    "attempts": len(ip_attempts),
                    "max_attempts": self.config.max_attempts_per_ip,
                    "window_seconds": self.config.time_window_seconds
                }

            # User-based rate limiting
            user_attempts = [
                a for a in self.login_attempts
                if a.username == username and a.timestamp > window_start
            ]

            if len(user_attempts) >= self.config.max_attempts_per_user:
                logger.warning(f"User rate limit exceeded: {username} ({len(user_attempts)} attempts)")
                return False, {
                    "error": "rate_limit_exceeded",
                    "reason": f"Too many login attempts for this user",
                    "attempts": len(user_attempts),
                    "max_attempts": self.config.max_attempts_per_user,
                    "window_seconds": self.config.time_window_seconds
                }

            return True, {
                "ip_attempts_remaining": self.config.max_attempts_per_ip - len(ip_attempts),
                "user_attempts_remaining": self.config.max_attempts_per_user - len(user_attempts)
            }

    async def record_attempt(
        self,
        request: Request,
        username: str,
        success: bool,
        password_length: int = 0,
        response_time: float = 0.0
    ) -> Dict[str, Any]:
        """Record a login attempt and update threat profiles."""
        async with self.lock:
            current_time = time.time()
            ip_address = self._get_client_ip(request)
            user_agent = request.headers.get("User-Agent", "unknown")
            geolocation = self._get_geolocation(ip_address)

            # Create attempt record
            attempt = LoginAttempt(
                timestamp=current_time,
                username=username,
                ip_address=ip_address,
                user_agent=user_agent,
                success=success,
                password_length=password_length,
                response_time=response_time,
                geolocation=geolocation
            )

            # Add to attempts list
            self.login_attempts.append(attempt)

            # Keep only recent attempts (last 24 hours)
            cutoff_time = current_time - 86400
            self.login_attempts = [a for a in self.login_attempts if a.timestamp > cutoff_time]

            # Update statistics
            self.stats["total_attempts"] += 1
            if not success:
                # Update threat profiles
                ip_profile = self._update_threat_profile(ip_address, "ip", attempt)
                user_profile = self._update_threat_profile(username, "user", attempt)

                # Check for automatic blocking
                profiles_to_check = [ip_profile, user_profile]

                for profile in profiles_to_check:
                    if (self.config.auto_block_critical_threats and
                        profile.threat_level == ThreatLevel.CRITICAL and
                        profile.identifier not in self.blocked_identifiers):

                        # Calculate block duration
                        block_duration = self._calculate_block_duration(profile.escalation_count)
                        block_until = current_time + block_duration

                        self.blocked_identifiers[profile.identifier] = block_until
                        profile.escalation_count += 1

                        logger.critical(f"Auto-blocked {profile.identifier_type} due to critical threat: "
                                      f"{profile.identifier} for {block_duration}s")

                        self.stats["blocked_attempts"] += 1

                return {
                    "attempt_recorded": True,
                    "success": success,
                    "ip_threat_level": ip_profile.threat_level.value,
                    "user_threat_level": user_profile.threat_level.value,
                    "patterns_detected": list(ip_profile.attack_patterns.union(user_profile.attack_patterns)),
                    "geographical_locations": list(ip_profile.geographical_spread)
                }

            return {
                "attempt_recorded": True,
                "success": success
            }

    async def get_threat_assessment(self, identifier: str, identifier_type: str = "ip") -> Dict[str, Any]:
        """Get threat assessment for an identifier."""
        async with self.lock:
            if identifier not in self.threat_profiles:
                return {
                    "threat_level": ThreatLevel.LOW.value,
                    "profile_exists": False
                }

            profile = self.threat_profiles[identifier]

            return {
                "identifier": identifier,
                "identifier_type": profile.identifier_type,
                "threat_level": profile.threat_level.value,
                "total_attempts": profile.total_attempts,
                "failed_attempts": profile.failed_attempts,
                "success_rate": profile.success_rate,
                "attack_patterns": [pattern.value for pattern in profile.attack_patterns],
                "first_seen": datetime.fromtimestamp(profile.first_seen).isoformat(),
                "last_seen": datetime.fromtimestamp(profile.last_seen).isoformat(),
                "geographical_spread": list(profile.geographical_spread),
                "user_agents_count": len(profile.user_agents),
                "targeted_users_count": len(profile.targeted_users),
                "blocked": identifier in self.blocked_identifiers,
                "profile_exists": True
            }

    async def block_identifier(
        self,
        identifier: str,
        duration_seconds: int,
        reason: str = "Manual block"
    ) -> bool:
        """Manually block an identifier."""
        async with self.lock:
            current_time = time.time()
            block_until = current_time + duration_seconds

            self.blocked_identifiers[identifier] = block_until

            logger.info(f"Manually blocked {identifier} for {duration_seconds}s: {reason}")

            return True

    async def unblock_identifier(self, identifier: str) -> bool:
        """Manually unblock an identifier."""
        async with self.lock:
            if identifier in self.blocked_identifiers:
                del self.blocked_identifiers[identifier]
                logger.info(f"Manually unblocked {identifier}")
                return True
            return False

    async def get_statistics(self) -> Dict[str, Any]:
        """Get protection statistics."""
        async with self.lock:
            current_time = time.time()

            # Recent activity (last hour)
            hour_ago = current_time - 3600
            recent_attempts = [a for a in self.login_attempts if a.timestamp > hour_ago]
            recent_failed = [a for a in recent_attempts if not a.success]

            # Blocked identifiers
            active_blocks = {
                identifier: block_until for identifier, block_until in self.blocked_identifiers.items()
                if block_until > current_time
            }

            # Threat levels
            threat_counts = {level.value: 0 for level in ThreatLevel}
            for profile in self.threat_profiles.values():
                threat_counts[profile.threat_level.value] += 1

            return {
                "total_attempts": self.stats["total_attempts"],
                "blocked_attempts": self.stats["blocked_attempts"],
                "patterns_detected": self.stats["patterns_detected"],
                "threats_identified": self.stats["threats_identified"],
                "recent_attempts_hour": len(recent_attempts),
                "recent_failed_hour": len(recent_failed),
                "active_blocks": len(active_blocks),
                "threat_profiles": len(self.threat_profiles),
                "threat_level_distribution": threat_counts,
                "attack_patterns_detected": len(set().union(*[p.attack_patterns for p in self.threat_profiles.values()])),
                "geographical_coverage": len(set().union(*[p.geographical_spread for p in self.threat_profiles.values()]))
            }

    async def cleanup_expired_data(self) -> Dict[str, int]:
        """Clean up expired data."""
        async with self.lock:
            current_time = time.time()
            cleanup_stats = {"attempts": 0, "blocks": 0, "profiles": 0}

            # Clean up old attempts (older than 24 hours)
            old_count = len(self.login_attempts)
            cutoff_time = current_time - 86400
            self.login_attempts = [a for a in self.login_attempts if a.timestamp > cutoff_time]
            cleanup_stats["attempts"] = old_count - len(self.login_attempts)

            # Clean up expired blocks
            expired_blocks = [
                identifier for identifier, block_until in self.blocked_identifiers.items()
                if block_until <= current_time
            ]
            for identifier in expired_blocks:
                del self.blocked_identifiers[identifier]
            cleanup_stats["blocks"] = len(expired_blocks)

            # Clean up old threat profiles (no activity for 7 days)
            week_ago = current_time - (7 * 86400)
            old_profiles = [
                identifier for identifier, profile in self.threat_profiles.items()
                if profile.last_seen < week_ago
            ]
            for identifier in old_profiles:
                del self.threat_profiles[identifier]
            cleanup_stats["profiles"] = len(old_profiles)

            if sum(cleanup_stats.values()) > 0:
                logger.info(f"Cleaned up expired data: {cleanup_stats}")

            return cleanup_stats


# Global brute force protection instance
_brute_force_protection: Optional[BruteForceProtection] = None


def get_brute_force_protection() -> BruteForceProtection:
    """Get the global brute force protection instance."""
    global _brute_force_protection
    if _brute_force_protection is None:
        _brute_force_protection = BruteForceProtection()
    return _brute_force_protection


async def check_brute_force_protection(request: Request, username: str) -> None:
    """FastAPI dependency for brute force protection."""
    protection = get_brute_force_protection()
    allowed, info = await protection.check_attempt_allowed(request, username)

    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "message": "Login attempt blocked by security system",
                **info
            },
            headers={"Retry-After": str(info.get("retry_after", 300))}
        )
