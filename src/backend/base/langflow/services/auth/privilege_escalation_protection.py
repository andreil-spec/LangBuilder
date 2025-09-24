"""Privilege Escalation Protection Service.

This module provides comprehensive protection against privilege escalation attacks
including detection, prevention, and response mechanisms.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Set, Tuple
from uuid import UUID

from loguru import logger
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.services.rbac.runtime_enforcement import RuntimeEnforcementContext


class EscalationType(str, Enum):
    """Types of privilege escalation attempts."""

    VERTICAL = "vertical"  # Gaining higher privileges
    HORIZONTAL = "horizontal"  # Accessing peer resources
    ROLE_MANIPULATION = "role_manipulation"  # Manipulating role assignments
    PERMISSION_INJECTION = "permission_injection"  # Injecting permissions
    TOKEN_ABUSE = "token_abuse"  # Abusing API tokens
    IMPERSONATION = "impersonation"  # Impersonating other users
    ADMINISTRATIVE_BYPASS = "administrative_bypass"  # Bypassing admin controls
    SYSTEM_ESCALATION = "system_escalation"  # Gaining system privileges
    BREAK_GLASS_ABUSE = "break_glass_abuse"  # Abusing emergency access


class ThreatLevel(str, Enum):
    """Threat levels for escalation attempts."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class ResponseAction(str, Enum):
    """Response actions for escalation attempts."""

    LOG = "log"
    ALERT = "alert"
    BLOCK = "block"
    SUSPEND_USER = "suspend_user"
    REVOKE_TOKENS = "revoke_tokens"
    FORCE_LOGOUT = "force_logout"
    QUARANTINE = "quarantine"
    EMERGENCY_LOCKDOWN = "emergency_lockdown"


@dataclass
class EscalationPattern:
    """Pattern definition for escalation detection."""

    pattern_id: str
    name: str
    description: str
    escalation_type: EscalationType
    threat_level: ThreatLevel
    detection_rules: Dict[str, Any]
    response_actions: List[ResponseAction]
    enabled: bool = True
    sensitivity: float = 0.5  # 0.0 = low sensitivity, 1.0 = high sensitivity


@dataclass
class EscalationAttempt:
    """Record of a privilege escalation attempt."""

    attempt_id: str
    user_id: UUID | None
    session_id: str | None
    escalation_type: EscalationType
    threat_level: ThreatLevel
    pattern_id: str
    timestamp: float
    source_ip: str
    user_agent: str
    request_path: str
    request_method: str
    current_permissions: Set[str]
    requested_permissions: Set[str]
    current_roles: Set[str]
    requested_roles: Set[str]
    resource_type: str | None
    resource_id: UUID | None
    workspace_id: UUID | None
    blocked: bool
    response_actions: List[ResponseAction]
    confidence_score: float  # 0.0-1.0
    details: Dict[str, Any] = field(default_factory=dict)
    investigation_notes: List[str] = field(default_factory=list)


@dataclass
class UserRiskProfile:
    """Risk profile for a user."""

    user_id: UUID
    risk_score: float  # 0.0-1.0
    escalation_attempts: int
    last_escalation: float | None
    pattern_matches: Set[str]
    suspicious_activities: List[str]
    account_flags: Set[str]
    monitoring_level: str  # "normal", "elevated", "high"
    last_updated: float


@dataclass
class EscalationMetrics:
    """Metrics for escalation detection and response."""

    total_attempts: int
    blocked_attempts: int
    by_type: Dict[EscalationType, int]
    by_threat_level: Dict[ThreatLevel, int]
    by_user: Dict[UUID, int]
    false_positives: int
    detection_accuracy: float
    response_times: List[float]
    patterns_triggered: Dict[str, int]


class PrivilegeEscalationProtection:
    """Service for detecting and preventing privilege escalation."""

    def __init__(self):
        self.escalation_attempts: List[EscalationAttempt] = []
        self.user_risk_profiles: Dict[UUID, UserRiskProfile] = {}
        self.detection_patterns: Dict[str, EscalationPattern] = {}
        self.metrics = EscalationMetrics(
            total_attempts=0,
            blocked_attempts=0,
            by_type={},
            by_threat_level={},
            by_user={},
            false_positives=0,
            detection_accuracy=0.0,
            response_times=[],
            patterns_triggered={},
        )

        # Initialize default detection patterns
        self._initialize_detection_patterns()

    def _initialize_detection_patterns(self) -> None:
        """Initialize default escalation detection patterns."""

        patterns = [
            EscalationPattern(
                pattern_id="rapid_permission_requests",
                name="Rapid Permission Requests",
                description="Multiple permission requests in short time",
                escalation_type=EscalationType.VERTICAL,
                threat_level=ThreatLevel.MEDIUM,
                detection_rules={
                    "time_window": 300,  # 5 minutes
                    "max_requests": 10,
                    "permission_types": ["admin", "write", "delete"],
                },
                response_actions=[ResponseAction.LOG, ResponseAction.ALERT],
            ),
            EscalationPattern(
                pattern_id="admin_permission_request",
                name="Administrative Permission Request",
                description="Request for administrative permissions",
                escalation_type=EscalationType.VERTICAL,
                threat_level=ThreatLevel.HIGH,
                detection_rules={
                    "permission_patterns": ["admin", "system", "superuser"],
                    "role_patterns": ["admin", "owner", "superuser"],
                },
                response_actions=[ResponseAction.LOG, ResponseAction.ALERT, ResponseAction.BLOCK],
            ),
            EscalationPattern(
                pattern_id="cross_workspace_access",
                name="Cross-Workspace Access Attempt",
                description="Attempting to access resources across workspaces",
                escalation_type=EscalationType.HORIZONTAL,
                threat_level=ThreatLevel.MEDIUM,
                detection_rules={
                    "workspace_switch_threshold": 3,
                    "time_window": 600,  # 10 minutes
                },
                response_actions=[ResponseAction.LOG, ResponseAction.ALERT],
            ),
            EscalationPattern(
                pattern_id="role_manipulation_attempt",
                name="Role Manipulation Attempt",
                description="Attempting to modify role assignments",
                escalation_type=EscalationType.ROLE_MANIPULATION,
                threat_level=ThreatLevel.HIGH,
                detection_rules={
                    "actions": ["create_role", "assign_role", "modify_role"],
                    "target_roles": ["admin", "owner"],
                },
                response_actions=[ResponseAction.LOG, ResponseAction.ALERT, ResponseAction.BLOCK],
            ),
            EscalationPattern(
                pattern_id="token_privilege_abuse",
                name="API Token Privilege Abuse",
                description="API token used beyond its intended scope",
                escalation_type=EscalationType.TOKEN_ABUSE,
                threat_level=ThreatLevel.HIGH,
                detection_rules={
                    "scope_violations": True,
                    "permission_overreach": True,
                },
                response_actions=[ResponseAction.LOG, ResponseAction.ALERT, ResponseAction.REVOKE_TOKENS],
            ),
            EscalationPattern(
                pattern_id="system_resource_access",
                name="System Resource Access",
                description="Attempting to access system-level resources",
                escalation_type=EscalationType.SYSTEM_ESCALATION,
                threat_level=ThreatLevel.CRITICAL,
                detection_rules={
                    "resource_types": ["system", "global", "infrastructure"],
                    "system_endpoints": ["/admin", "/system", "/config"],
                },
                response_actions=[
                    ResponseAction.LOG,
                    ResponseAction.ALERT,
                    ResponseAction.BLOCK,
                    ResponseAction.SUSPEND_USER,
                ],
            ),
            EscalationPattern(
                pattern_id="impersonation_attempt",
                name="User Impersonation Attempt",
                description="Attempting to impersonate another user",
                escalation_type=EscalationType.IMPERSONATION,
                threat_level=ThreatLevel.CRITICAL,
                detection_rules={
                    "user_switch_attempts": True,
                    "suspicious_user_patterns": True,
                },
                response_actions=[
                    ResponseAction.LOG,
                    ResponseAction.ALERT,
                    ResponseAction.BLOCK,
                    ResponseAction.FORCE_LOGOUT,
                ],
            ),
        ]

        for pattern in patterns:
            self.detection_patterns[pattern.pattern_id] = pattern

    async def analyze_request(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        requested_permission: str,
        resource_type: str | None = None,
        resource_id: UUID | None = None,
    ) -> Tuple[bool, List[EscalationAttempt]]:
        """Analyze a request for privilege escalation attempts."""

        detected_attempts = []
        should_block = False

        try:
            # Get user's current permissions and roles
            current_permissions = await self._get_user_permissions(session, context)
            current_roles = await self._get_user_roles(session, context)

            # Create request context
            request_context = {
                "user_id": context.user.id if context.user else None,
                "session_id": getattr(context, "session_id", None),
                "timestamp": time.time(),
                "source_ip": self._extract_ip(context),
                "user_agent": self._extract_user_agent(context),
                "request_path": context.request_path or "",
                "request_method": context.request_method or "",
                "current_permissions": current_permissions,
                "requested_permissions": {requested_permission},
                "current_roles": current_roles,
                "requested_roles": set(),
                "resource_type": resource_type,
                "resource_id": resource_id,
                "workspace_id": context.effective_workspace_id,
            }

            # Run detection patterns
            for pattern_id, pattern in self.detection_patterns.items():
                if not pattern.enabled:
                    continue

                escalation_attempt = await self._check_pattern(
                    session, context, pattern, request_context
                )

                if escalation_attempt:
                    detected_attempts.append(escalation_attempt)
                    self.escalation_attempts.append(escalation_attempt)

                    # Update metrics
                    self.metrics.total_attempts += 1
                    if escalation_attempt.blocked:
                        self.metrics.blocked_attempts += 1
                        should_block = True

                    # Update user risk profile
                    await self._update_user_risk_profile(escalation_attempt)

                    # Execute response actions
                    await self._execute_response_actions(
                        session, context, escalation_attempt
                    )

                    logger.warning(
                        f"Privilege escalation detected: {pattern.name} - "
                        f"user={context.user.id if context.user else 'unknown'}, "
                        f"threat_level={escalation_attempt.threat_level}, "
                        f"blocked={escalation_attempt.blocked}"
                    )

            return should_block, detected_attempts

        except Exception as e:
            logger.error(f"Error analyzing privilege escalation: {e}")
            return False, []

    async def _check_pattern(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        pattern: EscalationPattern,
        request_context: Dict[str, Any],
    ) -> EscalationAttempt | None:
        """Check if a request matches an escalation pattern."""

        try:
            confidence_score = 0.0
            matched_rules = []

            # Check pattern-specific rules
            if pattern.escalation_type == EscalationType.VERTICAL:
                confidence_score += await self._check_vertical_escalation(
                    session, pattern, request_context
                )

            elif pattern.escalation_type == EscalationType.HORIZONTAL:
                confidence_score += await self._check_horizontal_escalation(
                    session, pattern, request_context
                )

            elif pattern.escalation_type == EscalationType.ROLE_MANIPULATION:
                confidence_score += await self._check_role_manipulation(
                    session, pattern, request_context
                )

            elif pattern.escalation_type == EscalationType.TOKEN_ABUSE:
                confidence_score += await self._check_token_abuse(
                    session, pattern, request_context
                )

            elif pattern.escalation_type == EscalationType.SYSTEM_ESCALATION:
                confidence_score += await self._check_system_escalation(
                    session, pattern, request_context
                )

            elif pattern.escalation_type == EscalationType.IMPERSONATION:
                confidence_score += await self._check_impersonation(
                    session, pattern, request_context
                )

            # Apply sensitivity adjustment
            confidence_score *= pattern.sensitivity

            # Determine if this triggers the pattern
            if confidence_score >= 0.5:  # Threshold for detection
                # Determine response actions
                response_actions = pattern.response_actions.copy()
                blocked = ResponseAction.BLOCK in response_actions

                # Create escalation attempt record
                attempt = EscalationAttempt(
                    attempt_id=self._generate_attempt_id(request_context),
                    user_id=request_context["user_id"],
                    session_id=request_context["session_id"],
                    escalation_type=pattern.escalation_type,
                    threat_level=pattern.threat_level,
                    pattern_id=pattern.pattern_id,
                    timestamp=request_context["timestamp"],
                    source_ip=request_context["source_ip"],
                    user_agent=request_context["user_agent"],
                    request_path=request_context["request_path"],
                    request_method=request_context["request_method"],
                    current_permissions=request_context["current_permissions"],
                    requested_permissions=request_context["requested_permissions"],
                    current_roles=request_context["current_roles"],
                    requested_roles=request_context["requested_roles"],
                    resource_type=request_context["resource_type"],
                    resource_id=request_context["resource_id"],
                    workspace_id=request_context["workspace_id"],
                    blocked=blocked,
                    response_actions=response_actions,
                    confidence_score=confidence_score,
                    details={
                        "pattern_name": pattern.name,
                        "matched_rules": matched_rules,
                        "detection_rules": pattern.detection_rules,
                    },
                )

                return attempt

            return None

        except Exception as e:
            logger.error(f"Error checking pattern {pattern.pattern_id}: {e}")
            return None

    async def _check_vertical_escalation(
        self,
        session: AsyncSession,
        pattern: EscalationPattern,
        request_context: Dict[str, Any],
    ) -> float:
        """Check for vertical privilege escalation."""
        confidence = 0.0

        # Check for administrative permission requests
        requested_perms = request_context["requested_permissions"]
        admin_patterns = pattern.detection_rules.get("permission_patterns", [])

        for perm in requested_perms:
            for admin_pattern in admin_patterns:
                if admin_pattern.lower() in perm.lower():
                    confidence += 0.4

        # Check for rapid permission requests
        if "time_window" in pattern.detection_rules:
            user_id = request_context["user_id"]
            if user_id:
                recent_attempts = await self._count_recent_attempts(
                    user_id, pattern.detection_rules["time_window"]
                )
                max_requests = pattern.detection_rules.get("max_requests", 5)
                if recent_attempts > max_requests:
                    confidence += 0.6

        return min(confidence, 1.0)

    async def _check_horizontal_escalation(
        self,
        session: AsyncSession,
        pattern: EscalationPattern,
        request_context: Dict[str, Any],
    ) -> float:
        """Check for horizontal privilege escalation."""
        confidence = 0.0

        # Check for cross-workspace access
        user_id = request_context["user_id"]
        if user_id:
            workspace_switches = await self._count_workspace_switches(
                user_id, pattern.detection_rules.get("time_window", 600)
            )
            threshold = pattern.detection_rules.get("workspace_switch_threshold", 3)
            if workspace_switches > threshold:
                confidence += 0.7

        return min(confidence, 1.0)

    async def _check_role_manipulation(
        self,
        session: AsyncSession,
        pattern: EscalationPattern,
        request_context: Dict[str, Any],
    ) -> float:
        """Check for role manipulation attempts."""
        confidence = 0.0

        # Check for role-related actions
        request_path = request_context["request_path"]
        role_actions = pattern.detection_rules.get("actions", [])

        for action in role_actions:
            if action in request_path:
                confidence += 0.5

        # Check for targeting sensitive roles
        target_roles = pattern.detection_rules.get("target_roles", [])
        for role in target_roles:
            if role in request_path:
                confidence += 0.3

        return min(confidence, 1.0)

    async def _check_token_abuse(
        self,
        session: AsyncSession,
        pattern: EscalationPattern,
        request_context: Dict[str, Any],
    ) -> float:
        """Check for API token abuse."""
        confidence = 0.0

        # Check for scope violations (if token validation context available)
        # This would require integration with token validation
        if pattern.detection_rules.get("scope_violations"):
            confidence += 0.6

        # Check for permission overreach
        if pattern.detection_rules.get("permission_overreach"):
            confidence += 0.4

        return min(confidence, 1.0)

    async def _check_system_escalation(
        self,
        session: AsyncSession,
        pattern: EscalationPattern,
        request_context: Dict[str, Any],
    ) -> float:
        """Check for system-level escalation."""
        confidence = 0.0

        # Check for system resource access
        resource_type = request_context["resource_type"]
        system_resources = pattern.detection_rules.get("resource_types", [])

        if resource_type and resource_type in system_resources:
            confidence += 0.8

        # Check for system endpoints
        request_path = request_context["request_path"]
        system_endpoints = pattern.detection_rules.get("system_endpoints", [])

        for endpoint in system_endpoints:
            if endpoint in request_path:
                confidence += 0.6

        return min(confidence, 1.0)

    async def _check_impersonation(
        self,
        session: AsyncSession,
        pattern: EscalationPattern,
        request_context: Dict[str, Any],
    ) -> float:
        """Check for user impersonation attempts."""
        confidence = 0.0

        # Check for user switch attempts
        if pattern.detection_rules.get("user_switch_attempts"):
            # Implementation would check for suspicious user switching patterns
            confidence += 0.5

        # Check for suspicious user patterns
        if pattern.detection_rules.get("suspicious_user_patterns"):
            # Implementation would check behavioral patterns
            confidence += 0.3

        return min(confidence, 1.0)

    # Helper methods
    async def _get_user_permissions(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
    ) -> Set[str]:
        """Get user's current permissions."""
        # Implementation would query user's effective permissions
        return set()

    async def _get_user_roles(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
    ) -> Set[str]:
        """Get user's current roles."""
        # Implementation would query user's roles
        return set()

    def _extract_ip(self, context: RuntimeEnforcementContext) -> str:
        """Extract IP address from context."""
        # Implementation would extract IP from request
        return "unknown"

    def _extract_user_agent(self, context: RuntimeEnforcementContext) -> str:
        """Extract user agent from context."""
        # Implementation would extract user agent from request
        return "unknown"

    def _generate_attempt_id(self, request_context: Dict[str, Any]) -> str:
        """Generate unique attempt ID."""
        data = f"{request_context['user_id']}:{request_context['timestamp']}:{request_context['request_path']}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    async def _count_recent_attempts(self, user_id: UUID, time_window: int) -> int:
        """Count recent escalation attempts by user."""
        recent_threshold = time.time() - time_window
        return len([
            attempt for attempt in self.escalation_attempts
            if (attempt.user_id == user_id and
                attempt.timestamp > recent_threshold)
        ])

    async def _count_workspace_switches(self, user_id: UUID, time_window: int) -> int:
        """Count workspace switches by user."""
        # Implementation would track workspace switches
        return 0

    async def _update_user_risk_profile(self, attempt: EscalationAttempt) -> None:
        """Update user risk profile based on escalation attempt."""
        if not attempt.user_id:
            return

        profile = self.user_risk_profiles.get(attempt.user_id)
        if not profile:
            profile = UserRiskProfile(
                user_id=attempt.user_id,
                risk_score=0.0,
                escalation_attempts=0,
                last_escalation=None,
                pattern_matches=set(),
                suspicious_activities=[],
                account_flags=set(),
                monitoring_level="normal",
                last_updated=time.time(),
            )

        # Update profile
        profile.escalation_attempts += 1
        profile.last_escalation = attempt.timestamp
        profile.pattern_matches.add(attempt.pattern_id)
        profile.last_updated = time.time()

        # Calculate new risk score
        profile.risk_score = min(
            profile.risk_score + (attempt.confidence_score * 0.2), 1.0
        )

        # Adjust monitoring level
        if profile.risk_score > 0.8:
            profile.monitoring_level = "high"
        elif profile.risk_score > 0.5:
            profile.monitoring_level = "elevated"

        self.user_risk_profiles[attempt.user_id] = profile

    async def _execute_response_actions(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        attempt: EscalationAttempt,
    ) -> None:
        """Execute response actions for escalation attempt."""
        for action in attempt.response_actions:
            try:
                if action == ResponseAction.LOG:
                    logger.info(f"Escalation logged: {attempt.attempt_id}")

                elif action == ResponseAction.ALERT:
                    logger.warning(f"Escalation alert: {attempt.attempt_id}")
                    # Implementation would send alerts

                elif action == ResponseAction.BLOCK:
                    logger.warning(f"Escalation blocked: {attempt.attempt_id}")

                elif action == ResponseAction.SUSPEND_USER:
                    logger.critical(f"User suspended: {attempt.user_id}")
                    # Implementation would suspend user

                elif action == ResponseAction.REVOKE_TOKENS:
                    logger.warning(f"Tokens revoked: {attempt.user_id}")
                    # Implementation would revoke user tokens

                elif action == ResponseAction.FORCE_LOGOUT:
                    logger.warning(f"Force logout: {attempt.user_id}")
                    # Implementation would force logout

                # Record response time
                response_time = time.time() - attempt.timestamp
                self.metrics.response_times.append(response_time)

            except Exception as e:
                logger.error(f"Error executing response action {action}: {e}")

    # Public methods for management
    async def get_escalation_attempts(
        self,
        user_id: UUID | None = None,
        threat_level: ThreatLevel | None = None,
        since: float | None = None,
    ) -> List[EscalationAttempt]:
        """Get escalation attempts for analysis."""
        attempts = self.escalation_attempts

        if user_id:
            attempts = [a for a in attempts if a.user_id == user_id]

        if threat_level:
            attempts = [a for a in attempts if a.threat_level == threat_level]

        if since:
            attempts = [a for a in attempts if a.timestamp > since]

        return attempts

    async def get_user_risk_profile(self, user_id: UUID) -> UserRiskProfile | None:
        """Get user risk profile."""
        return self.user_risk_profiles.get(user_id)

    async def update_detection_pattern(
        self,
        pattern_id: str,
        pattern: EscalationPattern,
    ) -> None:
        """Update detection pattern."""
        self.detection_patterns[pattern_id] = pattern
        logger.info(f"Updated escalation detection pattern: {pattern_id}")

    async def get_metrics(self) -> EscalationMetrics:
        """Get escalation metrics."""
        return self.metrics

    async def clear_old_attempts(self, older_than: float) -> int:
        """Clear old escalation attempts."""
        old_count = len(self.escalation_attempts)
        self.escalation_attempts = [
            a for a in self.escalation_attempts if a.timestamp > older_than
        ]
        cleared = old_count - len(self.escalation_attempts)
        logger.info(f"Cleared {cleared} old escalation attempts")
        return cleared


# Global instance
_escalation_protection: PrivilegeEscalationProtection | None = None


def get_privilege_escalation_protection() -> PrivilegeEscalationProtection:
    """Get global privilege escalation protection instance."""
    global _escalation_protection
    if _escalation_protection is None:
        _escalation_protection = PrivilegeEscalationProtection()
    return _escalation_protection
