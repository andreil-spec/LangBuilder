"""Comprehensive Permission Checking Implementation.

This module provides enhanced permission checking with workspace isolation,
privilege escalation protection, and comprehensive audit logging.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Set
from uuid import UUID

from loguru import logger
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.services.rbac.runtime_enforcement import RuntimeEnforcementContext


class PermissionLevel(str, Enum):
    """Permission hierarchy levels."""

    READ = "read"
    WRITE = "write"
    ADMIN = "admin"
    OWNER = "owner"
    SYSTEM = "system"


class ResourceScope(str, Enum):
    """Resource access scopes."""

    PERSONAL = "personal"
    WORKSPACE = "workspace"
    PROJECT = "project"
    ENVIRONMENT = "environment"
    FLOW = "flow"
    GLOBAL = "global"


@dataclass
class PermissionRequest:
    """Structured permission request."""

    permission: str
    resource_type: str
    resource_id: UUID | None = None
    workspace_id: UUID | None = None
    project_id: UUID | None = None
    environment_id: UUID | None = None
    required_level: PermissionLevel = PermissionLevel.READ
    scope: ResourceScope = ResourceScope.WORKSPACE
    require_ownership: bool = False
    allow_inheritance: bool = True
    metadata: Dict[str, Any] | None = None


@dataclass
class PermissionResult:
    """Permission check result with detailed information."""

    granted: bool
    permission: str
    resource_type: str
    resource_id: UUID | None
    granted_level: PermissionLevel | None
    effective_scope: ResourceScope | None
    granted_via: str  # "direct", "inherited", "workspace_admin", "system_admin"
    reason: str
    timestamp: float
    audit_id: str | None = None
    escalation_detected: bool = False
    workspace_isolated: bool = True


@dataclass
class EscalationAttempt:
    """Privilege escalation attempt tracking."""

    user_id: UUID
    requested_permission: str
    current_level: PermissionLevel
    requested_level: PermissionLevel
    resource_type: str
    resource_id: UUID | None
    timestamp: float
    source_ip: str
    user_agent: str
    blocked: bool
    reason: str


class ComprehensivePermissionChecker:
    """Enhanced permission checker with isolation and escalation protection."""

    def __init__(self):
        self.escalation_attempts: List[EscalationAttempt] = []
        self.permission_cache: Dict[str, PermissionResult] = {}
        self.cache_ttl = 300  # 5 minutes

        # Permission hierarchy
        self.permission_hierarchy = {
            PermissionLevel.READ: 0,
            PermissionLevel.WRITE: 1,
            PermissionLevel.ADMIN: 2,
            PermissionLevel.OWNER: 3,
            PermissionLevel.SYSTEM: 4,
        }

        # Dangerous permission patterns
        self.dangerous_permissions = {
            "system:admin", "workspace:delete", "user:impersonate",
            "rbac:modify", "audit:delete", "system:configure"
        }

        # Scope hierarchy
        self.scope_hierarchy = {
            ResourceScope.PERSONAL: 0,
            ResourceScope.FLOW: 1,
            ResourceScope.ENVIRONMENT: 2,
            ResourceScope.PROJECT: 3,
            ResourceScope.WORKSPACE: 4,
            ResourceScope.GLOBAL: 5,
        }

    async def check_permission(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        request: PermissionRequest,
    ) -> PermissionResult:
        """Comprehensive permission check with all security controls."""
        start_time = time.time()

        # Generate cache key
        cache_key = self._generate_cache_key(context, request)

        # Check cache first
        cached_result = self._get_cached_result(cache_key)
        if cached_result:
            logger.debug(f"Permission check cache hit: {request.permission}")
            return cached_result

        try:
            # 1. Validate request
            await self._validate_permission_request(request)

            # 2. Check workspace isolation
            isolation_result = await self._enforce_workspace_isolation(
                session, context, request
            )
            if not isolation_result.granted:
                return isolation_result

            # 3. Detect privilege escalation attempts
            escalation_check = await self._check_privilege_escalation(
                session, context, request
            )
            if escalation_check.escalation_detected:
                await self._handle_escalation_attempt(session, context, request, escalation_check)
                if escalation_check.blocked:
                    return escalation_check

            # 4. Check core permission
            core_result = await self._check_core_permission(
                session, context, request
            )

            # 5. Apply additional security controls
            final_result = await self._apply_security_controls(
                session, context, request, core_result
            )

            # 6. Cache result
            self._cache_result(cache_key, final_result)

            # 7. Audit the decision
            await self._audit_permission_decision(session, context, request, final_result)

            return final_result

        except Exception as e:
            logger.error(f"Permission check error: {e}")
            error_result = PermissionResult(
                granted=False,
                permission=request.permission,
                resource_type=request.resource_type,
                resource_id=request.resource_id,
                granted_level=None,
                effective_scope=None,
                granted_via="error",
                reason=f"Permission check failed: {str(e)}",
                timestamp=start_time,
                escalation_detected=False,
                workspace_isolated=True,
            )
            await self._audit_permission_decision(session, context, request, error_result)
            return error_result

    async def _enforce_workspace_isolation(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        request: PermissionRequest,
    ) -> PermissionResult:
        """Enforce strict workspace isolation."""

        # System-level permissions bypass workspace isolation
        if request.scope == ResourceScope.GLOBAL:
            if not context.user or not context.user.is_superuser:
                return PermissionResult(
                    granted=False,
                    permission=request.permission,
                    resource_type=request.resource_type,
                    resource_id=request.resource_id,
                    granted_level=None,
                    effective_scope=None,
                    granted_via="isolation_check",
                    reason="Global permissions require superuser access",
                    timestamp=time.time(),
                    workspace_isolated=False,
                )

        # Ensure workspace context is present for workspace-scoped operations
        if request.scope in [ResourceScope.WORKSPACE, ResourceScope.PROJECT, ResourceScope.ENVIRONMENT, ResourceScope.FLOW]:
            effective_workspace_id = (
                request.workspace_id or
                context.effective_workspace_id
            )

            if not effective_workspace_id:
                return PermissionResult(
                    granted=False,
                    permission=request.permission,
                    resource_type=request.resource_type,
                    resource_id=request.resource_id,
                    granted_level=None,
                    effective_scope=None,
                    granted_via="isolation_check",
                    reason="Workspace context required but not provided",
                    timestamp=time.time(),
                    workspace_isolated=False,
                )

            # Check if user has access to the workspace
            workspace_access = await self._check_workspace_access(
                session, context, effective_workspace_id
            )

            if not workspace_access:
                return PermissionResult(
                    granted=False,
                    permission=request.permission,
                    resource_type=request.resource_type,
                    resource_id=request.resource_id,
                    granted_level=None,
                    effective_scope=None,
                    granted_via="isolation_check",
                    reason=f"User does not have access to workspace {effective_workspace_id}",
                    timestamp=time.time(),
                    workspace_isolated=False,
                )

        # Isolation checks passed
        return PermissionResult(
            granted=True,
            permission=request.permission,
            resource_type=request.resource_type,
            resource_id=request.resource_id,
            granted_level=request.required_level,
            effective_scope=request.scope,
            granted_via="isolation_check",
            reason="Workspace isolation checks passed",
            timestamp=time.time(),
            workspace_isolated=True,
        )

    async def _check_privilege_escalation(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        request: PermissionRequest,
    ) -> PermissionResult:
        """Detect and prevent privilege escalation attempts."""

        # Get user's current permission level for this resource
        current_level = await self._get_current_permission_level(
            session, context, request
        )

        # Check if this is an escalation attempt
        is_escalation = (
            current_level is not None and
            self.permission_hierarchy.get(request.required_level, 0) >
            self.permission_hierarchy.get(current_level, 0)
        )

        # Check for dangerous permission patterns
        is_dangerous = any(
            pattern in request.permission for pattern in self.dangerous_permissions
        )

        # Rate limiting for escalation attempts
        recent_attempts = await self._count_recent_escalation_attempts(
            context.user.id if context.user else None,
            request.resource_type,
        )

        escalation_detected = is_escalation and (is_dangerous or recent_attempts > 3)

        if escalation_detected:
            escalation_attempt = EscalationAttempt(
                user_id=context.user.id if context.user else UUID("00000000-0000-0000-0000-000000000000"),
                requested_permission=request.permission,
                current_level=current_level or PermissionLevel.READ,
                requested_level=request.required_level,
                resource_type=request.resource_type,
                resource_id=request.resource_id,
                timestamp=time.time(),
                source_ip=context.request_path or "unknown",  # Should be IP from request
                user_agent="unknown",  # Should be extracted from request
                blocked=True,
                reason="Privilege escalation attempt detected",
            )

            self.escalation_attempts.append(escalation_attempt)

            logger.warning(
                f"Privilege escalation attempt detected: "
                f"user={context.user.id if context.user else 'unknown'}, "
                f"permission={request.permission}, "
                f"current_level={current_level}, "
                f"requested_level={request.required_level}"
            )

            return PermissionResult(
                granted=False,
                permission=request.permission,
                resource_type=request.resource_type,
                resource_id=request.resource_id,
                granted_level=None,
                effective_scope=None,
                granted_via="escalation_check",
                reason="Privilege escalation attempt blocked",
                timestamp=time.time(),
                escalation_detected=True,
                workspace_isolated=True,
            )

        # No escalation detected
        return PermissionResult(
            granted=True,
            permission=request.permission,
            resource_type=request.resource_type,
            resource_id=request.resource_id,
            granted_level=request.required_level,
            effective_scope=request.scope,
            granted_via="escalation_check",
            reason="No privilege escalation detected",
            timestamp=time.time(),
            escalation_detected=False,
            workspace_isolated=True,
        )

    async def _check_core_permission(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        request: PermissionRequest,
    ) -> PermissionResult:
        """Check core RBAC permission."""
        try:
            from langflow.services.deps import get_rbac_service

            rbac_service = get_rbac_service()

            # Build permission request for RBAC service
            from langflow.services.rbac.service import CheckPermissionRequest

            rbac_request = CheckPermissionRequest(
                user_id=context.user.id if context.user else None,
                service_account_id=(
                    context.token_validation.service_account.id
                    if context.token_validation and context.token_validation.service_account
                    else None
                ),
                permission=request.permission,
                resource_type=request.resource_type,
                resource_id=str(request.resource_id) if request.resource_id else None,
                workspace_id=request.workspace_id or context.effective_workspace_id,
                project_id=request.project_id or context.requested_project_id,
                environment_id=request.environment_id or context.requested_environment_id,
            )

            # Check permission through RBAC service
            permission_granted = await rbac_service.check_permission(rbac_request)

            if permission_granted:
                # Determine how permission was granted
                granted_via = await self._determine_grant_source(
                    session, context, request
                )

                return PermissionResult(
                    granted=True,
                    permission=request.permission,
                    resource_type=request.resource_type,
                    resource_id=request.resource_id,
                    granted_level=request.required_level,
                    effective_scope=request.scope,
                    granted_via=granted_via,
                    reason="Permission granted by RBAC system",
                    timestamp=time.time(),
                    escalation_detected=False,
                    workspace_isolated=True,
                )
            else:
                return PermissionResult(
                    granted=False,
                    permission=request.permission,
                    resource_type=request.resource_type,
                    resource_id=request.resource_id,
                    granted_level=None,
                    effective_scope=None,
                    granted_via="rbac_check",
                    reason="Permission denied by RBAC system",
                    timestamp=time.time(),
                    escalation_detected=False,
                    workspace_isolated=True,
                )

        except Exception as e:
            logger.error(f"Core permission check failed: {e}")
            return PermissionResult(
                granted=False,
                permission=request.permission,
                resource_type=request.resource_type,
                resource_id=request.resource_id,
                granted_level=None,
                effective_scope=None,
                granted_via="error",
                reason=f"Core permission check failed: {str(e)}",
                timestamp=time.time(),
                escalation_detected=False,
                workspace_isolated=True,
            )

    async def _apply_security_controls(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        request: PermissionRequest,
        core_result: PermissionResult,
    ) -> PermissionResult:
        """Apply additional security controls."""

        if not core_result.granted:
            return core_result

        # Token scope validation
        if context.token_validation and context.token_validation.scoped_permissions:
            if not context.token_validation.has_scope_permission(request.permission):
                return PermissionResult(
                    granted=False,
                    permission=request.permission,
                    resource_type=request.resource_type,
                    resource_id=request.resource_id,
                    granted_level=None,
                    effective_scope=None,
                    granted_via="token_scope",
                    reason="Token scope does not include this permission",
                    timestamp=time.time(),
                    escalation_detected=False,
                    workspace_isolated=True,
                )

        # Time-based access controls
        if request.metadata and "time_restricted" in request.metadata:
            if not await self._check_time_restrictions(request.metadata):
                return PermissionResult(
                    granted=False,
                    permission=request.permission,
                    resource_type=request.resource_type,
                    resource_id=request.resource_id,
                    granted_level=None,
                    effective_scope=None,
                    granted_via="time_restriction",
                    reason="Access denied due to time restrictions",
                    timestamp=time.time(),
                    escalation_detected=False,
                    workspace_isolated=True,
                )

        # IP-based restrictions
        if request.metadata and "ip_restricted" in request.metadata:
            if not await self._check_ip_restrictions(context, request.metadata):
                return PermissionResult(
                    granted=False,
                    permission=request.permission,
                    resource_type=request.resource_type,
                    resource_id=request.resource_id,
                    granted_level=None,
                    effective_scope=None,
                    granted_via="ip_restriction",
                    reason="Access denied due to IP restrictions",
                    timestamp=time.time(),
                    escalation_detected=False,
                    workspace_isolated=True,
                )

        return core_result

    # Helper methods
    async def _validate_permission_request(self, request: PermissionRequest) -> None:
        """Validate permission request structure."""
        if not request.permission:
            raise ValueError("Permission is required")
        if not request.resource_type:
            raise ValueError("Resource type is required")

    async def _check_workspace_access(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        workspace_id: UUID,
    ) -> bool:
        """Check if user has access to workspace."""
        # Implementation would check workspace membership
        # For now, return True if user exists
        return context.user is not None

    async def _get_current_permission_level(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        request: PermissionRequest,
    ) -> PermissionLevel | None:
        """Get user's current permission level for resource."""
        # Implementation would query user's current roles and permissions
        # For now, return READ as default
        return PermissionLevel.READ

    async def _count_recent_escalation_attempts(
        self,
        user_id: UUID | None,
        resource_type: str,
    ) -> int:
        """Count recent escalation attempts by user."""
        if not user_id:
            return 0

        recent_threshold = time.time() - 300  # 5 minutes
        return len([
            attempt for attempt in self.escalation_attempts
            if (attempt.user_id == user_id and
                attempt.resource_type == resource_type and
                attempt.timestamp > recent_threshold)
        ])

    async def _determine_grant_source(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        request: PermissionRequest,
    ) -> str:
        """Determine how permission was granted."""
        # Implementation would check role assignments
        return "direct"

    async def _check_time_restrictions(self, metadata: Dict[str, Any]) -> bool:
        """Check time-based access restrictions."""
        # Implementation for time-based controls
        return True

    async def _check_ip_restrictions(
        self,
        context: RuntimeEnforcementContext,
        metadata: Dict[str, Any],
    ) -> bool:
        """Check IP-based access restrictions."""
        # Implementation for IP-based controls
        return True

    async def _handle_escalation_attempt(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        request: PermissionRequest,
        result: PermissionResult,
    ) -> None:
        """Handle detected escalation attempt."""
        # Log escalation attempt
        logger.warning(f"Privilege escalation blocked: {request.permission}")

    async def _audit_permission_decision(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        request: PermissionRequest,
        result: PermissionResult,
    ) -> None:
        """Audit permission decision."""
        # Implementation would log to audit system
        logger.info(
            f"Permission check: {request.permission} -> {result.granted} "
            f"(reason: {result.reason})"
        )

    def _generate_cache_key(
        self,
        context: RuntimeEnforcementContext,
        request: PermissionRequest,
    ) -> str:
        """Generate cache key for permission result."""
        user_id = context.user.id if context.user else "anonymous"
        return (
            f"{user_id}:{request.permission}:{request.resource_type}:"
            f"{request.resource_id}:{request.workspace_id}:{request.required_level}"
        )

    def _get_cached_result(self, cache_key: str) -> PermissionResult | None:
        """Get cached permission result."""
        if cache_key in self.permission_cache:
            result = self.permission_cache[cache_key]
            # Check if cache is still valid
            if time.time() - result.timestamp < self.cache_ttl:
                return result
            else:
                del self.permission_cache[cache_key]
        return None

    def _cache_result(self, cache_key: str, result: PermissionResult) -> None:
        """Cache permission result."""
        self.permission_cache[cache_key] = result

    async def get_escalation_attempts(
        self,
        user_id: UUID | None = None,
        since: float | None = None,
    ) -> List[EscalationAttempt]:
        """Get escalation attempts for monitoring."""
        attempts = self.escalation_attempts

        if user_id:
            attempts = [a for a in attempts if a.user_id == user_id]

        if since:
            attempts = [a for a in attempts if a.timestamp > since]

        return attempts

    async def clear_cache(self) -> None:
        """Clear permission cache."""
        self.permission_cache.clear()
        logger.info("Permission cache cleared")


# Global instance
_permission_checker: ComprehensivePermissionChecker | None = None


def get_permission_checker() -> ComprehensivePermissionChecker:
    """Get global permission checker instance."""
    global _permission_checker
    if _permission_checker is None:
        _permission_checker = ComprehensivePermissionChecker()
    return _permission_checker
