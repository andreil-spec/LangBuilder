"""Workspace Isolation Enforcement Service.

This module provides strict workspace isolation to prevent cross-tenant data access
and ensures proper multi-tenancy security boundaries.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Set
from uuid import UUID

from loguru import logger
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.services.rbac.runtime_enforcement import RuntimeEnforcementContext


class IsolationViolationType(str, Enum):
    """Types of workspace isolation violations."""

    CROSS_TENANT_ACCESS = "cross_tenant_access"
    MISSING_WORKSPACE_CONTEXT = "missing_workspace_context"
    INVALID_WORKSPACE_ID = "invalid_workspace_id"
    UNAUTHORIZED_WORKSPACE_ACCESS = "unauthorized_workspace_access"
    GLOBAL_ACCESS_WITHOUT_PERMISSION = "global_access_without_permission"
    RESOURCE_LEAK = "resource_leak"
    TENANT_BOUNDARY_VIOLATION = "tenant_boundary_violation"


@dataclass
class IsolationViolation:
    """Workspace isolation violation record."""

    violation_type: IsolationViolationType
    user_id: UUID | None
    attempted_workspace_id: UUID | None
    authorized_workspace_ids: Set[UUID]
    resource_type: str
    resource_id: UUID | None
    request_path: str
    timestamp: float
    blocked: bool
    details: Dict[str, Any]


@dataclass
class WorkspaceAccessResult:
    """Result of workspace access validation."""

    allowed: bool
    workspace_id: UUID | None
    user_workspaces: Set[UUID]
    violation: IsolationViolation | None
    reason: str
    enforcement_level: str  # "strict", "relaxed", "disabled"


@dataclass
class TenantBoundary:
    """Definition of tenant boundaries."""

    workspace_id: UUID
    allowed_resources: Set[str]
    blocked_resources: Set[str]
    cross_tenant_rules: Dict[str, Any]
    isolation_level: str  # "strict", "normal", "relaxed"


class WorkspaceIsolationService:
    """Service for enforcing strict workspace isolation."""

    def __init__(self):
        self.violations: List[IsolationViolation] = []
        self.tenant_boundaries: Dict[UUID, TenantBoundary] = {}
        self.global_resources = {
            "system", "global_settings", "user_profile", "authentication"
        }
        self.cross_tenant_allowed_resources = {
            "public_templates", "marketplace", "documentation"
        }

    async def enforce_workspace_isolation(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        resource_type: str,
        resource_id: UUID | None = None,
        workspace_id: UUID | None = None,
    ) -> WorkspaceAccessResult:
        """Enforce workspace isolation for a resource access."""

        # Determine effective workspace ID
        effective_workspace_id = workspace_id or context.effective_workspace_id

        # Check if this is a global resource
        if self._is_global_resource(resource_type):
            return await self._validate_global_access(
                session, context, resource_type, resource_id
            )

        # Check if workspace context is required
        if self._requires_workspace_context(resource_type):
            if not effective_workspace_id:
                violation = await self._record_violation(
                    IsolationViolationType.MISSING_WORKSPACE_CONTEXT,
                    context,
                    None,
                    resource_type,
                    resource_id,
                    {"required_for": resource_type}
                )
                return WorkspaceAccessResult(
                    allowed=False,
                    workspace_id=None,
                    user_workspaces=set(),
                    violation=violation,
                    reason="Workspace context required but not provided",
                    enforcement_level="strict",
                )

        # Get user's authorized workspaces
        user_workspaces = await self._get_user_workspaces(session, context)

        # Validate workspace access
        if effective_workspace_id:
            workspace_access = await self._validate_workspace_access(
                session, context, effective_workspace_id, user_workspaces
            )
            if not workspace_access.allowed:
                return workspace_access

        # Check cross-tenant resource access
        cross_tenant_result = await self._check_cross_tenant_access(
            session, context, resource_type, resource_id, effective_workspace_id
        )
        if not cross_tenant_result.allowed:
            return cross_tenant_result

        # Validate resource ownership within workspace
        ownership_result = await self._validate_resource_ownership(
            session, context, resource_type, resource_id, effective_workspace_id
        )
        if not ownership_result.allowed:
            return ownership_result

        # Check tenant boundary rules
        boundary_result = await self._check_tenant_boundaries(
            session, context, resource_type, resource_id, effective_workspace_id
        )
        if not boundary_result.allowed:
            return boundary_result

        # All checks passed
        return WorkspaceAccessResult(
            allowed=True,
            workspace_id=effective_workspace_id,
            user_workspaces=user_workspaces,
            violation=None,
            reason="Workspace isolation checks passed",
            enforcement_level="strict",
        )

    async def _validate_global_access(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        resource_type: str,
        resource_id: UUID | None,
    ) -> WorkspaceAccessResult:
        """Validate access to global resources."""

        # System administrators can access all global resources
        if context.user and context.user.is_superuser:
            return WorkspaceAccessResult(
                allowed=True,
                workspace_id=None,
                user_workspaces=set(),
                violation=None,
                reason="Global access granted for system administrator",
                enforcement_level="relaxed",
            )

        # Check if user has specific global permissions
        has_global_permission = await self._check_global_permission(
            session, context, resource_type
        )

        if not has_global_permission:
            violation = await self._record_violation(
                IsolationViolationType.GLOBAL_ACCESS_WITHOUT_PERMISSION,
                context,
                None,
                resource_type,
                resource_id,
                {"required_permission": f"global:{resource_type}"}
            )
            return WorkspaceAccessResult(
                allowed=False,
                workspace_id=None,
                user_workspaces=set(),
                violation=violation,
                reason="Global access permission required",
                enforcement_level="strict",
            )

        return WorkspaceAccessResult(
            allowed=True,
            workspace_id=None,
            user_workspaces=set(),
            violation=None,
            reason="Global access permission verified",
            enforcement_level="normal",
        )

    async def _validate_workspace_access(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        workspace_id: UUID,
        user_workspaces: Set[UUID],
    ) -> WorkspaceAccessResult:
        """Validate user's access to specific workspace."""

        # Check if workspace exists
        workspace_exists = await self._workspace_exists(session, workspace_id)
        if not workspace_exists:
            violation = await self._record_violation(
                IsolationViolationType.INVALID_WORKSPACE_ID,
                context,
                workspace_id,
                "workspace",
                workspace_id,
                {"workspace_id": str(workspace_id)}
            )
            return WorkspaceAccessResult(
                allowed=False,
                workspace_id=workspace_id,
                user_workspaces=user_workspaces,
                violation=violation,
                reason="Workspace does not exist",
                enforcement_level="strict",
            )

        # Check if user has access to this workspace
        if workspace_id not in user_workspaces:
            violation = await self._record_violation(
                IsolationViolationType.UNAUTHORIZED_WORKSPACE_ACCESS,
                context,
                workspace_id,
                "workspace",
                workspace_id,
                {
                    "attempted_workspace": str(workspace_id),
                    "authorized_workspaces": [str(w) for w in user_workspaces]
                }
            )
            return WorkspaceAccessResult(
                allowed=False,
                workspace_id=workspace_id,
                user_workspaces=user_workspaces,
                violation=violation,
                reason="User does not have access to this workspace",
                enforcement_level="strict",
            )

        return WorkspaceAccessResult(
            allowed=True,
            workspace_id=workspace_id,
            user_workspaces=user_workspaces,
            violation=None,
            reason="Workspace access authorized",
            enforcement_level="normal",
        )

    async def _check_cross_tenant_access(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        resource_type: str,
        resource_id: UUID | None,
        workspace_id: UUID | None,
    ) -> WorkspaceAccessResult:
        """Check for cross-tenant resource access attempts."""

        if not resource_id or not workspace_id:
            return WorkspaceAccessResult(
                allowed=True,
                workspace_id=workspace_id,
                user_workspaces=set(),
                violation=None,
                reason="No resource ID to validate",
                enforcement_level="normal",
            )

        # Check if resource belongs to the specified workspace
        resource_workspace = await self._get_resource_workspace(
            session, resource_type, resource_id
        )

        if resource_workspace and resource_workspace != workspace_id:
            # Check if cross-tenant access is allowed for this resource type
            if resource_type not in self.cross_tenant_allowed_resources:
                violation = await self._record_violation(
                    IsolationViolationType.CROSS_TENANT_ACCESS,
                    context,
                    workspace_id,
                    resource_type,
                    resource_id,
                    {
                        "resource_workspace": str(resource_workspace),
                        "requested_workspace": str(workspace_id),
                        "resource_type": resource_type,
                    }
                )
                return WorkspaceAccessResult(
                    allowed=False,
                    workspace_id=workspace_id,
                    user_workspaces=set(),
                    violation=violation,
                    reason="Cross-tenant access not allowed for this resource type",
                    enforcement_level="strict",
                )

        return WorkspaceAccessResult(
            allowed=True,
            workspace_id=workspace_id,
            user_workspaces=set(),
            violation=None,
            reason="Cross-tenant access validation passed",
            enforcement_level="normal",
        )

    async def _validate_resource_ownership(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        resource_type: str,
        resource_id: UUID | None,
        workspace_id: UUID | None,
    ) -> WorkspaceAccessResult:
        """Validate resource ownership within workspace."""

        if not resource_id:
            return WorkspaceAccessResult(
                allowed=True,
                workspace_id=workspace_id,
                user_workspaces=set(),
                violation=None,
                reason="No resource to validate ownership",
                enforcement_level="normal",
            )

        # Check if resource exists and belongs to the workspace
        resource_valid = await self._validate_resource_in_workspace(
            session, resource_type, resource_id, workspace_id
        )

        if not resource_valid:
            violation = await self._record_violation(
                IsolationViolationType.RESOURCE_LEAK,
                context,
                workspace_id,
                resource_type,
                resource_id,
                {
                    "resource_type": resource_type,
                    "resource_id": str(resource_id),
                    "workspace_id": str(workspace_id) if workspace_id else None,
                }
            )
            return WorkspaceAccessResult(
                allowed=False,
                workspace_id=workspace_id,
                user_workspaces=set(),
                violation=violation,
                reason="Resource does not belong to the specified workspace",
                enforcement_level="strict",
            )

        return WorkspaceAccessResult(
            allowed=True,
            workspace_id=workspace_id,
            user_workspaces=set(),
            violation=None,
            reason="Resource ownership validated",
            enforcement_level="normal",
        )

    async def _check_tenant_boundaries(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        resource_type: str,
        resource_id: UUID | None,
        workspace_id: UUID | None,
    ) -> WorkspaceAccessResult:
        """Check tenant boundary rules."""

        if not workspace_id:
            return WorkspaceAccessResult(
                allowed=True,
                workspace_id=workspace_id,
                user_workspaces=set(),
                violation=None,
                reason="No workspace to check boundaries",
                enforcement_level="normal",
            )

        # Get tenant boundary rules
        boundary = self.tenant_boundaries.get(workspace_id)
        if not boundary:
            # Create default boundary
            boundary = TenantBoundary(
                workspace_id=workspace_id,
                allowed_resources=set(),
                blocked_resources=set(),
                cross_tenant_rules={},
                isolation_level="normal",
            )
            self.tenant_boundaries[workspace_id] = boundary

        # Check if resource type is blocked
        if resource_type in boundary.blocked_resources:
            violation = await self._record_violation(
                IsolationViolationType.TENANT_BOUNDARY_VIOLATION,
                context,
                workspace_id,
                resource_type,
                resource_id,
                {
                    "boundary_rule": "blocked_resource",
                    "resource_type": resource_type,
                }
            )
            return WorkspaceAccessResult(
                allowed=False,
                workspace_id=workspace_id,
                user_workspaces=set(),
                violation=violation,
                reason="Resource type is blocked by tenant boundary rules",
                enforcement_level="strict",
            )

        return WorkspaceAccessResult(
            allowed=True,
            workspace_id=workspace_id,
            user_workspaces=set(),
            violation=None,
            reason="Tenant boundary checks passed",
            enforcement_level="normal",
        )

    # Helper methods
    def _is_global_resource(self, resource_type: str) -> bool:
        """Check if resource is global (not workspace-scoped)."""
        return resource_type in self.global_resources

    def _requires_workspace_context(self, resource_type: str) -> bool:
        """Check if resource type requires workspace context."""
        return not self._is_global_resource(resource_type)

    async def _get_user_workspaces(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
    ) -> Set[UUID]:
        """Get workspaces user has access to."""
        if not context.user:
            return set()

        try:
            from langflow.services.database.models.rbac.workspace import Workspace
            from langflow.services.database.models.rbac.role_assignment import RoleAssignment

            # Query user's workspace access through role assignments
            statement = select(Workspace.id).join(RoleAssignment).where(
                RoleAssignment.user_id == context.user.id,
                RoleAssignment.is_active == True,
                Workspace.is_deleted == False,
            )

            result = await session.exec(statement)
            workspace_ids = result.all()
            return set(workspace_ids)

        except Exception as e:
            logger.error(f"Error getting user workspaces: {e}")
            return set()

    async def _workspace_exists(
        self,
        session: AsyncSession,
        workspace_id: UUID,
    ) -> bool:
        """Check if workspace exists."""
        try:
            from langflow.services.database.models.rbac.workspace import Workspace

            statement = select(Workspace).where(
                Workspace.id == workspace_id,
                Workspace.is_deleted == False,
            )
            result = await session.exec(statement)
            return result.first() is not None

        except Exception as e:
            logger.error(f"Error checking workspace existence: {e}")
            return False

    async def _check_global_permission(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        resource_type: str,
    ) -> bool:
        """Check if user has global permission for resource type."""
        # Implementation would check for global permissions
        # For now, return False to require explicit global permissions
        return False

    async def _get_resource_workspace(
        self,
        session: AsyncSession,
        resource_type: str,
        resource_id: UUID,
    ) -> UUID | None:
        """Get the workspace that owns a resource."""
        try:
            # Dynamic lookup based on resource type
            if resource_type == "project":
                from langflow.services.database.models.rbac.project import Project
                statement = select(Project.workspace_id).where(Project.id == resource_id)
            elif resource_type == "flow":
                from langflow.services.database.models.flow.model import Flow
                statement = select(Flow.workspace_id).where(Flow.id == resource_id)
            elif resource_type == "environment":
                from langflow.services.database.models.rbac.environment import Environment
                statement = select(Environment.project).join(
                    "langflow.services.database.models.rbac.project.Project"
                ).where(Environment.id == resource_id)
                # Would need to join to get workspace_id
                return None
            else:
                return None

            result = await session.exec(statement)
            workspace_id = result.first()
            return workspace_id

        except Exception as e:
            logger.error(f"Error getting resource workspace: {e}")
            return None

    async def _validate_resource_in_workspace(
        self,
        session: AsyncSession,
        resource_type: str,
        resource_id: UUID,
        workspace_id: UUID | None,
    ) -> bool:
        """Validate that resource belongs to workspace."""
        if not workspace_id:
            return True

        resource_workspace = await self._get_resource_workspace(
            session, resource_type, resource_id
        )
        return resource_workspace == workspace_id

    async def _record_violation(
        self,
        violation_type: IsolationViolationType,
        context: RuntimeEnforcementContext,
        workspace_id: UUID | None,
        resource_type: str,
        resource_id: UUID | None,
        details: Dict[str, Any],
    ) -> IsolationViolation:
        """Record a workspace isolation violation."""

        violation = IsolationViolation(
            violation_type=violation_type,
            user_id=context.user.id if context.user else None,
            attempted_workspace_id=workspace_id,
            authorized_workspace_ids=set(),  # Would be populated with user's workspaces
            resource_type=resource_type,
            resource_id=resource_id,
            request_path=context.request_path or "unknown",
            timestamp=time.time(),
            blocked=True,
            details=details,
        )

        self.violations.append(violation)

        logger.warning(
            f"Workspace isolation violation: {violation_type} - "
            f"user={context.user.id if context.user else 'unknown'}, "
            f"resource={resource_type}:{resource_id}, "
            f"workspace={workspace_id}"
        )

        return violation

    async def get_violations(
        self,
        workspace_id: UUID | None = None,
        user_id: UUID | None = None,
        since: float | None = None,
    ) -> List[IsolationViolation]:
        """Get isolation violations for monitoring."""
        violations = self.violations

        if workspace_id:
            violations = [v for v in violations if v.attempted_workspace_id == workspace_id]

        if user_id:
            violations = [v for v in violations if v.user_id == user_id]

        if since:
            violations = [v for v in violations if v.timestamp > since]

        return violations

    async def configure_tenant_boundary(
        self,
        workspace_id: UUID,
        boundary: TenantBoundary,
    ) -> None:
        """Configure tenant boundary rules."""
        self.tenant_boundaries[workspace_id] = boundary
        logger.info(f"Configured tenant boundary for workspace {workspace_id}")

    async def clear_violations(self, older_than: float | None = None) -> int:
        """Clear old violation records."""
        if older_than:
            old_count = len(self.violations)
            self.violations = [v for v in self.violations if v.timestamp > older_than]
            cleared = old_count - len(self.violations)
        else:
            cleared = len(self.violations)
            self.violations.clear()

        logger.info(f"Cleared {cleared} isolation violation records")
        return cleared


# Global instance
_isolation_service: WorkspaceIsolationService | None = None


def get_workspace_isolation_service() -> WorkspaceIsolationService:
    """Get global workspace isolation service instance."""
    global _isolation_service
    if _isolation_service is None:
        _isolation_service = WorkspaceIsolationService()
    return _isolation_service
