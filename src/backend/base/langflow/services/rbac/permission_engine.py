"""High-performance permission engine for RBAC system.

This module provides a caching-enabled permission evaluation engine designed to handle
<100ms p95 latency requirements for permission checks.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any
from uuid import UUID

from pydantic import BaseModel
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

if TYPE_CHECKING:
    from langflow.services.database.models.rbac.permission import Permission
    from langflow.services.database.models.rbac.role import Role
    from langflow.services.database.models.user.model import User


class PermissionDecision(str, Enum):
    """Permission decision outcomes."""

    ALLOW = "allow"
    DENY = "deny"
    NOT_APPLICABLE = "not_applicable"


@dataclass
class PermissionResult:
    """Result of a permission check operation."""

    decision: PermissionDecision
    reason: str
    cached: bool = False
    evaluation_time_ms: float = 0.0
    resource_hierarchy: list[str] | None = None
    applied_roles: list[str] | None = None

    @property
    def allowed(self) -> bool:
        """Check if permission is allowed."""
        return self.decision == PermissionDecision.ALLOW


class PermissionContext(BaseModel):
    """Context for permission evaluation."""

    user_id: UUID
    resource_type: str
    resource_id: UUID | None = None
    action: str
    workspace_id: UUID | None = None
    project_id: UUID | None = None
    environment_id: UUID | None = None
    additional_context: dict[str, Any] | None = None

    def cache_key(self) -> str:
        """Generate cache key for this permission context."""
        key_data = {
            "user_id": str(self.user_id),
            "resource_type": self.resource_type,
            "resource_id": str(self.resource_id) if self.resource_id else None,
            "action": self.action,
            "workspace_id": str(self.workspace_id) if self.workspace_id else None,
            "project_id": str(self.project_id) if self.project_id else None,
            "environment_id": str(self.environment_id) if self.environment_id else None,
        }
        key_json = json.dumps(key_data, sort_keys=True)
        return f"rbac:perm:{hashlib.sha256(key_json.encode()).hexdigest()[:16]}"


class PermissionEngine:
    """High-performance permission evaluation engine with Redis caching.

    This engine provides <100ms p95 latency for permission checks by:
    1. In-memory caching of frequently accessed permissions
    2. Optimized database queries with proper indexing
    3. Hierarchical permission resolution (workspace -> project -> environment)
    4. Bulk role evaluation for groups and service accounts
    """

    def __init__(self, redis_client: Any = None, cache_ttl: int = 300):
        """Initialize permission engine.

        Args:
            redis_client: Optional Redis client for distributed caching
            cache_ttl: Cache TTL in seconds (default: 5 minutes)
        """
        self.redis_client = redis_client
        self.cache_ttl = cache_ttl
        self._memory_cache: dict[str, tuple[PermissionResult, datetime]] = {}
        self._cache_max_size = 10000  # Prevent memory bloat

    async def check_permission(
        self,
        session: AsyncSession,
        user: User,
        resource_type: str,
        action: str,
        resource_id: UUID | None = None,
        workspace_id: UUID | None = None,
        project_id: UUID | None = None,
        environment_id: UUID | None = None,
        use_cache: bool = True,
    ) -> PermissionResult:
        """Check if user has permission for the specified action on resource.

        Args:
            session: Database session
            user: User requesting permission
            resource_type: Type of resource (workspace, project, environment, etc.)
            action: Action being performed (create, read, update, delete, etc.)
            resource_id: Specific resource ID (optional)
            workspace_id: Workspace context (optional)
            project_id: Project context (optional)
            environment_id: Environment context (optional)
            use_cache: Whether to use caching (default: True)

        Returns:
            PermissionResult with decision and metadata
        """
        start_time = datetime.now(timezone.utc)

        # Create permission context
        context = PermissionContext(
            user_id=user.id,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            workspace_id=workspace_id,
            project_id=project_id,
            environment_id=environment_id,
        )

        # Check cache first
        if use_cache:
            cached_result = await self._get_cached_result(context)
            if cached_result:
                cached_result.evaluation_time_ms = (
                    datetime.now(timezone.utc) - start_time
                ).total_seconds() * 1000
                return cached_result

        # Evaluate permission
        result = await self._evaluate_permission(session, user, context)

        # Calculate evaluation time
        result.evaluation_time_ms = (
            datetime.now(timezone.utc) - start_time
        ).total_seconds() * 1000

        # Cache result
        if use_cache and result.decision != PermissionDecision.NOT_APPLICABLE:
            await self._cache_result(context, result)

        return result

    async def _evaluate_permission(
        self,
        session: AsyncSession,
        user: User,
        context: PermissionContext,
    ) -> PermissionResult:
        """Evaluate permission using hierarchical rules."""
        # Superuser check - highest priority
        if user.is_superuser:
            return PermissionResult(
                decision=PermissionDecision.ALLOW,
                reason="User is superuser",
                applied_roles=["superuser"],
            )

        # Resource owner checks
        if context.resource_id:
            owner_result = await self._check_resource_ownership(session, user, context)
            if owner_result.decision == PermissionDecision.ALLOW:
                return owner_result

        # Role-based permission checks
        role_result = await self._check_role_permissions(session, user, context)
        if role_result.decision == PermissionDecision.ALLOW:
            return role_result

        # Group membership checks
        group_result = await self._check_group_permissions(session, user, context)
        if group_result.decision == PermissionDecision.ALLOW:
            return group_result

        # Default deny
        return PermissionResult(
            decision=PermissionDecision.DENY,
            reason="No applicable permissions found",
        )

    async def batch_check_permissions(
        self,
        session: AsyncSession,
        user: User,
        permission_requests: list[dict[str, Any]]
    ) -> list[PermissionResult]:
        """Check multiple permissions efficiently."""
        results = []

        for request in permission_requests:
            try:
                resource_type = request.get("resource_type")
                action = request.get("action")

                if not resource_type or not action:
                    results.append(PermissionResult(
                        allowed=False,
                        reason="Missing resource_type or action",
                        decision="DENY"
                    ))
                    continue

                result = await self.check_permission(
                    session=session,
                    user=user,
                    resource_type=str(resource_type),
                    action=str(action),
                    resource_id=request.get("resource_id"),
                    workspace_id=request.get("workspace_id"),
                    project_id=request.get("project_id"),
                    environment_id=request.get("environment_id"),
                )
                results.append(result)
            except Exception as e:
                results.append(PermissionResult(
                    decision=PermissionDecision.DENY,
                    reason=f"Error checking permission: {e!s}",
                    cached=False
                ))

        return results

    async def _resolve_hierarchical_permissions(
        self,
        session: AsyncSession,
        user: User,
        context: PermissionContext,
    ) -> PermissionResult:
        """Resolve permissions through hierarchy (workspace -> project -> environment -> flow)."""
        # Check direct permissions first
        direct_result = await self._check_role_permissions(session, user, context)
        if direct_result.decision == PermissionDecision.ALLOW:
            return direct_result

        # Check parent resource permissions
        if context.project_id and context.resource_type != "workspace":
            # Check workspace-level permissions for project access
            workspace_context = PermissionContext(
                resource_type="workspace",
                action=context.action,
                resource_id=context.workspace_id,
                workspace_id=context.workspace_id,
            )
            workspace_result = await self._check_role_permissions(session, user, workspace_context)
            if workspace_result.decision == PermissionDecision.ALLOW:
                return PermissionResult(
                    decision=PermissionDecision.ALLOW,
                    reason="Inherited from workspace permissions",
                    cached=False
                )

        return PermissionResult(
            decision=PermissionDecision.DENY,
            reason="No hierarchical permissions found",
            cached=False
        )

    async def _get_user_roles(
        self,
        session: AsyncSession,
        user: User,
        workspace_id: UUID | None = None,
        project_id: UUID | None = None,
    ) -> list[Role]:
        """Get all roles assigned to user in given scope."""
        from langflow.services.database.models.rbac.role import Role
        from langflow.services.database.models.rbac.role_assignment import RoleAssignment

        # Build query for role assignments
        statement = select(Role).join(RoleAssignment).where(
            RoleAssignment.user_id == user.id,
            RoleAssignment.is_active == True,
            Role.is_active == True
        )

        # Add scope filters
        if workspace_id:
            statement = statement.where(
                (RoleAssignment.workspace_id == workspace_id) |
                (RoleAssignment.workspace_id is None)  # Include system roles
            )

        if project_id:
            statement = statement.where(
                (RoleAssignment.project_id == project_id) |
                (RoleAssignment.project_id is None)  # Include broader scope roles
            )

        result = await session.exec(statement)
        return result.all()

    async def _get_role_permissions(
        self,
        session: AsyncSession,
        role: Role,
    ) -> list[Permission]:
        """Get all permissions granted to a role."""
        from langflow.services.database.models.rbac.permission import Permission, RolePermission

        statement = select(Permission).join(RolePermission).where(
            RolePermission.role_id == role.id,
            RolePermission.is_granted == True
        )

        result = await session.exec(statement)
        return result.all()

    async def _check_cached_permission(
        self,
        cache_key: str,
    ) -> PermissionResult | None:
        """Check if permission result is cached."""
        try:
            if self.redis_client:
                cached_result = await self.redis_client.get(cache_key)
                if cached_result:
                    decision = PermissionDecision.ALLOW if cached_result.get("allowed", False) else PermissionDecision.DENY
                    return PermissionResult(
                        decision=decision,
                        reason=cached_result.get("reason", "Cached result"),
                        cached=True
                    )
        except Exception:
            # Cache errors should not break permission checking
            pass

        return None

    async def _check_resource_ownership(
        self,
        session: AsyncSession,
        user: User,
        context: PermissionContext,
    ) -> PermissionResult:
        """Check if user owns the resource."""
        from langflow.services.database.models.rbac.environment import Environment
        from langflow.services.database.models.rbac.project import Project
        from langflow.services.database.models.rbac.workspace import Workspace

        if context.resource_type == "workspace" and context.resource_id:
            workspace = await session.get(Workspace, context.resource_id)
            if workspace and workspace.owner_id == user.id:
                return PermissionResult(
                    decision=PermissionDecision.ALLOW,
                    reason="User owns workspace",
                    applied_roles=["workspace_owner"],
                )

        elif context.resource_type == "project" and context.resource_id:
            project = await session.get(Project, context.resource_id)
            if project and project.owner_id == user.id:
                return PermissionResult(
                    decision=PermissionDecision.ALLOW,
                    reason="User owns project",
                    applied_roles=["project_owner"],
                )

        elif context.resource_type == "environment" and context.resource_id:
            environment = await session.get(Environment, context.resource_id)
            if environment and environment.owner_id == user.id:
                return PermissionResult(
                    decision=PermissionDecision.ALLOW,
                    reason="User owns environment",
                    applied_roles=["environment_owner"],
                )

        return PermissionResult(
            decision=PermissionDecision.NOT_APPLICABLE,
            reason="User does not own resource",
        )

    async def _check_role_permissions(
        self,
        session: AsyncSession,
        user: User,
        context: PermissionContext,
    ) -> PermissionResult:
        """Check user's direct role assignments."""
        from langflow.services.database.models.rbac.permission import Permission, RolePermission
        from langflow.services.database.models.rbac.role import Role
        from langflow.services.database.models.rbac.role_assignment import RoleAssignment

        # Get user's active role assignments in relevant scope
        role_query = select(RoleAssignment).where(
            RoleAssignment.user_id == user.id,
            RoleAssignment.is_active == True,
        )

        # Filter by scope hierarchy
        if context.workspace_id:
            role_query = role_query.where(
                (RoleAssignment.workspace_id == context.workspace_id) |
                (RoleAssignment.workspace_id is None)  # System-wide roles
            )

        if context.project_id:
            role_query = role_query.where(
                (RoleAssignment.project_id == context.project_id) |
                (RoleAssignment.project_id is None)
            )

        if context.environment_id:
            role_query = role_query.where(
                (RoleAssignment.environment_id == context.environment_id) |
                (RoleAssignment.environment_id is None)
            )

        result = await session.exec(role_query)
        role_assignments = result.all()

        if not role_assignments:
            return PermissionResult(
                decision=PermissionDecision.NOT_APPLICABLE,
                reason="No role assignments found",
            )

        # Check each role's permissions
        applied_roles = []
        for assignment in role_assignments:
            role = await session.get(Role, assignment.role_id)
            if not role or not role.is_active:
                continue

            applied_roles.append(role.name)

            # Check role permissions
            perm_query = select(RolePermission).join(Permission).where(
                RolePermission.role_id == role.id,
                RolePermission.is_granted == True,
                Permission.resource_type == context.resource_type,
                Permission.action == context.action,
            )

            perm_result = await session.exec(perm_query)
            permissions = perm_result.all()

            if permissions:
                return PermissionResult(
                    decision=PermissionDecision.ALLOW,
                    reason=f"Permission granted via role: {role.name}",
                    applied_roles=applied_roles,
                )

        return PermissionResult(
            decision=PermissionDecision.DENY,
            reason="No matching permissions in assigned roles",
            applied_roles=applied_roles,
        )

    async def _check_group_permissions(
        self,
        session: AsyncSession,
        user: User,
        context: PermissionContext,
    ) -> PermissionResult:
        """Check permissions via group membership."""
        from langflow.services.database.models.rbac.role_assignment import RoleAssignment
        from langflow.services.database.models.rbac.user_group import UserGroupMembership

        # Get user's active group memberships
        group_query = select(UserGroupMembership).where(
            UserGroupMembership.user_id == user.id,
            UserGroupMembership.is_active == True,
        )

        result = await session.exec(group_query)
        memberships = result.all()

        if not memberships:
            return PermissionResult(
                decision=PermissionDecision.NOT_APPLICABLE,
                reason="No group memberships found",
            )

        # Check role assignments for each group
        group_ids = [m.group_id for m in memberships if m.group_id is not None]

        role_query = select(RoleAssignment).where(
            RoleAssignment.group_id.in_(group_ids),
            RoleAssignment.is_active == True,
        )

        # Apply scope filters
        if context.workspace_id:
            role_query = role_query.where(
                (RoleAssignment.workspace_id == context.workspace_id) |
                (RoleAssignment.workspace_id is None)
            )

        result = await session.exec(role_query)
        group_assignments = result.all()

        if group_assignments:
            # For group permissions, we create a new context and check role permissions
            # This reuses the role permission logic
            for assignment in group_assignments:
                # Create a temporary user context with the group's role
                role_result = await self._check_specific_role_permission(
                    session, assignment.role_id, context
                )
                if role_result.decision == PermissionDecision.ALLOW:
                    role_result.reason = "Permission granted via group role assignment"
                    return role_result

        return PermissionResult(
            decision=PermissionDecision.NOT_APPLICABLE,
            reason="No applicable group permissions",
        )

    async def _check_specific_role_permission(
        self,
        session: AsyncSession,
        role_id: UUID,
        context: PermissionContext,
    ) -> PermissionResult:
        """Check if a specific role has the required permission."""
        from langflow.services.database.models.rbac.permission import Permission, RolePermission
        from langflow.services.database.models.rbac.role import Role

        role = await session.get(Role, role_id)
        if not role or not role.is_active:
            return PermissionResult(
                decision=PermissionDecision.NOT_APPLICABLE,
                reason="Role not found or inactive",
            )

        # Check role permissions
        perm_query = select(RolePermission).join(Permission).where(
            RolePermission.role_id == role_id,
            RolePermission.is_granted == True,
            Permission.resource_type == context.resource_type,
            Permission.action == context.action,
        )

        result = await session.exec(perm_query)
        permissions = result.all()

        if permissions:
            return PermissionResult(
                decision=PermissionDecision.ALLOW,
                reason=f"Permission granted via role: {role.name}",
                applied_roles=[role.name],
            )

        return PermissionResult(
            decision=PermissionDecision.NOT_APPLICABLE,
            reason=f"Role {role.name} does not have required permission",
        )

    async def _get_cached_result(self, context: PermissionContext) -> PermissionResult | None:
        """Get cached permission result."""
        cache_key = context.cache_key()

        # Check memory cache first
        if cache_key in self._memory_cache:
            result, timestamp = self._memory_cache[cache_key]
            if (datetime.now(timezone.utc) - timestamp).seconds < self.cache_ttl:
                result.cached = True
                return result
            # Remove expired entry
            del self._memory_cache[cache_key]

        # Check Redis cache if available
        if self.redis_client:
            try:
                cached_data = await self.redis_client.get(cache_key)
                if cached_data:
                    # Deserialize result
                    data = json.loads(cached_data)
                    result = PermissionResult(
                        decision=PermissionDecision(data["decision"]),
                        reason=data["reason"],
                        cached=True,
                        applied_roles=data.get("applied_roles"),
                    )
                    return result
            except Exception:
                # Cache miss or error - continue with evaluation
                pass

        return None

    async def _cache_result(self, context: PermissionContext, result: PermissionResult) -> None:
        """Cache permission result."""
        cache_key = context.cache_key()

        # Memory cache
        if len(self._memory_cache) >= self._cache_max_size:
            # Remove oldest entries
            oldest_keys = sorted(
                self._memory_cache.keys(),
                key=lambda k: self._memory_cache[k][1]
            )[:100]
            for key in oldest_keys:
                del self._memory_cache[key]

        self._memory_cache[cache_key] = (result, datetime.now(timezone.utc))

        # Redis cache if available
        if self.redis_client:
            try:
                cache_data = {
                    "decision": result.decision.value,
                    "reason": result.reason,
                    "applied_roles": result.applied_roles,
                }
                await self.redis_client.setex(
                    cache_key,
                    self.cache_ttl,
                    json.dumps(cache_data)
                )
            except Exception:
                # Cache write failure - not critical
                pass

    async def invalidate_user_cache(self, user_id: UUID) -> None:
        """Invalidate all cached permissions for a user."""
        # Remove from memory cache
        keys_to_remove = [
            key for key in self._memory_cache.keys()
            if f'user_id":"{user_id}"' in key
        ]
        for key in keys_to_remove:
            del self._memory_cache[key]

        # Remove from Redis cache if available
        if self.redis_client:
            try:
                pattern = f"rbac:perm:*{user_id}*"
                keys = await self.redis_client.keys(pattern)
                if keys:
                    await self.redis_client.delete(*keys)
            except Exception:
                # Cache invalidation failure - not critical
                pass

    async def invalidate_resource_cache(self, resource_type: str, resource_id: UUID) -> None:
        """Invalidate all cached permissions for a specific resource."""
        # Remove from memory cache
        keys_to_remove = [
            key for key in self._memory_cache.keys()
            if f'resource_type":"{resource_type}"' in key and f'resource_id":"{resource_id}"' in key
        ]
        for key in keys_to_remove:
            del self._memory_cache[key]

        # Remove from Redis cache if available
        if self.redis_client:
            try:
                pattern = f"rbac:perm:*{resource_type}*{resource_id}*"
                keys = await self.redis_client.keys(pattern)
                if keys:
                    await self.redis_client.delete(*keys)
            except Exception:
                # Cache invalidation failure - not critical
                pass
