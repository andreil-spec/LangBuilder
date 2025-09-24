"""RBAC business logic service following LangBuilder service patterns.

This module provides high-level RBAC operations with performance optimization,
audit logging, and integration with existing LangBuilder services.
"""

# NO future annotations per Phase 1 requirements
import asyncio
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional
from uuid import UUID

from loguru import logger
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.schema.serialize import UUIDstr
from langflow.services.base import Service
from langflow.services.rbac.permission_engine import PermissionEngine, PermissionResult

if TYPE_CHECKING:
    from langflow.services.cache.service import CacheService
    from langflow.services.database.models.rbac.role import Role
    from langflow.services.database.models.rbac.role_assignment import RoleAssignment
    from langflow.services.database.models.rbac.workspace import Workspace
    from langflow.services.database.models.user.model import User
    from langflow.services.rbac.audit_service import AuditService


class RBACService(Service):
    """RBAC business logic service following LangBuilder patterns.

    Provides high-level RBAC operations including:
    - Permission evaluation with caching
    - Role management and assignment
    - Hierarchical permission resolution
    - Audit logging integration
    - Performance monitoring
    """

    name = "rbac_service"

    def __init__(self, cache_service: Optional["CacheService"] = None, audit_service: Optional["AuditService"] = None):
        """Initialize RBAC service with optional cache and audit integration."""
        self.cache_service = cache_service
        self.audit_service = audit_service or self._create_audit_service()
        self.permission_engine = PermissionEngine(
            redis_client=cache_service._client if cache_service else None
        )
        self._performance_metrics = {
            "permission_checks": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "avg_evaluation_time_ms": 0.0,
        }

    def _create_audit_service(self) -> "AuditService":
        """Create a default audit service instance."""
        from langflow.services.rbac.audit_service import AuditService
        return AuditService()

    async def evaluate_permission(
        self,
        session: AsyncSession,
        user: "User",
        resource_type: str,
        action: str,
        resource_id: UUIDstr | None = None,
        workspace_id: UUIDstr | None = None,
        project_id: UUIDstr | None = None,
        environment_id: UUIDstr | None = None,
        audit_context: dict[str, Any] | None = None,
    ) -> PermissionResult:
        """Evaluate permission with audit logging and performance tracking.

        Args:
            session: Database session
            user: User requesting permission
            resource_type: Type of resource being accessed
            action: Action being performed
            resource_id: Specific resource ID (optional)
            workspace_id: Workspace context (optional)
            project_id: Project context (optional)
            environment_id: Environment context (optional)
            audit_context: Additional context for audit logging

        Returns:
            PermissionResult with decision and metadata
        """
        start_time = datetime.now(timezone.utc)

        try:
            # Evaluate permission using engine
            result = await self.permission_engine.check_permission(
                session=session,
                user=user,
                resource_type=resource_type,
                action=action,
                resource_id=UUID(resource_id) if resource_id else None,
                workspace_id=UUID(workspace_id) if workspace_id else None,
                project_id=UUID(project_id) if project_id else None,
                environment_id=UUID(environment_id) if environment_id else None,
            )

            # Update performance metrics
            self._update_performance_metrics(result)

            # Log audit event
            await self._log_permission_check(
                user=user,
                resource_type=resource_type,
                action=action,
                resource_id=resource_id,
                workspace_id=workspace_id,
                result=result,
                audit_context=audit_context,
            )

            return result

        except Exception as e:
            logger.error(f"Permission evaluation failed: {e}")

            # Log audit event for error
            error_result = PermissionResult(
                decision="deny",
                reason=f"Permission evaluation error: {e!s}",
                cached=False,
                evaluation_time_ms=(datetime.now(timezone.utc) - start_time).total_seconds() * 1000,
            )

            await self._log_permission_check(
                user=user,
                resource_type=resource_type,
                action=action,
                resource_id=resource_id,
                workspace_id=workspace_id,
                result=error_result,
                audit_context=audit_context,
            )

            return error_result

    async def batch_evaluate_permissions(
        self,
        session: AsyncSession,
        user: "User",
        permission_requests: list[dict[str, Any]],
    ) -> list[PermissionResult]:
        """Efficiently evaluate multiple permissions with batch optimization.

        Args:
            session: Database session
            user: User requesting permissions
            permission_requests: List of permission request dictionaries

        Returns:
            List of PermissionResult objects
        """
        # Use engine's batch processing for efficiency
        results = await self.permission_engine.batch_check_permissions(
            session=session,
            user=user,
            permission_requests=permission_requests,
        )

        # Update metrics for batch operations
        for result in results:
            self._update_performance_metrics(result)

        # Async audit logging for batch operations
        audit_tasks = [
            self._log_permission_check(
                user=user,
                resource_type=req.get("resource_type"),
                action=req.get("action"),
                resource_id=req.get("resource_id"),
                workspace_id=req.get("workspace_id"),
                result=result,
                audit_context={"batch_operation": True},
            )
            for req, result in zip(permission_requests, results, strict=False)
        ]

        # Execute audit logging in parallel
        await asyncio.gather(*audit_tasks, return_exceptions=True)

        return results

    async def assign_role_to_user(
        self,
        session: AsyncSession,
        user_id: UUIDstr,
        role_id: UUIDstr,
        scope_type: str,
        scope_id: UUIDstr | None = None,
        assigned_by: "User" = None,
        valid_until: datetime | None = None,
    ) -> "RoleAssignment":
        """Assign role to user with hierarchical scope validation.

        Args:
            session: Database session
            user_id: User receiving the role
            role_id: Role being assigned
            scope_type: Type of scope (workspace, project, environment)
            scope_id: Specific scope ID (optional for system roles)
            assigned_by: User performing the assignment
            valid_until: Optional expiration date

        Returns:
            Created RoleAssignment object
        """
        from langflow.services.database.models.rbac.role import Role
        from langflow.services.database.models.rbac.role_assignment import RoleAssignment
        from langflow.services.database.models.user.model import User

        # Validate role exists and is active
        role = await session.get(Role, role_id)
        if not role or not role.is_active:
            raise ValueError(f"Role {role_id} not found or inactive")

        # Validate user exists
        user = await session.get(User, user_id)
        if not user:
            raise ValueError(f"User {user_id} not found")

        # Validate scope-specific constraints
        await self._validate_role_assignment_scope(session, role, scope_type, scope_id)

        # Check if assignment already exists
        existing_query = select(RoleAssignment).where(
            RoleAssignment.user_id == user_id,
            RoleAssignment.role_id == role_id,
            RoleAssignment.is_active == True,
        )

        # Add scope filters
        if scope_type == "workspace" and scope_id:
            existing_query = existing_query.where(RoleAssignment.workspace_id == scope_id)
        elif scope_type == "project" and scope_id:
            existing_query = existing_query.where(RoleAssignment.project_id == scope_id)
        elif scope_type == "environment" and scope_id:
            existing_query = existing_query.where(RoleAssignment.environment_id == scope_id)

        result = await session.exec(existing_query)
        existing_assignment = result.first()

        if existing_assignment:
            raise ValueError(f"Role assignment already exists for user {user_id} and role {role_id}")

        # Create role assignment
        assignment_data = {
            "user_id": user_id,
            "role_id": role_id,
            "assigned_by_id": assigned_by.id if assigned_by else None,
            "valid_until": valid_until,
            "is_active": True,
        }

        # Set scope-specific fields
        if scope_type == "workspace" and scope_id:
            assignment_data["workspace_id"] = scope_id
        elif scope_type == "project" and scope_id:
            assignment_data["project_id"] = scope_id
        elif scope_type == "environment" and scope_id:
            assignment_data["environment_id"] = scope_id

        assignment = RoleAssignment(**assignment_data)
        session.add(assignment)
        await session.commit()
        await session.refresh(assignment)

        # Invalidate user's permission cache
        await self.permission_engine.invalidate_user_cache(UUID(user_id))

        # Log audit event
        await self._log_role_assignment(
            assignment=assignment,
            action="assigned",
            assigned_by=assigned_by,
        )

        return assignment

    async def revoke_role_from_user(
        self,
        session: AsyncSession,
        assignment_id: UUIDstr,
        revoked_by: "User" = None,
    ) -> None:
        """Revoke role assignment with audit logging.

        Args:
            session: Database session
            assignment_id: Role assignment to revoke
            revoked_by: User performing the revocation
        """
        from langflow.services.database.models.rbac.role_assignment import RoleAssignment

        assignment = await session.get(RoleAssignment, assignment_id)
        if not assignment:
            raise ValueError(f"Role assignment {assignment_id} not found")

        if not assignment.is_active:
            raise ValueError(f"Role assignment {assignment_id} is already inactive")

        # Deactivate assignment
        assignment.is_active = False
        assignment.revoked_at = datetime.now(timezone.utc)
        assignment.revoked_by_id = revoked_by.id if revoked_by else None

        await session.commit()

        # Invalidate user's permission cache
        await self.permission_engine.invalidate_user_cache(assignment.user_id)

        # Log audit event
        await self._log_role_assignment(
            assignment=assignment,
            action="revoked",
            assigned_by=revoked_by,
        )

    async def check_workspace_access(
        self,
        session: AsyncSession,
        user: "User",
        workspace_id: UUIDstr,
        required_action: str = "read",
    ) -> bool:
        """Check if user has access to workspace with specified action.

        Args:
            session: Database session
            user: User to check
            workspace_id: Workspace to check access for
            required_action: Required action (default: "read")

        Returns:
            True if user has access, False otherwise
        """
        result = await self.evaluate_permission(
            session=session,
            user=user,
            resource_type="workspace",
            action=required_action,
            resource_id=workspace_id,
            workspace_id=workspace_id,
        )

        return result.allowed

    async def get_user_workspaces(
        self,
        session: AsyncSession,
        user: "User",
    ) -> list["Workspace"]:
        """Get all workspaces user has access to.

        Args:
            session: Database session
            user: User to get workspaces for

        Returns:
            List of accessible workspaces
        """
        from langflow.services.database.models.rbac.role_assignment import RoleAssignment
        from langflow.services.database.models.rbac.workspace import Workspace

        # Get workspaces where user is owner
        owner_query = select(Workspace).where(
            Workspace.owner_id == user.id,
            Workspace.is_deleted == False,
        )
        owner_result = await session.exec(owner_query)
        owner_workspaces = owner_result.all()

        # Get workspaces where user has role assignments
        assignment_query = select(Workspace).join(RoleAssignment).where(
            RoleAssignment.user_id == user.id,
            RoleAssignment.is_active == True,
            Workspace.is_deleted == False,
        )
        assignment_result = await session.exec(assignment_query)
        assigned_workspaces = assignment_result.all()

        # Combine and deduplicate
        all_workspaces = {ws.id: ws for ws in owner_workspaces + assigned_workspaces}

        return list(all_workspaces.values())

    async def validate_break_glass_access(
        self,
        session: AsyncSession,
        user: "User",
        justification: str,
        target_resource_type: str,
        target_resource_id: UUIDstr,
    ) -> bool:
        """Validate and log break-glass emergency access.

        Args:
            session: Database session
            user: User requesting break-glass access
            justification: Required justification for emergency access
            target_resource_type: Type of resource for emergency access
            target_resource_id: Specific resource ID for emergency access

        Returns:
            True if break-glass access is granted
        """
        if not justification or len(justification.strip()) < 10:
            raise ValueError("Break-glass access requires detailed justification (minimum 10 characters)")

        # Check if user has break-glass permission
        break_glass_result = await self.evaluate_permission(
            session=session,
            user=user,
            resource_type="system",
            action="break_glass_access",
            audit_context={
                "break_glass": True,
                "justification": justification,
                "target_resource_type": target_resource_type,
                "target_resource_id": target_resource_id,
            },
        )

        if not break_glass_result.allowed:
            return False

        # Log break-glass access event
        await self._log_break_glass_access(
            user=user,
            justification=justification,
            target_resource_type=target_resource_type,
            target_resource_id=target_resource_id,
        )

        return True

    def get_performance_metrics(self) -> dict[str, Any]:
        """Get current performance metrics for monitoring.

        Returns:
            Dictionary with performance metrics
        """
        return {
            **self._performance_metrics,
            "cache_hit_ratio": (
                self._performance_metrics["cache_hits"] /
                max(1, self._performance_metrics["permission_checks"])
            ),
        }

    async def _validate_role_assignment_scope(
        self,
        session: AsyncSession,
        role: "Role",
        scope_type: str,
        scope_id: UUIDstr | None,
    ) -> None:
        """Validate that role assignment scope is valid."""
        if scope_type == "workspace" and scope_id:
            from langflow.services.database.models.rbac.workspace import Workspace
            workspace = await session.get(Workspace, scope_id)
            if not workspace or workspace.is_deleted:
                raise ValueError(f"Workspace {scope_id} not found or deleted")

        elif scope_type == "project" and scope_id:
            from langflow.services.database.models.rbac.project import Project
            project = await session.get(Project, scope_id)
            if not project or not project.is_active:
                raise ValueError(f"Project {scope_id} not found or inactive")

        elif scope_type == "environment" and scope_id:
            from langflow.services.database.models.rbac.environment import Environment
            environment = await session.get(Environment, scope_id)
            if not environment or not environment.is_active:
                raise ValueError(f"Environment {scope_id} not found or inactive")

    def _update_performance_metrics(self, result: PermissionResult) -> None:
        """Update internal performance metrics."""
        self._performance_metrics["permission_checks"] += 1

        if result.cached:
            self._performance_metrics["cache_hits"] += 1
        else:
            self._performance_metrics["cache_misses"] += 1

        # Update rolling average
        current_avg = self._performance_metrics["avg_evaluation_time_ms"]
        total_checks = self._performance_metrics["permission_checks"]
        new_avg = ((current_avg * (total_checks - 1)) + result.evaluation_time_ms) / total_checks
        self._performance_metrics["avg_evaluation_time_ms"] = new_avg

    async def _log_permission_check(
        self,
        user: "User",
        resource_type: str,
        action: str,
        resource_id: UUIDstr | None,
        workspace_id: UUIDstr | None,
        result: PermissionResult,
        audit_context: dict[str, Any] | None = None,
    ) -> None:
        """Log permission check for audit trail."""
        try:
            from langflow.services.database.models.rbac.audit_log import ActorType, AuditEventType, AuditLog

            audit_log = AuditLog(
                event_type=AuditEventType.AUTHORIZATION,
                actor_type=ActorType.USER,
                actor_id=user.id,
                target_type=resource_type,
                target_id=UUID(resource_id) if resource_id else None,
                action=action,
                workspace_id=UUID(workspace_id) if workspace_id else None,
                success=result.allowed,
                metadata={
                    "decision": result.decision,
                    "reason": result.reason,
                    "cached": result.cached,
                    "evaluation_time_ms": result.evaluation_time_ms,
                    "applied_roles": result.applied_roles,
                    **(audit_context or {}),
                },
            )

            # Note: This would be handled by a separate audit service in production
            logger.info(f"Permission check: {user.id} -> {action} on {resource_type} = {result.decision}")

        except Exception as e:
            logger.error(f"Failed to log permission check: {e}")

    async def _log_role_assignment(
        self,
        assignment: "RoleAssignment",
        action: str,
        assigned_by: Optional["User"] = None,
    ) -> None:
        """Log role assignment event for audit trail."""
        try:
            logger.info(f"Role assignment {action}: {assignment.user_id} -> {assignment.role_id}")
        except Exception as e:
            logger.error(f"Failed to log role assignment: {e}")

    async def _log_break_glass_access(
        self,
        user: "User",
        justification: str,
        target_resource_type: str,
        target_resource_id: UUIDstr,
    ) -> None:
        """Log break-glass access event with high priority."""
        try:
            logger.warning(
                f"BREAK-GLASS ACCESS: User {user.id} accessed {target_resource_type}:{target_resource_id} "
                f"with justification: {justification}"
            )
        except Exception as e:
            logger.error(f"Failed to log break-glass access: {e}")
