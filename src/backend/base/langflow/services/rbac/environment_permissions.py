"""Multi-environment permission scoping service.

This module implements environment-aware permissions, allowing different access
levels across development, staging, and production environments.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any

from loguru import logger
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.schema.serialize import UUIDstr
from langflow.services.base import Service

if TYPE_CHECKING:
    from langflow.services.database.models.rbac.environment import Environment, EnvironmentType
    from langflow.services.database.models.rbac.role_assignment import RoleAssignment


class EnvironmentPermissionLevel(str, Enum):
    """Permission levels for different environments."""

    NONE = "none"           # No access
    READ = "read"          # Read-only access
    WRITE = "write"        # Read and write access
    ADMIN = "admin"        # Full administrative access
    DEPLOY = "deploy"      # Deployment permissions
    DEBUG = "debug"        # Debug and troubleshoot access


class EnvironmentAccessPolicy(str, Enum):
    """Access policies for environments."""

    OPEN = "open"          # Anyone with workspace access
    RESTRICTED = "restricted"  # Explicit permission required
    LOCKED = "locked"      # Admin approval required
    EMERGENCY_ONLY = "emergency_only"  # Break-glass access only


class EnvironmentPermissionMatrix:
    """Permission matrix for environment-specific access control."""

    # Default permission mapping by environment type
    DEFAULT_PERMISSIONS = {
        "development": {
            "flows.create": EnvironmentPermissionLevel.WRITE,
            "flows.read": EnvironmentPermissionLevel.READ,
            "flows.update": EnvironmentPermissionLevel.WRITE,
            "flows.delete": EnvironmentPermissionLevel.WRITE,
            "flows.deploy": EnvironmentPermissionLevel.DEPLOY,
            "variables.create": EnvironmentPermissionLevel.WRITE,
            "variables.read": EnvironmentPermissionLevel.READ,
            "variables.update": EnvironmentPermissionLevel.WRITE,
            "variables.delete": EnvironmentPermissionLevel.WRITE,
            "environment.configure": EnvironmentPermissionLevel.ADMIN,
            "environment.debug": EnvironmentPermissionLevel.DEBUG,
        },
        "staging": {
            "flows.create": EnvironmentPermissionLevel.WRITE,
            "flows.read": EnvironmentPermissionLevel.READ,
            "flows.update": EnvironmentPermissionLevel.WRITE,
            "flows.delete": EnvironmentPermissionLevel.RESTRICTED,
            "flows.deploy": EnvironmentPermissionLevel.DEPLOY,
            "variables.create": EnvironmentPermissionLevel.WRITE,
            "variables.read": EnvironmentPermissionLevel.READ,
            "variables.update": EnvironmentPermissionLevel.WRITE,
            "variables.delete": EnvironmentPermissionLevel.RESTRICTED,
            "environment.configure": EnvironmentPermissionLevel.ADMIN,
            "environment.debug": EnvironmentPermissionLevel.DEBUG,
        },
        "production": {
            "flows.create": EnvironmentPermissionLevel.RESTRICTED,
            "flows.read": EnvironmentPermissionLevel.READ,
            "flows.update": EnvironmentPermissionLevel.RESTRICTED,
            "flows.delete": EnvironmentPermissionLevel.NONE,
            "flows.deploy": EnvironmentPermissionLevel.ADMIN,
            "variables.create": EnvironmentPermissionLevel.RESTRICTED,
            "variables.read": EnvironmentPermissionLevel.READ,
            "variables.update": EnvironmentPermissionLevel.RESTRICTED,
            "variables.delete": EnvironmentPermissionLevel.NONE,
            "environment.configure": EnvironmentPermissionLevel.ADMIN,
            "environment.debug": EnvironmentPermissionLevel.RESTRICTED,
        },
        "testing": {
            "flows.create": EnvironmentPermissionLevel.WRITE,
            "flows.read": EnvironmentPermissionLevel.READ,
            "flows.update": EnvironmentPermissionLevel.WRITE,
            "flows.delete": EnvironmentPermissionLevel.WRITE,
            "flows.deploy": EnvironmentPermissionLevel.DEPLOY,
            "variables.create": EnvironmentPermissionLevel.WRITE,
            "variables.read": EnvironmentPermissionLevel.READ,
            "variables.update": EnvironmentPermissionLevel.WRITE,
            "variables.delete": EnvironmentPermissionLevel.WRITE,
            "environment.configure": EnvironmentPermissionLevel.ADMIN,
            "environment.debug": EnvironmentPermissionLevel.DEBUG,
        },
        "preview": {
            "flows.create": EnvironmentPermissionLevel.READ,
            "flows.read": EnvironmentPermissionLevel.READ,
            "flows.update": EnvironmentPermissionLevel.NONE,
            "flows.delete": EnvironmentPermissionLevel.NONE,
            "flows.deploy": EnvironmentPermissionLevel.NONE,
            "variables.create": EnvironmentPermissionLevel.NONE,
            "variables.read": EnvironmentPermissionLevel.READ,
            "variables.update": EnvironmentPermissionLevel.NONE,
            "variables.delete": EnvironmentPermissionLevel.NONE,
            "environment.configure": EnvironmentPermissionLevel.NONE,
            "environment.debug": EnvironmentPermissionLevel.NONE,
        }
    }


class EnvironmentPermissionService(Service):
    """Service for managing environment-scoped permissions."""

    name = "environment_permission_service"

    def __init__(self):
        super().__init__()
        self._permission_cache = {}
        self._cache_ttl = 300  # 5 minutes

    async def check_environment_permission(
        self,
        session: AsyncSession,
        user_id: UUIDstr,
        environment_id: UUIDstr,
        permission: str,
        *,
        bypass_cache: bool = False
    ) -> bool:
        """Check if user has permission in specific environment.

        Args:
            session: Database session
            user_id: User ID to check
            environment_id: Environment ID
            permission: Permission to check (e.g., 'flows.deploy')
            bypass_cache: Skip cache and query database

        Returns:
            True if user has permission in environment
        """
        cache_key = f"{user_id}:{environment_id}:{permission}"

        if not bypass_cache and cache_key in self._permission_cache:
            cached_result, timestamp = self._permission_cache[cache_key]
            if (datetime.now(timezone.utc) - timestamp).seconds < self._cache_ttl:
                return cached_result

        try:
            # Get environment details
            from langflow.services.database.models.rbac.environment import Environment

            environment = await session.get(Environment, environment_id)
            if not environment or not environment.is_active:
                return False

            # Check if environment is locked
            if environment.is_locked:
                # Only allow break-glass access for locked environments
                return await self._check_break_glass_permission(
                    session, user_id, environment_id, permission
                )

            # Get user's environment-specific roles
            environment_roles = await self._get_user_environment_roles(
                session, user_id, environment_id
            )

            # Check permission level required for this environment type
            required_level = self._get_required_permission_level(
                environment.type, permission
            )

            # Check if user has sufficient permission level
            has_permission = await self._check_permission_level(
                session, environment_roles, permission, required_level
            )

            # Cache result
            if not bypass_cache:
                self._permission_cache[cache_key] = (
                    has_permission,
                    datetime.now(timezone.utc)
                )

            return has_permission

        except Exception as e:
            logger.error(f"Environment permission check failed: {e}")
            return False

    async def grant_environment_permission(
        self,
        session: AsyncSession,
        user_id: UUIDstr,
        environment_id: UUIDstr,
        permission: str,
        level: EnvironmentPermissionLevel,
        *,
        granted_by: UUIDstr,
        expires_at: datetime | None = None,
        justification: str | None = None
    ) -> bool:
        """Grant specific permission to user in environment.

        Args:
            session: Database session
            user_id: User to grant permission to
            environment_id: Environment ID
            permission: Permission to grant
            level: Permission level to grant
            granted_by: User granting the permission
            expires_at: When permission expires (optional)
            justification: Reason for granting permission

        Returns:
            True if permission was granted successfully
        """
        try:
            from langflow.services.database.models.rbac.role_assignment import RoleAssignment

            # Create environment-specific role assignment
            assignment = RoleAssignment(
                user_id=user_id,
                environment_id=environment_id,
                permission_scope=permission,
                permission_level=level.value,
                granted_by_id=granted_by,
                expires_at=expires_at,
                justification=justification,
                is_temporary=expires_at is not None,
                is_active=True
            )

            session.add(assignment)
            await session.commit()

            # Clear cache for this user/environment
            self._clear_user_cache(user_id, environment_id)

            # Log the permission grant
            await self._log_permission_change(
                session, "permission_granted", user_id, environment_id,
                permission, level.value, granted_by, justification
            )

            return True

        except Exception as e:
            logger.error(f"Failed to grant environment permission: {e}")
            await session.rollback()
            return False

    async def revoke_environment_permission(
        self,
        session: AsyncSession,
        user_id: UUIDstr,
        environment_id: UUIDstr,
        permission: str,
        *,
        revoked_by: UUIDstr,
        reason: str | None = None
    ) -> bool:
        """Revoke specific permission from user in environment.

        Args:
            session: Database session
            user_id: User to revoke permission from
            environment_id: Environment ID
            permission: Permission to revoke
            revoked_by: User revoking the permission
            reason: Reason for revocation

        Returns:
            True if permission was revoked successfully
        """
        try:
            from langflow.services.database.models.rbac.role_assignment import RoleAssignment

            # Find and deactivate the role assignment
            query = select(RoleAssignment).where(
                RoleAssignment.user_id == user_id,
                RoleAssignment.environment_id == environment_id,
                RoleAssignment.permission_scope == permission,
                RoleAssignment.is_active.is_(True)
            )

            result = await session.exec(query)
            assignments = result.all()

            for assignment in assignments:
                assignment.is_active = False
                assignment.revoked_at = datetime.now(timezone.utc)
                assignment.revoked_by_id = revoked_by
                assignment.revoke_reason = reason

            await session.commit()

            # Clear cache
            self._clear_user_cache(user_id, environment_id)

            # Log the permission revocation
            await self._log_permission_change(
                session, "permission_revoked", user_id, environment_id,
                permission, None, revoked_by, reason
            )

            return True

        except Exception as e:
            logger.error(f"Failed to revoke environment permission: {e}")
            await session.rollback()
            return False

    async def get_user_environment_permissions(
        self,
        session: AsyncSession,
        user_id: UUIDstr,
        environment_id: UUIDstr
    ) -> dict[str, EnvironmentPermissionLevel]:
        """Get all permissions for user in specific environment.

        Args:
            session: Database session
            user_id: User ID
            environment_id: Environment ID

        Returns:
            Dictionary of permission to level mappings
        """
        try:
            from langflow.services.database.models.rbac.environment import Environment
            from langflow.services.database.models.rbac.role_assignment import RoleAssignment

            # Get environment
            environment = await session.get(Environment, environment_id)
            if not environment:
                return {}

            # Get user's role assignments for this environment
            query = select(RoleAssignment).where(
                RoleAssignment.user_id == user_id,
                RoleAssignment.environment_id == environment_id,
                RoleAssignment.is_active.is_(True)
            )

            result = await session.exec(query)
            assignments = result.all()

            permissions = {}

            # Process explicit assignments
            for assignment in assignments:
                if assignment.permission_scope and assignment.permission_level:
                    permissions[assignment.permission_scope] = EnvironmentPermissionLevel(
                        assignment.permission_level
                    )

            # Add default permissions based on environment type
            default_perms = EnvironmentPermissionMatrix.DEFAULT_PERMISSIONS.get(
                environment.type.value, {}
            )

            for permission, level in default_perms.items():
                if permission not in permissions:
                    # Check if user has workspace-level access
                    if await self._has_workspace_permission(session, user_id, environment.project.workspace_id, permission):
                        permissions[permission] = level

            return permissions

        except Exception as e:
            logger.error(f"Failed to get user environment permissions: {e}")
            return {}

    async def list_environment_users_with_permissions(
        self,
        session: AsyncSession,
        environment_id: UUIDstr
    ) -> list[dict[str, Any]]:
        """List all users with permissions in environment.

        Args:
            session: Database session
            environment_id: Environment ID

        Returns:
            List of users with their permission details
        """
        try:
            from langflow.services.database.models.rbac.role_assignment import RoleAssignment
            from langflow.services.database.models.user.model import User

            # Get all active role assignments for this environment
            query = select(RoleAssignment, User).join(User).where(
                RoleAssignment.environment_id == environment_id,
                RoleAssignment.is_active.is_(True)
            )

            result = await session.exec(query)
            assignments_with_users = result.all()

            user_permissions = {}

            for assignment, user in assignments_with_users:
                user_id = str(user.id)

                if user_id not in user_permissions:
                    user_permissions[user_id] = {
                        "user_id": user_id,
                        "username": user.username,
                        "email": user.email,
                        "permissions": {},
                        "last_access": None,
                        "assignment_count": 0
                    }

                user_permissions[user_id]["permissions"][assignment.permission_scope] = {
                    "level": assignment.permission_level,
                    "granted_by_id": assignment.granted_by_id,
                    "granted_at": assignment.created_at,
                    "expires_at": assignment.expires_at,
                    "is_temporary": assignment.is_temporary,
                    "justification": assignment.justification
                }
                user_permissions[user_id]["assignment_count"] += 1

            return list(user_permissions.values())

        except Exception as e:
            logger.error(f"Failed to list environment users: {e}")
            return []

    async def promote_to_production(
        self,
        session: AsyncSession,
        source_environment_id: UUIDstr,
        target_environment_id: UUIDstr,
        promoted_by: UUIDstr,
        *,
        approval_required: bool = True,
        auto_approve: bool = False
    ) -> dict[str, Any]:
        """Promote resources from staging to production environment.

        Args:
            session: Database session
            source_environment_id: Source environment (usually staging)
            target_environment_id: Target environment (usually production)
            promoted_by: User performing the promotion
            approval_required: Whether approval is required
            auto_approve: Auto-approve if user has admin permissions

        Returns:
            Promotion result details
        """
        try:
            from langflow.services.database.models.rbac.environment import Environment

            # Get environments
            source_env = await session.get(Environment, source_environment_id)
            target_env = await session.get(Environment, target_environment_id)

            if not source_env or not target_env:
                return {"success": False, "error": "Environment not found"}

            # Check promotion permissions
            can_promote = await self.check_environment_permission(
                session, promoted_by, target_environment_id, "flows.deploy"
            )

            if not can_promote:
                return {"success": False, "error": "Insufficient permissions to promote to production"}

            # Check if approval is required and handle accordingly
            if approval_required and not auto_approve:
                # Create promotion request for approval
                promotion_request = await self._create_promotion_request(
                    session, source_environment_id, target_environment_id, promoted_by
                )
                return {
                    "success": True,
                    "status": "pending_approval",
                    "promotion_request_id": promotion_request["id"]
                }

            # Perform the promotion
            promotion_result = await self._execute_promotion(
                session, source_env, target_env, promoted_by
            )

            return promotion_result

        except Exception as e:
            logger.error(f"Environment promotion failed: {e}")
            return {"success": False, "error": str(e)}

    async def _get_user_environment_roles(
        self,
        session: AsyncSession,
        user_id: UUIDstr,
        environment_id: UUIDstr
    ) -> list["RoleAssignment"]:
        """Get user's role assignments for specific environment."""
        from langflow.services.database.models.rbac.role_assignment import RoleAssignment

        query = select(RoleAssignment).where(
            RoleAssignment.user_id == user_id,
            RoleAssignment.environment_id == environment_id,
            RoleAssignment.is_active.is_(True)
        )

        result = await session.exec(query)
        return result.all()

    def _get_required_permission_level(
        self,
        environment_type: "EnvironmentType",
        permission: str
    ) -> EnvironmentPermissionLevel:
        """Get required permission level for environment type and permission."""
        env_permissions = EnvironmentPermissionMatrix.DEFAULT_PERMISSIONS.get(
            environment_type.value, {}
        )
        return env_permissions.get(permission, EnvironmentPermissionLevel.NONE)

    async def _check_permission_level(
        self,
        session: AsyncSession,
        role_assignments: list["RoleAssignment"],
        permission: str,
        required_level: EnvironmentPermissionLevel
    ) -> bool:
        """Check if role assignments provide sufficient permission level."""
        # Permission level hierarchy
        level_hierarchy = {
            EnvironmentPermissionLevel.NONE: 0,
            EnvironmentPermissionLevel.READ: 1,
            EnvironmentPermissionLevel.WRITE: 2,
            EnvironmentPermissionLevel.DEPLOY: 3,
            EnvironmentPermissionLevel.DEBUG: 3,
            EnvironmentPermissionLevel.ADMIN: 4
        }

        required_rank = level_hierarchy.get(required_level, 0)

        for assignment in role_assignments:
            if assignment.permission_scope == permission:
                user_level = EnvironmentPermissionLevel(assignment.permission_level)
                user_rank = level_hierarchy.get(user_level, 0)

                if user_rank >= required_rank:
                    return True

        return False

    async def _check_break_glass_permission(
        self,
        session: AsyncSession,
        user_id: UUIDstr,
        environment_id: UUIDstr,
        permission: str
    ) -> bool:
        """Check break-glass emergency access permissions."""
        # This will be implemented in the break-glass module
        # For now, only allow admin users
        from langflow.services.database.models.user.model import User

        user = await session.get(User, user_id)
        return user and user.is_superuser

    async def _has_workspace_permission(
        self,
        session: AsyncSession,
        user_id: UUIDstr,
        workspace_id: UUIDstr,
        permission: str
    ) -> bool:
        """Check if user has workspace-level permission."""
        # Check workspace role assignments
        from langflow.services.database.models.rbac.role_assignment import RoleAssignment

        query = select(RoleAssignment).where(
            RoleAssignment.user_id == user_id,
            RoleAssignment.workspace_id == workspace_id,
            RoleAssignment.is_active.is_(True)
        )

        result = await session.exec(query)
        assignments = result.all()

        # Simple check - expand based on actual permission system
        return len(assignments) > 0

    def _clear_user_cache(self, user_id: UUIDstr, environment_id: UUIDstr) -> None:
        """Clear permission cache for user/environment."""
        keys_to_remove = [
            key for key in self._permission_cache.keys()
            if key.startswith(f"{user_id}:{environment_id}:")
        ]

        for key in keys_to_remove:
            del self._permission_cache[key]

    async def _log_permission_change(
        self,
        session: AsyncSession,
        event_type: str,
        user_id: UUIDstr,
        environment_id: UUIDstr,
        permission: str,
        level: str | None,
        changed_by: UUIDstr,
        reason: str | None
    ) -> None:
        """Log permission change for audit purposes."""
        from langflow.services.database.models.rbac.audit_log import AuditEventType, AuditLog

        audit_log = AuditLog(
            event_type=AuditEventType.PERMISSION_GRANTED if "granted" in event_type else AuditEventType.PERMISSION_REVOKED,
            action=f"environment_{event_type}",
            outcome="success",
            actor_type="user",
            actor_id=changed_by,
            resource_type="environment_permission",
            resource_id=environment_id,
            environment_id=environment_id,
            event_metadata={
                "target_user_id": user_id,
                "permission": permission,
                "level": level,
                "reason": reason
            }
        )

        session.add(audit_log)
        await session.commit()

    async def _create_promotion_request(
        self,
        session: AsyncSession,
        source_environment_id: UUIDstr,
        target_environment_id: UUIDstr,
        requested_by: UUIDstr
    ) -> dict[str, Any]:
        """Create a promotion request for approval workflow."""
        # This would integrate with an approval workflow system
        # For now, return a placeholder
        return {
            "id": "promotion_request_123",
            "status": "pending",
            "source_environment_id": source_environment_id,
            "target_environment_id": target_environment_id,
            "requested_by": requested_by,
            "created_at": datetime.now(timezone.utc)
        }

    async def _execute_promotion(
        self,
        session: AsyncSession,
        source_env: "Environment",
        target_env: "Environment",
        promoted_by: UUIDstr
    ) -> dict[str, Any]:
        """Execute the actual promotion between environments."""
        # This would copy flows, variables, etc. from source to target
        # For now, return a success placeholder
        return {
            "success": True,
            "promoted_flows": 0,
            "promoted_variables": 0,
            "promotion_id": "promotion_123",
            "promoted_at": datetime.now(timezone.utc)
        }
