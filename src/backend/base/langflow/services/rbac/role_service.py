"""Role hierarchy and management service for RBAC system.

This module provides role hierarchy logic, inheritance management, and role
validation following LangBuilder service patterns.
"""

# NO future annotations per Phase 1 requirements
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Optional
from uuid import UUID

from loguru import logger
from pydantic import BaseModel
from sqlmodel import or_, select
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.schema.serialize import UUIDstr
from langflow.services.base import Service

if TYPE_CHECKING:
    from langflow.services.database.models.rbac.role import Role
    from langflow.services.database.models.user.model import User


class RoleType(str, Enum):
    """Role types in the hierarchy."""

    SYSTEM = "system"          # Built-in system roles
    WORKSPACE = "workspace"    # Workspace-scoped roles
    PROJECT = "project"        # Project-scoped roles
    ENVIRONMENT = "environment" # Environment-scoped roles
    CUSTOM = "custom"          # User-defined roles


class RoleScope(str, Enum):
    """Role scope levels."""

    GLOBAL = "global"          # System-wide scope
    WORKSPACE = "workspace"    # Workspace scope
    PROJECT = "project"        # Project scope
    ENVIRONMENT = "environment" # Environment scope


@dataclass
class RoleValidationResult:
    """Result of role validation operation."""

    is_valid: bool
    errors: list[str]
    warnings: list[str]
    suggested_permissions: list[str] | None = None


@dataclass
class RoleHierarchyNode:
    """Node in role hierarchy tree."""

    role_id: UUID
    role_name: str
    role_type: RoleType
    parent_role_id: UUID | None
    children: list["RoleHierarchyNode"]
    permissions: set[str]
    inherited_permissions: set[str]
    level: int  # Distance from root


class RoleHierarchy(BaseModel):
    """Complete role hierarchy representation."""

    root_roles: list[RoleHierarchyNode]
    total_roles: int
    max_depth: int
    circular_dependencies: list[str]
    orphaned_roles: list[str]


class PermissionInheritanceTrace(BaseModel):
    """Trace of permission inheritance through role hierarchy."""

    permission: str
    inheritance_path: list[str]  # Role names in inheritance order
    direct_grant: bool
    inherited_from: str | None


class RoleService(Service):
    """Role hierarchy and management service following LangBuilder patterns.

    Provides comprehensive role management including:
    - Hierarchical role structures with inheritance
    - Role validation and conflict detection
    - Permission aggregation and resolution
    - Role template management
    - Bulk role operations with validation
    - Performance-optimized hierarchy traversal
    """

    name = "role_service"

    def __init__(self):
        """Initialize role service."""
        self._hierarchy_cache: RoleHierarchy | None = None
        self._cache_expires_at: datetime | None = None
        self._cache_ttl = 300  # 5 minutes

        # Built-in system roles
        self._system_roles = {
            "system_admin": {
                "name": "System Administrator",
                "description": "Full system access with all permissions",
                "permissions": ["*"],  # Wildcard for all permissions
                "type": RoleType.SYSTEM,
                "scope": RoleScope.GLOBAL,
            },
            "workspace_owner": {
                "name": "Workspace Owner",
                "description": "Full access within workspace scope",
                "permissions": [
                    "workspace:*",
                    "project:*",
                    "environment:*",
                    "flow:*",
                    "invite_users",
                    "manage_roles",
                ],
                "type": RoleType.SYSTEM,
                "scope": RoleScope.WORKSPACE,
            },
            "project_admin": {
                "name": "Project Administrator",
                "description": "Full access within project scope",
                "permissions": [
                    "project:read",
                    "project:update",
                    "environment:*",
                    "flow:*",
                    "deploy_environment",
                ],
                "type": RoleType.SYSTEM,
                "scope": RoleScope.PROJECT,
            },
            "editor": {
                "name": "Editor",
                "description": "Read and write access to flows and components",
                "permissions": [
                    "flow:read",
                    "flow:create",
                    "flow:update",
                    "component:read",
                    "component:update",
                    "environment:read",
                ],
                "type": RoleType.SYSTEM,
                "scope": RoleScope.PROJECT,
            },
            "viewer": {
                "name": "Viewer",
                "description": "Read-only access to flows and components",
                "permissions": [
                    "flow:read",
                    "component:read",
                    "environment:read",
                ],
                "type": RoleType.SYSTEM,
                "scope": RoleScope.PROJECT,
            },
        }

    async def create_role(
        self,
        session: AsyncSession,
        name: str,
        description: str,
        permissions: list[str],
        role_type: RoleType = RoleType.CUSTOM,
        scope: RoleScope = RoleScope.WORKSPACE,
        parent_role_id: UUIDstr | None = None,
        workspace_id: UUIDstr | None = None,
        created_by: Optional["User"] = None,
    ) -> "Role":
        """Create new role with validation and hierarchy checking.

        Args:
            session: Database session
            name: Role name
            description: Role description
            permissions: List of permission codes
            role_type: Type of role being created
            scope: Scope level for the role
            parent_role_id: Optional parent role for inheritance
            workspace_id: Workspace scope (if applicable)
            created_by: User creating the role

        Returns:
            Created role object
        """
        from langflow.services.database.models.rbac.role import Role

        # Validate role creation
        validation = await self.validate_role_creation(
            session=session,
            name=name,
            permissions=permissions,
            parent_role_id=parent_role_id,
            workspace_id=workspace_id,
        )

        if not validation.is_valid:
            raise ValueError(f"Role validation failed: {', '.join(validation.errors)}")

        # Check if role name already exists in scope
        existing_query = select(Role).where(Role.name == name, Role.is_active == True)
        if workspace_id:
            existing_query = existing_query.where(Role.workspace_id == workspace_id)
        else:
            existing_query = existing_query.where(Role.workspace_id is None)

        existing_result = await session.exec(existing_query)
        existing_role = existing_result.first()

        if existing_role:
            raise ValueError(f"Role '{name}' already exists in this scope")

        # Create role
        role_data = {
            "name": name,
            "description": description,
            "role_type": role_type.value,
            "scope": scope.value,
            "parent_role_id": UUID(parent_role_id) if parent_role_id else None,
            "workspace_id": UUID(workspace_id) if workspace_id else None,
            "created_by_id": created_by.id if created_by else None,
            "is_active": True,
            "is_system": role_type == RoleType.SYSTEM,
        }

        role = Role(**role_data)
        session.add(role)
        await session.commit()
        await session.refresh(role)

        # Add permissions to role
        await self._assign_permissions_to_role(session, role, permissions)

        # Invalidate hierarchy cache
        self._invalidate_hierarchy_cache()

        logger.info(f"Created role '{name}' with {len(permissions)} permissions")

        return role

    async def update_role_permissions(
        self,
        session: AsyncSession,
        role_id: UUIDstr,
        permissions: list[str],
        updated_by: Optional["User"] = None,
    ) -> "Role":
        """Update role permissions with validation.

        Args:
            session: Database session
            role_id: Role to update
            permissions: New list of permission codes
            updated_by: User performing the update

        Returns:
            Updated role object
        """
        from langflow.services.database.models.rbac.permission import RolePermission
        from langflow.services.database.models.rbac.role import Role

        role = await session.get(Role, role_id)
        if not role:
            raise ValueError(f"Role {role_id} not found")

        if not role.is_active:
            raise ValueError(f"Role {role_id} is not active")

        if role.is_system:
            raise ValueError("Cannot modify system role permissions")

        # Validate permissions
        validation = await self.validate_permissions(session, permissions)
        if not validation.is_valid:
            raise ValueError(f"Permission validation failed: {', '.join(validation.errors)}")

        # Remove existing permissions
        delete_query = select(RolePermission).where(RolePermission.role_id == role.id)
        delete_result = await session.exec(delete_query)
        for role_perm in delete_result.all():
            await session.delete(role_perm)

        # Add new permissions
        await self._assign_permissions_to_role(session, role, permissions)

        # Update role metadata
        role.updated_at = datetime.now(timezone.utc)
        if updated_by:
            role.updated_by_id = updated_by.id

        await session.commit()

        # Invalidate hierarchy cache
        self._invalidate_hierarchy_cache()

        logger.info(f"Updated permissions for role '{role.name}' - {len(permissions)} permissions")

        return role

    async def get_role_hierarchy(
        self,
        session: AsyncSession,
        workspace_id: UUIDstr | None = None,
        refresh_cache: bool = False,
    ) -> RoleHierarchy:
        """Get complete role hierarchy with inheritance.

        Args:
            session: Database session
            workspace_id: Optional workspace scope
            refresh_cache: Force cache refresh

        Returns:
            Complete role hierarchy
        """
        # Check cache
        if (not refresh_cache and
            self._hierarchy_cache and
            self._cache_expires_at and
            datetime.now(timezone.utc) < self._cache_expires_at):
            return self._hierarchy_cache

        from langflow.services.database.models.rbac.role import Role

        # Get all roles in scope
        query = select(Role).where(Role.is_active == True)
        if workspace_id:
            query = query.where(
                or_(
                    Role.workspace_id == workspace_id,
                    Role.workspace_id is None  # Include global roles
                )
            )

        result = await session.exec(query)
        roles = result.all()

        # Build hierarchy
        role_nodes = {}
        root_roles = []
        circular_deps = []
        orphaned_roles = []

        # Create nodes
        for role in roles:
            permissions = await self._get_role_permissions(session, role)
            node = RoleHierarchyNode(
                role_id=role.id,
                role_name=role.name,
                role_type=RoleType(role.role_type),
                parent_role_id=role.parent_role_id,
                children=[],
                permissions=set(permissions),
                inherited_permissions=set(),
                level=0,
            )
            role_nodes[role.id] = node

        # Build parent-child relationships
        for node in role_nodes.values():
            if node.parent_role_id:
                if node.parent_role_id in role_nodes:
                    parent_node = role_nodes[node.parent_role_id]
                    parent_node.children.append(node)
                else:
                    orphaned_roles.append(node.role_name)
            else:
                root_roles.append(node)

        # Calculate inheritance and detect circular dependencies
        visited = set()
        max_depth = 0

        for root in root_roles:
            depth = self._calculate_inheritance(root, visited, circular_deps, 0)
            max_depth = max(max_depth, depth)

        # Cache result
        hierarchy = RoleHierarchy(
            root_roles=root_roles,
            total_roles=len(roles),
            max_depth=max_depth,
            circular_dependencies=circular_deps,
            orphaned_roles=orphaned_roles,
        )

        self._hierarchy_cache = hierarchy
        self._cache_expires_at = datetime.now(timezone.utc) + timedelta(seconds=self._cache_ttl)

        return hierarchy

    async def get_effective_permissions(
        self,
        session: AsyncSession,
        user: "User",
        workspace_id: UUIDstr | None = None,
        project_id: UUIDstr | None = None,
        environment_id: UUIDstr | None = None,
    ) -> set[str]:
        """Get effective permissions for user considering role hierarchy.

        Args:
            session: Database session
            user: User to get permissions for
            workspace_id: Workspace context
            project_id: Project context
            environment_id: Environment context

        Returns:
            Set of effective permission codes
        """
        from langflow.services.database.models.rbac.role_assignment import RoleAssignment

        # Get user's active role assignments
        assignment_query = select(RoleAssignment).where(
            RoleAssignment.user_id == user.id,
            RoleAssignment.is_active == True,
        )

        # Apply scope filters
        if workspace_id:
            assignment_query = assignment_query.where(
                or_(
                    RoleAssignment.workspace_id == workspace_id,
                    RoleAssignment.workspace_id is None  # System-wide roles
                )
            )

        if project_id:
            assignment_query = assignment_query.where(
                or_(
                    RoleAssignment.project_id == project_id,
                    RoleAssignment.project_id is None
                )
            )

        if environment_id:
            assignment_query = assignment_query.where(
                or_(
                    RoleAssignment.environment_id == environment_id,
                    RoleAssignment.environment_id is None
                )
            )

        assignment_result = await session.exec(assignment_query)
        assignments = assignment_result.all()

        # Collect permissions from all assigned roles
        effective_permissions = set()

        for assignment in assignments:
            role_permissions = await self.get_role_effective_permissions(
                session, assignment.role_id
            )
            effective_permissions.update(role_permissions)

        return effective_permissions

    async def get_role_effective_permissions(
        self,
        session: AsyncSession,
        role_id: UUIDstr,
    ) -> set[str]:
        """Get effective permissions for role including inherited permissions.

        Args:
            session: Database session
            role_id: Role ID to get permissions for

        Returns:
            Set of effective permission codes
        """
        from langflow.services.database.models.rbac.role import Role

        role = await session.get(Role, role_id)
        if not role or not role.is_active:
            return set()

        # Get direct permissions
        direct_permissions = await self._get_role_permissions(session, role)
        effective_permissions = set(direct_permissions)

        # Add inherited permissions from parent roles
        if role.parent_role_id:
            parent_permissions = await self.get_role_effective_permissions(
                session, str(role.parent_role_id)
            )
            effective_permissions.update(parent_permissions)

        return effective_permissions

    async def trace_permission_inheritance(
        self,
        session: AsyncSession,
        role_id: UUIDstr,
        permission: str,
    ) -> PermissionInheritanceTrace:
        """Trace how a permission is inherited through role hierarchy.

        Args:
            session: Database session
            role_id: Role to trace permission for
            permission: Permission code to trace

        Returns:
            Inheritance trace showing path
        """
        from langflow.services.database.models.rbac.role import Role

        role = await session.get(Role, role_id)
        if not role:
            return PermissionInheritanceTrace(
                permission=permission,
                inheritance_path=[],
                direct_grant=False,
                inherited_from=None,
            )

        inheritance_path = [role.name]

        # Check direct grant
        direct_permissions = await self._get_role_permissions(session, role)
        if permission in direct_permissions:
            return PermissionInheritanceTrace(
                permission=permission,
                inheritance_path=inheritance_path,
                direct_grant=True,
                inherited_from=None,
            )

        # Trace through parent hierarchy
        current_role = role
        while current_role.parent_role_id:
            parent = await session.get(Role, current_role.parent_role_id)
            if not parent:
                break

            inheritance_path.append(parent.name)

            parent_permissions = await self._get_role_permissions(session, parent)
            if permission in parent_permissions:
                return PermissionInheritanceTrace(
                    permission=permission,
                    inheritance_path=inheritance_path,
                    direct_grant=False,
                    inherited_from=parent.name,
                )

            current_role = parent

        # Permission not found
        return PermissionInheritanceTrace(
            permission=permission,
            inheritance_path=inheritance_path,
            direct_grant=False,
            inherited_from=None,
        )

    async def validate_role_creation(
        self,
        session: AsyncSession,
        name: str,
        permissions: list[str],
        parent_role_id: UUIDstr | None = None,
        workspace_id: UUIDstr | None = None,
    ) -> RoleValidationResult:
        """Validate role creation parameters.

        Args:
            session: Database session
            name: Proposed role name
            permissions: Proposed permissions
            parent_role_id: Optional parent role
            workspace_id: Workspace scope

        Returns:
            Validation result with errors and warnings
        """
        errors = []
        warnings = []
        suggested_permissions = []

        # Validate name
        if not name or len(name.strip()) < 2:
            errors.append("Role name must be at least 2 characters long")

        if len(name) > 100:
            errors.append("Role name must be less than 100 characters")

        # Validate permissions
        permission_validation = await self.validate_permissions(session, permissions)
        if not permission_validation.is_valid:
            errors.extend(permission_validation.errors)

        # Validate parent role
        if parent_role_id:
            from langflow.services.database.models.rbac.role import Role

            parent = await session.get(Role, parent_role_id)
            if not parent:
                errors.append(f"Parent role {parent_role_id} not found")
            elif not parent.is_active:
                errors.append(f"Parent role {parent_role_id} is not active")
            else:
                # Check for circular dependency
                if await self._would_create_circular_dependency(session, parent_role_id, None):
                    errors.append("Parent role assignment would create circular dependency")

                # Check permission inheritance conflicts
                parent_permissions = await self.get_role_effective_permissions(session, parent_role_id)
                redundant_permissions = set(permissions) & parent_permissions
                if redundant_permissions:
                    warnings.append(f"Permissions already inherited from parent: {', '.join(redundant_permissions)}")

        # Suggest complementary permissions
        if "read" in [p.split(":")[-1] for p in permissions]:
            if not any("update" in p for p in permissions):
                suggested_permissions.append("Consider adding update permissions")

        return RoleValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            suggested_permissions=suggested_permissions,
        )

    async def validate_permissions(
        self,
        session: AsyncSession,
        permissions: list[str],
    ) -> RoleValidationResult:
        """Validate permission codes.

        Args:
            session: Database session
            permissions: List of permission codes to validate

        Returns:
            Validation result
        """
        from langflow.services.database.models.rbac.permission import Permission

        errors = []
        warnings = []

        if not permissions:
            errors.append("At least one permission is required")
            return RoleValidationResult(is_valid=False, errors=errors, warnings=warnings)

        # Get all valid permissions
        valid_perms_query = select(Permission).where(Permission.is_active == True)
        valid_perms_result = await session.exec(valid_perms_query)
        valid_permissions = {perm.code for perm in valid_perms_result.all()}

        # Validate each permission
        for permission in permissions:
            if permission == "*":  # Wildcard permission
                warnings.append("Wildcard permission grants all access")
                continue

            if permission not in valid_permissions:
                errors.append(f"Invalid permission code: {permission}")

        # Check for redundant permissions
        duplicates = set([p for p in permissions if permissions.count(p) > 1])
        if duplicates:
            warnings.append(f"Duplicate permissions: {', '.join(duplicates)}")

        return RoleValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
        )

    async def _assign_permissions_to_role(
        self,
        session: AsyncSession,
        role: "Role",
        permissions: list[str],
    ) -> None:
        """Assign permissions to role."""
        from langflow.services.database.models.rbac.permission import Permission, RolePermission

        for permission_code in permissions:
            # Handle wildcard permission
            if permission_code == "*":
                # Create special wildcard permission entry
                role_perm = RolePermission(
                    role_id=role.id,
                    permission_id=None,  # Special case for wildcard
                    permission_code="*",
                    is_granted=True,
                )
                session.add(role_perm)
                continue

            # Find permission by code
            perm_query = select(Permission).where(Permission.code == permission_code)
            perm_result = await session.exec(perm_query)
            permission = perm_result.first()

            if permission:
                role_perm = RolePermission(
                    role_id=role.id,
                    permission_id=permission.id,
                    permission_code=permission_code,
                    is_granted=True,
                )
                session.add(role_perm)

        await session.commit()

    async def _get_role_permissions(
        self,
        session: AsyncSession,
        role: "Role",
    ) -> list[str]:
        """Get direct permissions for role."""
        from langflow.services.database.models.rbac.permission import RolePermission

        query = select(RolePermission).where(
            RolePermission.role_id == role.id,
            RolePermission.is_granted == True,
        )

        result = await session.exec(query)
        role_permissions = result.all()

        return [rp.permission_code for rp in role_permissions]

    def _calculate_inheritance(
        self,
        node: RoleHierarchyNode,
        visited: set[UUID],
        circular_deps: list[str],
        level: int,
    ) -> int:
        """Calculate permission inheritance and detect circular dependencies."""
        if node.role_id in visited:
            circular_deps.append(node.role_name)
            return level

        visited.add(node.role_id)
        node.level = level

        max_child_depth = level

        # Process children
        for child in node.children:
            child_depth = self._calculate_inheritance(child, visited.copy(), circular_deps, level + 1)
            max_child_depth = max(max_child_depth, child_depth)

            # Inherit permissions from parent
            child.inherited_permissions.update(node.permissions)
            child.inherited_permissions.update(node.inherited_permissions)

        return max_child_depth

    async def _would_create_circular_dependency(
        self,
        session: AsyncSession,
        parent_role_id: UUIDstr,
        child_role_id: UUIDstr | None,
    ) -> bool:
        """Check if role assignment would create circular dependency."""
        if not child_role_id:
            return False

        from langflow.services.database.models.rbac.role import Role

        # Traverse up the hierarchy from parent to see if we reach child
        current_id = UUID(parent_role_id)
        visited = set()

        while current_id and current_id not in visited:
            if str(current_id) == child_role_id:
                return True

            visited.add(current_id)

            role = await session.get(Role, current_id)
            if not role:
                break

            current_id = role.parent_role_id

        return False

    def _invalidate_hierarchy_cache(self) -> None:
        """Invalidate cached role hierarchy."""
        self._hierarchy_cache = None
        self._cache_expires_at = None
