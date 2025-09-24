"""RBAC dependencies for FastAPI endpoints."""

# NO future annotations per Phase 1 requirements
# from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import TYPE_CHECKING

from fastapi import Depends, HTTPException, Path, status
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.api.utils import CurrentActiveUser, get_session
from langflow.schema.serialize import UUIDstr
from langflow.services.rbac.audit_service import AuditService
from langflow.services.rbac.permission_engine import PermissionEngine

if TYPE_CHECKING:
    from langflow.services.database.models.flow.model import Flow
    from langflow.services.database.models.rbac.environment import Environment
    from langflow.services.database.models.rbac.project import Project
    from langflow.services.database.models.rbac.role import Role
    from langflow.services.database.models.rbac.workspace import Workspace
    from langflow.services.database.models.user.model import User

# NO direct model imports at module level to prevent circular dependencies
# Models will be imported inside functions where needed


class PermissionChecker:
    """Permission checking utility class for RBAC system."""

    def __init__(self, session: AsyncSession, user: "User"):
        self.session = session
        self.user = user

    def has_workspace_permission(self, workspace: "Workspace", action: str) -> bool:
        """Check if user has permission on workspace."""
        # Superuser always has access
        if self.user.is_superuser:
            return True

        # Owner has full access
        if workspace.owner_id == self.user.id:
            return True

        # For now, implement basic permission checking
        # In a full implementation, this would check role assignments
        return False

    def has_project_permission(self, project: "Project", action: str) -> bool:
        """Check if user has permission on project."""
        # Superuser always has access
        if self.user.is_superuser:
            return True

        # Check workspace permission (inherits from workspace)
        if hasattr(project, "workspace"):
            workspace = project.workspace
        else:
            # Need to fetch workspace
            return self.user.is_superuser

        return self.has_workspace_permission(workspace, action)

    def has_environment_permission(self, environment: "Environment", action: str) -> bool:
        """Check if user has permission on environment."""
        # Superuser always has access
        if self.user.is_superuser:
            return True

        # Check project permission (inherits from project)
        if hasattr(environment, "project"):
            project = environment.project
            return self.has_project_permission(project, action)

        return False

    def has_flow_permission(self, flow: "Flow", action: str) -> bool:
        """Check if user has permission on flow."""
        # Superuser always has access
        if self.user.is_superuser:
            return True

        # Flow owner has access
        if hasattr(flow, "user_id") and flow.user_id == self.user.id:
            return True

        return False

    def has_role_permission(self, role: "Role", action: str) -> bool:
        """Check if user has permission on role."""
        # Superuser always has access
        if self.user.is_superuser:
            return True

        # Check workspace permission
        if hasattr(role, "workspace"):
            workspace = role.workspace
            return self.has_workspace_permission(workspace, action)

        return False


async def get_workspace_by_id(
    workspace_id: UUIDstr = Path(...),
    session: AsyncSession = Depends(get_session),
) -> "Workspace":
    """Get workspace by ID or raise 404."""
    from langflow.services.database.models.rbac.workspace import Workspace

    workspace = await session.get(Workspace, workspace_id)
    if not workspace or workspace.is_deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Workspace not found",
        )
    return workspace


async def get_project_by_id(
    project_id: UUIDstr = Path(...),
    session: AsyncSession = Depends(get_session),
) -> "Project":
    """Get project by ID or raise 404."""
    from langflow.services.database.models.rbac.project import Project

    project = await session.get(Project, project_id)
    if not project or not project.is_active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    return project


async def get_environment_by_id(
    environment_id: UUIDstr = Path(...),
    session: AsyncSession = Depends(get_session),
) -> "Environment":
    """Get environment by ID or raise 404."""
    from langflow.services.database.models.rbac.environment import Environment

    environment = await session.get(Environment, environment_id)
    if not environment or not environment.is_active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Environment not found"
        )
    return environment


async def get_role_by_id(
    role_id: UUIDstr = Path(...),
    session: AsyncSession = Depends(get_session),
) -> "Role":
    """Get role by ID or raise 404."""
    from langflow.services.database.models.rbac.role import Role

    role = await session.get(Role, role_id)
    if not role or not role.is_active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )
    return role


async def get_flow_by_id(
    flow_id: UUIDstr = Path(...),
    session: AsyncSession = Depends(get_session),
) -> "Flow":
    """Get flow by ID or raise 404."""
    from langflow.services.database.models.flow.model import Flow

    flow = await session.get(Flow, flow_id)
    if not flow:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Flow not found"
        )
    return flow


# Permission engine instance (singleton)
_permission_engine = PermissionEngine()


async def get_permission_engine() -> PermissionEngine:
    """Get the permission engine instance."""
    return _permission_engine


def check_workspace_permission(permission: str):
    """Dependency factory for workspace permission checking."""
    async def dependency(
        current_user: CurrentActiveUser,
        workspace: "Workspace" = Depends(get_workspace_by_id),
        session: AsyncSession = Depends(get_session),
        permission_engine: PermissionEngine = Depends(get_permission_engine),
    ) -> "Workspace":
        result = await permission_engine.check_permission(
            session=session,
            user=current_user,
            resource_type="workspace",
            action=permission.split(":")[-1],
            resource_id=workspace.id,
            workspace_id=workspace.id,
        )

        if not result.allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions: {permission}. Reason: {result.reason}"
            )
        return workspace

    return dependency


def check_project_permission(permission: str):
    """Dependency factory for project permission checking."""
    async def dependency(
        current_user: CurrentActiveUser,
        project: "Project" = Depends(get_project_by_id),
        session: AsyncSession = Depends(get_session),
        permission_engine: PermissionEngine = Depends(get_permission_engine),
    ) -> "Project":
        result = await permission_engine.check_permission(
            session=session,
            user=current_user,
            resource_type="project",
            action=permission.split(":")[-1],
            resource_id=project.id,
            workspace_id=project.workspace_id,
            project_id=project.id,
        )

        if not result.allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions: {permission}. Reason: {result.reason}"
            )
        return project

    return dependency


def check_environment_permission(permission: str):
    """Dependency factory for environment permission checking."""
    async def dependency(
        current_user: CurrentActiveUser,
        environment: "Environment" = Depends(get_environment_by_id),
        session: AsyncSession = Depends(get_session),
        permission_engine: PermissionEngine = Depends(get_permission_engine),
    ) -> "Environment":
        # Get workspace_id via proper relationship loading
        workspace_id = None
        if environment.project_id:
            from langflow.services.database.models.rbac.project import Project
            project = await session.get(Project, environment.project_id)
            if project:
                workspace_id = project.workspace_id

        result = await permission_engine.check_permission(
            session=session,
            user=current_user,
            resource_type="environment",
            action=permission.split(":")[-1],
            resource_id=environment.id,
            workspace_id=workspace_id,
            project_id=environment.project_id,
            environment_id=environment.id,
        )

        if not result.allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions: {permission}. Reason: {result.reason}"
            )
        return environment

    return dependency


def check_flow_permission(permission: str):
    """Dependency factory for flow permission checking."""
    async def dependency(
        current_user: CurrentActiveUser,
        flow: "Flow" = Depends(get_flow_by_id),
        session: AsyncSession = Depends(get_session),
        permission_engine: PermissionEngine = Depends(get_permission_engine),
    ) -> "Flow":
        result = await permission_engine.check_permission(
            session=session,
            user=current_user,
            resource_type="flow",
            action=permission.split(":")[-1],
            resource_id=flow.id,
            workspace_id=getattr(flow, "workspace_id", None),
            project_id=getattr(flow, "project_id", None),
            environment_id=getattr(flow, "environment_id", None),
        )

        if not result.allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions: {permission}. Reason: {result.reason}"
            )
        return flow

    return dependency


def check_role_permission(permission: str):
    """Dependency factory for role permission checking."""
    async def dependency(
        current_user: CurrentActiveUser,
        role: "Role" = Depends(get_role_by_id),
        session: AsyncSession = Depends(get_session),
        permission_engine: PermissionEngine = Depends(get_permission_engine),
    ) -> "Role":
        result = await permission_engine.check_permission(
            session=session,
            user=current_user,
            resource_type="role",
            action=permission.split(":")[-1],
            resource_id=role.id,
            workspace_id=role.workspace_id,
        )

        if not result.allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions: {permission}. Reason: {result.reason}"
            )
        return role

    return dependency


def require_permission(permission: str):
    """Decorator for checking permissions in route handlers."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # This is a placeholder - would need proper implementation
            # based on the specific resource type and context
            return await func(*args, **kwargs)
        return wrapper
    return decorator


async def check_api_key_permissions(
    api_key: str,
    permission: str,
    resource_type: str,
    resource_id: UUIDstr | None = None,
    session: AsyncSession = Depends(get_session),
) -> bool:
    """Check if API key has required permissions for resource."""
    from langflow.services.database.models.api_key.model import ApiKey

    # Get API key from database using async SQLModel pattern
    statement = select(ApiKey).where(
        ApiKey.api_key == api_key,
        ApiKey.is_active == True
    )
    result = await session.exec(statement)
    db_api_key = result.first()

    if not db_api_key:
        return False

    # Update last used timestamp
    from datetime import datetime, timezone
    db_api_key.last_used_at = datetime.now(timezone.utc)
    db_api_key.total_uses += 1
    await session.commit()

    # Check if API key has scoped permissions
    if db_api_key.scoped_permissions:
        permission_code = f"{resource_type}:{permission}"
        if permission_code not in db_api_key.scoped_permissions:
            return False

    # Check scope restrictions
    if db_api_key.scope_type and db_api_key.scope_id:
        if resource_type != db_api_key.scope_type:
            return False
        if resource_id and str(resource_id) != str(db_api_key.scope_id):
            return False

    return True


def get_audit_service() -> AuditService:
    """Get audit service instance."""
    return AuditService()


def create_audit_context(
    workspace_id: UUIDstr | None = None,
    client_ip: str | None = None,
    user_agent: str | None = None,
    session_id: str | None = None,
    request_id: str | None = None,
    **additional_data
) -> "AuditContext":
    """Create audit context for logging."""
    from langflow.services.rbac.audit_service import AuditContext

    return AuditContext(
        workspace_id=workspace_id,
        client_ip=client_ip,
        user_agent=user_agent,
        session_id=session_id,
        request_id=request_id,
        additional_data=additional_data
    )
