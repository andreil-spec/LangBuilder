"""RBAC permission decorators for API endpoints.

This module provides decorators and dependency injection functions for enforcing
RBAC permissions in FastAPI endpoints following LangBuilder patterns.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, status
from loguru import logger
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.api.utils import CurrentActiveUser, DbSession
from langflow.services.rbac.permission_engine import PermissionEngine, PermissionResult

if TYPE_CHECKING:
    from langflow.services.database.models.user.model import User


# Dependency to get permission engine
async def get_permission_engine() -> PermissionEngine:
    """Get permission engine instance.

    Returns:
        PermissionEngine: Permission engine for checking permissions
    """
    # Create permission engine instance
    # In production, this would be injected from a service
    return PermissionEngine()


# Type alias for permission engine dependency
PermissionEngineDep = Annotated[PermissionEngine, Depends(get_permission_engine)]


class PermissionRequirement:
    """Class to represent permission requirements for endpoints."""

    def __init__(
        self,
        resource_type: str,
        action: str,
        resource_id_param: str | None = None,
        workspace_id_param: str | None = None,
        project_id_param: str | None = None,
        environment_id_param: str | None = None,
    ):
        """Initialize permission requirement.

        Args:
            resource_type: Type of resource (workspace, project, flow, etc.)
            action: Action being performed (create, read, update, delete, etc.)
            resource_id_param: Name of parameter containing resource ID
            workspace_id_param: Name of parameter containing workspace ID
            project_id_param: Name of parameter containing project ID
            environment_id_param: Name of parameter containing environment ID
        """
        self.resource_type = resource_type
        self.action = action
        self.resource_id_param = resource_id_param
        self.workspace_id_param = workspace_id_param
        self.project_id_param = project_id_param
        self.environment_id_param = environment_id_param


def require_permission(
    resource_type: str,
    action: str,
    resource_id_param: str | None = None,
    workspace_id_param: str | None = "workspace_id",
    project_id_param: str | None = "project_id",
    environment_id_param: str | None = "environment_id",
) -> Callable:
    """Decorator to require specific permission for endpoint access.

    Args:
        resource_type: Type of resource being accessed
        action: Action being performed
        resource_id_param: Parameter name containing resource ID
        workspace_id_param: Parameter name containing workspace ID
        project_id_param: Parameter name containing project ID
        environment_id_param: Parameter name containing environment ID

    Returns:
        Callable: Decorator function

    Example:
        @require_permission("flow", "read", resource_id_param="flow_id")
        async def get_flow(flow_id: UUID, user: CurrentActiveUser, ...):
            # This endpoint requires 'read' permission on 'flow' resource
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract required parameters
            session = None
            user = None
            permission_engine = None

            # Find session, user, and permission engine from kwargs
            for key, value in kwargs.items():
                if isinstance(value, AsyncSession):
                    session = value
                elif hasattr(value, "id") and hasattr(value, "username"):  # User-like object
                    user = value
                elif isinstance(value, PermissionEngine):
                    permission_engine = value

            if not session:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Database session not found in endpoint parameters"
                )

            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User authentication required"
                )

            if not permission_engine:
                permission_engine = PermissionEngine()

            # Extract resource IDs from parameters
            resource_id = kwargs.get(resource_id_param) if resource_id_param else None
            workspace_id = kwargs.get(workspace_id_param) if workspace_id_param else None
            project_id = kwargs.get(project_id_param) if project_id_param else None
            environment_id = kwargs.get(environment_id_param) if environment_id_param else None

            # Check permission
            try:
                result = await permission_engine.check_permission(
                    session=session,
                    user=user,
                    resource_type=resource_type,
                    action=action,
                    resource_id=resource_id,
                    workspace_id=workspace_id,
                    project_id=project_id,
                    environment_id=environment_id,
                )

                if not result.allowed:
                    logger.warning("Permission denied", extra={
                        "user_id": str(user.id),
                        "resource_type": resource_type,
                        "action": action,
                        "resource_id": str(resource_id) if resource_id else None,
                        "reason": result.reason
                    })

                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Insufficient permissions: {result.reason}"
                    )

                logger.debug("Permission granted", extra={
                    "user_id": str(user.id),
                    "resource_type": resource_type,
                    "action": action,
                    "resource_id": str(resource_id) if resource_id else None,
                    "reason": result.reason
                })

            except Exception as e:
                logger.error("Permission check failed", extra={
                    "user_id": str(user.id),
                    "resource_type": resource_type,
                    "action": action,
                    "error": str(e)
                }, exc_info=True)

                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Permission check failed"
                )

            # Call the original function
            return await func(*args, **kwargs)

        return wrapper
    return decorator


def require_workspace_permission(action: str, workspace_id_param: str = "workspace_id") -> Callable:
    """Decorator to require workspace-level permission.

    Args:
        action: Action being performed (create, read, update, delete, etc.)
        workspace_id_param: Parameter name containing workspace ID

    Returns:
        Callable: Decorator function
    """
    return require_permission(
        resource_type="workspace",
        action=action,
        resource_id_param=workspace_id_param,
        workspace_id_param=workspace_id_param
    )


def require_project_permission(action: str, project_id_param: str = "project_id") -> Callable:
    """Decorator to require project-level permission.

    Args:
        action: Action being performed
        project_id_param: Parameter name containing project ID

    Returns:
        Callable: Decorator function
    """
    return require_permission(
        resource_type="project",
        action=action,
        resource_id_param=project_id_param,
        project_id_param=project_id_param
    )


def require_flow_permission(action: str, flow_id_param: str = "flow_id") -> Callable:
    """Decorator to require flow-level permission.

    Args:
        action: Action being performed
        flow_id_param: Parameter name containing flow ID

    Returns:
        Callable: Decorator function
    """
    return require_permission(
        resource_type="flow",
        action=action,
        resource_id_param=flow_id_param
    )


# Dependency injection functions for common permission checks
async def check_workspace_permission(
    workspace_id: UUID,
    action: str,
    session: DbSession,
    current_user: CurrentActiveUser,
    permission_engine: PermissionEngineDep,
) -> None:
    """Check workspace permission via dependency injection.

    Args:
        workspace_id: Workspace ID to check
        action: Action being performed
        session: Database session
        current_user: Current authenticated user
        permission_engine: Permission engine

    Raises:
        HTTPException: If permission is denied
    """
    result = await permission_engine.check_permission(
        session=session,
        user=current_user,
        resource_type="workspace",
        action=action,
        resource_id=workspace_id,
        workspace_id=workspace_id,
    )

    if not result.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Insufficient workspace permissions: {result.reason}"
        )


async def check_project_permission(
    project_id: UUID,
    action: str,
    session: DbSession,
    current_user: CurrentActiveUser,
    permission_engine: PermissionEngineDep,
) -> None:
    """Check project permission via dependency injection.

    Args:
        project_id: Project ID to check
        action: Action being performed
        session: Database session
        current_user: Current authenticated user
        permission_engine: Permission engine

    Raises:
        HTTPException: If permission is denied
    """
    result = await permission_engine.check_permission(
        session=session,
        user=current_user,
        resource_type="project",
        action=action,
        resource_id=project_id,
        project_id=project_id,
    )

    if not result.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Insufficient project permissions: {result.reason}"
        )


async def check_flow_permission(
    flow_id: UUID,
    action: str,
    session: DbSession,
    current_user: CurrentActiveUser,
    permission_engine: PermissionEngineDep,
) -> None:
    """Check flow permission via dependency injection.

    Args:
        flow_id: Flow ID to check
        action: Action being performed
        session: Database session
        current_user: Current authenticated user
        permission_engine: Permission engine

    Raises:
        HTTPException: If permission is denied
    """
    result = await permission_engine.check_permission(
        session=session,
        user=current_user,
        resource_type="flow",
        action=action,
        resource_id=flow_id,
    )

    if not result.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Insufficient flow permissions: {result.reason}"
        )


# Permission checking dependencies that can be used in endpoint signatures
def require_workspace_read(workspace_id: UUID) -> Callable:
    """Dependency to require workspace read permission."""
    async def dependency(
        session: DbSession,
        current_user: CurrentActiveUser,
        permission_engine: PermissionEngineDep,
    ):
        await check_workspace_permission(workspace_id, "read", session, current_user, permission_engine)
    return Depends(dependency)


def require_workspace_write(workspace_id: UUID) -> Callable:
    """Dependency to require workspace write permission."""
    async def dependency(
        session: DbSession,
        current_user: CurrentActiveUser,
        permission_engine: PermissionEngineDep,
    ):
        await check_workspace_permission(workspace_id, "update", session, current_user, permission_engine)
    return Depends(dependency)


def require_project_read(project_id: UUID) -> Callable:
    """Dependency to require project read permission."""
    async def dependency(
        session: DbSession,
        current_user: CurrentActiveUser,
        permission_engine: PermissionEngineDep,
    ):
        await check_project_permission(project_id, "read", session, current_user, permission_engine)
    return Depends(dependency)


def require_project_write(project_id: UUID) -> Callable:
    """Dependency to require project write permission."""
    async def dependency(
        session: DbSession,
        current_user: CurrentActiveUser,
        permission_engine: PermissionEngineDep,
    ):
        await check_project_permission(project_id, "update", session, current_user, permission_engine)
    return Depends(dependency)


def require_flow_read(flow_id: UUID) -> Callable:
    """Dependency to require flow read permission."""
    async def dependency(
        session: DbSession,
        current_user: CurrentActiveUser,
        permission_engine: PermissionEngineDep,
    ):
        await check_flow_permission(flow_id, "read", session, current_user, permission_engine)
    return Depends(dependency)


def require_flow_write(flow_id: UUID) -> Callable:
    """Dependency to require flow write permission."""
    async def dependency(
        session: DbSession,
        current_user: CurrentActiveUser,
        permission_engine: PermissionEngineDep,
    ):
        await check_flow_permission(flow_id, "update", session, current_user, permission_engine)
    return Depends(dependency)


def require_flow_execute(flow_id: UUID) -> Callable:
    """Dependency to require flow execute permission."""
    async def dependency(
        session: DbSession,
        current_user: CurrentActiveUser,
        permission_engine: PermissionEngineDep,
    ):
        await check_flow_permission(flow_id, "execute", session, current_user, permission_engine)
    return Depends(dependency)


# Superuser check decorator
def require_superuser(func: Callable) -> Callable:
    """Decorator to require superuser access.

    Args:
        func: Function to decorate

    Returns:
        Callable: Decorated function
    """
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        # Find user from kwargs
        user = None
        for key, value in kwargs.items():
            if hasattr(value, "id") and hasattr(value, "is_superuser"):  # User-like object
                user = value
                break

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User authentication required"
            )

        if not user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Superuser access required"
            )

        return await func(*args, **kwargs)
    return wrapper


# Enhanced permission check with context
async def check_permission_with_context(
    session: AsyncSession,
    user: User,
    resource_type: str,
    action: str,
    resource_id: UUID | None = None,
    workspace_id: UUID | None = None,
    project_id: UUID | None = None,
    environment_id: UUID | None = None,
    permission_engine: PermissionEngine | None = None,
) -> PermissionResult:
    """Check permission with full context.

    Args:
        session: Database session
        user: User requesting permission
        resource_type: Type of resource
        action: Action being performed
        resource_id: Resource ID
        workspace_id: Workspace context
        project_id: Project context
        environment_id: Environment context
        permission_engine: Permission engine (optional)

    Returns:
        PermissionResult: Result of permission check
    """
    if not permission_engine:
        permission_engine = PermissionEngine()

    return await permission_engine.check_permission(
        session=session,
        user=user,
        resource_type=resource_type,
        action=action,
        resource_id=resource_id,
        workspace_id=workspace_id,
        project_id=project_id,
        environment_id=environment_id,
    )
