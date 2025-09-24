"""Enhanced dependency injection with RBAC integration.

This module provides FastAPI dependencies that integrate RBAC permission checking
with LangBuilder's existing authentication system. Follows existing patterns while
adding comprehensive permission enforcement.

Implementation follows Phase 4 requirements:
- Integration with existing authentication dependencies
- High-performance permission evaluation
- Comprehensive resource-level access control
- Backward compatibility with existing endpoints
"""

# NO future annotations per Phase 1 requirements
import functools
from typing import TYPE_CHECKING, Annotated, Optional

from fastapi import Depends, HTTPException, Request, status
from loguru import logger
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.services.auth.utils import get_current_active_user
from langflow.services.deps import get_session

if TYPE_CHECKING:
    from langflow.services.database.models.user.model import User
    from langflow.services.rbac.service import RBACService


class RBACPermissionChecker:
    """RBAC permission checker for dependency injection.

    This class provides a callable dependency that can be used to check
    specific permissions in FastAPI endpoints.
    """

    def __init__(
        self,
        resource_type: str,
        action: str,
        resource_id_param: str | None = None,
        workspace_id_param: str | None = None,
        project_id_param: str | None = None,
        allow_superuser_bypass: bool = True,
        cache_result: bool = True
    ):
        """Initialize permission checker.

        Args:
            resource_type: Type of resource being accessed (e.g., 'flow', 'project')
            action: Action being performed (e.g., 'read', 'write', 'delete')
            resource_id_param: Parameter name for resource ID (e.g., 'flow_id')
            workspace_id_param: Parameter name for workspace ID
            project_id_param: Parameter name for project ID
            allow_superuser_bypass: Whether superusers bypass permission checks
            cache_result: Whether to cache permission results
        """
        self.resource_type = resource_type
        self.action = action
        self.resource_id_param = resource_id_param
        self.workspace_id_param = workspace_id_param
        self.project_id_param = project_id_param
        self.allow_superuser_bypass = allow_superuser_bypass
        self.cache_result = cache_result

    async def __call__(
        self,
        request: Request,
        current_user: "User" = Depends(get_current_active_user),
        session: AsyncSession = Depends(get_session)
    ) -> "User":
        """Check RBAC permissions and return user if authorized.

        Args:
            request: FastAPI request object
            current_user: Current authenticated user
            session: Database session

        Returns:
            User: Current user if permissions are granted

        Raises:
            HTTPException: If permissions are denied
        """
        try:
            # Superuser bypass (if enabled)
            if self.allow_superuser_bypass and current_user.is_superuser:
                logger.debug(f"Superuser bypass for {self.resource_type}:{self.action}", extra={
                    "user_id": str(current_user.id),
                    "resource_type": self.resource_type,
                    "action": self.action
                })
                return current_user

            # Extract resource identifiers from request
            resource_id = self._extract_resource_id(request)
            workspace_id = self._extract_workspace_id(request)
            project_id = self._extract_project_id(request)

            # Get RBAC service
            rbac_service = await self._get_rbac_service()
            if not rbac_service:
                # If RBAC service is not available, allow access for superusers only
                if current_user.is_superuser:
                    logger.warning("RBAC service unavailable, allowing superuser access", extra={
                        "user_id": str(current_user.id),
                        "resource_type": self.resource_type
                    })
                    return current_user
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Permission service temporarily unavailable"
                )

            # Evaluate permission
            result = await rbac_service.evaluate_permission(
                session=session,
                user=current_user,
                resource_type=self.resource_type,
                action=self.action,
                resource_id=resource_id,
                workspace_id=workspace_id,
                project_id=project_id
            )

            if not result.granted:
                logger.warning("RBAC permission denied", extra={
                    "user_id": str(current_user.id),
                    "resource_type": self.resource_type,
                    "action": self.action,
                    "resource_id": resource_id,
                    "reason": result.reason
                })

                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions to {self.action} {self.resource_type}",
                    headers={"X-Permission-Denied-Reason": result.reason or "insufficient_permissions"}
                )

            logger.debug("RBAC permission granted", extra={
                "user_id": str(current_user.id),
                "resource_type": self.resource_type,
                "action": self.action,
                "resource_id": resource_id,
                "evaluation_time": result.evaluation_time
            })

            return current_user

        except HTTPException:
            # Re-raise HTTP exceptions
            raise
        except Exception as exc:
            logger.error("Error in RBAC permission check", extra={
                "user_id": str(current_user.id),
                "resource_type": self.resource_type,
                "action": self.action,
                "error": str(exc)
            }, exc_info=True)

            # For safety, deny access on unexpected errors
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal error during permission evaluation"
            )

    def _extract_resource_id(self, request: Request) -> str | None:
        """Extract resource ID from request."""
        if not self.resource_id_param:
            return None

        # Try path parameters first
        resource_id = request.path_params.get(self.resource_id_param)

        # Fallback to query parameters
        if not resource_id:
            resource_id = request.query_params.get(self.resource_id_param)

        return resource_id

    def _extract_workspace_id(self, request: Request) -> str | None:
        """Extract workspace ID from request."""
        if not self.workspace_id_param:
            return None

        # Try path parameters first
        workspace_id = request.path_params.get(self.workspace_id_param)

        # Fallback to query parameters
        if not workspace_id:
            workspace_id = request.query_params.get(self.workspace_id_param)

        return workspace_id

    def _extract_project_id(self, request: Request) -> str | None:
        """Extract project ID from request."""
        if not self.project_id_param:
            return None

        # Try path parameters first
        project_id = request.path_params.get(self.project_id_param)

        # Fallback to query parameters
        if not project_id:
            project_id = request.query_params.get(self.project_id_param)

        return project_id

    async def _get_rbac_service(self) -> Optional["RBACService"]:
        """Get RBAC service instance."""
        try:
            from langflow.services.rbac.service import RBACService
            return RBACService()
        except ImportError:
            return None


# Common RBAC permission dependencies following LangBuilder patterns

# Flow permissions
RequireFlowRead = RBACPermissionChecker(
    resource_type="flow",
    action="read",
    resource_id_param="flow_id"
)

RequireFlowWrite = RBACPermissionChecker(
    resource_type="flow",
    action="write",
    resource_id_param="flow_id"
)

RequireFlowDelete = RBACPermissionChecker(
    resource_type="flow",
    action="delete",
    resource_id_param="flow_id"
)

RequireFlowExecute = RBACPermissionChecker(
    resource_type="flow",
    action="execute",
    resource_id_param="flow_id"
)

# Project permissions
RequireProjectRead = RBACPermissionChecker(
    resource_type="project",
    action="read",
    resource_id_param="project_id"
)

RequireProjectWrite = RBACPermissionChecker(
    resource_type="project",
    action="write",
    resource_id_param="project_id"
)

RequireProjectDelete = RBACPermissionChecker(
    resource_type="project",
    action="delete",
    resource_id_param="project_id"
)

# Workspace permissions
RequireWorkspaceRead = RBACPermissionChecker(
    resource_type="workspace",
    action="read",
    resource_id_param="workspace_id"
)

RequireWorkspaceWrite = RBACPermissionChecker(
    resource_type="workspace",
    action="write",
    resource_id_param="workspace_id"
)

RequireWorkspaceAdmin = RBACPermissionChecker(
    resource_type="workspace",
    action="admin",
    resource_id_param="workspace_id"
)

# File permissions
RequireFileRead = RBACPermissionChecker(
    resource_type="file",
    action="read",
    resource_id_param="file_id"
)

RequireFileWrite = RBACPermissionChecker(
    resource_type="file",
    action="write",
    resource_id_param="file_id"
)

RequireFileDelete = RBACPermissionChecker(
    resource_type="file",
    action="delete",
    resource_id_param="file_id"
)

# RBAC admin permissions
RequireRBACAdmin = RBACPermissionChecker(
    resource_type="rbac",
    action="admin",
    allow_superuser_bypass=True
)

RequireRBACRead = RBACPermissionChecker(
    resource_type="rbac",
    action="read"
)


# Helper functions for custom permission checking

async def check_custom_permission(
    user: "User",
    session: AsyncSession,
    resource_type: str,
    action: str,
    resource_id: str | None = None,
    workspace_id: str | None = None,
    project_id: str | None = None
) -> bool:
    """Check custom RBAC permission.

    This function allows for programmatic permission checking outside
    of the dependency injection system.

    Args:
        user: User to check permissions for
        session: Database session
        resource_type: Type of resource
        action: Action being performed
        resource_id: Specific resource ID
        workspace_id: Workspace scope
        project_id: Project scope

    Returns:
        bool: True if permission is granted
    """
    try:
        # Superuser bypass
        if user.is_superuser:
            return True

        # Get RBAC service
        from langflow.services.rbac.service import RBACService
        rbac_service = RBACService()

        # Evaluate permission
        result = await rbac_service.evaluate_permission(
            session=session,
            user=user,
            resource_type=resource_type,
            action=action,
            resource_id=resource_id,
            workspace_id=workspace_id,
            project_id=project_id
        )

        return result.granted

    except Exception as exc:
        logger.error("Error in custom permission check", extra={
            "user_id": str(user.id),
            "resource_type": resource_type,
            "action": action,
            "error": str(exc)
        }, exc_info=True)
        return False


def require_permission(
    resource_type: str,
    action: str,
    resource_id_param: str | None = None,
    workspace_id_param: str | None = None,
    project_id_param: str | None = None
):
    """Decorator factory for requiring specific permissions.

    This decorator can be used on FastAPI endpoints to require specific
    permissions beyond the standard dependency injection.

    Args:
        resource_type: Type of resource
        action: Action being performed
        resource_id_param: Parameter name for resource ID
        workspace_id_param: Parameter name for workspace ID
        project_id_param: Parameter name for project ID

    Returns:
        Callable: Decorator function
    """
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request and user from function arguments
            request = None
            user = None
            session = None

            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                elif hasattr(arg, "id") and hasattr(arg, "is_active"):
                    user = arg
                elif hasattr(arg, "exec"):
                    session = arg

            # Also check keyword arguments
            if not request:
                request = kwargs.get("request")
            if not user:
                user = kwargs.get("current_user") or kwargs.get("user")
            if not session:
                session = kwargs.get("session")

            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )

            if not session:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Database session not available"
                )

            # Extract resource parameters
            resource_id = None
            workspace_id = None
            project_id = None

            if request:
                if resource_id_param:
                    resource_id = (request.path_params.get(resource_id_param) or
                                 request.query_params.get(resource_id_param))
                if workspace_id_param:
                    workspace_id = (request.path_params.get(workspace_id_param) or
                                  request.query_params.get(workspace_id_param))
                if project_id_param:
                    project_id = (request.path_params.get(project_id_param) or
                                request.query_params.get(project_id_param))

            # Check permission
            has_permission = await check_custom_permission(
                user=user,
                session=session,
                resource_type=resource_type,
                action=action,
                resource_id=resource_id,
                workspace_id=workspace_id,
                project_id=project_id
            )

            if not has_permission:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions to {action} {resource_type}"
                )

            return await func(*args, **kwargs)

        return wrapper
    return decorator


# Typed dependencies for common use cases
AuthenticatedUser = Annotated["User", Depends(get_current_active_user)]
FlowReader = Annotated["User", Depends(RequireFlowRead)]
FlowWriter = Annotated["User", Depends(RequireFlowWrite)]
FlowExecutor = Annotated["User", Depends(RequireFlowExecute)]
ProjectReader = Annotated["User", Depends(RequireProjectRead)]
ProjectWriter = Annotated["User", Depends(RequireProjectWrite)]
WorkspaceReader = Annotated["User", Depends(RequireWorkspaceRead)]
WorkspaceWriter = Annotated["User", Depends(RequireWorkspaceWrite)]
WorkspaceAdmin = Annotated["User", Depends(RequireWorkspaceAdmin)]
RBACAdmin = Annotated["User", Depends(RequireRBACAdmin)]
