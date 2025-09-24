"""Scoped Authentication Middleware.

This middleware enforces token scoping at the API endpoint level,
ensuring that API keys can only access resources within their defined scope.
"""

from collections.abc import Callable
from uuid import UUID

from fastapi import HTTPException, Request, Response, status
from loguru import logger
from starlette.middleware.base import BaseHTTPMiddleware

from langflow.services.auth.enhanced_auth import EnhancedAuthenticationService
from langflow.services.database.models.api_key.crud import check_key_with_scoping
from langflow.services.deps import get_db_service


class ScopedAuthenticationMiddleware(BaseHTTPMiddleware):
    """Middleware that enforces token scoping for API requests."""

    def __init__(self, app, skip_paths: list | None = None):
        super().__init__(app)
        self.skip_paths = skip_paths or [
            "/docs",
            "/redoc",
            "/openapi.json",
            "/health",
            "/api/v1/login",
            "/api/v1/register",
            "/api/v1/auto_login",
        ]
        self.auth_service = EnhancedAuthenticationService()

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request with scoped authentication."""
        # Skip authentication for certain paths
        if any(request.url.path.startswith(skip_path) for skip_path in self.skip_paths):
            return await call_next(request)

        # Extract API key from request
        api_key = self._extract_api_key(request)
        if not api_key:
            # If no API key, let the regular auth system handle it
            return await call_next(request)

        # Validate token and check scoping
        async with get_db_service().with_session() as session:
            user, api_key_obj = await check_key_with_scoping(session, api_key)

            if not user or not api_key_obj:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or inactive API key")

            # Extract resource information from the request
            resource_info = self._extract_resource_info(request)

            # Check token scoping if resource information is available
            if resource_info and api_key_obj.scoped_permissions:
                scope_valid = await self._validate_token_scope(
                    api_key_obj=api_key_obj, resource_info=resource_info, request=request
                )

                if not scope_valid:
                    logger.warning(
                        f"Token scope violation: {api_key_obj.id} attempted to access {resource_info}",
                        extra={
                            "api_key_id": str(api_key_obj.id),
                            "user_id": str(user.id),
                            "scoped_permissions": api_key_obj.scoped_permissions,
                            "scope_type": api_key_obj.scope_type,
                            "scope_id": api_key_obj.scope_id,
                            "resource_info": resource_info,
                            "path": request.url.path,
                            "method": request.method,
                        },
                    )
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Token scope does not allow access to this resource",
                    )

            # Add scoping information to request state for use in endpoints
            request.state.api_key = api_key_obj
            request.state.scoped_permissions = api_key_obj.scoped_permissions or []
            request.state.scope_type = api_key_obj.scope_type
            request.state.scope_id = UUID(api_key_obj.scope_id) if api_key_obj.scope_id else None
            request.state.token_workspace_id = UUID(api_key_obj.workspace_id) if api_key_obj.workspace_id else None

        return await call_next(request)

    def _extract_api_key(self, request: Request) -> str | None:
        """Extract API key from request headers or query parameters."""
        # Check header
        api_key = request.headers.get("x-api-key")
        if api_key:
            return api_key

        # Check query parameter
        api_key = request.query_params.get("x-api-key")
        if api_key:
            return api_key

        # Check Authorization header
        auth_header = request.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            return auth_header.split(" ", 1)[1]

        return None

    def _extract_resource_info(self, request: Request) -> dict | None:
        """Extract resource information from the request path."""
        path = request.url.path
        method = request.method

        # Parse common resource patterns
        resource_info = {"method": method, "path": path}

        # Extract IDs from path segments
        path_segments = [seg for seg in path.split("/") if seg]

        # Look for common resource patterns
        for i, segment in enumerate(path_segments):
            if segment in ["flows", "flow"]:
                resource_info["resource_type"] = "flow"
                if i + 1 < len(path_segments):
                    try:
                        resource_info["resource_id"] = UUID(path_segments[i + 1])
                    except ValueError:
                        pass

            elif segment in ["projects", "project"]:
                resource_info["resource_type"] = "project"
                if i + 1 < len(path_segments):
                    try:
                        resource_info["resource_id"] = UUID(path_segments[i + 1])
                    except ValueError:
                        pass

            elif segment in ["workspaces", "workspace"]:
                resource_info["resource_type"] = "workspace"
                if i + 1 < len(path_segments):
                    try:
                        resource_info["resource_id"] = UUID(path_segments[i + 1])
                    except ValueError:
                        pass

            elif segment in ["environments", "environment"]:
                resource_info["resource_type"] = "environment"
                if i + 1 < len(path_segments):
                    try:
                        resource_info["resource_id"] = UUID(path_segments[i + 1])
                    except ValueError:
                        pass

        # Determine required permission based on HTTP method
        if "resource_type" in resource_info:
            resource_type = resource_info["resource_type"]
            if method == "GET":
                resource_info["required_permission"] = f"{resource_type}:read"
            elif method == "POST" or method in ["PUT", "PATCH"]:
                resource_info["required_permission"] = f"{resource_type}:write"
            elif method == "DELETE":
                resource_info["required_permission"] = f"{resource_type}:delete"

        return resource_info if "resource_type" in resource_info else None

    async def _validate_token_scope(self, api_key_obj, resource_info: dict, request: Request) -> bool:
        """Validate if the token scope allows access to the requested resource."""
        # Check permission scope
        required_permission = resource_info.get("required_permission")
        if required_permission and api_key_obj.scoped_permissions:
            has_permission = self._check_permission_in_scope(required_permission, api_key_obj.scoped_permissions)
            if not has_permission:
                return False

        # Check resource scope
        resource_type = resource_info.get("resource_type")
        resource_id = resource_info.get("resource_id")

        if api_key_obj.scope_type and resource_type:
            # If token is scoped to a specific resource type
            if api_key_obj.scope_type == resource_type:
                # Check if specific resource ID matches
                if api_key_obj.scope_id and resource_id:
                    token_scope_id = UUID(api_key_obj.scope_id)
                    return token_scope_id == resource_id
                # If no specific resource ID, allow access to all resources of this type
                return True

            # Check scope hierarchy (workspace > project > environment > flow > component)
            scope_hierarchy = {"workspace": 0, "project": 1, "environment": 2, "flow": 3, "component": 4}

            token_scope_level = scope_hierarchy.get(api_key_obj.scope_type, -1)
            resource_level = scope_hierarchy.get(resource_type, -1)

            # Higher-level scopes can access lower-level resources
            if token_scope_level >= 0 and resource_level >= 0:
                return token_scope_level <= resource_level

        return True  # Default to allow if no specific scope restrictions

    def _check_permission_in_scope(self, required_permission: str, scoped_permissions: list) -> bool:
        """Check if a required permission is within the token's scoped permissions."""
        if not scoped_permissions:
            return True  # No scope restrictions

        # Check exact match
        if required_permission in scoped_permissions:
            return True

        # Check wildcard permissions
        for scoped_perm in scoped_permissions:
            if scoped_perm.endswith(":*"):
                resource_type = scoped_perm.split(":")[0]
                if required_permission.startswith(f"{resource_type}:"):
                    return True

        return False


# Dependency function to get scoped authentication context
def get_scoped_auth_context(request: Request) -> dict:
    """Get scoped authentication context from request state."""
    return {
        "api_key": getattr(request.state, "api_key", None),
        "scoped_permissions": getattr(request.state, "scoped_permissions", []),
        "scope_type": getattr(request.state, "scope_type", None),
        "scope_id": getattr(request.state, "scope_id", None),
        "token_workspace_id": getattr(request.state, "token_workspace_id", None),
    }


# Enhanced dependency for endpoints that need scope validation
async def require_scoped_permission(
    request: Request, required_permission: str, resource_type: str | None = None, resource_id: UUID | None = None
) -> bool:
    """Dependency that validates scoped permissions for specific endpoints."""
    auth_context = get_scoped_auth_context(request)

    # If no scoped permissions, allow (handled by regular RBAC)
    scoped_permissions = auth_context.get("scoped_permissions", [])
    if not scoped_permissions:
        return True

    # Check permission scope
    has_permission = False
    for scoped_perm in scoped_permissions:
        if scoped_perm == required_permission:
            has_permission = True
            break
        if scoped_perm.endswith(":*"):
            perm_resource_type = scoped_perm.split(":")[0]
            if required_permission.startswith(f"{perm_resource_type}:"):
                has_permission = True
                break

    if not has_permission:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Token does not have required permission: {required_permission}",
        )

    # Check resource scope if specified
    scope_type = auth_context.get("scope_type")
    scope_id = auth_context.get("scope_id")

    if scope_type and resource_type and scope_id and resource_id:
        if scope_type == resource_type and scope_id != resource_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Token scope does not allow access to {resource_type}:{resource_id}",
            )

    return True
