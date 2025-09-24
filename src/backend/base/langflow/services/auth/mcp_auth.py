"""Enhanced MCP Authentication and Authorization Module.

This module provides comprehensive security for MCP (Model Context Protocol) endpoints
with RBAC integration, token scoping, and secure default configurations.
"""

from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from langflow.api.utils import CurrentActiveUser, DbSession
from langflow.services.auth.enhanced_auth import EnhancedAuthenticationService
from langflow.services.rbac.runtime_enforcement import RBACRuntimeEnforcementService, RuntimeEnforcementContext
from loguru import logger

# Security scheme for extracting API keys
security = HTTPBearer(auto_error=False)


async def get_mcp_enforcement_context(
    request: Request,
    session: DbSession,
    current_user: CurrentActiveUser,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)] = None,
) -> RuntimeEnforcementContext:
    """Create MCP-specific enforcement context with proper authorization checks."""
    # Initialize services
    auth_service = EnhancedAuthenticationService()
    from langflow.services.deps import get_rbac_service

    rbac_service = get_rbac_service()
    enforcement_service = RBACRuntimeEnforcementService(rbac_service, auth_service)

    # Extract API key from multiple sources
    api_key = None
    if credentials:
        api_key = credentials.credentials
    else:
        # Check headers and query parameters
        api_key = request.headers.get("x-api-key") or request.query_params.get("x-api-key")

    # Extract MCP-specific context from request
    workspace_id = request.path_params.get("workspace_id")
    project_id = request.path_params.get("project_id")
    environment_id = request.path_params.get("environment_id")
    server_name = request.path_params.get("server_name")

    # Extract client information for audit logging
    client_ip = None
    if request.client:
        client_ip = request.client.host
    user_agent = request.headers.get("user-agent")

    # Create enforcement context with MCP-specific permissions
    context = await enforcement_service.create_enforcement_context(
        session=session,
        api_key=api_key,
        user=current_user,
        workspace_id=UUID(workspace_id) if workspace_id else None,
        project_id=UUID(project_id) if project_id else None,
        environment_id=UUID(environment_id) if environment_id else None,
        request_path=request.url.path,
        request_method=request.method,
        client_ip=client_ip,
        user_agent=user_agent,
    )

    # Validate MCP-specific permissions
    await _validate_mcp_permissions(enforcement_service, session, context, request, server_name)

    return context


async def _validate_mcp_permissions(
    enforcement_service: RBACRuntimeEnforcementService,
    session: DbSession,
    context: RuntimeEnforcementContext,
    request: Request,
    server_name: str | None = None,
) -> None:
    """Validate MCP-specific permissions based on the request."""
    # Determine required permission based on HTTP method and path
    method = request.method.upper()
    path = request.url.path

    # Map MCP operations to required permissions
    if "/mcp/sse" in path:
        required_permission = "mcp:connect"
        resource_type = "mcp_server"
    elif "/mcp/servers" in path:
        if method in ["GET"]:
            required_permission = "mcp:read"
        elif method in ["POST", "PUT", "PATCH"]:
            required_permission = "mcp:write"
        elif method in ["DELETE"]:
            required_permission = "mcp:delete"
        else:
            required_permission = "mcp:read"
        resource_type = "mcp_server"
    elif "/mcp/" in path and method == "POST":
        required_permission = "mcp:execute"
        resource_type = "mcp_tool"
    else:
        required_permission = "mcp:read"
        resource_type = "mcp_server"

    # Check workspace-level MCP permissions first
    if context.effective_workspace_id:
        workspace_access = await enforcement_service.check_resource_access(
            session=session,
            context=context,
            permission=required_permission,
            resource_type="workspace",
            resource_id=context.effective_workspace_id,
        )

        if not workspace_access:
            await enforcement_service.audit_enforcement_decision(
                context=context,
                operation=method.lower(),
                resource_type=resource_type,
                permission=required_permission,
                decision=False,
                reason="Insufficient workspace permissions for MCP access",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions for MCP {required_permission} in this workspace",
            )

    # Check server-specific permissions if server_name is provided
    if server_name:
        # Note: In a full implementation, you would have server-specific resource IDs
        # For now, we'll use the server name as a pseudo-resource identifier
        server_access = await enforcement_service.check_resource_access(
            session=session,
            context=context,
            permission=required_permission,
            resource_type=resource_type,
            # In production, you'd have actual MCP server resource IDs
            resource_id=None,
        )

        if not server_access:
            await enforcement_service.audit_enforcement_decision(
                context=context,
                operation=method.lower(),
                resource_type=resource_type,
                resource_id=None,
                permission=required_permission,
                decision=False,
                reason=f"Access denied to MCP server: {server_name}",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied to MCP server: {server_name}",
            )

    # Audit successful authorization
    await enforcement_service.audit_enforcement_decision(
        context=context,
        operation=method.lower(),
        resource_type=resource_type,
        permission=required_permission,
        decision=True,
        reason=f"MCP {required_permission} access granted",
    )

    logger.debug(f"MCP authorization successful: {required_permission} for user {context.user.id}")


# Enhanced MCP user dependency with RBAC integration
async def get_mcp_authorized_user(
    context: Annotated[RuntimeEnforcementContext, Depends(get_mcp_enforcement_context)],
) -> CurrentActiveUser:
    """Get current user with MCP authorization validation.

    This dependency ensures that:
    1. User is properly authenticated
    2. User has appropriate MCP permissions
    3. All access is properly audited
    """
    if not context.user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Inactive user cannot access MCP endpoints"
        )

    return context.user


# Permission validators for specific MCP operations
def require_mcp_permission(permission: str):
    """Decorator factory for requiring specific MCP permissions."""

    async def permission_validator(
        context: Annotated[RuntimeEnforcementContext, Depends(get_mcp_enforcement_context)],
        session: DbSession,
    ) -> bool:
        from langflow.services.deps import get_rbac_service

        rbac_service = get_rbac_service()
        enforcement_service = RBACRuntimeEnforcementService(rbac_service)

        # Check if user has the required permission
        has_permission = await enforcement_service.check_resource_access(
            session=session,
            context=context,
            permission=permission,
            resource_type="mcp_server",
            resource_id=context.effective_workspace_id,
        )

        if not has_permission:
            await enforcement_service.audit_enforcement_decision(
                context=context,
                operation="permission_check",
                resource_type="mcp_server",
                permission=permission,
                decision=False,
                reason=f"Required MCP permission {permission} not granted",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required MCP permission: {permission}",
            )

        return True

    return Depends(permission_validator)


# Specific permission requirements for common MCP operations
RequireMCPRead = require_mcp_permission("mcp:read")
RequireMCPWrite = require_mcp_permission("mcp:write")
RequireMCPExecute = require_mcp_permission("mcp:execute")
RequireMCPConnect = require_mcp_permission("mcp:connect")
RequireMCPDelete = require_mcp_permission("mcp:delete")
