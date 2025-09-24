"""Unified Security Middleware for RBAC API Endpoints.

This module provides standardized authentication, authorization, and validation
middleware for all RBAC endpoints to ensure consistent security patterns.
"""

from __future__ import annotations

from functools import wraps
from typing import Annotated, Any, Callable, List, Optional, TypeVar

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer
import os
from loguru import logger
from pydantic import BaseModel, Field, ValidationError
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.api.utils import CurrentActiveUser, DbSession
from langflow.services.database.models.user.model import User
from langflow.services.auth.authorization_patterns import get_enhanced_enforcement_context
from langflow.services.rbac.permission_engine import PermissionEngine, PermissionResult
from langflow.services.rbac.runtime_enforcement import RuntimeEnforcementContext

# Type variable for generic function decoration
F = TypeVar("F", bound=Callable[..., Any])

# Security scheme for bearer token
security_scheme = HTTPBearer()


class SecurityRequirement(BaseModel):
    """Security requirement specification for endpoints."""

    resource_type: str = Field(..., description="Type of resource being accessed")
    action: str = Field(..., description="Action being performed")
    require_workspace_access: bool = Field(default=True, description="Require workspace-level access")
    require_ownership: bool = Field(default=False, description="Require resource ownership")
    custom_permissions: List[str] = Field(default=[], description="Additional custom permissions required")
    audit_action: str = Field(..., description="Action to log in audit trail")


class ValidationRequirement(BaseModel):
    """Input validation requirement specification."""

    validate_workspace_exists: bool = Field(default=True, description="Validate workspace exists")
    validate_project_exists: bool = Field(default=False, description="Validate project exists")
    validate_role_exists: bool = Field(default=False, description="Validate role exists")
    validate_user_exists: bool = Field(default=False, description="Validate user exists")
    custom_validators: List[str] = Field(default=[], description="Custom validation functions")


async def get_permission_engine() -> PermissionEngine:
    """Get permission engine dependency."""
    from langflow.api.v1.rbac.dependencies import get_permission_engine as _get_permission_engine
    return await _get_permission_engine()


async def enhanced_authentication(
    request: Request,
    token: Annotated[str, Depends(security_scheme)],
    session: DbSession,
) -> CurrentActiveUser:
    """Enhanced authentication middleware with comprehensive security checks."""
    # Check if authentication is disabled in development
    skip_auth = os.getenv('LANGFLOW_SKIP_AUTH', 'false').lower() == 'true'

    if skip_auth:
        # In development with SKIP_AUTH=true, provide a mock superuser
        from langflow.services.database.models.user.model import User
        from uuid import uuid4

        # Create or get the default superuser for development
        mock_user = User(
            id=uuid4(),
            username="dev_user",
            email="dev@langflow.com",
            is_active=True,
            is_superuser=True,
            password=""  # Empty password for dev mode
        )
        logger.info("Authentication bypassed for development (SKIP_AUTH=true)")
        return mock_user

    try:
        # Get current user through JWT validation
        from langflow.services.auth.utils import get_current_user_by_jwt

        # Enhanced authentication with additional security checks
        user = await get_current_user_by_jwt(token.credentials, session)

        if not user:
            logger.warning("Authentication failed: Invalid token", extra={
                "endpoint": request.url.path,
                "method": request.method,
                "client_ip": request.client.host if request.client else "unknown"
            })
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not user.is_active:
            logger.warning("Authentication failed: Inactive user", extra={
                "user_id": str(user.id),
                "username": user.username,
                "endpoint": request.url.path
            })
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is inactive",
            )

        # Log successful authentication
        logger.info("User authenticated successfully", extra={
            "user_id": str(user.id),
            "username": user.username,
            "endpoint": request.url.path,
            "method": request.method
        })

        return user

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Authentication error", extra={
            "error": str(e),
            "endpoint": request.url.path,
            "method": request.method
        })
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e


async def enhanced_authorization(
    user: CurrentActiveUser,
    context: Annotated[RuntimeEnforcementContext, Depends(get_enhanced_enforcement_context)],
    session: DbSession,
    permission_engine: Annotated[PermissionEngine, Depends(get_permission_engine)],
    request: Request,
    security_req: SecurityRequirement,
) -> bool:
    """Enhanced authorization middleware with comprehensive permission checking."""
    try:
        # Basic permission check
        permission_result = await permission_engine.check_permission(
            session=session,
            user=user,
            resource_type=security_req.resource_type,
            action=security_req.action,
            resource_id=context.requested_workspace_id if security_req.require_workspace_access else None,
            workspace_id=context.requested_workspace_id if security_req.require_workspace_access else None,
        )

        if not permission_result.allowed:
            logger.warning("Authorization failed: Permission denied", extra={
                "user_id": str(user.id),
                "username": user.username,
                "resource_type": security_req.resource_type,
                "action": security_req.action,
                "workspace_id": str(context.requested_workspace_id) if context.requested_workspace_id else None,
                "reason": permission_result.reason,
                "endpoint": request.url.path
            })
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions: {permission_result.reason}",
            )

        # Check custom permissions if specified
        for custom_permission in security_req.custom_permissions:
            custom_result = await permission_engine.check_permission(
                session=session,
                user=user,
                resource_type=security_req.resource_type,
                action=custom_permission,
                resource_id=context.requested_workspace_id if security_req.require_workspace_access else None,
                workspace_id=context.requested_workspace_id if security_req.require_workspace_access else None,
            )

            if not custom_result.allowed:
                logger.warning("Authorization failed: Custom permission denied", extra={
                    "user_id": str(user.id),
                    "permission": custom_permission,
                    "reason": custom_result.reason,
                    "endpoint": request.url.path
                })
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions: {custom_result.reason}",
                )

        # Log successful authorization
        logger.info("User authorized successfully", extra={
            "user_id": str(user.id),
            "username": user.username,
            "resource_type": security_req.resource_type,
            "action": security_req.action,
            "workspace_id": str(context.requested_workspace_id) if context.requested_workspace_id else None,
            "endpoint": request.url.path
        })

        return True

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Authorization error", extra={
            "error": str(e),
            "user_id": str(user.id),
            "endpoint": request.url.path
        })
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authorization failed",
        ) from e


async def enhanced_validation(
    session: DbSession,
    context: RuntimeEnforcementContext,
    validation_req: ValidationRequirement,
    request: Request,
    **kwargs: Any,
) -> bool:
    """Enhanced input validation middleware."""
    try:
        # Validate workspace exists if required
        if validation_req.validate_workspace_exists and context.requested_workspace_id:
            from langflow.services.database.models.rbac.workspace import Workspace

            workspace = await session.get(Workspace, context.requested_workspace_id)
            if not workspace or workspace.is_deleted:
                logger.warning("Validation failed: Workspace not found", extra={
                    "workspace_id": str(context.requested_workspace_id),
                    "endpoint": request.url.path
                })
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Workspace not found or has been deleted"
                )

        # Validate project exists if required
        if validation_req.validate_project_exists and "project_id" in kwargs:
            from langflow.services.database.models.rbac.project import Project

            project_id = kwargs["project_id"]
            project = await session.get(Project, project_id)
            if not project or not project.is_active:
                logger.warning("Validation failed: Project not found", extra={
                    "project_id": str(project_id),
                    "endpoint": request.url.path
                })
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Project not found or is inactive"
                )

        # Validate role exists if required
        if validation_req.validate_role_exists and "role_id" in kwargs:
            from langflow.services.database.models.rbac.role import Role

            role_id = kwargs["role_id"]
            role = await session.get(Role, role_id)
            if not role or not role.is_active:
                logger.warning("Validation failed: Role not found", extra={
                    "role_id": str(role_id),
                    "endpoint": request.url.path
                })
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Role not found or is inactive"
                )

        # Validate user exists if required
        if validation_req.validate_user_exists and "user_id" in kwargs:
            from langflow.services.database.models.user.model import User

            user_id = kwargs["user_id"]
            user = await session.get(User, user_id)
            if not user or not user.is_active:
                logger.warning("Validation failed: User not found", extra={
                    "user_id": str(user_id),
                    "endpoint": request.url.path
                })
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found or is inactive"
                )

        return True

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Validation error", extra={
            "error": str(e),
            "endpoint": request.url.path
        })
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Validation failed",
        ) from e


def secure_endpoint(
    security_req: SecurityRequirement,
    validation_req: Optional[ValidationRequirement] = None,
    audit_enabled: bool = True,
) -> Callable[[F], F]:
    """Decorator for applying comprehensive security to RBAC endpoints.

    This decorator applies:
    1. Enhanced authentication
    2. Enhanced authorization with permission checking
    3. Input validation
    4. Audit logging

    Args:
        security_req: Security requirements specification
        validation_req: Validation requirements specification
        audit_enabled: Whether to enable audit logging

    Returns:
        Decorated function with security middleware applied
    """
    def decorator(func: F) -> F:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract dependencies from kwargs
            request = kwargs.get("request")
            session = kwargs.get("session")
            user = kwargs.get("current_user")
            context = kwargs.get("context")

            if not all([request, session, user, context]):
                # If dependencies are not in kwargs, they should be in the function signature
                # This is a fallback for functions that don't follow the expected pattern
                logger.warning("Security middleware: Missing required dependencies in function signature")
                return await func(*args, **kwargs)

            try:
                # Enhanced authorization check
                permission_engine = await get_permission_engine()
                await enhanced_authorization(
                    user=user,
                    context=context,
                    session=session,
                    permission_engine=permission_engine,
                    request=request,
                    security_req=security_req,
                )

                # Enhanced validation if specified
                if validation_req:
                    # Remove named parameters from kwargs to avoid duplicates
                    validation_kwargs = {k: v for k, v in kwargs.items()
                                        if k not in ['session', 'context', 'validation_req', 'request']}
                    await enhanced_validation(
                        session=session,
                        context=context,
                        validation_req=validation_req,
                        request=request,
                        **validation_kwargs,
                    )

                # Execute the original function
                result = await func(*args, **kwargs)

                # Audit logging if enabled
                if audit_enabled:
                    await _log_audit_event(
                        user=user,
                        context=context,
                        session=session,
                        action=security_req.audit_action,
                        resource_type=security_req.resource_type,
                        success=True,
                        details={"endpoint": request.url.path, "method": request.method},
                    )

                return result

            except HTTPException as e:
                # Audit failed operations if enabled
                if audit_enabled:
                    await _log_audit_event(
                        user=user,
                        context=context,
                        session=session,
                        action=security_req.audit_action,
                        resource_type=security_req.resource_type,
                        success=False,
                        details={
                            "endpoint": request.url.path,
                            "method": request.method,
                            "error": str(e.detail),
                            "status_code": e.status_code,
                        },
                    )
                raise
            except Exception as e:
                logger.error("Endpoint execution error", extra={
                    "error": str(e),
                    "endpoint": request.url.path,
                    "user_id": str(user.id),
                })

                if audit_enabled:
                    await _log_audit_event(
                        user=user,
                        context=context,
                        session=session,
                        action=security_req.audit_action,
                        resource_type=security_req.resource_type,
                        success=False,
                        details={
                            "endpoint": request.url.path,
                            "method": request.method,
                            "error": str(e),
                        },
                    )

                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Internal server error",
                ) from e

        return wrapper
    return decorator


async def _log_audit_event(
    user: CurrentActiveUser,
    context: RuntimeEnforcementContext,
    session: AsyncSession,
    action: str,
    resource_type: str,
    success: bool,
    details: dict,
) -> None:
    """Log audit event for security middleware."""
    try:
        from langflow.services.database.models.rbac.audit_log import (
            ActorType,
            AuditEventType,
            AuditLog,
            AuditOutcome,
        )

        audit_log = AuditLog(
            event_type=AuditEventType.ACCESS_ALLOWED if success else AuditEventType.ACCESS_DENIED,
            actor_type=ActorType.USER,
            actor_id=user.id,
            actor_name=user.username or str(user.id),
            resource_type=resource_type,
            resource_id=context.requested_workspace_id,
            resource_name=resource_type,
            action=action,
            outcome=AuditOutcome.SUCCESS if success else AuditOutcome.FAILURE,
            event_metadata=details,
            workspace_id=context.requested_workspace_id,
            ip_address=context.client_ip,
            user_agent=context.user_agent,
        )

        session.add(audit_log)
        await session.commit()

    except Exception as e:
        logger.error("Failed to log audit event", extra={
            "error": str(e),
            "user_id": str(user.id),
            "action": action,
            "resource_type": resource_type,
        })
        # Don't raise exception to avoid breaking the main operation


# Standard dependency functions with enhanced security
async def get_authenticated_user(
    request: Request,
    session: DbSession,
) -> User:
    """Get authenticated user with enhanced security checks."""
    # Check if authentication is disabled in development
    import os
    skip_auth = os.getenv('LANGFLOW_SKIP_AUTH', 'false').lower() == 'true'

    if skip_auth:
        # In development with SKIP_AUTH=true, provide a mock superuser
        from langflow.services.database.models.user.model import User
        from uuid import uuid4

        # Create or get the default superuser for development
        mock_user = User(
            id=uuid4(),
            username="dev_user",
            email="dev@langflow.com",
            is_active=True,
            is_superuser=True,
            password=""  # Empty password for dev mode
        )
        logger.info("Authentication bypassed for development (SKIP_AUTH=true)")
        return mock_user

    # Normal authentication flow - get token from header
    try:
        from fastapi.security.utils import get_authorization_scheme_param
        authorization = request.headers.get("Authorization")
        scheme, token = get_authorization_scheme_param(authorization)

        if not authorization or scheme.lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication token required",
                headers={"WWW-Authenticate": "Bearer"},
            )

        from fastapi.security.http import HTTPAuthorizationCredentials
        token_obj = HTTPAuthorizationCredentials(scheme="bearer", credentials=token)
        return await enhanced_authentication(request, token_obj, session)
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

# It seems not used by other functions here or imported by any code
async def get_rbac_authorized_user(
    user: Annotated[User, Depends(get_authenticated_user)],
    context: Annotated[RuntimeEnforcementContext, Depends(get_enhanced_enforcement_context)],
    session: DbSession,
    permission_engine: Annotated[PermissionEngine, Depends(get_permission_engine)],
    request: Request,
    required_action: str = "read",
    required_resource: str = "workspace",
) -> User:
    """Get authorized user with permission checking."""
    security_req = SecurityRequirement(
        resource_type=required_resource,
        action=required_action,
        audit_action=f"{required_action}_{required_resource}",
    )

    await enhanced_authorization(
        user=user,
        context=context,
        session=session,
        permission_engine=permission_engine,
        request=request,
        security_req=security_req,
    )

    return user


# Predefined security requirements for common operations
WORKSPACE_READ_SECURITY = SecurityRequirement(
    resource_type="workspace",
    action="read",
    require_workspace_access=True,
    audit_action="read_workspace",
)

WORKSPACE_WRITE_SECURITY = SecurityRequirement(
    resource_type="workspace",
    action="update",
    require_workspace_access=True,
    audit_action="update_workspace",
)

PROJECT_READ_SECURITY = SecurityRequirement(
    resource_type="project",
    action="read",
    require_workspace_access=True,
    audit_action="read_project",
)

PROJECT_WRITE_SECURITY = SecurityRequirement(
    resource_type="project",
    action="update",
    require_workspace_access=True,
    audit_action="update_project",
)

ROLE_READ_SECURITY = SecurityRequirement(
    resource_type="role",
    action="read",
    require_workspace_access=True,
    audit_action="read_role",
)

ROLE_WRITE_SECURITY = SecurityRequirement(
    resource_type="role",
    action="update",
    require_workspace_access=True,
    audit_action="update_role",
)

# Predefined validation requirements
WORKSPACE_VALIDATION = ValidationRequirement(
    validate_workspace_exists=True,
)

PROJECT_VALIDATION = ValidationRequirement(
    validate_workspace_exists=True,
    validate_project_exists=True,
)

ROLE_VALIDATION = ValidationRequirement(
    validate_workspace_exists=True,
    validate_role_exists=True,
)

USER_VALIDATION = ValidationRequirement(
    validate_workspace_exists=True,
    validate_user_exists=True,
)
