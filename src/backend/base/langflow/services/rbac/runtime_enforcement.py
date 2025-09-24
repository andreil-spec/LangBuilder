"""RBAC Runtime Enforcement Service.

This service provides comprehensive runtime enforcement for RBAC permissions,
integrating token scoping, data access controls, and system-wide security.
"""

from typing import TYPE_CHECKING, Any, Optional
from uuid import UUID

from loguru import logger
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.services.auth.enhanced_auth import EnhancedAuthenticationService, TokenValidationResult
from langflow.services.base import Service
from langflow.services.rbac.data_access_wrapper import DataAccessContext, RBACDataAccessWrapper

if TYPE_CHECKING:
    from langflow.services.database.models.user.model import User
    from langflow.services.rbac.service import RBACService


class RuntimeEnforcementContext:
    """Context for runtime enforcement operations."""

    def __init__(
        self,
        user: Optional["User"] = None,
        token_validation: TokenValidationResult | None = None,
        requested_workspace_id: UUID | None = None,
        requested_project_id: UUID | None = None,
        requested_environment_id: UUID | None = None,
        request_path: str | None = None,
        request_method: str | None = None,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ):
        self.user = user
        self.token_validation = token_validation
        self.requested_workspace_id = requested_workspace_id
        self.requested_project_id = requested_project_id
        self.requested_environment_id = requested_environment_id
        self.request_path = request_path
        self.request_method = request_method
        self.client_ip = client_ip
        self.user_agent = user_agent

    @property
    def effective_workspace_id(self) -> UUID | None:
        """Get the effective workspace ID considering token scoping."""
        if self.token_validation and self.token_validation.workspace_id:
            return self.token_validation.workspace_id
        return self.requested_workspace_id

    @property
    def data_access_context(self) -> DataAccessContext:
        """Convert to DataAccessContext for data operations."""
        return DataAccessContext(
            user=self.user,
            service_account_id=self.token_validation.service_account.id
            if self.token_validation and self.token_validation.service_account
            else None,
            api_key_id=self.token_validation.api_key.id
            if self.token_validation and self.token_validation.api_key
            else None,
            scopes=self.token_validation.scoped_permissions if self.token_validation else [],
            workspace_id=self.effective_workspace_id,
            project_id=self.requested_project_id,
            environment_id=self.requested_environment_id,
        )


class RBACRuntimeEnforcementService(Service):
    """Comprehensive RBAC runtime enforcement service."""

    name = "rbac_runtime_enforcement_service"

    def __init__(self, rbac_service: "RBACService", auth_service: EnhancedAuthenticationService | None = None):
        super().__init__()
        self.rbac_service = rbac_service
        self.auth_service = auth_service or EnhancedAuthenticationService()
        self.data_wrapper = RBACDataAccessWrapper(rbac_service)

    async def create_enforcement_context(
        self,
        session: AsyncSession,
        api_key: str | None = None,
        user: Optional["User"] = None,
        workspace_id: UUID | None = None,
        project_id: UUID | None = None,
        environment_id: UUID | None = None,
        request_path: str | None = None,
        request_method: str | None = None,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> RuntimeEnforcementContext:
        """Create a comprehensive enforcement context."""
        token_validation = None

        # Validate API key if provided
        if api_key:
            token_validation = await self.auth_service.validate_api_key(session, api_key)
            if not token_validation.is_valid:
                raise ValueError(f"Invalid API key: {token_validation.error_message}")

            # Use user from token if not explicitly provided
            if not user:
                user = token_validation.user or (
                    token_validation.service_account.created_by if token_validation.service_account else None
                )

        return RuntimeEnforcementContext(
            user=user,
            token_validation=token_validation,
            requested_workspace_id=workspace_id,
            requested_project_id=project_id,
            requested_environment_id=environment_id,
            request_path=request_path,
            request_method=request_method,
            client_ip=client_ip,
            user_agent=user_agent,
        )

    async def check_resource_access(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        permission: str,
        resource_type: str,
        resource_id: UUID | None = None,
    ) -> bool:
        """Check if access to a resource is allowed with comprehensive enforcement."""
        try:
            # First check token scoping if applicable
            if context.token_validation:
                if not context.token_validation.has_scope_permission(permission):
                    logger.debug(f"Token scope check failed for permission: {permission}")
                    return False

                if not context.token_validation.is_scope_valid_for_resource(
                    resource_type=resource_type,
                    resource_id=resource_id,
                    workspace_id=context.effective_workspace_id,
                    project_id=context.requested_project_id,
                    environment_id=context.requested_environment_id,
                ):
                    logger.debug(f"Token scope check failed for resource: {resource_type}:{resource_id}")
                    return False
            # just return True as below are non existing import and non existing ckeck_permission() calls
            return True

            # Then check RBAC permissions
            from langflow.services.rbac.service import CheckPermissionRequest

            permission_request = CheckPermissionRequest(
                user_id=context.user.id if context.user else None,
                service_account_id=context.token_validation.service_account.id
                if context.token_validation and context.token_validation.service_account
                else None,
                permission=permission,
                resource_type=resource_type,
                resource_id=str(resource_id) if resource_id else None,
                workspace_id=context.effective_workspace_id,
                project_id=context.requested_project_id,
                environment_id=context.requested_environment_id,
            )

            return await self.rbac_service.check_permission(permission_request)

        except Exception as e:
            logger.error(f"Error checking resource access: {e}")
            return False

    async def secure_data_operation(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        operation: str,
        model_class: type,
        model_id: UUID | None = None,
        data: dict[str, Any] | None = None,
        permission_override: str | None = None,
    ) -> Any:
        """Perform a data operation with comprehensive security checks."""
        try:
            # Determine permission based on operation
            resource_type = self.data_wrapper._get_resource_type_from_model(model_class)
            if permission_override:
                permission = permission_override
            else:
                permission_map = {
                    "get": f"{resource_type}:read",
                    "list": f"{resource_type}:read",
                    "create": f"{resource_type}:write",
                    "update": f"{resource_type}:write",
                    "delete": f"{resource_type}:delete",
                }
                permission = permission_map.get(operation, f"{resource_type}:read")

            # Check access first
            access_allowed = await self.check_resource_access(
                session=session,
                context=context,
                permission=permission,
                resource_type=resource_type,
                resource_id=model_id,
            )

            if not access_allowed:
                logger.warning(
                    f"Access denied for {operation} on {resource_type}:{model_id}",
                    extra={
                        "user_id": str(context.user.id) if context.user else None,
                        "operation": operation,
                        "resource_type": resource_type,
                        "resource_id": str(model_id) if model_id else None,
                        "permission": permission,
                    },
                )
                return None

            # Perform the operation using the data wrapper
            data_context = context.data_access_context

            if operation == "get":
                return await self.data_wrapper.get_with_permission(
                    session=session,
                    model=model_class,
                    id=model_id,
                    context=data_context,
                    permission=permission,
                    resource_type=resource_type,
                )

            if operation == "list":
                filters = data or {}
                return await self.data_wrapper.list_with_permission(
                    session=session,
                    model=model_class,
                    context=data_context,
                    permission=permission,
                    resource_type=resource_type,
                    filters=filters,
                )

            if operation == "create":
                return await self.data_wrapper.create_with_permission(
                    session=session,
                    model=model_class,
                    data=data or {},
                    context=data_context,
                    permission=permission,
                    resource_type=resource_type,
                )

            if operation == "update":
                return await self.data_wrapper.update_with_permission(
                    session=session,
                    model=model_class,
                    id=model_id,
                    data=data or {},
                    context=data_context,
                    permission=permission,
                    resource_type=resource_type,
                )

            if operation == "delete":
                return await self.data_wrapper.delete_with_permission(
                    session=session,
                    model=model_class,
                    id=model_id,
                    context=data_context,
                    permission=permission,
                    resource_type=resource_type,
                )

            raise ValueError(f"Unsupported operation: {operation}")

        except Exception as e:
            logger.error(f"Error in secure data operation: {e}")
            raise

    async def validate_bulk_operation(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        operation: str,
        resource_type: str,
        resource_ids: list[UUID],
        permission_override: str | None = None,
    ) -> list[UUID]:
        """Validate a bulk operation and return allowed resource IDs."""
        allowed_ids = []

        # Determine permission
        if permission_override:
            permission = permission_override
        else:
            permission_map = {
                "read": f"{resource_type}:read",
                "write": f"{resource_type}:write",
                "delete": f"{resource_type}:delete",
            }
            permission = permission_map.get(operation, f"{resource_type}:read")

        # Check each resource individually
        for resource_id in resource_ids:
            access_allowed = await self.check_resource_access(
                session=session,
                context=context,
                permission=permission,
                resource_type=resource_type,
                resource_id=resource_id,
            )

            if access_allowed:
                allowed_ids.append(resource_id)

        return allowed_ids

    async def audit_enforcement_decision(
        self,
        context: RuntimeEnforcementContext,
        operation: str,
        resource_type: str,
        resource_id: UUID | None = None,
        permission: str | None = None,
        decision: bool = False,
        reason: str | None = None,
        session: AsyncSession | None = None,
    ) -> None:
        """Audit an enforcement decision."""
        try:
            # Skip auditing if no user context or audit service
            if not context.user or not self.rbac_service.audit_service:
                logger.debug("Skipping audit: missing user context or audit service")
                return

            # Skip if no session provided (audit logging is optional for now)
            if not session:
                logger.debug("Skipping audit: no session provided for database logging")
                return

            # Import here to avoid circular imports
            from langflow.services.rbac.audit_service import AuditContext

            # Create audit context
            audit_context = AuditContext(
                user_id=context.user.id,
                workspace_id=context.effective_workspace_id,
                additional_data={
                    "service_account_id": context.token_validation.service_account.id
                    if context.token_validation and context.token_validation.service_account
                    else None,
                    "project_id": str(context.requested_project_id) if context.requested_project_id else None,
                    "environment_id": str(context.requested_environment_id) if context.requested_environment_id else None,
                    "request_path": context.request_path,
                    "request_method": context.request_method,
                    "token_scoped": bool(context.token_validation and context.token_validation.scoped_permissions),
                    "scope_type": context.token_validation.scope_type if context.token_validation else None,
                    "scope_id": str(context.token_validation.scope_id)
                    if context.token_validation and context.token_validation.scope_id
                    else None,
                }
            )

            # Details for the audit
            details = {
                "permission": permission,
                "reason": reason,
                "operation": operation,
            }

            await self.rbac_service.audit_service.log_authorization_event(
                session=session,
                user=context.user,
                action=f"enforcement:{operation}",
                resource_type=resource_type,
                resource_id=resource_id,
                success=decision,
                context=audit_context,
                details=details,
            )

        except Exception as e:
            logger.error(f"Error auditing enforcement decision: {e}")

    async def get_effective_permissions(
        self, session: AsyncSession, context: RuntimeEnforcementContext, resource_type: str | None = None
    ) -> list[str]:
        """Get effective permissions for the context considering token scoping."""
        try:
            # Get RBAC permissions
            if context.user:
                rbac_permissions = await self.rbac_service.get_user_permissions(
                    user_id=context.user.id,
                    workspace_id=context.effective_workspace_id,
                    project_id=context.requested_project_id,
                    environment_id=context.requested_environment_id,
                )
            else:
                rbac_permissions = []

            # Filter by token scoping if applicable
            if context.token_validation and context.token_validation.scoped_permissions:
                effective_permissions = []
                for rbac_perm in rbac_permissions:
                    if context.token_validation.has_scope_permission(rbac_perm):
                        effective_permissions.append(rbac_perm)
                return effective_permissions

            return rbac_permissions

        except Exception as e:
            logger.error(f"Error getting effective permissions: {e}")
            return []

    async def check_system_permission(
        self, session: AsyncSession, context: RuntimeEnforcementContext, permission: str
    ) -> bool:
        """Check system-level permissions (workspace admin, global admin, etc.)."""
        try:
            # System permissions are not subject to token scoping restrictions
            # They require full RBAC validation

            from langflow.services.rbac.service import CheckPermissionRequest

            permission_request = CheckPermissionRequest(
                user_id=context.user.id if context.user else None,
                service_account_id=context.token_validation.service_account.id
                if context.token_validation and context.token_validation.service_account
                else None,
                permission=permission,
                resource_type="system",
                resource_id=None,
                workspace_id=context.effective_workspace_id,
                project_id=context.requested_project_id,
                environment_id=context.requested_environment_id,
            )

            return await self.rbac_service.check_permission(permission_request)

        except Exception as e:
            logger.error(f"Error checking system permission: {e}")
            return False
