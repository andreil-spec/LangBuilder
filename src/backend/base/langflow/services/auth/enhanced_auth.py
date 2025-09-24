"""Enhanced Authentication Service with Token Scoping Enforcement.

This module provides comprehensive token scoping enforcement for API keys
and service account tokens, ensuring that tokens can only access resources
and perform actions within their defined scope.
"""

from typing import TYPE_CHECKING, Optional
from uuid import UUID

from loguru import logger
from sqlalchemy.orm import selectinload
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.services.base import Service
from langflow.services.database.models.api_key.model import ApiKey
from langflow.services.database.models.user.model import User

if TYPE_CHECKING:
    from langflow.services.database.models.rbac.service_account import ServiceAccount


class TokenValidationResult:
    """Result of token validation with scoping information."""

    def __init__(
        self,
        is_valid: bool,
        user: User | None = None,
        api_key: ApiKey | None = None,
        service_account: Optional["ServiceAccount"] = None,
        scoped_permissions: list[str] | None = None,
        scope_type: str | None = None,
        scope_id: UUID | None = None,
        workspace_id: UUID | None = None,
        error_message: str | None = None,
    ):
        self.is_valid = is_valid
        self.user = user
        self.api_key = api_key
        self.service_account = service_account
        self.scoped_permissions = scoped_permissions or []
        self.scope_type = scope_type
        self.scope_id = scope_id
        self.workspace_id = workspace_id
        self.error_message = error_message

    @property
    def user_id(self) -> UUID | None:
        """Get user ID from user or service account."""
        if self.user:
            return self.user.id
        if self.service_account:
            return self.service_account.created_by_id
        return None

    def has_scope_permission(self, permission: str) -> bool:
        """Check if the token has a specific scoped permission."""
        if not self.scoped_permissions:
            return True  # No scope restrictions means full access

        # Check exact permission match
        if permission in self.scoped_permissions:
            return True

        # Check wildcard permissions (e.g., "flow:*" matches "flow:read")
        for scoped_perm in self.scoped_permissions:
            if scoped_perm.endswith(":*"):
                resource_type = scoped_perm.split(":")[0]
                if permission.startswith(f"{resource_type}:"):
                    return True

        return False

    def is_scope_valid_for_resource(
        self,
        resource_type: str,
        resource_id: UUID | None = None,
        workspace_id: UUID | None = None,
        project_id: UUID | None = None,
        environment_id: UUID | None = None,
    ) -> bool:
        """Check if the token scope is valid for accessing a specific resource."""
        # If no scope restrictions, allow access
        if not self.scope_type:
            return True

        # Check workspace-level scoping
        if self.scope_type == "workspace":
            if self.workspace_id and workspace_id:
                return self.workspace_id == workspace_id
            return True  # No specific workspace restriction

        # Check project-level scoping
        if self.scope_type == "project":
            if self.scope_id and project_id:
                return self.scope_id == project_id
            return False  # Project scope requires specific project

        # Check environment-level scoping
        if self.scope_type == "environment":
            if self.scope_id and environment_id:
                return self.scope_id == environment_id
            return False  # Environment scope requires specific environment

        # Check resource-level scoping (flow, component)
        if self.scope_type == resource_type:
            if self.scope_id and resource_id:
                return self.scope_id == resource_id
            return False  # Resource scope requires specific resource

        # If scope type doesn't match resource type, check hierarchy
        # For example, workspace scope can access projects within that workspace
        scope_hierarchy = ["workspace", "project", "environment", "flow", "component"]
        try:
            scope_level = scope_hierarchy.index(self.scope_type)
            resource_level = scope_hierarchy.index(resource_type)

            # Higher-level scopes can access lower-level resources
            if scope_level <= resource_level:
                return True
        except ValueError:
            # Unknown scope or resource type
            pass

        return False


class EnhancedAuthenticationService(Service):
    """Enhanced authentication service with comprehensive token scoping."""

    name = "enhanced_authentication_service"

    async def validate_api_key(self, session: AsyncSession, api_key: str) -> TokenValidationResult:
        """Validate API key with comprehensive scoping check."""
        try:
            # Query API key with all relationships
            query = (
                select(ApiKey)
                .options(selectinload(ApiKey.user), selectinload(ApiKey.service_account))
                .where(ApiKey.api_key == api_key)
            )

            result = await session.exec(query)
            api_key_obj = result.first()

            if not api_key_obj:
                return TokenValidationResult(is_valid=False, error_message="Invalid API key")

            # Check if API key is active
            if not api_key_obj.is_active:
                return TokenValidationResult(is_valid=False, error_message="API key is deactivated")

            # Check expiration if applicable
            # TODO: Add expiration check when expiration field is added to model

            # For service account tokens
            if api_key_obj.service_account_id:
                service_account = api_key_obj.service_account
                if not service_account or not service_account.is_active:
                    return TokenValidationResult(is_valid=False, error_message="Service account is inactive")

                return TokenValidationResult(
                    is_valid=True,
                    service_account=service_account,
                    api_key=api_key_obj,
                    scoped_permissions=api_key_obj.scoped_permissions,
                    scope_type=api_key_obj.scope_type,
                    scope_id=UUID(api_key_obj.scope_id) if api_key_obj.scope_id else None,
                    workspace_id=UUID(api_key_obj.workspace_id) if api_key_obj.workspace_id else None,
                )

            # For user tokens
            user = api_key_obj.user
            if not user or not user.is_active:
                return TokenValidationResult(is_valid=False, error_message="User is inactive")

            return TokenValidationResult(
                is_valid=True,
                user=user,
                api_key=api_key_obj,
                scoped_permissions=api_key_obj.scoped_permissions,
                scope_type=api_key_obj.scope_type,
                scope_id=UUID(api_key_obj.scope_id) if api_key_obj.scope_id else None,
                workspace_id=UUID(api_key_obj.workspace_id) if api_key_obj.workspace_id else None,
            )

        except Exception as e:
            logger.error(f"Error validating API key: {e}")
            return TokenValidationResult(is_valid=False, error_message=f"Authentication error: {e!s}")

    async def check_token_permission(
        self,
        session: AsyncSession,
        api_key: str,
        required_permission: str,
        resource_type: str,
        resource_id: UUID | None = None,
        workspace_id: UUID | None = None,
        project_id: UUID | None = None,
        environment_id: UUID | None = None,
    ) -> tuple[bool, str | None]:
        """Check if an API key has permission to access a specific resource."""
        try:
            # Validate the token first
            validation_result = await self.validate_api_key(session, api_key)

            if not validation_result.is_valid:
                return False, validation_result.error_message

            # Check scoped permissions
            if not validation_result.has_scope_permission(required_permission):
                return False, f"Token does not have required permission: {required_permission}"

            # Check scope validity for the resource
            if not validation_result.is_scope_valid_for_resource(
                resource_type=resource_type,
                resource_id=resource_id,
                workspace_id=workspace_id,
                project_id=project_id,
                environment_id=environment_id,
            ):
                return False, f"Token scope does not allow access to {resource_type}:{resource_id}"

            return True, None

        except Exception as e:
            logger.error(f"Error checking token permission: {e}")
            return False, f"Permission check error: {e!s}"

    async def create_scoped_api_key(
        self,
        session: AsyncSession,
        user_id: UUID | None = None,
        service_account_id: UUID | None = None,
        name: str = "Scoped API Key",
        permissions: list[str] | None = None,
        scope_type: str | None = None,
        scope_id: UUID | None = None,
        workspace_id: UUID | None = None,
    ) -> ApiKey:
        """Create a new scoped API key with specific permissions and scope."""
        import secrets

        # Generate a secure API key
        api_key_value = f"sk-{secrets.token_urlsafe(32)}"

        # Create the API key
        api_key = ApiKey(
            api_key=api_key_value,
            name=name,
            user_id=user_id,
            service_account_id=service_account_id,
            scoped_permissions=permissions or [],
            scope_type=scope_type,
            scope_id=str(scope_id) if scope_id else None,
            workspace_id=str(workspace_id) if workspace_id else None,
            is_active=True,
        )

        session.add(api_key)
        await session.flush()

        logger.info(f"Created scoped API key {api_key.id} with permissions: {permissions}")

        return api_key

    async def update_api_key_scope(
        self,
        session: AsyncSession,
        api_key_id: UUID,
        permissions: list[str] | None = None,
        scope_type: str | None = None,
        scope_id: UUID | None = None,
        workspace_id: UUID | None = None,
    ) -> bool:
        """Update the scope of an existing API key."""
        try:
            api_key = await session.get(ApiKey, api_key_id)
            if not api_key:
                return False

            # Update scoping fields
            if permissions is not None:
                api_key.scoped_permissions = permissions
            if scope_type is not None:
                api_key.scope_type = scope_type
            if scope_id is not None:
                api_key.scope_id = str(scope_id)
            if workspace_id is not None:
                api_key.workspace_id = str(workspace_id)

            session.add(api_key)
            await session.flush()

            logger.info(f"Updated scope for API key {api_key_id}")
            return True

        except Exception as e:
            logger.error(f"Error updating API key scope: {e}")
            return False

    async def revoke_api_key(self, session: AsyncSession, api_key_id: UUID) -> bool:
        """Revoke an API key by deactivating it."""
        try:
            api_key = await session.get(ApiKey, api_key_id)
            if not api_key:
                return False

            api_key.is_active = False
            session.add(api_key)
            await session.flush()

            logger.info(f"Revoked API key {api_key_id}")
            return True

        except Exception as e:
            logger.error(f"Error revoking API key: {e}")
            return False

    async def list_api_keys_by_scope(
        self,
        session: AsyncSession,
        scope_type: str | None = None,
        scope_id: UUID | None = None,
        workspace_id: UUID | None = None,
        user_id: UUID | None = None,
        service_account_id: UUID | None = None,
    ) -> list[ApiKey]:
        """List API keys by scope criteria."""
        try:
            query = select(ApiKey).where(ApiKey.is_active == True)

            if scope_type:
                query = query.where(ApiKey.scope_type == scope_type)
            if scope_id:
                query = query.where(ApiKey.scope_id == str(scope_id))
            if workspace_id:
                query = query.where(ApiKey.workspace_id == str(workspace_id))
            if user_id:
                query = query.where(ApiKey.user_id == user_id)
            if service_account_id:
                query = query.where(ApiKey.service_account_id == service_account_id)

            result = await session.exec(query)
            return result.all()

        except Exception as e:
            logger.error(f"Error listing API keys by scope: {e}")
            return []

    def validate_permission_scope(self, permission: str, allowed_permissions: list[str]) -> bool:
        """Validate if a permission is within the allowed scope."""
        if not allowed_permissions:
            return True  # No restrictions

        # Check exact match
        if permission in allowed_permissions:
            return True

        # Check wildcard permissions
        for allowed_perm in allowed_permissions:
            if allowed_perm.endswith(":*"):
                resource_type = allowed_perm.split(":")[0]
                if permission.startswith(f"{resource_type}:"):
                    return True

        return False

    def get_effective_workspace_id(
        self, token_result: TokenValidationResult, requested_workspace_id: UUID | None = None
    ) -> UUID | None:
        """Get the effective workspace ID based on token scope and request."""
        # If token has workspace scoping, use that
        if token_result.workspace_id:
            return token_result.workspace_id

        # If no workspace scoping, use requested workspace
        return requested_workspace_id
