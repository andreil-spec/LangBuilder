"""RBAC Data Access Wrapper.

This module provides a comprehensive wrapper around database operations
to enforce RBAC permissions at the data access layer, preventing unauthorized
data access and ensuring all database operations respect user permissions.
"""

from typing import TYPE_CHECKING, Any, Optional, TypeVar
from uuid import UUID

from loguru import logger
from sqlmodel import SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.services.base import Service

if TYPE_CHECKING:
    from langflow.services.database.models.user.model import User
    from langflow.services.rbac.service import RBACService

T = TypeVar("T", bound=SQLModel)


class DataAccessContext:
    """Context for data access operations with user and permission information."""

    def __init__(
        self,
        user: Optional["User"] = None,
        service_account_id: UUID | None = None,
        api_key_id: UUID | None = None,
        scopes: list[str] | None = None,
        workspace_id: UUID | None = None,
        project_id: UUID | None = None,
        environment_id: UUID | None = None,
    ):
        self.user = user
        self.service_account_id = service_account_id
        self.api_key_id = api_key_id
        self.scopes = scopes or []
        self.workspace_id = workspace_id
        self.project_id = project_id
        self.environment_id = environment_id

    @property
    def user_id(self) -> UUID | None:
        """Get the user ID from the context."""
        return self.user.id if self.user else None

    def has_scope(self, scope: str) -> bool:
        """Check if the context has a specific scope."""
        return scope in self.scopes

    def to_dict(self) -> dict[str, Any]:
        """Convert context to dictionary for logging."""
        return {
            "user_id": str(self.user_id) if self.user_id else None,
            "service_account_id": str(self.service_account_id) if self.service_account_id else None,
            "api_key_id": str(self.api_key_id) if self.api_key_id else None,
            "scopes": self.scopes,
            "workspace_id": str(self.workspace_id) if self.workspace_id else None,
            "project_id": str(self.project_id) if self.project_id else None,
            "environment_id": str(self.environment_id) if self.environment_id else None,
        }


class RBACDataAccessWrapper(Service):
    """RBAC-aware data access wrapper that enforces permissions for all database operations."""

    name = "rbac_data_access_wrapper"

    def __init__(self, rbac_service: "RBACService"):
        super().__init__()
        self.rbac_service = rbac_service

    async def get_with_permission(
        self,
        session: AsyncSession,
        model: type[T],
        id: UUID | str,
        context: DataAccessContext,
        permission: str,
        resource_type: str | None = None,
    ) -> T | None:
        """Get a single record with permission check."""
        try:
            # Get the record first
            record = await session.get(model, id)
            if not record:
                return None

            # Determine resource type if not provided
            if not resource_type:
                resource_type = self._get_resource_type_from_model(model)

            # Check permission
            has_permission = await self._check_permission(
                context=context,
                permission=permission,
                resource_type=resource_type,
                resource_id=str(id),
                resource=record,
            )

            if not has_permission:
                logger.warning(
                    f"Permission denied for {context.user_id} to {permission} on {resource_type}:{id}",
                    extra={"context": context.to_dict(), "permission": permission, "resource_type": resource_type},
                )
                return None

            return record

        except Exception as e:
            logger.error(f"Error in get_with_permission: {e}", extra={"context": context.to_dict()})
            raise

    async def list_with_permission(
        self,
        session: AsyncSession,
        model: type[T],
        context: DataAccessContext,
        permission: str,
        resource_type: str | None = None,
        filters: dict[str, Any] | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[T]:
        """List records with permission filtering."""
        try:
            # Build base query
            query = select(model)

            # Apply filters
            if filters:
                for field, value in filters.items():
                    if hasattr(model, field):
                        query = query.where(getattr(model, field) == value)

            # Apply pagination
            if offset:
                query = query.offset(offset)
            if limit:
                query = query.limit(limit)

            # Execute query
            result = await session.exec(query)
            records = result.all()

            # Determine resource type if not provided
            if not resource_type:
                resource_type = self._get_resource_type_from_model(model)

            # Filter records based on permissions
            allowed_records = []
            for record in records:
                has_permission = await self._check_permission(
                    context=context,
                    permission=permission,
                    resource_type=resource_type,
                    resource_id=str(getattr(record, "id", None)),
                    resource=record,
                )

                if has_permission:
                    allowed_records.append(record)

            return allowed_records

        except Exception as e:
            logger.error(f"Error in list_with_permission: {e}", extra={"context": context.to_dict()})
            raise

    async def create_with_permission(
        self,
        session: AsyncSession,
        model: type[T],
        data: dict[str, Any],
        context: DataAccessContext,
        permission: str,
        resource_type: str | None = None,
    ) -> T | None:
        """Create a record with permission check."""
        try:
            # Determine resource type if not provided
            if not resource_type:
                resource_type = self._get_resource_type_from_model(model)

            # Check permission to create
            has_permission = await self._check_permission(
                context=context,
                permission=permission,
                resource_type=resource_type,
                resource_id=None,  # No ID for new resources
                resource=None,
            )

            if not has_permission:
                logger.warning(
                    f"Permission denied for {context.user_id} to {permission} on {resource_type}",
                    extra={"context": context.to_dict(), "permission": permission, "resource_type": resource_type},
                )
                return None

            # Create the record
            record = model(**data)
            session.add(record)
            await session.flush()  # Get the ID without committing

            return record

        except Exception as e:
            logger.error(f"Error in create_with_permission: {e}", extra={"context": context.to_dict()})
            raise

    async def update_with_permission(
        self,
        session: AsyncSession,
        model: type[T],
        id: UUID | str,
        data: dict[str, Any],
        context: DataAccessContext,
        permission: str,
        resource_type: str | None = None,
    ) -> T | None:
        """Update a record with permission check."""
        try:
            # Get the existing record
            record = await session.get(model, id)
            if not record:
                return None

            # Determine resource type if not provided
            if not resource_type:
                resource_type = self._get_resource_type_from_model(model)

            # Check permission to update
            has_permission = await self._check_permission(
                context=context,
                permission=permission,
                resource_type=resource_type,
                resource_id=str(id),
                resource=record,
            )

            if not has_permission:
                logger.warning(
                    f"Permission denied for {context.user_id} to {permission} on {resource_type}:{id}",
                    extra={"context": context.to_dict(), "permission": permission, "resource_type": resource_type},
                )
                return None

            # Update the record
            for field, value in data.items():
                if hasattr(record, field):
                    setattr(record, field, value)

            session.add(record)
            await session.flush()

            return record

        except Exception as e:
            logger.error(f"Error in update_with_permission: {e}", extra={"context": context.to_dict()})
            raise

    async def delete_with_permission(
        self,
        session: AsyncSession,
        model: type[T],
        id: UUID | str,
        context: DataAccessContext,
        permission: str,
        resource_type: str | None = None,
    ) -> bool:
        """Delete a record with permission check."""
        try:
            # Get the existing record
            record = await session.get(model, id)
            if not record:
                return False

            # Determine resource type if not provided
            if not resource_type:
                resource_type = self._get_resource_type_from_model(model)

            # Check permission to delete
            has_permission = await self._check_permission(
                context=context,
                permission=permission,
                resource_type=resource_type,
                resource_id=str(id),
                resource=record,
            )

            if not has_permission:
                logger.warning(
                    f"Permission denied for {context.user_id} to {permission} on {resource_type}:{id}",
                    extra={"context": context.to_dict(), "permission": permission, "resource_type": resource_type},
                )
                return False

            # Delete the record
            await session.delete(record)
            await session.flush()

            return True

        except Exception as e:
            logger.error(f"Error in delete_with_permission: {e}", extra={"context": context.to_dict()})
            raise

    async def _check_permission(
        self,
        context: DataAccessContext,
        permission: str,
        resource_type: str,
        resource_id: str | None = None,
        resource: SQLModel | None = None,
    ) -> bool:
        """Check if the context has the required permission."""
        try:
            # If no user context, deny access
            if not context.user_id and not context.service_account_id:
                return False

            # Extract workspace, project, environment context from resource or context
            workspace_id = context.workspace_id
            project_id = context.project_id
            environment_id = context.environment_id

            # Try to extract context from the resource if available
            if resource:
                if hasattr(resource, "workspace_id") and resource.workspace_id:
                    workspace_id = resource.workspace_id
                if hasattr(resource, "project_id") and resource.project_id:
                    project_id = resource.project_id
                if hasattr(resource, "environment_id") and resource.environment_id:
                    environment_id = resource.environment_id

            # Check token scopes if API key is being used
            if context.api_key_id and context.scopes:
                scope_permission = f"{resource_type}:{permission.split(':')[-1]}"
                if not context.has_scope(scope_permission):
                    logger.debug(f"Token scope check failed for {scope_permission}")
                    return False

            # Use RBAC service to check permission
            from langflow.services.rbac.service import CheckPermissionRequest

            permission_request = CheckPermissionRequest(
                user_id=context.user_id,
                service_account_id=context.service_account_id,
                permission=permission,
                resource_type=resource_type,
                resource_id=resource_id,
                workspace_id=workspace_id,
                project_id=project_id,
                environment_id=environment_id,
            )

            return await self.rbac_service.check_permission(permission_request)

        except Exception as e:
            logger.error(f"Error checking permission: {e}")
            return False

    def _get_resource_type_from_model(self, model: type[SQLModel]) -> str:
        """Get resource type from model class."""
        model_name = model.__name__.lower()

        # Map model names to resource types
        resource_type_mapping = {
            "flow": "flow",
            "project": "project",
            "environment": "environment",
            "workspace": "workspace",
            "variable": "variable",
            "folder": "folder",
            "apikey": "api_key",
            "user": "user",
            "role": "role",
            "permission": "permission",
            "roleassignment": "role_assignment",
            "usergroup": "user_group",
            "serviceaccount": "service_account",
            "auditlog": "audit_log",
        }

        return resource_type_mapping.get(model_name, model_name)

    async def check_scope_permission(self, context: DataAccessContext, required_scope: str) -> bool:
        """Check if the context has the required scope."""
        if not context.scopes:
            return True  # No scope restrictions

        return context.has_scope(required_scope)

    async def audit_data_access(
        self,
        context: DataAccessContext,
        operation: str,
        resource_type: str,
        resource_id: str | None = None,
        success: bool = True,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Audit data access operations."""
        try:
            # Create audit log entry
            audit_data = {
                "user_id": context.user_id,
                "service_account_id": context.service_account_id,
                "action": f"data_access:{operation}",
                "resource_type": resource_type,
                "resource_id": resource_id,
                "workspace_id": context.workspace_id,
                "project_id": context.project_id,
                "environment_id": context.environment_id,
                "success": success,
                "details": details or {},
                "api_key_id": context.api_key_id,
                "scopes": context.scopes,
            }

            # Log to audit service
            await self.rbac_service.audit_service.log_action(**audit_data)

        except Exception as e:
            logger.error(f"Error auditing data access: {e}")


# Convenience functions for common operations
async def get_flow_with_permission(
    session: AsyncSession, flow_id: UUID, context: DataAccessContext, permission: str = "flow:read"
):
    """Get a flow with permission check."""
    wrapper = RBACDataAccessWrapper(rbac_service=None)  # Will be injected
    from langflow.services.database.models.flow.model import Flow

    return await wrapper.get_with_permission(
        session=session, model=Flow, id=flow_id, context=context, permission=permission, resource_type="flow"
    )


async def list_flows_with_permission(
    session: AsyncSession,
    context: DataAccessContext,
    permission: str = "flow:read",
    workspace_id: UUID | None = None,
    limit: int | None = None,
    offset: int | None = None,
):
    """List flows with permission filtering."""
    wrapper = RBACDataAccessWrapper(rbac_service=None)  # Will be injected
    from langflow.services.database.models.flow.model import Flow

    filters = {}
    if workspace_id:
        filters["workspace_id"] = workspace_id

    return await wrapper.list_with_permission(
        session=session,
        model=Flow,
        context=context,
        permission=permission,
        resource_type="flow",
        filters=filters,
        limit=limit,
        offset=offset,
    )


async def get_project_with_permission(
    session: AsyncSession, project_id: UUID, context: DataAccessContext, permission: str = "project:read"
):
    """Get a project with permission check."""
    wrapper = RBACDataAccessWrapper(rbac_service=None)  # Will be injected
    from langflow.services.database.models.rbac.project import Project

    return await wrapper.get_with_permission(
        session=session, model=Project, id=project_id, context=context, permission=permission, resource_type="project"
    )
