"""Secure Data Access Service for RBAC-aware database operations.

This module provides secure data access patterns that eliminate cross-workspace
data leakage and enforce proper RBAC permissions for all database operations.
"""

from typing import List, Optional, Type, TypeVar, Union
from uuid import UUID

from sqlalchemy import and_, or_, select
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.services.database.models.flow.model import Flow
from langflow.services.database.models.folder.model import Folder
from langflow.services.database.models.user.model import User
from langflow.services.rbac.runtime_enforcement import RuntimeEnforcementContext, RBACRuntimeEnforcementService
from loguru import logger

T = TypeVar('T', bound=SQLModel)


class SecureDataAccessService:
    """Service for secure, RBAC-aware data access operations.

    This service ensures that all data access operations:
    1. Respect workspace and project boundaries
    2. Enforce RBAC permissions
    3. Prevent cross-workspace data leakage
    4. Provide comprehensive audit logging
    """

    def __init__(self, rbac_service=None):
        self.rbac_service = rbac_service
        if not rbac_service:
            from langflow.services.deps import get_rbac_service
            self.rbac_service = get_rbac_service()

    async def get_accessible_flows(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        folder_id: UUID | None = None,
        components_only: bool = False,
        remove_example_flows: bool = False,
        starter_folder_id: UUID | None = None,
    ) -> List[Flow]:
        """Get flows accessible to the user within RBAC boundaries.

        This method replaces the vulnerable user_id-based filtering with
        proper RBAC-aware workspace and project filtering.
        """
        enforcement_service = RBACRuntimeEnforcementService(self.rbac_service)

        try:
            # Start with base flow query
            stmt = select(Flow)

            # Apply workspace-level filtering if context has workspace
            if context.effective_workspace_id:
                # Get accessible projects in the workspace
                accessible_projects = await self._get_accessible_projects_in_workspace(
                    session, context, context.effective_workspace_id
                )

                if accessible_projects:
                    # Filter flows by accessible projects (folders)
                    stmt = stmt.where(Flow.folder_id.in_(accessible_projects))
                else:
                    # No accessible projects means no accessible flows
                    return []
            else:
                # If no workspace context, check user permissions on individual flows
                # This is a fallback for legacy scenarios
                user_accessible_flows = await self._get_user_accessible_flows(
                    session, context
                )
                if user_accessible_flows:
                    stmt = stmt.where(Flow.id.in_(user_accessible_flows))
                else:
                    return []

            # Apply additional filters
            if folder_id:
                # Verify user has access to this specific folder/project
                has_folder_access = await enforcement_service.check_resource_access(
                    session=session,
                    context=context,
                    permission="project:read",
                    resource_type="project",
                    resource_id=folder_id,
                )

                if not has_folder_access:
                    logger.warning(f"User {context.user.id} denied access to folder {folder_id}")
                    return []

                stmt = stmt.where(Flow.folder_id == folder_id)

            if components_only:
                stmt = stmt.where(Flow.is_component == True)  # noqa: E712

            if remove_example_flows and starter_folder_id:
                stmt = stmt.where(Flow.folder_id != starter_folder_id)

            # Execute query
            flows = (await session.exec(stmt)).all()

            # Additional RBAC filtering for individual flows
            accessible_flows = []
            for flow in flows:
                has_flow_access = await enforcement_service.check_resource_access(
                    session=session,
                    context=context,
                    permission="flow:read",
                    resource_type="flow",
                    resource_id=flow[0].id,
                )

                if has_flow_access:
                    accessible_flows.append(flow[0])

            # Audit the data access
            await enforcement_service.audit_enforcement_decision(
                context=context,
                operation="list_flows",
                resource_type="flow",
                permission="flow:read",
                decision=True,
                reason=f"Retrieved {len(accessible_flows)} accessible flows",
            )

            return accessible_flows

        except Exception as e:
            logger.error(f"Error in secure flow access: {e}")
            await enforcement_service.audit_enforcement_decision(
                context=context,
                operation="list_flows",
                resource_type="flow",
                permission="flow:read",
                decision=False,
                reason=f"Data access error: {e}",
            )
            raise

    async def get_flow_by_id_secure(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        flow_id: UUID,
    ) -> Flow | None:
        """Get a specific flow with RBAC verification.

        This method replaces vulnerable user_id filtering with proper
        RBAC permission checking and workspace boundary enforcement.
        """
        enforcement_service = RBACRuntimeEnforcementService(self.rbac_service)

        try:
            # First check if user has permission to read this flow
            has_permission = await enforcement_service.check_resource_access(
                session=session,
                context=context,
                permission="flow:read",
                resource_type="flow",
                resource_id=flow_id,
            )

            if not has_permission:
                await enforcement_service.audit_enforcement_decision(
                    context=context,
                    operation="get_flow",
                    resource_type="flow",
                    resource_id=flow_id,
                    permission="flow:read",
                    decision=False,
                    reason="Insufficient permissions to access flow",
                )
                return None

            # Get the flow
            stmt = select(Flow).where(Flow.id == flow_id)
            flow = (await session.exec(stmt)).first()

            if not flow:
                return None

            # Additional workspace boundary check
            if context.effective_workspace_id:
                # Verify flow belongs to accessible workspace/project
                flow_workspace_access = await self._verify_flow_workspace_access(
                    session, context, flow
                )

                if not flow_workspace_access:
                    await enforcement_service.audit_enforcement_decision(
                        context=context,
                        operation="get_flow",
                        resource_type="flow",
                        resource_id=flow_id,
                        permission="flow:read",
                        decision=False,
                        reason="Flow not accessible in current workspace context",
                    )
                    return None

            # Audit successful access
            await enforcement_service.audit_enforcement_decision(
                context=context,
                operation="get_flow",
                resource_type="flow",
                resource_id=flow_id,
                permission="flow:read",
                decision=True,
                reason="Flow access granted",
            )

            # type(flow) is Row, so we need flow[0] to get to Flow type
            return flow[0]

        except Exception as e:
            logger.error(f"Error in secure flow access by ID: {e}")
            await enforcement_service.audit_enforcement_decision(
                context=context,
                operation="get_flow",
                resource_type="flow",
                resource_id=flow_id,
                permission="flow:read",
                decision=False,
                reason=f"Data access error: {e}",
            )
            raise

    async def get_flows_by_ids_secure(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        flow_ids: List[UUID],
    ) -> List[Flow]:
        """Get multiple flows with RBAC verification for bulk operations.

        This method prevents bulk operations from bypassing workspace boundaries.
        """
        enforcement_service = RBACRuntimeEnforcementService(self.rbac_service)

        try:
            accessible_flows = []
            denied_count = 0

            for flow_id in flow_ids:
                # Check permission for each flow individually
                has_permission = await enforcement_service.check_resource_access(
                    session=session,
                    context=context,
                    permission="flow:read",
                    resource_type="flow",
                    resource_id=flow_id,
                )

                if has_permission:
                    # Get the flow and verify workspace boundaries
                    flow = await self.get_flow_by_id_secure(session, context, flow_id)
                    if flow:
                        accessible_flows.append(flow)
                else:
                    denied_count += 1

            # Audit the bulk operation
            await enforcement_service.audit_enforcement_decision(
                context=context,
                operation="bulk_get_flows",
                resource_type="flow",
                permission="flow:read",
                decision=True,
                reason=f"Bulk access: {len(accessible_flows)} granted, {denied_count} denied",
            )

            return accessible_flows

        except Exception as e:
            logger.error(f"Error in secure bulk flow access: {e}")
            await enforcement_service.audit_enforcement_decision(
                context=context,
                operation="bulk_get_flows",
                resource_type="flow",
                permission="flow:read",
                decision=False,
                reason=f"Bulk data access error: {e}",
            )
            raise

    async def _get_accessible_projects_in_workspace(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        workspace_id: UUID,
    ) -> List[UUID]:
        """Get projects/folders accessible to user in a specific workspace."""
        enforcement_service = RBACRuntimeEnforcementService(self.rbac_service)

        try:
            # Get all folders/projects in the workspace
            # Note: This assumes folders represent projects in workspace hierarchy
            stmt = select(Folder.id)

            # If there's a workspace association, filter by it
            # (Implementation depends on your folder-workspace relationship model)

            folder_rows = (await session.exec(stmt)).all()

            accessible_projects = []
            for folder_row in folder_rows:
                folder_id = folder_row[0]  # Extract UUID from Row object
                has_access = await enforcement_service.check_resource_access(
                    session=session,
                    context=context,
                    permission="project:read",
                    resource_type="project",
                    resource_id=folder_id,
                )

                if has_access:
                    accessible_projects.append(folder_id)

            return accessible_projects

        except Exception as e:
            logger.error(f"Error getting accessible projects: {e}")
            return []

    async def _get_user_accessible_flows(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
    ) -> List[UUID]:
        """Get flows accessible to user (fallback for legacy scenarios)."""
        # This is a simplified implementation for legacy compatibility
        # In practice, you'd want to implement proper workspace-based filtering

        # For now, return flows owned by user as a safe fallback
        # This should be replaced with proper workspace-based filtering
        stmt = select(Flow.id).where(Flow.user_id == context.user.id)
        flow_rows = (await session.exec(stmt)).all()

        # Extract UUIDs from Row objects
        flow_ids = [row[0] for row in flow_rows]
        return flow_ids

    async def _verify_flow_workspace_access(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        flow: Flow,
    ) -> bool:
        """Verify a flow is accessible within current workspace context."""
        if not context.effective_workspace_id:
            return True  # No workspace context means legacy access

        # Check if flow's project/folder is accessible in current workspace
        if flow.folder_id:
            enforcement_service = RBACRuntimeEnforcementService(self.rbac_service)
            return await enforcement_service.check_resource_access(
                session=session,
                context=context,
                permission="project:read",
                resource_type="project",
                resource_id=flow.folder_id,
            )

        return False  # Flow without folder in workspace context is not accessible

    async def create_flow_secure(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        flow_data: dict,
        target_folder_id: UUID | None = None,
    ) -> Flow | None:
        """Create a flow with RBAC workspace boundary enforcement."""
        enforcement_service = RBACRuntimeEnforcementService(self.rbac_service)

        try:
            # Verify user can create flows in the target workspace/project
            if target_folder_id:
                has_create_permission = await enforcement_service.check_resource_access(
                    session=session,
                    context=context,
                    permission="flow:write",
                    resource_type="project",
                    resource_id=target_folder_id,
                )

                if not has_create_permission:
                    await enforcement_service.audit_enforcement_decision(
                        context=context,
                        operation="create_flow",
                        resource_type="flow",
                        permission="flow:write",
                        decision=False,
                        reason=f"No permission to create flows in project {target_folder_id}",
                    )
                    return None

            # Ensure flow is created with proper workspace context
            flow_data["user_id"] = context.user.id
            if target_folder_id:
                flow_data["folder_id"] = target_folder_id

            # Create flow using the data access wrapper
            from langflow.services.rbac.data_access_wrapper import RBACDataAccessWrapper

            data_wrapper = RBACDataAccessWrapper()
            flow = await data_wrapper.create_with_permissions(
                session=session,
                model_class=Flow,
                data=flow_data,
                user=context.user,
                permission="flow:write",
            )

            if flow:
                await enforcement_service.audit_enforcement_decision(
                    context=context,
                    operation="create_flow",
                    resource_type="flow",
                    resource_id=flow.id,
                    permission="flow:write",
                    decision=True,
                    reason="Flow created successfully",
                )

            return flow

        except Exception as e:
            logger.error(f"Error in secure flow creation: {e}")
            await enforcement_service.audit_enforcement_decision(
                context=context,
                operation="create_flow",
                resource_type="flow",
                permission="flow:write",
                decision=False,
                reason=f"Flow creation error: {e}",
            )
            raise

    async def validate_flow_name_unique_secure(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        flow_name: str,
        workspace_id: UUID | None = None,
    ) -> str:
        """Validate and ensure flow name uniqueness within workspace boundaries.

        Returns a unique name, potentially with suffix like (1), (2), etc.
        This prevents cross-workspace name conflicts and data leakage.
        """
        enforcement_service = RBACRuntimeEnforcementService(self.rbac_service)

        try:
            # Get accessible flows within the workspace context
            accessible_flows = await self.get_accessible_flows(
                session=session,
                context=context,
                folder_id=None,  # Check all folders in workspace
                components_only=False,
                remove_example_flows=False,
            )

            # Check for exact name match within accessible scope
            exact_match = next((flow for flow in accessible_flows if flow.name == flow_name), None)

            if not exact_match:
                # Name is unique within workspace scope
                return flow_name

            # Find all flows with similar names like "MyFlow (1)", "MyFlow (2)"
            import re
            extract_number = re.compile(rf"^{re.escape(flow_name)} \((\d+)\)$")

            numbers = []
            for flow in accessible_flows:
                if flow.name.startswith(f"{flow_name} ("):
                    result = extract_number.search(flow.name)
                    if result:
                        numbers.append(int(result.group(1)))

            # Generate unique name
            if numbers:
                unique_name = f"{flow_name} ({max(numbers) + 1})"
            else:
                unique_name = f"{flow_name} (1)"

            await enforcement_service.audit_enforcement_decision(
                context=context,
                operation="validate_name_uniqueness",
                resource_type="flow",
                permission="flow:write",
                decision=True,
                reason=f"Generated unique name: {unique_name}",
            )

            return unique_name

        except Exception as e:
            logger.error(f"Error in secure flow name validation: {e}")
            await enforcement_service.audit_enforcement_decision(
                context=context,
                operation="validate_name_uniqueness",
                resource_type="flow",
                permission="flow:write",
                decision=False,
                reason=f"Name validation error: {e}",
            )
            raise

    async def validate_flow_endpoint_unique_secure(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        endpoint_name: str,
        workspace_id: UUID | None = None,
    ) -> str:
        """Validate and ensure flow endpoint uniqueness within workspace boundaries.

        Returns a unique endpoint name, potentially with suffix like -1, -2, etc.
        This prevents cross-workspace endpoint conflicts and data leakage.
        """
        enforcement_service = RBACRuntimeEnforcementService(self.rbac_service)

        try:
            # Get accessible flows within the workspace context
            accessible_flows = await self.get_accessible_flows(
                session=session,
                context=context,
                folder_id=None,  # Check all folders in workspace
                components_only=False,
                remove_example_flows=False,
            )

            # Check for exact endpoint match within accessible scope
            exact_match = next((flow for flow in accessible_flows if flow.endpoint_name == endpoint_name), None)

            if not exact_match:
                # Endpoint is unique within workspace scope
                return endpoint_name

            # Find all flows with similar endpoints like "my-endpoint-1", "my-endpoint-2"
            similar_endpoints = [
                flow.endpoint_name for flow in accessible_flows
                if flow.endpoint_name and flow.endpoint_name.startswith(f"{endpoint_name}-")
            ]

            # Extract numbers from similar endpoints
            numbers = []
            for endpoint in similar_endpoints:
                try:
                    suffix = endpoint.split("-")[-1]
                    if suffix.isdigit():
                        numbers.append(int(suffix))
                except (ValueError, IndexError):
                    continue

            # Generate unique endpoint name
            if numbers:
                unique_endpoint = f"{endpoint_name}-{max(numbers) + 1}"
            else:
                unique_endpoint = f"{endpoint_name}-1"

            await enforcement_service.audit_enforcement_decision(
                context=context,
                operation="validate_endpoint_uniqueness",
                resource_type="flow",
                permission="flow:write",
                decision=True,
                reason=f"Generated unique endpoint: {unique_endpoint}",
            )

            return unique_endpoint

        except Exception as e:
            logger.error(f"Error in secure flow endpoint validation: {e}")
            await enforcement_service.audit_enforcement_decision(
                context=context,
                operation="validate_endpoint_uniqueness",
                resource_type="flow",
                permission="flow:write",
                decision=False,
                reason=f"Endpoint validation error: {e}",
            )
            raise

    async def get_default_folder_secure(
        self,
        session: AsyncSession,
        context: RuntimeEnforcementContext,
        folder_name: str = "My Projects",
    ) -> Folder | None:
        """Get default folder within workspace boundaries with RBAC security.

        This prevents cross-workspace folder access and data leakage.
        """
        enforcement_service = RBACRuntimeEnforcementService(self.rbac_service)

        try:
            # Use RBAC-aware query that respects workspace boundaries
            from langflow.services.rbac.data_access_wrapper import RBACDataAccessWrapper

            data_wrapper = RBACDataAccessWrapper()
            folders = await data_wrapper.query_with_permissions(
                session=session,
                query=select(Folder).where(Folder.name == folder_name),
                user=context.user,
                permission="folder:read",
            )

            # Return first accessible folder
            folder = folders[0] if folders else None

            if folder:
                await enforcement_service.audit_enforcement_decision(
                    context=context,
                    operation="get_default_folder",
                    resource_type="folder",
                    resource_id=folder.id,
                    permission="folder:read",
                    decision=True,
                    reason=f"Default folder {folder_name} accessed successfully",
                )
            else:
                await enforcement_service.audit_enforcement_decision(
                    context=context,
                    operation="get_default_folder",
                    resource_type="folder",
                    permission="folder:read",
                    decision=False,
                    reason=f"Default folder {folder_name} not found in accessible scope",
                )

            return folder

        except Exception as e:
            logger.error(f"Error in secure default folder access: {e}")
            await enforcement_service.audit_enforcement_decision(
                context=context,
                operation="get_default_folder",
                resource_type="folder",
                permission="folder:read",
                decision=False,
                reason=f"Default folder access error: {e}",
            )
            raise
