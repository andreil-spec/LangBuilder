"""Role Assignment management API endpoints for RBAC system."""

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi_pagination import Params
from fastapi_pagination.ext.sqlmodel import apaginate
from loguru import logger
from sqlmodel import func, select

from langflow.api.utils import CurrentActiveUser, DbSession, custom_params
from langflow.services.database.models.user.model import User
from langflow.api.v1.rbac.dependencies import (
    create_audit_context,
    get_audit_service,
    get_permission_engine,
)
from langflow.api.v1.rbac.security_middleware import (
    SecurityRequirement,
    ValidationRequirement,
    get_authenticated_user,
    secure_endpoint,
)
from langflow.services.auth.authorization_patterns import get_enhanced_enforcement_context
from langflow.services.rbac.runtime_enforcement import RuntimeEnforcementContext
from langflow.schema.serialize import UUIDstr
from langflow.services.database.models.rbac.role_assignment import (
    RoleAssignment,
    RoleAssignmentRead,
    RoleAssignmentCreate,
    AssignmentType,
    AssignmentScope
)
from langflow.services.database.models.rbac.role import Role
from langflow.services.database.models.rbac.workspace import Workspace
from langflow.services.rbac.audit_service import AuditService
from langflow.services.rbac.permission_engine import PermissionEngine

router = APIRouter(
    prefix="/role-assignments",
    tags=["RBAC", "Role Assignments"],
    responses={
        401: {"description": "Unauthorized - Invalid or missing authentication"},
        403: {"description": "Forbidden - Insufficient permissions"},
        404: {"description": "Not Found - Resource does not exist"},
        422: {"description": "Validation Error - Invalid request data"},
    },
)


@router.get("/", response_model=list[RoleAssignmentRead])
# @secure_endpoint(
#     security_req=SecurityRequirement(
#         resource_type="rbac_resource",
#         action="read",
#         require_workspace_access=True,
#         audit_action="rbac_operation",
#     ),
#     validation_req=ValidationRequirement(
#         validate_workspace_exists=True,
#     ),
#     audit_enabled=True,
# )
async def list_role_assignments(
    session: DbSession,
    current_user: CurrentActiveUser,
    params: Annotated[Params | None, Depends(custom_params)],
    permission_engine: PermissionEngine = Depends(get_permission_engine),
    workspace_id: UUIDstr | None = Query(None),
    assignment_type: str | None = None,
    scope_type: str | None = None,
    is_active: bool | None = None,
) -> list[RoleAssignmentRead]:
    """List role assignments accessible to current user."""

    try:
        statement = select(RoleAssignment)

        # Filter by workspace if specified
        if workspace_id:
            workspace = await session.get(Workspace, workspace_id)
            if not workspace:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Workspace not found"
                )

            # Check workspace access
            result = await permission_engine.check_permission(
                session=session,
                user=current_user,
                resource_type="workspace",
                action="read_assignments",
                resource_id=workspace_id,
                workspace_id=workspace_id,
            )

            if not result.allowed:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions to read assignments in this workspace: {result.reason}"
                )

            statement = statement.where(RoleAssignment.workspace_id == workspace_id)

        # Apply filters
        if assignment_type:
            statement = statement.where(RoleAssignment.assignment_type == assignment_type)

        if scope_type:
            statement = statement.where(RoleAssignment.scope_type == scope_type)

        if is_active is not None:
            statement = statement.where(RoleAssignment.is_active == is_active)

        # Execute query
        result = await session.exec(statement)
        assignments = result.all()

        logger.info(f"Listed {len(assignments)} role assignments for user {current_user.id}")

        # Convert to response format with populated names
        assignment_reads = []
        for assignment in assignments:
            # Build the response with populated names
            assignment_dict = assignment.model_dump()

            # Fetch and populate role name
            if assignment.role_id:
                role = await session.get(Role, assignment.role_id)
                if role:
                    assignment_dict["role_name"] = role.name

            # Fetch and populate user name
            if assignment.user_id:
                user = await session.get(User, assignment.user_id)
                if user:
                    assignment_dict["user_name"] = user.username or f"{user.first_name or ''} {user.last_name or ''}".strip() or None

            # Fetch and populate assigned_by name
            if assignment.assigned_by_id:
                assigned_by = await session.get(User, assignment.assigned_by_id)
                if assigned_by:
                    assignment_dict["assigned_by_name"] = assigned_by.username or f"{assigned_by.first_name or ''} {assigned_by.last_name or ''}".strip() or None

            assignment_reads.append(RoleAssignmentRead(**assignment_dict))

        return assignment_reads

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to list role assignments: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve role assignments"
        )


@router.post("/", response_model=RoleAssignmentRead, status_code=status.HTTP_201_CREATED)
# @secure_endpoint(
#     security_req=SecurityRequirement(
#         resource_type="rbac_resource",
#         action="create",
#         require_workspace_access=True,
#         audit_action="rbac_operation",
#     ),
#     validation_req=ValidationRequirement(
#         validate_workspace_exists=True,
#     ),
#     audit_enabled=True,
# )
async def create_role_assignment(
    assignment_data: RoleAssignmentCreate,
    request: Request,
    session: DbSession,
    current_user: Annotated[User, Depends(get_authenticated_user)],
    context: Annotated[RuntimeEnforcementContext, Depends(get_enhanced_enforcement_context)],
    permission_engine: PermissionEngine = Depends(get_permission_engine),
    audit_service: AuditService = Depends(get_audit_service),
) -> RoleAssignmentRead:
    """Create a new role assignment."""

    try:
        # Validate required fields based on assignment_type
        if assignment_data.assignment_type == AssignmentType.USER and not assignment_data.user_id:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="user_id is required for user assignments"
            )
        elif assignment_data.assignment_type == AssignmentType.GROUP and not assignment_data.group_id:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="group_id is required for group assignments"
            )
        elif assignment_data.assignment_type == AssignmentType.SERVICE_ACCOUNT and not assignment_data.service_account_id:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="service_account_id is required for service account assignments"
            )

        # Validate scope fields based on scope_type
        if assignment_data.scope_type == AssignmentScope.WORKSPACE and not assignment_data.workspace_id:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="workspace_id is required for workspace scope"
            )
        elif assignment_data.scope_type == AssignmentScope.PROJECT and not assignment_data.project_id:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="project_id is required for project scope"
            )

        # Validate that the role exists
        role = await session.get(Role, assignment_data.role_id)
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found"
            )

        # Validate workspace access for workspace-scoped assignments
        if assignment_data.workspace_id:
            workspace = await session.get(Workspace, assignment_data.workspace_id)
            if not workspace or workspace.is_deleted:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Workspace not found"
                )

            # Check permission to create assignments in this workspace
            result = await permission_engine.check_permission(
                session=session,
                user=current_user,
                resource_type="workspace",
                action="create_assignment",
                resource_id=assignment_data.workspace_id,
                workspace_id=assignment_data.workspace_id,
            )

            if not result.allowed:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions to create assignments in this workspace: {result.reason}"
                )

        # Validate that the target user/group/service account exists
        if assignment_data.user_id:
            target_user = await session.get(User, assignment_data.user_id)
            if not target_user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Target user not found"
                )

        # Check for existing assignments to prevent duplicates
        existing_query = select(RoleAssignment).where(
            RoleAssignment.role_id == assignment_data.role_id,
            RoleAssignment.assignment_type == assignment_data.assignment_type,
            RoleAssignment.scope_type == assignment_data.scope_type,
            RoleAssignment.is_active == True,
        )

        if assignment_data.user_id:
            existing_query = existing_query.where(RoleAssignment.user_id == assignment_data.user_id)
        if assignment_data.workspace_id:
            existing_query = existing_query.where(RoleAssignment.workspace_id == assignment_data.workspace_id)
        if assignment_data.project_id:
            existing_query = existing_query.where(RoleAssignment.project_id == assignment_data.project_id)

        existing_result = await session.exec(existing_query)
        existing_assignment = existing_result.first()

        if existing_assignment:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A similar role assignment already exists"
            )

        # Create the role assignment
        now = datetime.now(timezone.utc)
        db_assignment = RoleAssignment(
            role_id=assignment_data.role_id,
            assignment_type=assignment_data.assignment_type,
            scope_type=assignment_data.scope_type,

            # Assignee fields
            user_id=assignment_data.user_id,
            group_id=assignment_data.group_id,
            service_account_id=assignment_data.service_account_id,

            # Scope fields
            workspace_id=assignment_data.workspace_id,
            project_id=assignment_data.project_id,
            environment_id=assignment_data.environment_id,
            flow_id=assignment_data.flow_id,
            component_id=assignment_data.component_id,

            # Assignment metadata
            valid_from=assignment_data.valid_from or now,
            valid_until=assignment_data.valid_until,
            conditions=assignment_data.conditions or {},
            ip_restrictions=assignment_data.ip_restrictions or [],
            time_restrictions=assignment_data.time_restrictions or {},
            reason=assignment_data.reason,

            # System fields
            is_active=True,
            assigned_by_id=current_user.id,
            assigned_at=now,
            updated_at=now,
        )

        session.add(db_assignment)
        await session.commit()
        await session.refresh(db_assignment)

        # Create audit log entry
        try:
            audit_context = create_audit_context(
                user_id=current_user.id,
                action="role_assignment_created",
                resource_type="role_assignment",
                resource_id=str(db_assignment.id),
                workspace_id=assignment_data.workspace_id,
            )

            await audit_service.log_role_management_event(
                session=session,
                context=audit_context,
                details={
                    "role_id": str(assignment_data.role_id),
                    "assignment_type": assignment_data.assignment_type.value,
                    "scope_type": assignment_data.scope_type.value,
                    "target_user_id": str(assignment_data.user_id) if assignment_data.user_id else None,
                    "workspace_id": str(assignment_data.workspace_id) if assignment_data.workspace_id else None,
                }
            )
        except Exception as audit_error:
            logger.error(f"⚠️ Failed to log role assignment creation audit: {str(audit_error)}")
            # Continue - don't fail the API call due to audit logging issues

        logger.info(f"✅ Role assignment created successfully: {db_assignment.id}")
        logger.info(f"   Role: {assignment_data.role_id}")
        logger.info(f"   Assignment Type: {assignment_data.assignment_type}")
        logger.info(f"   User ID: {assignment_data.user_id}")
        logger.info(f"   Scope: {assignment_data.scope_type}")
        logger.info(f"   Workspace ID: {assignment_data.workspace_id}")
        logger.info(f"   Assigned by: {current_user.id}")

        # Build the response with populated names using already-fetched objects
        assignment_dict = db_assignment.model_dump()

        # Populate role name (role object already fetched for validation above)
        assignment_dict["role_name"] = role.name

        # Populate user name (target_user already fetched for validation above)
        if assignment_data.user_id and 'target_user' in locals():
            assignment_dict["user_name"] = target_user.username or f"{target_user.first_name or ''} {target_user.last_name or ''}".strip() or None

        # Populate assigned_by name (current_user already available)
        assignment_dict["assigned_by_name"] = current_user.username or f"{current_user.first_name or ''} {current_user.last_name or ''}".strip() or None

        # Return the created assignment
        return RoleAssignmentRead(**assignment_dict)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to create role assignment: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create role assignment"
        )


@router.get("/{assignment_id}", response_model=RoleAssignmentRead)
# @secure_endpoint(
#     security_req=SecurityRequirement(
#         resource_type="rbac_resource",
#         action="read",
#         require_workspace_access=True,
#         audit_action="rbac_operation",
#     ),
#     validation_req=ValidationRequirement(
#         validate_workspace_exists=True,
#     ),
#     audit_enabled=True,
# )
async def get_role_assignment(
    assignment_id: UUIDstr,
    session: DbSession,
    current_user: CurrentActiveUser,
    permission_engine: PermissionEngine = Depends(get_permission_engine),
) -> RoleAssignmentRead:
    """Get a specific role assignment by ID."""

    try:
        assignment = await session.get(RoleAssignment, assignment_id)
        if not assignment or not assignment.is_active:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role assignment not found"
            )

        # Check permission to read this assignment
        if assignment.workspace_id:
            result = await permission_engine.check_permission(
                session=session,
                user=current_user,
                resource_type="workspace",
                action="read_assignments",
                resource_id=assignment.workspace_id,
                workspace_id=assignment.workspace_id,
            )

            if not result.allowed:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions to read this assignment: {result.reason}"
                )

        # Build the response with populated names
        assignment_dict = assignment.model_dump()

        # Fetch and populate role name
        if assignment.role_id:
            role = await session.get(Role, assignment.role_id)
            if role:
                assignment_dict["role_name"] = role.name

        # Fetch and populate user name
        if assignment.user_id:
            user = await session.get(User, assignment.user_id)
            if user:
                assignment_dict["user_name"] = user.username or f"{user.first_name or ''} {user.last_name or ''}".strip() or None

        # Fetch and populate assigned_by name
        if assignment.assigned_by_id:
            assigned_by = await session.get(User, assignment.assigned_by_id)
            if assigned_by:
                assignment_dict["assigned_by_name"] = assigned_by.username or f"{assigned_by.first_name or ''} {assigned_by.last_name or ''}".strip() or None

        logger.info(f"Retrieved role assignment {assignment_id} for user {current_user.id}")
        return RoleAssignmentRead(**assignment_dict)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get role assignment {assignment_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve role assignment"
        )


@router.delete("/{assignment_id}", status_code=status.HTTP_204_NO_CONTENT)
# @secure_endpoint(
#     security_req=SecurityRequirement(
#         resource_type="rbac_resource",
#         action="delete",
#         require_workspace_access=True,
#         audit_action="rbac_operation",
#         is_dangerous=True,
#     ),
#     validation_req=ValidationRequirement(
#         validate_workspace_exists=True,
#     ),
#     audit_enabled=True,
# )
async def delete_role_assignment(
    assignment_id: UUIDstr,
    session: DbSession,
    current_user: Annotated[User, Depends(get_authenticated_user)],
    permission_engine: PermissionEngine = Depends(get_permission_engine),
    audit_service: AuditService = Depends(get_audit_service),
) -> None:
    """Delete (deactivate) a role assignment."""

    try:
        assignment = await session.get(RoleAssignment, assignment_id)
        if not assignment:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role assignment not found"
            )

        # Check permission to delete assignments in this workspace
        if assignment.workspace_id:
            result = await permission_engine.check_permission(
                session=session,
                user=current_user,
                resource_type="workspace",
                action="delete_assignment",
                resource_id=assignment.workspace_id,
                workspace_id=assignment.workspace_id,
            )

            if not result.allowed:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions to delete assignments in this workspace: {result.reason}"
                )

        # Hard delete - remove the assignment completely
        await session.delete(assignment)
        await session.commit()

        # Create audit log entry
        try:
            audit_context = create_audit_context(
                user_id=current_user.id,
                action="role_assignment_deleted",
                resource_type="role_assignment",
                resource_id=str(assignment.id),
                workspace_id=assignment.workspace_id,
            )

            await audit_service.log_role_management_event(
                session=session,
                context=audit_context,
                details={
                    "assignment_id": str(assignment.id),
                    "role_id": str(assignment.role_id),
                    "assignment_type": assignment.assignment_type.value,
                    "target_user_id": str(assignment.user_id) if assignment.user_id else None,
                }
            )
        except Exception as audit_error:
            logger.error(f"⚠️ Failed to log role assignment deletion audit: {str(audit_error)}")
            # Continue - don't fail the API call due to audit logging issues

        logger.info(f"✅ Role assignment {assignment_id} deleted by user {current_user.id}")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to delete role assignment {assignment_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete role assignment"
        )
