"""Workspace management API endpoints for RBAC system."""

# NO future annotations per Phase 1 requirements
# from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING
from uuid import UUID

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi_pagination import Params
from fastapi_pagination.ext.sqlmodel import apaginate
from sqlmodel import or_, select

from langflow.api.utils import CurrentActiveUser, DbSession, custom_params
from langflow.services.database.models.user.model import User
from langflow.api.v1.rbac.dependencies import check_workspace_permission, create_audit_context, get_audit_service
from langflow.api.v1.rbac.security_middleware import (
    WORKSPACE_READ_SECURITY,
    WORKSPACE_VALIDATION,
    WORKSPACE_WRITE_SECURITY,
    SecurityRequirement,
    ValidationRequirement,
    get_authenticated_user,
    secure_endpoint,
)
from langflow.services.auth.authorization_patterns import get_enhanced_enforcement_context
from langflow.services.rbac.runtime_enforcement import RuntimeEnforcementContext
from langflow.services.database.models.rbac.workspace import (
    Workspace,
    WorkspaceCreate,
    WorkspaceInvitation,
    WorkspaceRead,
    WorkspaceUpdate,
)
from langflow.services.rbac.audit_service import AuditService

if TYPE_CHECKING:
    pass

router = APIRouter(
    prefix="/workspaces",
    tags=["RBAC", "Workspaces"],
    responses={
        401: {"description": "Unauthorized - Invalid or missing authentication"},
        403: {"description": "Forbidden - Insufficient permissions"},
        404: {"description": "Not Found - Resource does not exist"},
        422: {"description": "Validation Error - Invalid request data"},
    },
)


@router.post("/", response_model=WorkspaceRead, status_code=status.HTTP_201_CREATED)
@secure_endpoint(
    security_req=WORKSPACE_WRITE_SECURITY,
    validation_req=None,  # No specific validation needed for creation
    audit_enabled=True,
)
async def create_workspace(
    workspace_data: WorkspaceCreate,
    request: Request,
    session: DbSession,
    current_user: Annotated[User, Depends(get_authenticated_user)],
    context: Annotated[RuntimeEnforcementContext, Depends(get_enhanced_enforcement_context)],
    audit_service: AuditService = Depends(get_audit_service),
) -> WorkspaceRead:
    """Create a new workspace with comprehensive validation."""
    from loguru import logger

    from langflow.services.database.models.rbac.workspace import Workspace, WorkspaceRead
    from langflow.services.rbac.validation import get_validator

    # Initialize validator
    validator = get_validator(session)

    # Validate input data
    if not workspace_data.name or len(workspace_data.name.strip()) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Workspace name cannot be empty"
        )

    # Validate name length and format
    name = workspace_data.name.strip()
    if len(name) < 3:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Workspace name must be at least 3 characters long"
        )
    if len(name) > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Workspace name cannot exceed 100 characters"
        )

    # Validate workspace limits
    await validator.validate_workspace_limits(current_user.id)

    # Validate unique name
    await validator.validate_unique_workspace_name(name, current_user.id)

    # Create workspace with validated data
    workspace = Workspace(
        name=name,
        description=workspace_data.description,
        organization=workspace_data.organization,
        settings=workspace_data.settings or {},
        owner_id=current_user.id,
    )

    session.add(workspace)
    await session.commit()
    await session.refresh(workspace)

    # Log audit event
    try:
        context = create_audit_context(
            workspace_id=workspace.id,
            additional_data={"workspace_name": workspace.name, "organization": workspace.organization}
        )
        await audit_service.log_role_management_event(
            session=session,
            actor=current_user,
            action="create_workspace",
            target_user_id=None,
            role_id=workspace.id,  # Using workspace ID as target
            context=context,
            details={"workspace_name": workspace.name, "organization": workspace.organization}
        )
    except Exception as e:
        # Don't fail the operation if audit logging fails
        logger.error(f"Failed to log workspace creation audit event: {e}")

    return WorkspaceRead.model_validate(workspace)


@router.get("/list", response_model=list[WorkspaceRead])
@secure_endpoint(
    security_req=WORKSPACE_READ_SECURITY,
    validation_req=None,  # No specific validation needed for listing
    audit_enabled=True,
)
async def list_workspaces(
    session: DbSession,
    current_user: Annotated[User, Depends(get_authenticated_user)],
    search: str | None = Query(None, description="Search workspaces by name or description"),
    organization: str | None = Query(None, description="Filter by organization"),
    is_active: bool | None = Query(None, description="Filter by active status"),
    params: Annotated[Params | None, Depends(custom_params)] = None,
) -> list[WorkspaceRead]:
    """List workspaces accessible to current user."""
    # For now, return all active workspaces since we have no user context without auth
    statement = select(Workspace).where(Workspace.is_active == True, Workspace.is_deleted == False)

    # Apply filters
    if search:
        statement = statement.where(
            (Workspace.name.ilike(f"%{search}%")) |
            (Workspace.description.ilike(f"%{search}%"))
        )

    if organization:
        statement = statement.where(Workspace.organization.ilike(f"%{organization}%"))

    if is_active is not None:
        statement = statement.where(Workspace.is_active == is_active)

    # Apply pagination using fastapi_pagination (standard pattern)
    if params:
        import warnings
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore", category=DeprecationWarning, module=r"fastapi_pagination\.ext\.sqlalchemy"
            )
            paginated_result = await apaginate(session, statement, params=params)
            return [WorkspaceRead.model_validate(workspace) for workspace in paginated_result.items]
    else:
        result = await session.exec(statement)
        workspaces = result.all()
        return [WorkspaceRead.model_validate(workspace) for workspace in workspaces]


@router.get("/{workspace_id}", response_model=WorkspaceRead)
@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="rbac_resource",
        action="read",
        require_workspace_access=True,
        audit_action="rbac_operation",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)
async def get_workspace(
    workspace: Workspace = Depends(check_workspace_permission("read")),
) -> WorkspaceRead:
    """Get workspace by ID."""
    return WorkspaceRead.model_validate(workspace)


@router.put("/{workspace_id}", response_model=WorkspaceRead)
@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="rbac_resource",
        action="update",
        require_workspace_access=True,
        audit_action="rbac_operation",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)
async def update_workspace(
    workspace_id: UUID,
    workspace_data: WorkspaceUpdate,
    session: DbSession,
    # current_user: CurrentActiveUser,
    # workspace: Workspace = Depends(check_workspace_permission("update")),
    # audit_service: AuditService = Depends(get_audit_service),
) -> WorkspaceRead:
    """Update workspace."""
    from loguru import logger

    # Debug: Log the workspace_id being searched
    logger.info(f"Looking for workspace with ID: {workspace_id} (type: {type(workspace_id)})")

    # First, get the workspace to update
    workspace = await session.get(Workspace, workspace_id)
    if not workspace:
        # Debug: Try to find workspace by string ID
        statement = select(Workspace).where(Workspace.id == str(workspace_id))
        result = await session.exec(statement)
        workspace = result.first()

        if not workspace:
            logger.error(f"Workspace not found with ID: {workspace_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Workspace not found"
            )
        else:
            logger.info(f"Found workspace via string search: {workspace.name}")
    else:
        logger.info(f"Found workspace: {workspace.name}")

    # Check name uniqueness if changing name
    if workspace_data.name and workspace_data.name != workspace.name:
        statement = select(Workspace).where(
            Workspace.owner_id == workspace.owner_id,
            Workspace.name == workspace_data.name,
            Workspace.id != workspace_id,
            Workspace.is_deleted == False
        )
        result = await session.exec(statement)
        existing = result.first()

        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Workspace '{workspace_data.name}' already exists"
            )

    # Update workspace fields
    for field, value in workspace_data.model_dump(exclude_unset=True).items():
        setattr(workspace, field, value)

    workspace.updated_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(workspace)

    # TODO: Re-enable audit logging when authentication is restored
    # Log audit event
    # try:
    #     context = create_audit_context(
    #         workspace_id=workspace.id,
    #         additional_data={"updated_fields": list(workspace_data.model_dump(exclude_unset=True).keys())}
    #     )
    #     await audit_service.log_role_management_event(
    #         session=session,
    #         actor=current_user,
    #         action="update_workspace",
    #         target_user_id=None,
    #         role_id=workspace.id,
    #         context=context,
    #         details={"workspace_name": workspace.name, "updated_fields": list(workspace_data.model_dump(exclude_unset=True).keys())}
    #     )
    # except Exception as e:
    #     logger.error(f"Failed to log workspace update audit event: {e}")

    return WorkspaceRead.model_validate(workspace)


@router.delete("/{workspace_id}", status_code=status.HTTP_204_NO_CONTENT)
@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="rbac_resource",
        action="read",
        require_workspace_access=True,
        audit_action="rbac_operation",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)
async def delete_workspace(
    workspace_id: UUID,
    session: DbSession,
    current_user: CurrentActiveUser,
    workspace: Workspace = Depends(check_workspace_permission("delete")),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Soft delete workspace."""
    workspace.is_deleted = True
    workspace.deletion_requested_at = datetime.now(timezone.utc)
    workspace.updated_at = datetime.now(timezone.utc)

    await session.commit()

    # Log audit event
    try:
        context = create_audit_context(
            workspace_id=workspace.id,
            additional_data={"workspace_name": workspace.name}
        )
        await audit_service.log_role_management_event(
            session=session,
            actor=current_user,
            action="delete_workspace",
            target_user_id=None,
            role_id=workspace.id,
            context=context,
            details={"workspace_name": workspace.name, "deletion_type": "soft_delete"}
        )
    except Exception as e:
        logger.error(f"Failed to log workspace deletion audit event: {e}")

    # TODO: Handle cascade deletion/archiving of projects, etc.


@router.post("/{workspace_id}/invite", response_model=dict)
@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="rbac_resource",
        action="read",
        require_workspace_access=True,
        audit_action="rbac_operation",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)
async def invite_user_to_workspace(
    workspace_id: UUID,
    invitation_data: dict,  # TODO: Create proper schema
    session: DbSession,
    current_user: CurrentActiveUser,
    workspace: Workspace = Depends(check_workspace_permission("manage")),
    audit_service: AuditService = Depends(get_audit_service),
) -> dict:
    """Invite a user to the workspace."""
    email = invitation_data.get("email")
    role_id = invitation_data.get("role_id")

    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is required"
        )

    # Check if user is already invited
    statement = select(WorkspaceInvitation).where(
        WorkspaceInvitation.workspace_id == workspace_id,
        WorkspaceInvitation.email == email,
        WorkspaceInvitation.is_accepted == False
    )
    result = await session.exec(statement)
    existing_invitation = result.first()

    if existing_invitation:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already has a pending invitation"
        )

    # Create invitation
    invitation = WorkspaceInvitation(
        workspace_id=workspace_id,
        email=email,
        role_id=role_id,
        invited_by_id=current_user.id,
        invitation_code=secrets.token_urlsafe(32),
        expires_at=datetime.now(timezone.utc) + timedelta(days=7)
    )

    session.add(invitation)
    await session.commit()

    # Log audit event
    try:
        context = create_audit_context(
            workspace_id=workspace_id,
            additional_data={"invited_email": email, "role_id": str(role_id) if role_id else None}
        )
        await audit_service.log_role_management_event(
            session=session,
            actor=current_user,
            action="invite_user_to_workspace",
            target_user_id=None,
            role_id=workspace_id,
            context=context,
            details={"invited_email": email, "role_id": str(role_id) if role_id else None, "expires_at": invitation.expires_at.isoformat()}
        )
    except Exception as e:
        logger.error(f"Failed to log workspace invitation audit event: {e}")

    # TODO: Send invitation email

    return {
        "message": "Invitation sent successfully",
        "invitation_id": str(invitation.id),
        "expires_at": invitation.expires_at.isoformat()
    }


@router.get("/{workspace_id}/users", response_model=list[dict])
@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="rbac_resource",
        action="read",
        require_workspace_access=True,
        audit_action="rbac_operation",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)
async def list_workspace_users(
    workspace_id: UUID,
    session: DbSession,
    current_user: CurrentActiveUser,
    params: Annotated[Params | None, Depends(custom_params)],
    workspace: Workspace = Depends(check_workspace_permission("read")),
) -> list[dict]:
    """List users in workspace with their roles."""
    from langflow.services.database.models.rbac.role import Role
    from langflow.services.database.models.rbac.role_assignment import RoleAssignment
    from langflow.services.database.models.user.model import User

    # Get all active role assignments for this workspace
    assignments_statement = select(RoleAssignment, Role, User).join(
        Role, RoleAssignment.role_id == Role.id
    ).join(
        User, RoleAssignment.user_id == User.id
    ).where(
        RoleAssignment.workspace_id == workspace_id,
        RoleAssignment.is_active == True
    )

    # Apply pagination using fastapi_pagination (standard pattern)
    if params:
        import warnings
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore", category=DeprecationWarning, module=r"fastapi_pagination\.ext\.sqlalchemy"
            )
            paginated_result = await apaginate(session, assignments_statement, params=params)
            assignments = paginated_result.items
    else:
        result = await session.exec(assignments_statement)
        assignments = result.all()

    # Group users and their roles
    user_roles = {}
    for assignment, role, user in assignments:
        user_id = str(user.id)
        if user_id not in user_roles:
            user_roles[user_id] = {
                "user_id": user_id,
                "username": user.username,
                "email": user.email,
                "roles": [],
                "joined_at": assignment.assigned_at.isoformat() if assignment.assigned_at else None,
                "is_active": user.is_active
            }

        user_roles[user_id]["roles"].append({
            "role_id": str(role.id),
            "role_name": role.name,
            "assignment_type": assignment.assignment_type,
            "scope_type": assignment.scope_type,
            "scope_id": str(assignment.scope_id) if assignment.scope_id else None
        })

    # Always include workspace owner if not already included
    owner_id = str(workspace.owner_id)
    if owner_id not in user_roles:
        owner_user = await session.get(User, workspace.owner_id)
        if owner_user:
            user_roles[owner_id] = {
                "user_id": owner_id,
                "username": owner_user.username,
                "email": owner_user.email,
                "roles": [{
                    "role_id": None,
                    "role_name": "Workspace Owner",
                    "assignment_type": "ownership",
                    "scope_type": "workspace",
                    "scope_id": str(workspace_id)
                }],
                "joined_at": workspace.created_at.isoformat(),
                "is_active": owner_user.is_active
            }
    else:
        # Add ownership role to existing user
        user_roles[owner_id]["roles"].append({
            "role_id": None,
            "role_name": "Workspace Owner",
            "assignment_type": "ownership",
            "scope_type": "workspace",
            "scope_id": str(workspace_id)
        })

    return list(user_roles.values())


@router.get("/{workspace_id}/projects", response_model=list[dict])
@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="rbac_resource",
        action="read",
        require_workspace_access=True,
        audit_action="rbac_operation",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)
async def list_workspace_projects(
    workspace_id: UUID,
    session: DbSession,
    current_user: CurrentActiveUser,
    params: Annotated[Params | None, Depends(custom_params)],
    workspace: Workspace = Depends(check_workspace_permission("read")),
) -> list[dict]:
    """List projects in workspace."""
    from langflow.services.database.models.rbac.project import Project

    statement = select(Project).where(
        Project.workspace_id == workspace_id,
        Project.is_active == True
    )

    # Apply pagination using fastapi_pagination (standard pattern)
    if params:
        import warnings
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore", category=DeprecationWarning, module=r"fastapi_pagination\.ext\.sqlalchemy"
            )
            paginated_result = await apaginate(session, statement, params=params)
            projects = paginated_result.items
    else:
        result = await session.exec(statement)
        projects = result.all()

    return [
        {
            "id": str(project.id),
            "name": project.name,
            "description": project.description,
            "created_at": project.created_at.isoformat(),
            "is_active": project.is_active,
            "is_archived": project.is_archived
        }
        for project in projects
    ]


@router.get("/{workspace_id}/stats", response_model=dict)
@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="rbac_resource",
        action="read",
        require_workspace_access=True,
        audit_action="rbac_operation",
    ),
    validation_req=ValidationRequirement(
        validate_workspace_exists=True,
    ),
    audit_enabled=True,
)
async def get_workspace_statistics(
    workspace_id: UUID,
    session: DbSession,
    current_user: CurrentActiveUser,
    workspace: Workspace = Depends(check_workspace_permission("read")),
) -> dict:
    """Get workspace statistics."""
    from sqlmodel import func

    from langflow.services.database.models.flow.model import Flow
    from langflow.services.database.models.rbac.project import Project
    from langflow.services.database.models.rbac.role_assignment import RoleAssignment
    from langflow.services.database.models.rbac.user_group import UserGroup

    # Count projects
    project_statement = select(func.count(Project.id)).where(
        Project.workspace_id == workspace_id,
        Project.is_active == True
    )
    project_result = await session.exec(project_statement)
    project_count = project_result.one()

    # Count users (via role assignments)
    user_statement = select(func.count(func.distinct(RoleAssignment.user_id))).where(
        RoleAssignment.workspace_id == workspace_id,
        RoleAssignment.is_active == True,
        RoleAssignment.user_id.isnot(None)
    )
    user_result = await session.exec(user_statement)
    user_count = user_result.one()

    # Count groups
    group_statement = select(func.count(UserGroup.id)).where(
        UserGroup.workspace_id == workspace_id,
        UserGroup.is_active == True
    )
    group_result = await session.exec(group_statement)
    group_count = group_result.one()

    # Count flows (across all projects in workspace)
    flow_statement = select(func.count(Flow.id)).select_from(
        Flow.join(Project)
    ).where(
        Project.workspace_id == workspace_id,
        Project.is_active == True
    )
    flow_result = await session.exec(flow_statement)
    flow_count = flow_result.one()

    return {
        "workspace_id": str(workspace_id),
        "project_count": project_count,
        "user_count": user_count + 1,  # +1 for owner
        "group_count": group_count,
        "flow_count": flow_count,
        "created_at": workspace.created_at.isoformat(),
        "last_updated": workspace.updated_at.isoformat()
    }
