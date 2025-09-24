"""Permission management API endpoints for RBAC system."""

from fastapi import APIRouter, Depends, HTTPException, status
import uuid
from typing import Union
from pydantic import BaseModel
from sqlmodel import select

from langflow.api.utils import DbSession, CurrentActiveUser
from langflow.services.database.models.rbac.permission import Permission, PermissionRead, PermissionCreate, ResourceType, PermissionAction


class CheckPermissionRequest(BaseModel):
    """Request model for permission checking."""

    resource_type: str
    action: str
    resource_id: Union[str, None] = None
    workspace_id: Union[str, None] = None
    project_id: Union[str, None] = None
    environment_id: Union[str, None] = None


class PermissionResult(BaseModel):
    """Result model for permission checking."""

    allowed: bool
    reason: Union[str, None] = None
    cached: Union[bool, None] = None


router = APIRouter(
    prefix="/permissions",
    tags=["RBAC", "Permissions"],
    responses={
        401: {"description": "Unauthorized - Invalid or missing authentication"},
        403: {"description": "Forbidden - Insufficient permissions"},
        404: {"description": "Not Found - Resource does not exist"},
        422: {"description": "Validation Error - Invalid request data"},
    },
)


@router.get("/", response_model=list[PermissionRead])
async def list_permissions(
    session: DbSession,
    workspace_id: str = "00000000-0000-0000-0000-000000000000",
    limit: int = 100,
    is_system: Union[bool, None] = None,
) -> list[PermissionRead]:
    """List available permissions in the system from the database."""

    # Query permissions from database
    query = select(Permission)

    # Apply filters
    if is_system is not None:
        query = query.where(Permission.is_system == is_system)

    # Apply limit
    query = query.limit(limit)

    result = await session.exec(query)
    permissions = result.all()

    # If no permissions in database, return empty list (will be populated by init endpoint)
    if not permissions:
        return []

    # Convert to PermissionRead objects
    permission_reads = []
    for perm in permissions:
        permission_reads.append(PermissionRead(
            id=str(perm.id),
            name=perm.name,
            code=perm.code,
            description=perm.description,
            category=perm.category,
            resource_type=perm.resource_type,
            action=perm.action,
            scope=perm.scope,
            conditions=perm.conditions or {},
            is_system=perm.is_system,
            is_dangerous=perm.is_dangerous,
            requires_mfa=perm.requires_mfa,
            role_count=0  # TODO: Calculate actual role count
        ))

    return permission_reads


@router.post("/", response_model=PermissionRead, status_code=status.HTTP_201_CREATED)
async def create_permission(
    permission_data: PermissionCreate,
    session: DbSession,
    current_user: CurrentActiveUser,
) -> PermissionRead:
    """Create a new permission (admin only)."""

    # Check if user is superuser or admin
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only superusers can create permissions"
        )

    # Check if permission with same code already exists
    existing_query = select(Permission).where(Permission.code == permission_data.code)
    existing_result = await session.exec(existing_query)
    if existing_result.first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Permission with code '{permission_data.code}' already exists"
        )

    # Create the permission
    permission = Permission(**permission_data.model_dump())
    session.add(permission)
    await session.commit()
    await session.refresh(permission)

    # Convert to PermissionRead for response
    return PermissionRead(
        id=str(permission.id),
        name=permission.name,
        code=permission.code,
        description=permission.description,
        category=permission.category,
        resource_type=permission.resource_type,
        action=permission.action,
        scope=permission.scope,
        conditions=permission.conditions or {},
        is_system=permission.is_system,
        is_dangerous=permission.is_dangerous,
        requires_mfa=permission.requires_mfa,
        role_count=0  # New permission has no roles assigned yet
    )


@router.post("/initialize", status_code=status.HTTP_201_CREATED)
async def initialize_permissions(
    session: DbSession,
    current_user: CurrentActiveUser,
) -> dict:
    """Initialize default permissions in the database (admin only)."""

    # Check if user is superuser or admin
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only superusers can initialize permissions"
        )

    # Check if permissions already exist
    existing_query = select(Permission).limit(1)
    existing_result = await session.exec(existing_query)
    if existing_result.first():
        return {
            "message": "Permissions already initialized",
            "created": 0,
            "skipped": True
        }

    # Define all available permissions with sensible classifications
    all_permissions = [
        # ===== NORMAL USER PERMISSIONS (is_system=False, not dangerous) =====
        # These are basic operations any user should be able to be granted

        # Flow Management - Basic Operations
        Permission(
            name="Create Flows",
            code="flows.create",
            description="Create new flows in the workspace",
            category="Flow Management",
            resource_type=ResourceType.FLOW,
            action=PermissionAction.CREATE,
            scope="*",
            conditions={},
            is_system=False,
            is_dangerous=False,
            requires_mfa=False,
        ),
        Permission(
            name="Read Flows",
            code="flows.read",
            description="View and list flows in the workspace",
            category="Flow Management",
            resource_type=ResourceType.FLOW,
            action=PermissionAction.READ,
            scope="*",
            conditions={},
            is_system=False,
            is_dangerous=False,
            requires_mfa=False,
        ),
        Permission(
            name="Update Flows",
            code="flows.update",
            description="Modify and edit existing flows",
            category="Flow Management",
            resource_type=ResourceType.FLOW,
            action=PermissionAction.UPDATE,
            scope="*",
            conditions={},
            is_system=False,
            is_dangerous=False,
            requires_mfa=False,
        ),
        Permission(
            name="Execute Flows",
            code="flows.execute",
            description="Run and execute flows",
            category="Flow Management",
            resource_type=ResourceType.FLOW,
            action=PermissionAction.EXECUTE,
            scope="*",
            conditions={},
            is_system=False,
            is_dangerous=False,
            requires_mfa=False,
        ),

        # Project Management - Basic Operations
        Permission(
            name="Create Projects",
            code="project.create",
            description="Create new projects",
            category="Project Management",
            resource_type=ResourceType.PROJECT,
            action=PermissionAction.CREATE,
            scope="*",
            conditions={},
            is_system=False,
            is_dangerous=False,
            requires_mfa=False,
        ),
        Permission(
            name="Read Projects",
            code="project.read",
            description="View project information",
            category="Project Management",
            resource_type=ResourceType.PROJECT,
            action=PermissionAction.READ,
            scope="*",
            conditions={},
            is_system=False,
            is_dangerous=False,
            requires_mfa=False,
        ),
        Permission(
            name="Update Projects",
            code="project.update",
            description="Modify project settings",
            category="Project Management",
            resource_type=ResourceType.PROJECT,
            action=PermissionAction.UPDATE,
            scope="*",
            conditions={},
            is_system=False,
            is_dangerous=False,
            requires_mfa=False,
        ),

        # Workspace - Basic Access
        Permission(
            name="Read Workspace",
            code="workspace.read",
            description="View workspace information and settings",
            category="Workspace Management",
            resource_type=ResourceType.WORKSPACE,
            action=PermissionAction.READ,
            scope="*",
            conditions={},
            is_system=False,
            is_dangerous=False,
            requires_mfa=False,
        ),
        Permission(
            name="Update Workspace",
            code="workspace.update",
            description="Modify basic workspace settings",
            category="Workspace Management",
            resource_type=ResourceType.WORKSPACE,
            action=PermissionAction.UPDATE,
            scope="*",
            conditions={},
            is_system=False,
            is_dangerous=False,
            requires_mfa=False,
        ),

        # ===== EXTENDED PERMISSIONS FROM PRD (is_system=False, not dangerous) =====
        # Extended actions as specified in Story 1.1
        Permission(
            name="Export Flow",
            code="flows.export_flow",
            description="Export flows from the workspace",
            category="Extended Actions",
            resource_type=ResourceType.FLOW,
            action=PermissionAction.EXPORT_FLOW,
            scope="*",
            conditions={},
            is_system=False,
            is_dangerous=False,
            requires_mfa=False,
        ),
        Permission(
            name="Deploy Environment",
            code="environment.deploy_environment",
            description="Deploy to environments",
            category="Extended Actions",
            resource_type=ResourceType.ENVIRONMENT,
            action=PermissionAction.DEPLOY_ENVIRONMENT,
            scope="*",
            conditions={},
            is_system=False,
            is_dangerous=False,
            requires_mfa=False,
        ),
        Permission(
            name="Invite Users",
            code="user.invite_users",
            description="Invite users to workspaces and projects",
            category="Extended Actions",
            resource_type=ResourceType.USER,
            action=PermissionAction.INVITE_USERS,
            scope="*",
            conditions={},
            is_system=False,
            is_dangerous=False,
            requires_mfa=False,
        ),
        Permission(
            name="Modify Component Settings",
            code="component.modify_component_settings",
            description="Modify component settings and configurations",
            category="Extended Actions",
            resource_type=ResourceType.COMPONENT,
            action=PermissionAction.MODIFY_COMPONENT_SETTINGS,
            scope="*",
            conditions={},
            is_system=False,
            is_dangerous=False,
            requires_mfa=False,
        ),
        Permission(
            name="Manage Tokens",
            code="api_key.manage_tokens",
            description="Create, view, and manage API tokens",
            category="Extended Actions",
            resource_type=ResourceType.API_KEY,
            action=PermissionAction.MANAGE_TOKENS,
            scope="*",
            conditions={},
            is_system=False,
            is_dangerous=False,
            requires_mfa=False,
        ),

        # ===== DANGEROUS PERMISSIONS (is_system=False, but dangerous) =====
        # Only deleting operations are dangerous and require MFA

        Permission(
            name="Delete Flows",
            code="flows.delete",
            description="Delete flows from the workspace",
            category="Flow Management",
            resource_type=ResourceType.FLOW,
            action=PermissionAction.DELETE,
            scope="*",
            conditions={},
            is_system=False,
            is_dangerous=True,
            requires_mfa=True,
        ),
        Permission(
            name="Delete Projects",
            code="project.delete",
            description="Delete projects permanently",
            category="Project Management",
            resource_type=ResourceType.PROJECT,
            action=PermissionAction.DELETE,
            scope="*",
            conditions={},
            is_system=False,
            is_dangerous=True,
            requires_mfa=True,
        ),

        # ===== SYSTEM PERMISSIONS (is_system=True) =====
        # Only core system administration should be system-only

        Permission(
            name="Manage System Configuration",
            code="system.manage",
            description="Modify core system settings and configuration",
            category="System Administration",
            resource_type=ResourceType.WORKSPACE,
            action=PermissionAction.MANAGE,
            scope="*",
            conditions={},
            is_system=True,
            is_dangerous=True,
            requires_mfa=True,
        ),
        Permission(
            name="Manage RBAC System",
            code="rbac.manage",
            description="Manage RBAC roles, permissions, and security policies",
            category="System Administration",
            resource_type=ResourceType.WORKSPACE,
            action=PermissionAction.MANAGE,
            scope="*",
            conditions={},
            is_system=True,
            is_dangerous=True,
            requires_mfa=True,
        ),
    ]

    # Add all permissions to the database
    created_count = 0
    for perm in all_permissions:
        # Check if permission already exists by code
        existing = await session.exec(
            select(Permission).where(Permission.code == perm.code)
        )
        if not existing.first():
            session.add(perm)
            created_count += 1

    await session.commit()

    return {
        "message": f"Successfully created {created_count} permissions",
        "created": created_count,
        "total": len(all_permissions)
    }



@router.post("/check-permission", response_model=PermissionResult)
async def check_permission(
    request: CheckPermissionRequest,
) -> PermissionResult:
    """
    Check if the current user has permission to perform an action on a resource.

    This endpoint evaluates user permissions based on their roles and the
    requested resource/action combination. For now, it returns a simplified
    response to make the frontend work.
    """
    try:
        # For now, implement a simplified permission check
        # In a full RBAC implementation, this would:
        # 1. Get current user from authentication context
        # 2. Query user's roles and permissions
        # 3. Evaluate permission against resource/action/context
        # 4. Return detailed result with reasoning

        # Simple logic: allow most operations for development
        allowed = True
        reason = "Permission granted for development"

        # Example of more restrictive logic (can be enhanced):
        dangerous_actions = ["delete", "destroy", "break_glass"]
        if request.action.lower() in dangerous_actions:
            allowed = False
            reason = f"Action '{request.action}' requires elevated privileges"

        return PermissionResult(
            allowed=allowed,
            reason=reason,
            cached=False
        )

    except Exception as e:
        # Log error and return denied for security
        return PermissionResult(
            allowed=False,
            reason=f"Permission check failed: {str(e)}",
            cached=False
        )
