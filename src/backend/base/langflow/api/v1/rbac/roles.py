"""Role management API endpoints for RBAC system."""

# NO future annotations per Phase 1 requirements
# from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, TYPE_CHECKING

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
    ROLE_READ_SECURITY,
    ROLE_VALIDATION,
    ROLE_WRITE_SECURITY,
    SecurityRequirement,
    ValidationRequirement,
    get_authenticated_user,
    secure_endpoint,
)
from langflow.services.auth.authorization_patterns import get_enhanced_enforcement_context
from langflow.services.rbac.runtime_enforcement import RuntimeEnforcementContext
from langflow.schema.serialize import UUIDstr
from langflow.services.database.models.rbac.permission import (
    Permission,
    PermissionRead,
    RolePermissionCreate,
    RolePermissionRead,
)
from langflow.services.database.models.rbac.role import (
    Role,
    RoleCreate,
    RoleRead,
    RoleUpdate,
)
from langflow.services.database.models.rbac.workspace import Workspace
from langflow.services.rbac.audit_service import AuditService
from langflow.services.rbac.permission_engine import PermissionEngine

if TYPE_CHECKING:
    pass

router = APIRouter(
    prefix="/roles",
    tags=["RBAC", "Roles"],
    responses={
        401: {"description": "Unauthorized - Invalid or missing authentication"},
        403: {"description": "Forbidden - Insufficient permissions"},
        404: {"description": "Not Found - Resource does not exist"},
        422: {"description": "Validation Error - Invalid request data"},
    },
)


@router.post("/", response_model=RoleRead, status_code=status.HTTP_201_CREATED)
# @secure_endpoint(
#     security_req=ROLE_WRITE_SECURITY,
#     validation_req=ROLE_VALIDATION,
#     audit_enabled=True,
# )
async def create_role(
    role_data: RoleCreate,
    request: Request,
    session: DbSession,
    current_user: Annotated[User, Depends(get_authenticated_user)],
    context: Annotated[RuntimeEnforcementContext, Depends(get_enhanced_enforcement_context)],
    permission_engine: PermissionEngine = Depends(get_permission_engine),
    audit_service: AuditService = Depends(get_audit_service),
) -> RoleRead:
    """Create a new role."""
    # Validate workspace if specified
    workspace = None
    if role_data.workspace_id:
        workspace = await session.get(Workspace, role_data.workspace_id)
        if not workspace or workspace.is_deleted:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Workspace not found"
            )

        # Check workspace permissions
        result = await permission_engine.check_permission(
            session=session,
            user=current_user,
            resource_type="workspace",
            action="create_role",
            resource_id=role_data.workspace_id,
            workspace_id=role_data.workspace_id,
        )

        if not result.allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions to create roles in this workspace: {result.reason}"
            )
    # System-level role creation requires superuser
    elif not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only superusers can create system-level roles"
        )

    # Check if role name already exists in workspace/system
    statement = select(Role).where(
        Role.workspace_id == role_data.workspace_id,
        Role.name == role_data.name,
        Role.is_active == True
    )
    result = await session.exec(statement)
    existing = result.first()

    if existing:
        scope = "workspace" if role_data.workspace_id else "system"
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Role '{role_data.name}' already exists in this {scope}"
        )

    # Validate parent role if specified
    if role_data.parent_role_id:
        parent_role = await session.get(Role, role_data.parent_role_id)
        if not parent_role or not parent_role.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Parent role not found"
            )

        # Check that parent role is in same workspace
        if parent_role.workspace_id != role_data.workspace_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Parent role must be in the same workspace"
            )

    # Create role
    role = Role(
        **role_data.model_dump(),
        created_by_id=current_user.id
    )

    session.add(role)
    await session.commit()
    await session.refresh(role)

    # Log audit event
    try:
        context = create_audit_context(
            workspace_id=role.workspace_id,
            additional_data={"role_name": role.name, "role_type": role.type}
        )
        await audit_service.log_role_management_event(
            session=session,
            actor=current_user,
            action="create_role",
            target_user_id=None,
            role_id=role.id,
            context=context,
            details={"role_name": role.name, "role_type": role.type, "workspace_id": str(role.workspace_id) if role.workspace_id else None}
        )
    except Exception as e:
        logger.error(f"Failed to log role creation audit event: {e}")

    return RoleRead.model_validate(role)


@router.get("/", response_model=list[RoleRead])
@secure_endpoint(
    security_req=SecurityRequirement(
        resource_type="rbac_resource",
        action="read",
        require_workspace_access=True,
        audit_action="rbac_operation",
    ),
    # validation_req=ValidationRequirement(
    #     validate_workspace_exists=True,
    # ),
    audit_enabled=True,
)
async def list_roles(
    request: Request,
    session: DbSession,
    current_user: Annotated[User, Depends(get_authenticated_user)],
    context: Annotated[RuntimeEnforcementContext, Depends(get_enhanced_enforcement_context)],
    params: Annotated[Params | None, Depends(custom_params)],
    permission_engine: PermissionEngine = Depends(get_permission_engine),
    workspace_id: UUIDstr | None = Query(None),
    search: str | None = None,
    type: str | None = None,  # noqa: A002
    is_system: bool | None = None,
    is_active: bool | None = None,
) -> list[RoleRead]:
    """List roles accessible to current user."""
    statement = select(Role)

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
            action="read",
            resource_id=workspace_id,
            workspace_id=workspace_id,
        )

        if not result.allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied to this workspace: {result.reason}"
            )

        statement = statement.where(Role.workspace_id == workspace_id)
    # Filter by user's accessible workspaces + system roles
    elif current_user.is_superuser:
        # Superusers can see all roles
        pass
    else:
        # Regular users can see roles in their workspaces + system roles
        accessible_workspace_subquery = select(Workspace.id).where(
            Workspace.owner_id == current_user.id,
            Workspace.is_deleted == False
        )

        statement = statement.where(
            (Role.workspace_id.in_(accessible_workspace_subquery)) |
            (Role.workspace_id.is_(None))  # System roles
        )

    # Apply additional filters
    if search:
        search_condition = Role.name.ilike(f"%{search}%")
        if Role.description is not None:
            search_condition = search_condition | Role.description.ilike(f"%{search}%")
        statement = statement.where(search_condition)

    if type:
        statement = statement.where(Role.type == type)

    if is_system is not None:
        statement = statement.where(Role.is_system == is_system)

    if is_active is not None:
        statement = statement.where(Role.is_active == is_active)

    # Apply pagination using fastapi_pagination
    if params:
        import warnings
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore", category=DeprecationWarning, module=r"fastapi_pagination\.ext\.sqlalchemy"
            )
            paginated_result = await apaginate(session, statement, params=params)
            roles = paginated_result.items
    else:
        result = await session.exec(statement)
        roles = result.all()

    # Populate permission_count and assignment_count for each role
    role_reads = []
    for role in roles:
        role_dict = role.model_dump()

        # Calculate permission count
        from langflow.services.database.models.rbac.permission import RolePermission
        permission_count_stmt = select(func.count(RolePermission.id)).where(
            RolePermission.role_id == role.id,
            RolePermission.is_granted == True
        )
        permission_count_result = await session.exec(permission_count_stmt)
        role_dict["permission_count"] = permission_count_result.first() or 0

        # Calculate assignment count
        from langflow.services.database.models.rbac.role_assignment import RoleAssignment
        assignment_count_stmt = select(func.count(RoleAssignment.id)).where(
            RoleAssignment.role_id == role.id,
            RoleAssignment.is_active == True
        )
        assignment_count_result = await session.exec(assignment_count_stmt)
        role_dict["assignment_count"] = assignment_count_result.first() or 0

        role_reads.append(RoleRead(**role_dict))

    return role_reads


@router.get("/{role_id}", response_model=RoleRead)
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
async def get_role(
    role_id: UUIDstr,
    session: DbSession,
    current_user: CurrentActiveUser,
) -> "RoleRead":
    """Get role by ID."""
    from langflow.services.database.models.rbac.role import Role, RoleRead

    role = await session.get(Role, role_id)
    if not role or not role.is_active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )

    # Check access permissions
    if role.workspace_id:
        from langflow.services.database.models.rbac.workspace import Workspace
        workspace = await session.get(Workspace, role.workspace_id)
        if workspace and workspace.owner_id != current_user.id and not current_user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this role"
            )
    elif not current_user.is_superuser:
        # System roles can only be viewed by superusers
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to system roles"
        )

    # Populate permission_count and assignment_count for the role
    role_dict = role.model_dump()

    # Calculate permission count
    from langflow.services.database.models.rbac.permission import RolePermission
    permission_count_stmt = select(func.count(RolePermission.id)).where(
        RolePermission.role_id == role.id,
        RolePermission.is_granted == True
    )
    permission_count_result = await session.exec(permission_count_stmt)
    role_dict["permission_count"] = permission_count_result.first() or 0

    # Calculate assignment count
    from langflow.services.database.models.rbac.role_assignment import RoleAssignment
    assignment_count_stmt = select(func.count(RoleAssignment.id)).where(
        RoleAssignment.role_id == role.id,
        RoleAssignment.is_active == True
    )
    assignment_count_result = await session.exec(assignment_count_stmt)
    role_dict["assignment_count"] = assignment_count_result.first() or 0

    return RoleRead(**role_dict)


@router.put("/{role_id}", response_model=RoleRead)
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
async def update_role(
    role_id: UUIDstr,
    role_data: "RoleUpdate",
    session: DbSession,
    current_user: CurrentActiveUser,
    audit_service: AuditService = Depends(get_audit_service),
) -> "RoleRead":
    """Update role."""
    from langflow.services.database.models.rbac.role import Role, RoleRead

    role = await session.get(Role, role_id)
    if not role or not role.is_active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )

    # Check if role is system role
    if role.is_system:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="System roles cannot be modified"
        )

    # Check permissions
    if role.workspace_id:
        from langflow.services.database.models.rbac.workspace import Workspace
        workspace = await session.get(Workspace, role.workspace_id)
        if workspace and workspace.owner_id != current_user.id and not current_user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions to update this role"
            )
    elif not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only superusers can update system roles"
        )

    # Check name uniqueness if changing name
    if role_data.name and role_data.name != role.name:
        statement = select(Role).where(
            Role.workspace_id == role.workspace_id,
            Role.name == role_data.name,
            Role.id != role_id,
            Role.is_active == True
        )
        result = await session.exec(statement)
        existing = result.first()

        if existing:
            scope = "workspace" if role.workspace_id else "system"
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Role '{role_data.name}' already exists in this {scope}"
            )

    # Update role fields
    for field, value in role_data.model_dump(exclude_unset=True).items():
        setattr(role, field, value)

    role.updated_at = datetime.now(timezone.utc)
    role.version += 1
    await session.commit()
    await session.refresh(role)

    # Log audit event
    try:
        context = create_audit_context(
            workspace_id=role.workspace_id,
            additional_data={"role_name": role.name, "updated_fields": list(role_data.model_dump(exclude_unset=True).keys())}
        )
        await audit_service.log_role_management_event(
            session=session,
            actor=current_user,
            action="update_role",
            target_user_id=None,
            role_id=role.id,
            context=context,
            details={"role_name": role.name, "updated_fields": list(role_data.model_dump(exclude_unset=True).keys())}
        )
    except Exception as e:
        logger.error(f"Failed to log role update audit event: {e}")

    return RoleRead.model_validate(role)


@router.delete("/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
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
async def delete_role(
    role_id: UUIDstr,
    session: DbSession,
    current_user: CurrentActiveUser,
    audit_service: AuditService = Depends(get_audit_service),
):
    """Delete role (deactivate)."""
    from langflow.services.database.models.rbac.role import Role

    role = await session.get(Role, role_id)
    if not role or not role.is_active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )

    # Check if role is system role
    if role.is_system:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="System roles cannot be deleted"
        )

    # Check permissions
    if role.workspace_id:
        from langflow.services.database.models.rbac.workspace import Workspace
        workspace = await session.get(Workspace, role.workspace_id)
        if workspace and workspace.owner_id != current_user.id and not current_user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions to delete this role"
            )
    elif not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only superusers can delete system roles"
        )

    # Check if role has active assignments
    from langflow.services.database.models.rbac.role_assignment import RoleAssignment
    statement = select(func.count(RoleAssignment.id)).where(
        RoleAssignment.role_id == role_id,
        RoleAssignment.is_active == True
    )
    result = await session.exec(statement)
    active_assignments = result.one()

    if active_assignments > 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot delete role with {active_assignments} active assignments"
        )

    # Deactivate role
    role.is_active = False
    role.updated_at = datetime.now(timezone.utc)
    await session.commit()

    # Log audit event
    try:
        context = create_audit_context(
            workspace_id=role.workspace_id,
            additional_data={"role_name": role.name}
        )
        await audit_service.log_role_management_event(
            session=session,
            actor=current_user,
            action="delete_role",
            target_user_id=None,
            role_id=role.id,
            context=context,
            details={"role_name": role.name, "deletion_type": "deactivate"}
        )
    except Exception as e:
        logger.error(f"Failed to log role deletion audit event: {e}")


@router.get("/{role_id}/permissions", response_model=list[PermissionRead])
async def list_role_permissions(
    role_id: str,
    session: DbSession,
    current_user: CurrentActiveUser,
) -> list["PermissionRead"]:
    """List permissions assigned to role."""
    from langflow.services.database.models.rbac.permission import Permission, RolePermission
    from langflow.services.database.models.rbac.role import Role

    # Validate role exists
    role = await session.get(Role, role_id)
    if not role or not role.is_active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )

    # Query for role permissions from database
    role_permission_query = select(RolePermission).where(
        RolePermission.role_id == role_id,
        RolePermission.is_granted == True
    )
    role_permissions_result = await session.exec(role_permission_query)
    role_permissions = role_permissions_result.all()

    # Get the actual permission details
    assigned_permission_ids = [rp.permission_id for rp in role_permissions]

    if not assigned_permission_ids:
        return []

    # Query for permission details
    permission_query = select(Permission).where(
        Permission.id.in_(assigned_permission_ids)
    )
    permissions_result = await session.exec(permission_query)
    permissions = permissions_result.all()

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
            is_system=perm.is_system,
            is_dangerous=perm.is_dangerous,
            requires_mfa=perm.requires_mfa,
            created_at=perm.created_at.isoformat() if perm.created_at else datetime.now(timezone).isoformat(),
            updated_at=perm.updated_at.isoformat() if perm.updated_at else datetime.now(timezone).isoformat()
        ))

    return permission_reads


@router.post("/{role_id}/permissions", response_model=RolePermissionRead, status_code=status.HTTP_201_CREATED)
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
async def assign_permission_to_role(
    role_id: UUIDstr,
    permission_data: RolePermissionCreate,
    session: DbSession,
    current_user: CurrentActiveUser,
    permission_engine: PermissionEngine = Depends(get_permission_engine),
    audit_service: AuditService = Depends(get_audit_service),
) -> RolePermissionRead:
    """Assign permission to role with RBAC security and standardized workflow."""
    from langflow.services.database.models.rbac.permission import RolePermission
    from langflow.services.database.models.rbac.role import Role

    # Check permission to assign permissions to roles
    permission_check = await permission_engine.check_permission(
        session=session,
        user=current_user,
        resource_type="role",
        action="update",
        resource_id=role_id,
    )

    if not permission_check.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Insufficient permissions to assign permissions to role: {permission_check.reason}"
        )

    # Verify role exists and is active
    role = await session.get(Role, role_id)
    if not role or not role.is_active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found or inactive"
        )

    # Verify permission exists
    permission = await session.get(Permission, permission_data.permission_id)
    if not permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permission not found"
        )

    # Check if assignment already exists
    statement = select(RolePermission).where(
        RolePermission.role_id == role_id,
        RolePermission.permission_id == permission_data.permission_id
    )
    result = await session.exec(statement)
    existing = result.first()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Permission already assigned to role"
        )

    # Create role permission assignment with standardized data
    role_permission = RolePermission(
        role_id=role_id,
        permission_id=permission_data.permission_id,
        is_granted=permission_data.is_granted,
        conditions=permission_data.conditions,
        expires_at=permission_data.expires_at,
        metadata=permission_data.metadata,
        granted_by_id=current_user.id,
        granted_at=datetime.now(timezone.utc)
    )

    session.add(role_permission)
    await session.commit()
    await session.refresh(role_permission, ["permission"])

    # Log audit event
    try:
        context = create_audit_context(
            workspace_id=role.workspace_id,
            additional_data={"role_name": role.name, "permission_id": str(permission_data.permission_id)}
        )
        await audit_service.log_role_management_event(
            session=session,
            actor=current_user,
            action="assign_permission_to_role",
            target_user_id=None,
            role_id=role_id,
            context=context,
            details={"role_name": role.name, "permission_id": str(permission_data.permission_id), "permission_code": permission.code}
        )
    except Exception as e:
        logger.error(f"Failed to log permission assignment audit event: {e}")

    # Return standardized typed response
    return RolePermissionRead.model_validate(role_permission)


@router.delete("/{role_id}/permissions/{permission_id}", status_code=status.HTTP_204_NO_CONTENT)
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
async def remove_permission_from_role(
    role_id: UUIDstr,
    permission_id: UUIDstr,
    session: DbSession,
    current_user: CurrentActiveUser,
    audit_service: AuditService = Depends(get_audit_service),
):
    """Remove permission from role."""
    from langflow.services.database.models.rbac.permission import RolePermission

    statement = select(RolePermission).where(
        RolePermission.role_id == role_id,
        RolePermission.permission_id == permission_id
    )
    result = await session.exec(statement)
    role_permission = result.first()

    if not role_permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permission assignment not found"
        )

    await session.delete(role_permission)
    await session.commit()

    # Log audit event
    try:
        from langflow.services.database.models.rbac.role import Role
        role = await session.get(Role, role_id)
        if role:
            context = create_audit_context(
                workspace_id=role.workspace_id,
                additional_data={"role_name": role.name, "permission_id": str(permission_id)}
            )
            await audit_service.log_role_management_event(
                session=session,
                actor=current_user,
                action="remove_permission_from_role",
                target_user_id=None,
                role_id=role_id,
                context=context,
                details={"role_name": role.name, "permission_id": str(permission_id)}
            )
    except Exception as e:
        logger.error(f"Failed to log permission removal audit event: {e}")


@router.put("/{role_id}/permissions", status_code=status.HTTP_200_OK)
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
async def update_role_permissions(
    role_id: UUIDstr,
    permission_data: dict,
    session: DbSession,
    current_user: CurrentActiveUser,
    audit_service: AuditService = Depends(get_audit_service),
) -> dict:
    """Update role permissions (batch operation)."""
    from langflow.services.database.models.rbac.permission import RolePermission
    from langflow.services.database.models.rbac.role import Role

    # Validate role exists
    role = await session.get(Role, role_id)
    if not role or not role.is_active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )

    permission_ids = permission_data.get("permission_ids", [])
    if not isinstance(permission_ids, list):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="permission_ids must be a list"
        )

    # Convert permission IDs to UUIDs and validate they exist
    validated_permission_ids = []
    for perm_id in permission_ids:
        if isinstance(perm_id, str):
            try:
                perm_id = UUIDstr(perm_id)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid permission_id format: {perm_id}"
                )
        validated_permission_ids.append(perm_id)

    # Validate all permissions exist
    for perm_id in validated_permission_ids:
        permission = await session.get(Permission, perm_id)
        if not permission:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Permission not found: {perm_id}"
            )

    # Get current role permissions
    current_statement = select(RolePermission).where(
        RolePermission.role_id == role_id,
        RolePermission.is_granted == True
    )
    current_result = await session.exec(current_statement)
    current_role_permissions = current_result.all()
    current_permission_ids = [rp.permission_id for rp in current_role_permissions]

    # Calculate changes
    to_add = [pid for pid in validated_permission_ids if pid not in current_permission_ids]
    to_remove = [pid for pid in current_permission_ids if pid not in validated_permission_ids]

    # Remove permissions that are no longer needed
    for perm_id in to_remove:
        delete_statement = select(RolePermission).where(
            RolePermission.role_id == role_id,
            RolePermission.permission_id == perm_id
        )
        delete_result = await session.exec(delete_statement)
        role_permission = delete_result.first()
        if role_permission:
            await session.delete(role_permission)

    # Add new permissions
    for perm_id in to_add:
        # Check if assignment already exists (safety check)
        existing_statement = select(RolePermission).where(
            RolePermission.role_id == role_id,
            RolePermission.permission_id == perm_id
        )
        existing_result = await session.exec(existing_statement)
        existing = existing_result.first()

        if not existing:
            role_permission = RolePermission(
                role_id=role_id,
                permission_id=perm_id,
                is_granted=True,
                granted_by_id=current_user.id,
                reason=f"Batch update by {current_user.username}"
            )
            session.add(role_permission)

    await session.commit()

    # Log audit event
    try:
        context = create_audit_context(
            workspace_id=role.workspace_id,
            additional_data={"role_name": role.name, "permissions_added": len(to_add), "permissions_removed": len(to_remove)}
        )
        await audit_service.log_role_management_event(
            session=session,
            actor=current_user,
            action="update_role_permissions",
            target_user_id=None,
            role_id=role_id,
            context=context,
            details={"role_name": role.name, "permissions_added": len(to_add), "permissions_removed": len(to_remove)}
        )
    except Exception as e:
        logger.error(f"Failed to log role permissions update audit event: {e}")

    return {
        "success": True,
        "message": "Role permissions updated successfully",
        "permission_count": len(validated_permission_ids),
        "permission_ids": [str(pid) for pid in validated_permission_ids],
        "permissions_added": len(to_add),
        "permissions_removed": len(to_remove)
    }


@router.post("/initialize-system-roles", status_code=status.HTTP_201_CREATED)
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
async def initialize_system_roles(
    session: DbSession,
    current_user: CurrentActiveUser,
) -> dict:
    """Initialize system roles and permissions."""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only superusers can initialize system roles"
        )

    created_permissions = 0
    created_roles = 0

    # Create system permissions
    from langflow.services.database.models.rbac.permission import SYSTEM_PERMISSIONS
    from langflow.services.database.models.rbac.role import SYSTEM_ROLES, Role

    for perm_data in SYSTEM_PERMISSIONS:
        perm_dict = dict(perm_data)  # Ensure it's treated as a dict
        statement = select(Permission).where(Permission.code == perm_dict["code"])
        result = await session.exec(statement)
        existing = result.first()

        if not existing:
            # Only add is_system=True if not already specified in perm_data
            permission_data = perm_dict.copy()
            if "is_system" not in permission_data:
                permission_data["is_system"] = True

            permission = Permission(**permission_data)
            session.add(permission)
            created_permissions += 1

    # Create system roles
    for role_key, role_data in SYSTEM_ROLES.items():
        statement = select(Role).where(
            Role.name == role_data["name"],
            Role.workspace_id is None
        )
        result = await session.exec(statement)
        existing = result.first()

        if not existing:
            role = Role(
                **role_data,
                created_by_id=current_user.id,
                workspace_id=None
            )
            session.add(role)
            created_roles += 1

    await session.commit()

    return {
        "message": "System roles and permissions initialized",
        "permissions_created": created_permissions,
        "roles_created": created_roles
    }
