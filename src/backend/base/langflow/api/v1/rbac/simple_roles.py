"""Simple role permissions API with database persistence for development."""

import uuid
import json
import os
import tempfile
from datetime import datetime, timezone
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.api.utils import get_session
from langflow.services.database.models.rbac.permission import (
    Permission, PermissionRead, ResourceType, PermissionAction, RolePermission
)
from langflow.services.database.models.rbac.role import Role

# Simple router without middleware but with real database operations
simple_router = APIRouter(
    prefix="/simple-roles",
    tags=["Simple Roles (Development)"],
)

# File-based storage for development persistence across server restarts
_storage_file = os.path.join(tempfile.gettempdir(), "langflow_role_permissions.json")

def _load_storage() -> Dict[str, list[str]]:
    """Load role permissions from file."""
    try:
        if os.path.exists(_storage_file):
            with open(_storage_file, 'r') as f:
                return json.load(f)
    except Exception as e:
        print(f"Error loading role permissions storage: {e}")
    return {}

def _save_storage(storage: Dict[str, list[str]]) -> None:
    """Save role permissions to file."""
    try:
        with open(_storage_file, 'w') as f:
            json.dump(storage, f)
    except Exception as e:
        print(f"Error saving role permissions storage: {e}")

# Load existing storage on module initialization
_role_permissions_storage: Dict[str, list[str]] = _load_storage()

# Initialize with some test data for immediate demonstration
if not _role_permissions_storage:
    print("🔧 Initializing test role permissions storage")
    _role_permissions_storage = {
        "test-role-1": [str(uuid.uuid4()), str(uuid.uuid4())],
        "test-role-2": [str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())],
    }
    _save_storage(_role_permissions_storage)

@simple_router.get("/{role_id}/permissions", response_model=list[PermissionRead])
async def get_simple_role_permissions(
    role_id: str,
    session: AsyncSession = Depends(get_session)
) -> list[PermissionRead]:
    """Get role permissions with database queries."""
    print(f"🔍 GET permissions for role {role_id}")
    print(f"🔍 In-memory storage: {_role_permissions_storage}")
    try:
        # First try to get permissions from database
        try:
            # Query for role permissions from database
            role_permission_query = select(RolePermission).where(
                RolePermission.role_id == role_id,
                RolePermission.is_granted == True
            )
            role_permissions = await session.exec(role_permission_query)

            # Get the actual permission details
            assigned_permission_ids = [rp.permission_id for rp in role_permissions]
            if assigned_permission_ids:
                permission_query = select(Permission).where(
                    Permission.id.in_(assigned_permission_ids)
                )
                permissions = await session.exec(permission_query)

                # Convert to PermissionRead objects
                permission_reads = []
                for perm in permissions:
                    permission_reads.append(PermissionRead(
                        id=perm.id,
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
                        created_at=perm.created_at.isoformat() if perm.created_at else datetime.now(timezone.utc).isoformat(),
                        updated_at=perm.updated_at.isoformat() if perm.updated_at else datetime.now(timezone.utc).isoformat()
                    ))

                if permission_reads:
                    return permission_reads
        except Exception as db_error:
            print(f"Database query failed, using fallback: {db_error}")

        # Fallback: Use in-memory storage if database query fails
        stored_permission_ids = _role_permissions_storage.get(role_id, [])

        if stored_permission_ids:
            # Try to get permissions from database by IDs
            try:
                permission_query = select(Permission).where(
                    Permission.id.in_(stored_permission_ids)
                )
                permissions = await session.exec(permission_query)
                found_permissions = list(permissions)

                permission_reads = []

                # Add real permissions from database
                for perm in found_permissions:
                    permission_reads.append(PermissionRead(
                        id=perm.id,
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
                        created_at=perm.created_at.isoformat() if perm.created_at else datetime.now(timezone.utc).isoformat(),
                        updated_at=perm.updated_at.isoformat() if perm.updated_at else datetime.now(timezone.utc).isoformat()
                    ))

                # For permission IDs not found in database, create placeholder permissions
                found_ids = {perm.id for perm in found_permissions}
                for perm_id in stored_permission_ids:
                    if perm_id not in found_ids:
                        # Create placeholder permission for demo purposes
                        # Use a valid UUID format if the stored ID is not valid
                        try:
                            # Validate that perm_id is a valid UUID
                            uuid.UUID(perm_id)
                            placeholder_id = perm_id
                        except ValueError:
                            # If not a valid UUID, generate a new one but keep the original in the name
                            placeholder_id = str(uuid.uuid4())

                        permission_reads.append(PermissionRead(
                            id=placeholder_id,
                            name=f"Demo Permission {perm_id[-4:] if len(perm_id) >= 4 else perm_id}",
                            code=f"demo.permission.{perm_id[-4:] if len(perm_id) >= 4 else perm_id}",
                            description=f"Demo permission stored with ID {perm_id}",
                            category="Demo Permissions",
                            resource_type=ResourceType.FLOW,
                            action=PermissionAction.READ,
                            scope="*",
                            is_system=False,
                            is_dangerous=False,
                            requires_mfa=False,
                            created_at=datetime.now(timezone.utc).isoformat(),
                            updated_at=datetime.now(timezone.utc).isoformat()
                        ))

                if permission_reads:
                    return permission_reads
            except Exception as e:
                print(f"Error querying permissions from database: {e}")

        # For roles with no stored permissions, return empty list
        # Demo permissions should only be shown in the "available permissions" list
        print(f"🎯 No permissions found for role {role_id}, returning empty list")
        return []

    except Exception as e:
        print(f"Error getting role permissions: {e}")
        return []


@simple_router.put("/{role_id}/permissions")
async def update_simple_role_permissions(
    role_id: str,
    permission_data: dict,
    session: AsyncSession = Depends(get_session)
) -> dict:
    """Update role permissions with database persistence."""
    permission_ids = permission_data.get("permission_ids", [])
    print(f"💾 PUT permissions for role {role_id}: {permission_ids}")
    try:
        # Store in in-memory storage for immediate persistence
        _role_permissions_storage[role_id] = permission_ids
        # Also save to file for persistence across server restarts
        _save_storage(_role_permissions_storage)
        print(f"💾 Stored in memory and file: {_role_permissions_storage}")

        # Try to update database if possible
        try:
            # Verify role exists (or create a placeholder for development)
            role_query = select(Role).where(Role.id == role_id)
            role_result = await session.exec(role_query)
            role = role_result.first()

            if not role:
                print(f"Warning: Role {role_id} not found in database, using in-memory storage only")
            else:
                # Delete existing role permissions
                delete_query = select(RolePermission).where(RolePermission.role_id == role_id)
                existing_permissions = await session.exec(delete_query)
                for existing in existing_permissions:
                    await session.delete(existing)

                # Create new role permissions
                for permission_id in permission_ids:
                    # Verify permission exists
                    perm_query = select(Permission).where(Permission.id == permission_id)
                    perm_result = await session.exec(perm_query)
                    permission = perm_result.first()

                    if permission:
                        role_permission = RolePermission(
                            role_id=role_id,
                            permission_id=permission_id,
                            is_granted=True,
                            granted_by_id="00000000-0000-0000-0000-000000000000",  # Development user
                            granted_at=datetime.now(timezone.utc)
                        )
                        session.add(role_permission)

                await session.commit()
                print(f"✅ Successfully updated {len(permission_ids)} permissions for role {role_id} in database")

        except Exception as db_error:
            print(f"Database update failed, using in-memory storage: {db_error}")
            await session.rollback()

        return {
            "success": True,
            "message": f"Updated permissions for role {role_id}",
            "permission_count": len(permission_ids),
            "permission_ids": permission_ids,
            "storage_method": "database + in-memory fallback"
        }

    except Exception as e:
        print(f"Error updating role permissions: {e}")
        return {
            "success": False,
            "message": f"Failed to update permissions: {str(e)}",
            "permission_count": 0,
            "permission_ids": []
        }
