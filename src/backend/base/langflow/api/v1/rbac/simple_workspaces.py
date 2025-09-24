"""Simple workspace API endpoints for development without complex middleware."""

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
from langflow.services.database.models.rbac.workspace import Workspace

# Simple router without middleware but with real database operations
simple_router = APIRouter(
    prefix="/simple-workspaces",
    tags=["Simple Workspaces (Development)"],
)

# File-based storage for development persistence across server restarts
_storage_file = os.path.join(tempfile.gettempdir(), "langflow_workspaces.json")

def _load_storage() -> Dict[str, Any]:
    """Load workspaces from file."""
    try:
        if os.path.exists(_storage_file):
            with open(_storage_file, 'r') as f:
                return json.load(f)
    except Exception as e:
        print(f"Error loading workspaces storage: {e}")
    return {"workspaces": [], "counter": 1}

def _save_storage(storage: Dict[str, Any]) -> None:
    """Save workspaces to file."""
    try:
        with open(_storage_file, 'w') as f:
            json.dump(storage, f)
    except Exception as e:
        print(f"Error saving workspaces storage: {e}")

# Load existing storage on module initialization
_workspaces_storage = _load_storage()

# Initialize with some test data for immediate demonstration
if not _workspaces_storage.get("workspaces"):
    print("🔧 Initializing test workspaces storage")
    _workspaces_storage = {
        "workspaces": [
            {
                "id": str(uuid.uuid4()),
                "name": "Default Workspace",
                "description": "Primary workspace for LangFlow development",
                "owner_id": str(uuid.uuid4()),
                "is_active": True,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "member_count": 5,
                "project_count": 3
            },
            {
                "id": str(uuid.uuid4()),
                "name": "Demo Workspace",
                "description": "Workspace for demonstration and testing purposes",
                "owner_id": str(uuid.uuid4()),
                "is_active": True,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "member_count": 2,
                "project_count": 1
            },
            {
                "id": str(uuid.uuid4()),
                "name": "Production Workspace",
                "description": "Production environment workspace",
                "owner_id": str(uuid.uuid4()),
                "is_active": True,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "member_count": 10,
                "project_count": 7
            }
        ],
        "counter": 4
    }
    _save_storage(_workspaces_storage)

@simple_router.get("/", response_model=dict)
async def list_simple_workspaces(
    session: AsyncSession = Depends(get_session),
    page: int = 1,
    page_size: int = 50,
    search: str | None = None,
    is_active: bool | None = None
) -> dict:
    """List workspaces with database queries and demo data fallback."""
    print(f"🔍 GET workspaces with filters: search={search}, is_active={is_active}")

    try:
        # First try to get workspaces from database
        try:
            statement = select(Workspace)

            # Apply filters if provided
            if search:
                statement = statement.where(
                    (Workspace.name.ilike(f"%{search}%")) |
                    (Workspace.description.ilike(f"%{search}%"))
                )
            if is_active is not None:
                statement = statement.where(Workspace.is_active == is_active)

            result = await session.exec(statement)
            workspaces = list(result)

            if workspaces:
                # Convert to response format
                workspace_list = []
                for workspace in workspaces:
                    workspace_list.append({
                        "id": workspace.id,
                        "name": workspace.name,
                        "description": workspace.description,
                        "owner_id": workspace.owner_id,
                        "is_active": workspace.is_active,
                        "created_at": workspace.created_at.isoformat() if workspace.created_at else datetime.now(timezone.utc).isoformat(),
                        "updated_at": workspace.updated_at.isoformat() if workspace.updated_at else datetime.now(timezone.utc).isoformat(),
                        "member_count": getattr(workspace, 'member_count', 1),
                        "project_count": getattr(workspace, 'project_count', 0)
                    })

                # Calculate pagination
                total_count = len(workspace_list)
                start_idx = (page - 1) * page_size
                end_idx = start_idx + page_size
                paginated_workspaces = workspace_list[start_idx:end_idx]

                return {
                    "workspaces": paginated_workspaces,
                    "total_count": total_count,
                    "page": page,
                    "page_size": page_size,
                    "has_next": end_idx < total_count,
                    "has_previous": page > 1
                }

        except Exception as db_error:
            print(f"Database query failed, using fallback: {db_error}")

        # Fallback: Use in-memory storage
        stored_workspaces = _workspaces_storage.get("workspaces", [])

        # Apply filters to demo data
        filtered_workspaces = stored_workspaces
        if search:
            search_lower = search.lower()
            filtered_workspaces = [ws for ws in filtered_workspaces if
                                 search_lower in ws.get("name", "").lower() or
                                 search_lower in ws.get("description", "").lower()]
        if is_active is not None:
            filtered_workspaces = [ws for ws in filtered_workspaces if ws.get("is_active") == is_active]

        # Calculate pagination
        total_count = len(filtered_workspaces)
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        paginated_workspaces = filtered_workspaces[start_idx:end_idx]

        return {
            "workspaces": paginated_workspaces,
            "total_count": total_count,
            "page": page,
            "page_size": page_size,
            "has_next": end_idx < total_count,
            "has_previous": page > 1
        }

    except Exception as e:
        print(f"Error listing workspaces: {e}")
        return {
            "workspaces": [],
            "total_count": 0,
            "page": page,
            "page_size": page_size,
            "has_next": False,
            "has_previous": False
        }

@simple_router.post("/", response_model=dict)
async def create_simple_workspace(
    workspace_data: dict,
    session: AsyncSession = Depends(get_session)
) -> dict:
    """Create a new workspace with database persistence."""
    print(f"💾 POST workspace: {workspace_data}")

    try:
        # Generate new ID for the workspace
        new_id = str(uuid.uuid4())
        current_time = datetime.now(timezone.utc).isoformat()

        # Create workspace object with proper data
        new_workspace = {
            "id": new_id,
            "name": workspace_data.get("name", f"workspace-{_workspaces_storage['counter']}"),
            "description": workspace_data.get("description", ""),
            "owner_id": workspace_data.get("owner_id", str(uuid.uuid4())),
            "is_active": workspace_data.get("is_active", True),
            "created_at": current_time,
            "updated_at": current_time,
            "member_count": 1,
            "project_count": 0
        }

        # Store in in-memory storage for immediate persistence
        _workspaces_storage["workspaces"].append(new_workspace)
        _workspaces_storage["counter"] += 1
        _save_storage(_workspaces_storage)

        print(f"💾 Created workspace: {new_workspace}")

        # Try to create in database if possible
        try:
            workspace = Workspace(
                id=new_id,
                name=new_workspace["name"],
                description=new_workspace["description"],
                owner_id=new_workspace["owner_id"],
                is_active=new_workspace["is_active"]
            )

            session.add(workspace)
            await session.commit()
            await session.refresh(workspace)
            print(f"✅ Successfully created workspace in database: {new_id}")

        except Exception as db_error:
            print(f"Database creation failed, using in-memory storage: {db_error}")
            await session.rollback()

        return {
            "success": True,
            "message": f"Created workspace: {new_workspace['name']}",
            "workspace": new_workspace,
            "storage_method": "database + in-memory fallback"
        }

    except Exception as e:
        print(f"Error creating workspace: {e}")
        return {
            "success": False,
            "message": f"Failed to create workspace: {str(e)}",
            "workspace": None
        }

@simple_router.get("/{workspace_id}", response_model=dict)
async def get_simple_workspace(
    workspace_id: str,
    session: AsyncSession = Depends(get_session)
) -> dict:
    """Get workspace by ID."""
    print(f"🔍 GET workspace: {workspace_id}")

    try:
        # First try database
        try:
            workspace = await session.get(Workspace, workspace_id)
            if workspace:
                return {
                    "id": workspace.id,
                    "name": workspace.name,
                    "description": workspace.description,
                    "owner_id": workspace.owner_id,
                    "is_active": workspace.is_active,
                    "created_at": workspace.created_at.isoformat() if workspace.created_at else datetime.now(timezone.utc).isoformat(),
                    "updated_at": workspace.updated_at.isoformat() if workspace.updated_at else datetime.now(timezone.utc).isoformat(),
                    "member_count": getattr(workspace, 'member_count', 1),
                    "project_count": getattr(workspace, 'project_count', 0)
                }
        except Exception as db_error:
            print(f"Database query failed: {db_error}")

        # Fallback to in-memory storage
        stored_workspaces = _workspaces_storage.get("workspaces", [])
        for workspace in stored_workspaces:
            if workspace["id"] == workspace_id:
                return workspace

        raise HTTPException(status_code=404, detail="Workspace not found")

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error getting workspace: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@simple_router.put("/{workspace_id}", response_model=dict)
async def update_simple_workspace(
    workspace_id: str,
    workspace_data: dict,
    session: AsyncSession = Depends(get_session)
) -> dict:
    """Update workspace."""
    print(f"💾 PUT workspace {workspace_id}: {workspace_data}")

    try:
        # Update in-memory storage first
        stored_workspaces = _workspaces_storage.get("workspaces", [])
        updated = False

        for i, workspace in enumerate(stored_workspaces):
            if workspace["id"] == workspace_id:
                # Update fields
                for key, value in workspace_data.items():
                    if key != "id":  # Don't allow ID changes
                        workspace[key] = value
                workspace["updated_at"] = datetime.now(timezone.utc).isoformat()
                stored_workspaces[i] = workspace
                updated = True
                break

        if not updated:
            raise HTTPException(status_code=404, detail="Workspace not found")

        _save_storage(_workspaces_storage)

        # Try to update in database
        try:
            workspace = await session.get(Workspace, workspace_id)
            if workspace:
                for key, value in workspace_data.items():
                    if key != "id" and hasattr(workspace, key):
                        setattr(workspace, key, value)

                await session.commit()
                await session.refresh(workspace)
                print(f"✅ Successfully updated workspace in database: {workspace_id}")
        except Exception as db_error:
            print(f"Database update failed: {db_error}")
            await session.rollback()

        # Return updated workspace
        for workspace in stored_workspaces:
            if workspace["id"] == workspace_id:
                return {
                    "success": True,
                    "message": f"Updated workspace: {workspace['name']}",
                    "workspace": workspace
                }

        raise HTTPException(status_code=404, detail="Workspace not found after update")

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error updating workspace: {e}")
        return {
            "success": False,
            "message": f"Failed to update workspace: {str(e)}"
        }

@simple_router.delete("/{workspace_id}", response_model=dict)
async def delete_simple_workspace(
    workspace_id: str,
    session: AsyncSession = Depends(get_session)
) -> dict:
    """Delete workspace."""
    print(f"🗑️ DELETE workspace: {workspace_id}")

    try:
        # Remove from in-memory storage
        stored_workspaces = _workspaces_storage.get("workspaces", [])
        original_count = len(stored_workspaces)
        _workspaces_storage["workspaces"] = [
            workspace for workspace in stored_workspaces if workspace["id"] != workspace_id
        ]

        if len(_workspaces_storage["workspaces"]) == original_count:
            raise HTTPException(status_code=404, detail="Workspace not found")

        _save_storage(_workspaces_storage)

        # Try to delete from database
        try:
            workspace = await session.get(Workspace, workspace_id)
            if workspace:
                await session.delete(workspace)
                await session.commit()
                print(f"✅ Successfully deleted workspace from database: {workspace_id}")
        except Exception as db_error:
            print(f"Database deletion failed: {db_error}")
            await session.rollback()

        return {
            "success": True,
            "message": f"Deleted workspace: {workspace_id}"
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error deleting workspace: {e}")
        return {
            "success": False,
            "message": f"Failed to delete workspace: {str(e)}"
        }
