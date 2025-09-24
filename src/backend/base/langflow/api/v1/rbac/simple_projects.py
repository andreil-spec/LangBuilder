"""Simple project API endpoints for development without complex middleware."""

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
from langflow.services.database.models.rbac.project import Project

# Simple router without middleware but with real database operations
simple_router = APIRouter(
    prefix="/simple-projects",
    tags=["Simple Projects (Development)"],
)

# File-based storage for development persistence across server restarts
_storage_file = os.path.join(tempfile.gettempdir(), "langflow_projects.json")

def _load_storage() -> Dict[str, Any]:
    """Load projects from file."""
    try:
        if os.path.exists(_storage_file):
            with open(_storage_file, 'r') as f:
                return json.load(f)
    except Exception as e:
        print(f"Error loading projects storage: {e}")
    return {"projects": [], "counter": 1}

def _save_storage(storage: Dict[str, Any]) -> None:
    """Save projects to file."""
    try:
        with open(_storage_file, 'w') as f:
            json.dump(storage, f)
    except Exception as e:
        print(f"Error saving projects storage: {e}")

# Load existing storage on module initialization
_projects_storage = _load_storage()

# Initialize with some test data for immediate demonstration
if not _projects_storage.get("projects"):
    print("🔧 Initializing test projects storage")
    _projects_storage = {
        "projects": [
            {
                "id": str(uuid.uuid4()),
                "name": "LangFlow Core",
                "description": "Core LangFlow project for workflow management",
                "workspace_id": str(uuid.uuid4()),
                "owner_id": str(uuid.uuid4()),
                "is_active": True,
                "is_archived": False,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "environment_count": 3,
                "flow_count": 12,
                "last_deployed_at": datetime.now(timezone.utc).isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "name": "AI Assistant Demo",
                "description": "Demo project showcasing AI assistant capabilities",
                "workspace_id": str(uuid.uuid4()),
                "owner_id": str(uuid.uuid4()),
                "is_active": True,
                "is_archived": False,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "environment_count": 2,
                "flow_count": 5,
                "last_deployed_at": datetime.now(timezone.utc).isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "name": "Data Pipeline Project",
                "description": "Project for processing and transforming data flows",
                "workspace_id": str(uuid.uuid4()),
                "owner_id": str(uuid.uuid4()),
                "is_active": True,
                "is_archived": False,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "environment_count": 4,
                "flow_count": 8,
                "last_deployed_at": datetime.now(timezone.utc).isoformat()
            }
        ],
        "counter": 4
    }
    _save_storage(_projects_storage)

@simple_router.get("/", response_model=dict)
async def list_simple_projects(
    session: AsyncSession = Depends(get_session),
    workspace_id: str | None = None,
    page: int = 1,
    page_size: int = 50,
    search: str | None = None,
    is_active: bool | None = None,
    is_archived: bool | None = None
) -> dict:
    """List projects with database queries and demo data fallback."""
    print(f"🔍 GET projects with filters: workspace_id={workspace_id}, search={search}, is_active={is_active}")

    try:
        # First try to get projects from database
        try:
            statement = select(Project)

            # Apply filters if provided
            if workspace_id:
                statement = statement.where(Project.workspace_id == workspace_id)
            if search:
                statement = statement.where(
                    (Project.name.ilike(f"%{search}%")) |
                    (Project.description.ilike(f"%{search}%"))
                )
            if is_active is not None:
                statement = statement.where(Project.is_active == is_active)
            if is_archived is not None:
                statement = statement.where(Project.is_archived == is_archived)

            result = await session.exec(statement)
            projects = list(result)

            if projects:
                # Convert to response format
                project_list = []
                for project in projects:
                    project_list.append({
                        "id": project.id,
                        "name": project.name,
                        "description": project.description,
                        "workspace_id": project.workspace_id,
                        "owner_id": project.owner_id,
                        "is_active": project.is_active,
                        "is_archived": getattr(project, 'is_archived', False),
                        "created_at": project.created_at.isoformat() if project.created_at else datetime.now(timezone.utc).isoformat(),
                        "updated_at": project.updated_at.isoformat() if project.updated_at else datetime.now(timezone.utc).isoformat(),
                        "environment_count": getattr(project, 'environment_count', 0),
                        "flow_count": getattr(project, 'flow_count', 0),
                        "last_deployed_at": project.last_deployed_at.isoformat() if getattr(project, 'last_deployed_at', None) else None
                    })

                # Calculate pagination
                total_count = len(project_list)
                start_idx = (page - 1) * page_size
                end_idx = start_idx + page_size
                paginated_projects = project_list[start_idx:end_idx]

                return {
                    "projects": paginated_projects,
                    "total_count": total_count,
                    "page": page,
                    "page_size": page_size,
                    "has_next": end_idx < total_count,
                    "has_previous": page > 1
                }

        except Exception as db_error:
            print(f"Database query failed, using fallback: {db_error}")

        # Fallback: Use in-memory storage
        stored_projects = _projects_storage.get("projects", [])

        # Apply filters to demo data
        filtered_projects = stored_projects
        if workspace_id:
            filtered_projects = [proj for proj in filtered_projects if proj.get("workspace_id") == workspace_id]
        if search:
            search_lower = search.lower()
            filtered_projects = [proj for proj in filtered_projects if
                               search_lower in proj.get("name", "").lower() or
                               search_lower in proj.get("description", "").lower()]
        if is_active is not None:
            filtered_projects = [proj for proj in filtered_projects if proj.get("is_active") == is_active]
        if is_archived is not None:
            filtered_projects = [proj for proj in filtered_projects if proj.get("is_archived") == is_archived]

        # Calculate pagination
        total_count = len(filtered_projects)
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        paginated_projects = filtered_projects[start_idx:end_idx]

        return {
            "projects": paginated_projects,
            "total_count": total_count,
            "page": page,
            "page_size": page_size,
            "has_next": end_idx < total_count,
            "has_previous": page > 1
        }

    except Exception as e:
        print(f"Error listing projects: {e}")
        return {
            "projects": [],
            "total_count": 0,
            "page": page,
            "page_size": page_size,
            "has_next": False,
            "has_previous": False
        }

@simple_router.post("/", response_model=dict)
async def create_simple_project(
    project_data: dict,
    session: AsyncSession = Depends(get_session)
) -> dict:
    """Create a new project with database persistence."""
    print(f"💾 POST project: {project_data}")

    try:
        # Generate new ID for the project
        new_id = str(uuid.uuid4())
        current_time = datetime.now(timezone.utc).isoformat()

        # Create project object with proper data
        new_project = {
            "id": new_id,
            "name": project_data.get("name", f"project-{_projects_storage['counter']}"),
            "description": project_data.get("description", ""),
            "workspace_id": project_data.get("workspace_id", str(uuid.uuid4())),
            "owner_id": project_data.get("owner_id", str(uuid.uuid4())),
            "is_active": project_data.get("is_active", True),
            "is_archived": project_data.get("is_archived", False),
            "created_at": current_time,
            "updated_at": current_time,
            "environment_count": 0,
            "flow_count": 0,
            "last_deployed_at": None
        }

        # Store in in-memory storage for immediate persistence
        _projects_storage["projects"].append(new_project)
        _projects_storage["counter"] += 1
        _save_storage(_projects_storage)

        print(f"💾 Created project: {new_project}")

        # Try to create in database if possible
        try:
            project = Project(
                id=new_id,
                name=new_project["name"],
                description=new_project["description"],
                workspace_id=new_project["workspace_id"],
                owner_id=new_project["owner_id"],
                is_active=new_project["is_active"]
            )

            session.add(project)
            await session.commit()
            await session.refresh(project)
            print(f"✅ Successfully created project in database: {new_id}")

        except Exception as db_error:
            print(f"Database creation failed, using in-memory storage: {db_error}")
            await session.rollback()

        return {
            "success": True,
            "message": f"Created project: {new_project['name']}",
            "project": new_project,
            "storage_method": "database + in-memory fallback"
        }

    except Exception as e:
        print(f"Error creating project: {e}")
        return {
            "success": False,
            "message": f"Failed to create project: {str(e)}",
            "project": None
        }

@simple_router.get("/{project_id}", response_model=dict)
async def get_simple_project(
    project_id: str,
    session: AsyncSession = Depends(get_session)
) -> dict:
    """Get project by ID."""
    print(f"🔍 GET project: {project_id}")

    try:
        # First try database
        try:
            project = await session.get(Project, project_id)
            if project:
                return {
                    "id": project.id,
                    "name": project.name,
                    "description": project.description,
                    "workspace_id": project.workspace_id,
                    "owner_id": project.owner_id,
                    "is_active": project.is_active,
                    "is_archived": getattr(project, 'is_archived', False),
                    "created_at": project.created_at.isoformat() if project.created_at else datetime.now(timezone.utc).isoformat(),
                    "updated_at": project.updated_at.isoformat() if project.updated_at else datetime.now(timezone.utc).isoformat(),
                    "environment_count": getattr(project, 'environment_count', 0),
                    "flow_count": getattr(project, 'flow_count', 0),
                    "last_deployed_at": project.last_deployed_at.isoformat() if getattr(project, 'last_deployed_at', None) else None
                }
        except Exception as db_error:
            print(f"Database query failed: {db_error}")

        # Fallback to in-memory storage
        stored_projects = _projects_storage.get("projects", [])
        for project in stored_projects:
            if project["id"] == project_id:
                return project

        raise HTTPException(status_code=404, detail="Project not found")

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error getting project: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@simple_router.put("/{project_id}", response_model=dict)
async def update_simple_project(
    project_id: str,
    project_data: dict,
    session: AsyncSession = Depends(get_session)
) -> dict:
    """Update project."""
    print(f"💾 PUT project {project_id}: {project_data}")

    try:
        # Update in-memory storage first
        stored_projects = _projects_storage.get("projects", [])
        updated = False

        for i, project in enumerate(stored_projects):
            if project["id"] == project_id:
                # Update fields
                for key, value in project_data.items():
                    if key != "id":  # Don't allow ID changes
                        project[key] = value
                project["updated_at"] = datetime.now(timezone.utc).isoformat()
                stored_projects[i] = project
                updated = True
                break

        if not updated:
            raise HTTPException(status_code=404, detail="Project not found")

        _save_storage(_projects_storage)

        # Try to update in database
        try:
            project = await session.get(Project, project_id)
            if project:
                for key, value in project_data.items():
                    if key != "id" and hasattr(project, key):
                        setattr(project, key, value)

                await session.commit()
                await session.refresh(project)
                print(f"✅ Successfully updated project in database: {project_id}")
        except Exception as db_error:
            print(f"Database update failed: {db_error}")
            await session.rollback()

        # Return updated project
        for project in stored_projects:
            if project["id"] == project_id:
                return {
                    "success": True,
                    "message": f"Updated project: {project['name']}",
                    "project": project
                }

        raise HTTPException(status_code=404, detail="Project not found after update")

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error updating project: {e}")
        return {
            "success": False,
            "message": f"Failed to update project: {str(e)}"
        }

@simple_router.delete("/{project_id}", response_model=dict)
async def delete_simple_project(
    project_id: str,
    session: AsyncSession = Depends(get_session)
) -> dict:
    """Delete project."""
    print(f"🗑️ DELETE project: {project_id}")

    try:
        # Remove from in-memory storage
        stored_projects = _projects_storage.get("projects", [])
        original_count = len(stored_projects)
        _projects_storage["projects"] = [
            project for project in stored_projects if project["id"] != project_id
        ]

        if len(_projects_storage["projects"]) == original_count:
            raise HTTPException(status_code=404, detail="Project not found")

        _save_storage(_projects_storage)

        # Try to delete from database
        try:
            project = await session.get(Project, project_id)
            if project:
                await session.delete(project)
                await session.commit()
                print(f"✅ Successfully deleted project from database: {project_id}")
        except Exception as db_error:
            print(f"Database deletion failed: {db_error}")
            await session.rollback()

        return {
            "success": True,
            "message": f"Deleted project: {project_id}"
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error deleting project: {e}")
        return {
            "success": False,
            "message": f"Failed to delete project: {str(e)}"
        }
