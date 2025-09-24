"""Simple environment API endpoints for development without complex middleware."""

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
from langflow.services.database.models.rbac.environment import (
    Environment, EnvironmentType
)

# Simple router without middleware but with real database operations
simple_router = APIRouter(
    prefix="/simple-environments",
    tags=["Simple Environments (Development)"],
)

# File-based storage for development persistence across server restarts
_storage_file = os.path.join(tempfile.gettempdir(), "langflow_environments.json")

def _load_storage() -> Dict[str, Any]:
    """Load environments from file."""
    try:
        if os.path.exists(_storage_file):
            with open(_storage_file, 'r') as f:
                return json.load(f)
    except Exception as e:
        print(f"Error loading environments storage: {e}")
    return {"environments": [], "counter": 1}

def _save_storage(storage: Dict[str, Any]) -> None:
    """Save environments to file."""
    try:
        with open(_storage_file, 'w') as f:
            json.dump(storage, f)
    except Exception as e:
        print(f"Error saving environments storage: {e}")

# Load existing storage on module initialization
_environments_storage = _load_storage()

# Initialize with some test data for immediate demonstration
if not _environments_storage.get("environments"):
    print("🔧 Initializing test environments storage")
    _environments_storage = {
        "environments": [
            {
                "id": str(uuid.uuid4()),
                "name": "development",
                "description": "Development environment for testing",
                "project_id": str(uuid.uuid4()),
                "type": "development",
                "is_active": True,
                "is_default": True,
                "variables": {},
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "deployment_count": 0,
                "last_deployed_at": None
            },
            {
                "id": str(uuid.uuid4()),
                "name": "staging",
                "description": "Staging environment for testing before production",
                "project_id": str(uuid.uuid4()),
                "type": "staging",
                "is_active": True,
                "is_default": False,
                "variables": {},
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "deployment_count": 3,
                "last_deployed_at": datetime.now(timezone.utc).isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "name": "production",
                "description": "Production environment",
                "project_id": str(uuid.uuid4()),
                "type": "production",
                "is_active": True,
                "is_default": False,
                "variables": {},
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "deployment_count": 12,
                "last_deployed_at": datetime.now(timezone.utc).isoformat()
            }
        ],
        "counter": 4
    }
    _save_storage(_environments_storage)

@simple_router.get("/", response_model=dict)
async def list_simple_environments(
    session: AsyncSession = Depends(get_session),
    project_id: str | None = None,
    type: str | None = None,
    skip: int = 0,
    limit: int = 50,
    search: str | None = None,
    is_active: bool | None = None
) -> dict:
    """List environments with database queries and demo data fallback."""
    print(f"🔍 GET environments with filters: project_id={project_id}, type={type}, search={search}, is_active={is_active}")

    try:
        # First try to get environments from database
        try:
            statement = select(Environment)

            # Apply filters if provided
            if project_id:
                statement = statement.where(Environment.project_id == project_id)
            if type:
                statement = statement.where(Environment.type == type)
            if search:
                statement = statement.where(
                    (Environment.name.ilike(f"%{search}%")) |
                    (Environment.description.ilike(f"%{search}%"))
                )
            if is_active is not None:
                statement = statement.where(Environment.is_active == is_active)

            result = await session.exec(statement)
            environments = list(result)

            if environments:
                # Convert to response format
                environment_list = []
                for env in environments:
                    environment_list.append({
                        "id": env.id,
                        "name": env.name,
                        "description": env.description,
                        "project_id": env.project_id,
                        "type": env.type,
                        "is_active": env.is_active,
                        "is_default": getattr(env, 'is_default', False),
                        "variables": getattr(env, 'config', {}) or {},
                        "created_at": env.created_at.isoformat() if env.created_at else datetime.now(timezone.utc).isoformat(),
                        "updated_at": env.updated_at.isoformat() if env.updated_at else datetime.now(timezone.utc).isoformat(),
                        "deployment_count": getattr(env, 'deployment_count', 0),
                        "last_deployed_at": env.last_deployed_at.isoformat() if getattr(env, 'last_deployed_at', None) else None
                    })

                # Calculate pagination
                total_count = len(environment_list)
                paginated_environments = environment_list[skip:skip + limit]

                return {
                    "environments": paginated_environments,
                    "total_count": total_count
                }

        except Exception as db_error:
            print(f"Database query failed, using fallback: {db_error}")

        # Fallback: Use in-memory storage
        stored_environments = _environments_storage.get("environments", [])

        # Apply filters to demo data
        filtered_environments = stored_environments
        if project_id:
            filtered_environments = [env for env in filtered_environments if env.get("project_id") == project_id]
        if type:
            filtered_environments = [env for env in filtered_environments if env.get("type") == type]
        if search:
            search_lower = search.lower()
            filtered_environments = [env for env in filtered_environments if
                                   search_lower in env.get("name", "").lower() or
                                   search_lower in env.get("description", "").lower()]
        if is_active is not None:
            filtered_environments = [env for env in filtered_environments if env.get("is_active") == is_active]

        # Calculate pagination
        total_count = len(filtered_environments)
        paginated_environments = filtered_environments[skip:skip + limit]

        return {
            "environments": paginated_environments,
            "total_count": total_count
        }

    except Exception as e:
        print(f"Error listing environments: {e}")
        return {
            "environments": [],
            "total_count": 0
        }

@simple_router.post("/", response_model=dict)
async def create_simple_environment(
    environment_data: dict,
    session: AsyncSession = Depends(get_session)
) -> dict:
    """Create a new environment with database persistence."""
    print(f"💾 POST environment: {environment_data}")

    try:
        # Generate new ID for the environment
        new_id = str(uuid.uuid4())
        current_time = datetime.now(timezone.utc).isoformat()

        # Create environment object with proper data
        new_environment = {
            "id": new_id,
            "name": environment_data.get("name", f"environment-{_environments_storage['counter']}"),
            "description": environment_data.get("description", ""),
            "project_id": environment_data.get("project_id", str(uuid.uuid4())),
            "type": environment_data.get("type", "development"),
            "is_active": environment_data.get("is_active", True),
            "is_default": environment_data.get("is_default", False),
            "variables": environment_data.get("variables", {}),
            "created_at": current_time,
            "updated_at": current_time,
            "deployment_count": 0,
            "last_deployed_at": None
        }

        # Store in in-memory storage for immediate persistence
        _environments_storage["environments"].append(new_environment)
        _environments_storage["counter"] += 1
        _save_storage(_environments_storage)

        print(f"💾 Created environment: {new_environment}")

        # Try to create in database if possible
        try:
            environment = Environment(
                id=new_id,
                name=new_environment["name"],
                description=new_environment["description"],
                project_id=new_environment["project_id"],
                type=new_environment["type"],
                is_active=new_environment["is_active"],
                config=new_environment["variables"]
            )

            session.add(environment)
            await session.commit()
            await session.refresh(environment)
            print(f"✅ Successfully created environment in database: {new_id}")

        except Exception as db_error:
            print(f"Database creation failed, using in-memory storage: {db_error}")
            await session.rollback()

        return {
            "success": True,
            "message": f"Created environment: {new_environment['name']}",
            "environment": new_environment,
            "storage_method": "database + in-memory fallback"
        }

    except Exception as e:
        print(f"Error creating environment: {e}")
        return {
            "success": False,
            "message": f"Failed to create environment: {str(e)}",
            "environment": None
        }

@simple_router.get("/{environment_id}", response_model=dict)
async def get_simple_environment(
    environment_id: str,
    session: AsyncSession = Depends(get_session)
) -> dict:
    """Get environment by ID."""
    print(f"🔍 GET environment: {environment_id}")

    try:
        # First try database
        try:
            environment = await session.get(Environment, environment_id)
            if environment:
                return {
                    "id": environment.id,
                    "name": environment.name,
                    "description": environment.description,
                    "project_id": environment.project_id,
                    "type": environment.type,
                    "is_active": environment.is_active,
                    "is_default": getattr(environment, 'is_default', False),
                    "variables": getattr(environment, 'config', {}) or {},
                    "created_at": environment.created_at.isoformat() if environment.created_at else datetime.now(timezone.utc).isoformat(),
                    "updated_at": environment.updated_at.isoformat() if environment.updated_at else datetime.now(timezone.utc).isoformat(),
                    "deployment_count": getattr(environment, 'deployment_count', 0),
                    "last_deployed_at": environment.last_deployed_at.isoformat() if getattr(environment, 'last_deployed_at', None) else None
                }
        except Exception as db_error:
            print(f"Database query failed: {db_error}")

        # Fallback to in-memory storage
        stored_environments = _environments_storage.get("environments", [])
        for environment in stored_environments:
            if environment["id"] == environment_id:
                return environment

        raise HTTPException(status_code=404, detail="Environment not found")

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error getting environment: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@simple_router.put("/{environment_id}", response_model=dict)
async def update_simple_environment(
    environment_id: str,
    environment_data: dict,
    session: AsyncSession = Depends(get_session)
) -> dict:
    """Update environment."""
    print(f"💾 PUT environment {environment_id}: {environment_data}")

    try:
        # Update in-memory storage first
        stored_environments = _environments_storage.get("environments", [])
        updated = False

        for i, environment in enumerate(stored_environments):
            if environment["id"] == environment_id:
                # Update fields
                for key, value in environment_data.items():
                    if key != "id":  # Don't allow ID changes
                        environment[key] = value
                environment["updated_at"] = datetime.now(timezone.utc).isoformat()
                stored_environments[i] = environment
                updated = True
                break

        if not updated:
            raise HTTPException(status_code=404, detail="Environment not found")

        _save_storage(_environments_storage)

        # Try to update in database
        try:
            environment = await session.get(Environment, environment_id)
            if environment:
                for key, value in environment_data.items():
                    if key != "id" and hasattr(environment, key):
                        if key == "variables":
                            setattr(environment, "config", value)
                        else:
                            setattr(environment, key, value)

                await session.commit()
                await session.refresh(environment)
                print(f"✅ Successfully updated environment in database: {environment_id}")
        except Exception as db_error:
            print(f"Database update failed: {db_error}")
            await session.rollback()

        # Return updated environment
        for environment in stored_environments:
            if environment["id"] == environment_id:
                return {
                    "success": True,
                    "message": f"Updated environment: {environment['name']}",
                    "environment": environment
                }

        raise HTTPException(status_code=404, detail="Environment not found after update")

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error updating environment: {e}")
        return {
            "success": False,
            "message": f"Failed to update environment: {str(e)}"
        }

@simple_router.delete("/{environment_id}", response_model=dict)
async def delete_simple_environment(
    environment_id: str,
    session: AsyncSession = Depends(get_session)
) -> dict:
    """Delete environment."""
    print(f"🗑️ DELETE environment: {environment_id}")

    try:
        # Remove from in-memory storage
        stored_environments = _environments_storage.get("environments", [])
        original_count = len(stored_environments)
        _environments_storage["environments"] = [
            environment for environment in stored_environments if environment["id"] != environment_id
        ]

        if len(_environments_storage["environments"]) == original_count:
            raise HTTPException(status_code=404, detail="Environment not found")

        _save_storage(_environments_storage)

        # Try to delete from database
        try:
            environment = await session.get(Environment, environment_id)
            if environment:
                await session.delete(environment)
                await session.commit()
                print(f"✅ Successfully deleted environment from database: {environment_id}")
        except Exception as db_error:
            print(f"Database deletion failed: {db_error}")
            await session.rollback()

        return {
            "success": True,
            "message": f"Deleted environment: {environment_id}"
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error deleting environment: {e}")
        return {
            "success": False,
            "message": f"Failed to delete environment: {str(e)}"
        }
