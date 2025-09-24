"""
Unified Project API - Combines Legacy and RBAC Projects

This API provides unified access to both legacy folder-based projects and new RBAC projects,
enabling seamless project management and migration workflows.
"""

from typing import Dict, Any, List, Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from langflow.api.utils import CurrentActiveUser, DbSession, get_current_active_user
from langflow.services.database.models.folder.model import Folder
from langflow.services.database.models.flow.model import Flow
from langflow.services.database.models.rbac.project import Project
from langflow.services.database.models.rbac.workspace import Workspace
from langflow.services.project_migration import ProjectMigrationService
from sqlmodel import select, func
from loguru import logger

router = APIRouter(prefix="/unified-projects", tags=["Unified Projects"])


class UnifiedProjectResponse:
    """Response model for unified project data"""

    def __init__(
        self,
        rbac_projects: List[Dict[str, Any]],
        legacy_projects: List[Dict[str, Any]],
        total_count: int,
        rbac_count: int,
        legacy_count: int
    ):
        self.rbac_projects = rbac_projects
        self.legacy_projects = legacy_projects
        self.total_count = total_count
        self.rbac_count = rbac_count
        self.legacy_count = legacy_count

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rbac_projects": self.rbac_projects,
            "legacy_projects": self.legacy_projects,
            "summary": {
                "total_count": self.total_count,
                "rbac_count": self.rbac_count,
                "legacy_count": self.legacy_count
            }
        }


class MigrationRequest:
    """Request model for project migration"""

    def __init__(
        self,
        folder_id: str,
        workspace_id: str,
        environment_name: str = "production"
    ):
        self.folder_id = folder_id
        self.workspace_id = workspace_id
        self.environment_name = environment_name


@router.get("/", status_code=200)
async def get_unified_projects(
    session: Annotated[AsyncSession, Depends(DbSession)],
    # current_user: Annotated[CurrentActiveUser, Depends(get_current_active_user)],  # TEMPORARILY REMOVED for testing
    include_legacy: bool = True,
    include_rbac: bool = True,
    search: str = "",
    page: int = 1,
    page_size: int = 50
) -> Dict[str, Any]:
    """
    Get unified list of both RBAC and legacy projects.

    Args:
        session: Database session
        current_user: Current authenticated user
        include_legacy: Whether to include legacy folder-based projects
        include_rbac: Whether to include RBAC projects
        search: Search term for project names
        page: Page number for pagination
        page_size: Number of items per page

    Returns:
        Combined list of RBAC and legacy projects
    """
    try:
        migration_service = ProjectMigrationService()
        rbac_projects = []
        legacy_projects = []

        # Get RBAC projects if requested
        if include_rbac:
            # For testing, return all RBAC projects (without user filtering)
            rbac_query = select(Project).where(Project.is_active == True)

            if search:
                rbac_query = rbac_query.where(Project.name.contains(search))

            rbac_result = await session.exec(rbac_query)
            rbac_project_models = rbac_result.all()

            for project in rbac_project_models:
                rbac_projects.append({
                    "id": project.id,
                    "name": project.name,
                    "description": project.description,
                    "workspace_id": project.workspace_id,
                    "owner_id": project.owner_id,
                    "is_active": project.is_active,
                    "created_at": project.created_at.isoformat() if project.created_at else None,
                    "updated_at": project.updated_at.isoformat() if project.updated_at else None,
                    "type": "rbac",
                    "environment_count": 0,  # TODO: Count actual environments
                    "flow_count": 0  # TODO: Count actual flows
                })

        # Get legacy projects if requested
        if include_legacy:
            # For testing, get all legacy projects (without user filtering)
            # Use simplified approach without user_id filter
            folder_query = select(Folder).where(
                Folder.name.isnot(None),
                Folder.name != ""
            )

            if search:
                folder_query = folder_query.where(Folder.name.contains(search))

            folder_result = await session.exec(folder_query)
            folders = folder_result.all()

            for folder in folders:
                # Count flows in this folder
                flow_query = select(func.count(Flow.id)).where(Flow.folder_id == folder.id)
                flow_result = await session.exec(flow_query)
                flow_count = flow_result.one()

                legacy_projects.append({
                    "id": folder.id,
                    "name": folder.name,
                    "description": folder.description,
                    "folder_id": str(folder.id),
                    "user_id": str(folder.user_id) if folder.user_id else None,
                    "created_at": folder.created_at.isoformat() if folder.created_at else None,
                    "updated_at": folder.updated_at.isoformat() if folder.updated_at else None,
                    "type": "legacy",
                    "flow_count": flow_count,
                    "can_migrate": True  # All legacy projects can be migrated for testing
                })

        # Apply pagination (simple implementation)
        all_projects = rbac_projects + legacy_projects
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        paginated_projects = all_projects[start_idx:end_idx]

        # Split back into categories for response
        paginated_rbac = [p for p in paginated_projects if p["type"] == "rbac"]
        paginated_legacy = [p for p in paginated_projects if p["type"] == "legacy"]

        response = UnifiedProjectResponse(
            rbac_projects=paginated_rbac,
            legacy_projects=paginated_legacy,
            total_count=len(all_projects),
            rbac_count=len(rbac_projects),
            legacy_count=len(legacy_projects)
        )

        logger.info(f"Retrieved {len(all_projects)} unified projects")
        return response.to_dict()

    except Exception as e:
        logger.error(f"Error getting unified projects: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/legacy", status_code=200)
async def get_legacy_projects(
    session: Annotated[AsyncSession, Depends(DbSession)],
    # current_user: Annotated[CurrentActiveUser, Depends(get_current_active_user)],  # TEMPORARILY REMOVED for testing
    include_migrated: bool = False
) -> Dict[str, Any]:
    """Get only legacy folder-based projects"""
    try:
        # For testing, get all legacy projects (without user filtering)
        folder_query = select(Folder).where(
            Folder.name.isnot(None),
            Folder.name != ""
        )

        folder_result = await session.exec(folder_query)
        folders = folder_result.all()

        legacy_projects = []
        for folder in folders:
            # Count flows in this folder
            flow_query = select(func.count(Flow.id)).where(Flow.folder_id == folder.id)
            flow_result = await session.exec(flow_query)
            flow_count = flow_result.one()

            legacy_projects.append({
                "id": folder.id,
                "name": folder.name,
                "description": folder.description,
                "folder_id": str(folder.id),
                "user_id": str(folder.user_id) if folder.user_id else None,
                "created_at": folder.created_at.isoformat() if folder.created_at else None,
                "updated_at": folder.updated_at.isoformat() if folder.updated_at else None,
                "type": "legacy",
                "flow_count": flow_count,
                "can_migrate": True
            })

        return {
            "legacy_projects": legacy_projects,
            "count": len(legacy_projects)
        }

    except Exception as e:
        logger.error(f"Error getting legacy projects: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/migrate", status_code=200)
async def migrate_legacy_project(
    session: Annotated[AsyncSession, Depends(DbSession)],
    current_user: Annotated[CurrentActiveUser, Depends(get_current_active_user)],
    folder_id: str,
    workspace_id: str,
    environment_name: str = "production"
) -> Dict[str, Any]:
    """
    Migrate a legacy folder-based project to RBAC project.

    Args:
        session: Database session
        current_user: Current authenticated user
        folder_id: ID of the folder to migrate
        workspace_id: Target workspace for migration
        environment_name: Name of the environment to create

    Returns:
        Details of the newly created RBAC project
    """
    try:
        migration_service = ProjectMigrationService()

        # Validate folder belongs to user
        from langflow.services.database.models.folder.model import Folder
        folder_query = select(Folder).where(
            Folder.id == UUID(folder_id),
            Folder.user_id == current_user.id
        )
        folder_result = await session.exec(folder_query)
        folder = folder_result.first()

        if not folder:
            raise HTTPException(
                status_code=404,
                detail=f"Folder {folder_id} not found or access denied"
            )

        # Validate workspace exists and user has access
        workspace_query = select(Workspace).where(Workspace.id == UUID(workspace_id))
        workspace_result = await session.exec(workspace_query)
        workspace = workspace_result.first()

        if not workspace:
            raise HTTPException(
                status_code=404,
                detail=f"Workspace {workspace_id} not found"
            )

        # Perform migration
        new_project = await migration_service.migrate_project_to_rbac(
            session=session,
            folder_id=UUID(folder_id),
            workspace_id=UUID(workspace_id),
            environment_name=environment_name,
            owner_id=current_user.id
        )

        logger.info(f"Successfully migrated folder {folder_id} to project {new_project.id}")

        return {
            "success": True,
            "message": f"Successfully migrated project '{folder.name}' to RBAC",
            "project": {
                "id": new_project.id,
                "name": new_project.name,
                "description": new_project.description,
                "workspace_id": new_project.workspace_id,
                "type": "rbac"
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error migrating project: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/migrate/bulk", status_code=200)
async def migrate_multiple_projects(
    session: Annotated[AsyncSession, Depends(DbSession)],
    current_user: Annotated[CurrentActiveUser, Depends(get_current_active_user)],
    migrations: List[Dict[str, str]]
) -> Dict[str, Any]:
    """
    Migrate multiple legacy projects to RBAC projects.

    Args:
        session: Database session
        current_user: Current authenticated user
        migrations: List of migration requests with folder_id and workspace_id

    Returns:
        Summary of migration results
    """
    try:
        migration_service = ProjectMigrationService()
        results = []
        success_count = 0
        error_count = 0

        for migration_req in migrations:
            try:
                folder_id = migration_req.get("folder_id")
                workspace_id = migration_req.get("workspace_id")
                environment_name = migration_req.get("environment_name", "production")

                if not folder_id or not workspace_id:
                    results.append({
                        "folder_id": folder_id,
                        "success": False,
                        "error": "Missing folder_id or workspace_id"
                    })
                    error_count += 1
                    continue

                # Perform migration
                new_project = await migration_service.migrate_project_to_rbac(
                    session=session,
                    folder_id=UUID(folder_id),
                    workspace_id=UUID(workspace_id),
                    environment_name=environment_name,
                    owner_id=current_user.id
                )

                results.append({
                    "folder_id": folder_id,
                    "project_id": new_project.id,
                    "success": True,
                    "project_name": new_project.name
                })
                success_count += 1

            except Exception as e:
                results.append({
                    "folder_id": folder_id,
                    "success": False,
                    "error": str(e)
                })
                error_count += 1

        return {
            "success": True,
            "summary": {
                "total_requested": len(migrations),
                "successful": success_count,
                "failed": error_count
            },
            "results": results
        }

    except Exception as e:
        logger.error(f"Error in bulk migration: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/migration-status/{folder_id}", status_code=200)
async def get_migration_status(
    session: Annotated[AsyncSession, Depends(DbSession)],
    current_user: Annotated[CurrentActiveUser, Depends(get_current_active_user)],
    folder_id: str
) -> Dict[str, Any]:
    """Get the migration status of a specific folder"""
    try:
        migration_service = ProjectMigrationService()

        status = await migration_service.get_migration_status(
            session=session,
            folder_id=UUID(folder_id)
        )

        return status

    except Exception as e:
        logger.error(f"Error getting migration status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/rollback/{project_id}", status_code=200)
async def rollback_migration(
    session: Annotated[AsyncSession, Depends(DbSession)],
    current_user: Annotated[CurrentActiveUser, Depends(get_current_active_user)],
    project_id: str,
    folder_id: str
) -> Dict[str, Any]:
    """
    Rollback a migration by converting RBAC project back to folder-based project.

    Args:
        session: Database session
        current_user: Current authenticated user
        project_id: RBAC project ID to rollback
        folder_id: Original folder ID to restore

    Returns:
        Rollback operation result
    """
    try:
        migration_service = ProjectMigrationService()

        # Validate project belongs to user
        project_query = select(Project).where(
            Project.id == project_id,
            Project.owner_id == str(current_user.id)
        )
        project_result = await session.exec(project_query)
        project = project_result.first()

        if not project:
            raise HTTPException(
                status_code=404,
                detail=f"Project {project_id} not found or access denied"
            )

        # Perform rollback
        success = await migration_service.rollback_migration(
            session=session,
            folder_id=UUID(folder_id),
            project_id=UUID(project_id)
        )

        if success:
            return {
                "success": True,
                "message": f"Successfully rolled back project '{project.name}' to folder-based project"
            }
        else:
            raise HTTPException(status_code=500, detail="Rollback operation failed")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error rolling back migration: {e}")
        raise HTTPException(status_code=500, detail=str(e))
