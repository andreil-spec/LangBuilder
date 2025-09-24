"""
Project Migration Service for Legacy to RBAC Project Migration

This service handles the migration of legacy folder-based projects to the new RBAC project system.
It provides functionality to discover legacy projects, migrate them to RBAC projects, and track migration status.
"""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Dict, Any
from uuid import UUID

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlmodel import select, update

from langflow.services.database.models.flow.model import Flow
from langflow.services.database.models.folder.model import Folder
from langflow.services.database.models.rbac.project import Project
from langflow.services.database.models.rbac.workspace import Workspace
from langflow.services.database.models.rbac.environment import Environment
from langflow.services.database.models.user.model import User


class MigrationStatus(str, Enum):
    PENDING = "pending"
    MIGRATING = "migrating"
    COMPLETED = "completed"
    ERROR = "error"
    ROLLBACK = "rollback"


class LegacyProjectInfo:
    """Information about a legacy folder-based project"""

    def __init__(
        self,
        folder_id: str,
        name: str,
        description: Optional[str],
        user_id: str,
        flow_count: int,
        created_at: datetime,
        updated_at: Optional[datetime] = None,
        migration_status: MigrationStatus = MigrationStatus.PENDING,
        migrated_to_project_id: Optional[str] = None,
    ):
        self.folder_id = folder_id
        self.name = name
        self.description = description
        self.user_id = user_id
        self.flow_count = flow_count
        self.created_at = created_at
        self.updated_at = updated_at
        self.migration_status = migration_status
        self.migrated_to_project_id = migrated_to_project_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.folder_id,
            "name": self.name,
            "description": self.description,
            "user_id": self.user_id,
            "flow_count": self.flow_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "migration_status": self.migration_status.value,
            "migrated_to_project_id": self.migrated_to_project_id,
            "type": "legacy"
        }


class ProjectMigrationService:
    """Service for migrating legacy folder-based projects to RBAC projects"""

    def __init__(self):
        self.logger = logger.bind(service="ProjectMigrationService")

    async def get_legacy_projects(
        self,
        session: AsyncSession,
        user_id: Optional[UUID] = None,
        include_migrated: bool = False
    ) -> List[LegacyProjectInfo]:
        """
        Get all legacy folder-based projects that can be migrated.

        Args:
            session: Database session
            user_id: Optional user ID to filter projects
            include_migrated: Whether to include already migrated projects

        Returns:
            List of legacy project information
        """
        try:
            # Build query for folders that represent projects
            query = (
                select(Folder)
                .options(selectinload(Folder.flows))
                .where(Folder.parent_id.is_(None))  # Top-level folders only
            )

            if user_id:
                query = query.where(Folder.user_id == user_id)

            # Execute query
            result = await session.exec(query)
            folders = result.all()

            legacy_projects = []
            for folder in folders:
                # Skip special folders
                if folder.name in ["My Collection", "Starter Projects", "Examples"]:
                    continue

                # Check migration status (we'll add these columns in a migration)
                migration_status = getattr(folder, 'migration_status', MigrationStatus.PENDING.value)
                migrated_project_id = getattr(folder, 'migrated_to_project_id', None)

                # Skip migrated projects if not requested
                if not include_migrated and migration_status == MigrationStatus.COMPLETED.value:
                    continue

                # Count flows in this folder
                flow_count = len(folder.flows) if folder.flows else 0

                legacy_project = LegacyProjectInfo(
                    folder_id=str(folder.id),
                    name=folder.name,
                    description=folder.description,
                    user_id=str(folder.user_id),
                    flow_count=flow_count,
                    created_at=datetime.now(timezone.utc),  # Folders don't have created_at
                    migration_status=MigrationStatus(migration_status),
                    migrated_to_project_id=migrated_project_id
                )

                legacy_projects.append(legacy_project)

            self.logger.info(f"Found {len(legacy_projects)} legacy projects for user {user_id}")
            return legacy_projects

        except Exception as e:
            self.logger.error(f"Error getting legacy projects: {e}")
            raise

    async def migrate_project_to_rbac(
        self,
        session: AsyncSession,
        folder_id: UUID,
        workspace_id: UUID,
        environment_name: str = "production",
        owner_id: Optional[UUID] = None
    ) -> Project:
        """
        Migrate a legacy folder-based project to RBAC project.

        Args:
            session: Database session
            folder_id: ID of the folder to migrate
            workspace_id: Target workspace for the new project
            environment_name: Name of the environment to create
            owner_id: Owner of the new project (defaults to folder owner)

        Returns:
            The newly created RBAC project
        """
        try:
            # Step 1: Get the folder and validate
            folder_query = select(Folder).options(selectinload(Folder.flows)).where(Folder.id == folder_id)
            folder_result = await session.exec(folder_query)
            folder = folder_result.first()

            if not folder:
                raise ValueError(f"Folder {folder_id} not found")

            # Step 2: Validate workspace exists
            workspace_query = select(Workspace).where(Workspace.id == workspace_id)
            workspace_result = await session.exec(workspace_query)
            workspace = workspace_result.first()

            if not workspace:
                raise ValueError(f"Workspace {workspace_id} not found")

            # Step 3: Set migration status to migrating
            await self.update_migration_status(session, folder_id, MigrationStatus.MIGRATING)

            # Step 4: Create new RBAC project
            project_id = uuid.uuid4()
            project = Project(
                id=str(project_id),
                name=folder.name,
                description=folder.description or f"Migrated from legacy project: {folder.name}",
                workspace_id=str(workspace_id),
                owner_id=str(owner_id or folder.user_id),
                is_active=True,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )

            session.add(project)
            await session.flush()  # Get the project ID

            # Step 5: Create default environment for the project
            environment_id = uuid.uuid4()
            environment = Environment(
                id=str(environment_id),
                name=environment_name,
                description=f"Default environment for {folder.name}",
                type="production",
                project_id=str(project_id),
                owner_id=str(owner_id or folder.user_id),
                is_active=True,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )

            session.add(environment)
            await session.flush()

            # Step 6: Migrate flows to the new project and environment
            if folder.flows:
                flow_update = (
                    update(Flow)
                    .where(Flow.folder_id == folder_id)
                    .values(
                        project_id=str(project_id),
                        environment_id=str(environment_id)
                    )
                )
                await session.exec(flow_update)

            # Step 7: Update migration status
            await self.update_migration_status(
                session,
                folder_id,
                MigrationStatus.COMPLETED,
                migrated_project_id=str(project_id)
            )

            await session.commit()

            self.logger.info(f"Successfully migrated folder {folder_id} to project {project_id}")
            return project

        except Exception as e:
            await session.rollback()
            await self.update_migration_status(session, folder_id, MigrationStatus.ERROR)
            self.logger.error(f"Error migrating project {folder_id}: {e}")
            raise

    async def update_migration_status(
        self,
        session: AsyncSession,
        folder_id: UUID,
        status: MigrationStatus,
        migrated_project_id: Optional[str] = None
    ) -> None:
        """Update the migration status of a folder"""
        try:
            # Note: This requires adding migration_status and migrated_to_project_id columns to folder table
            # For now, we'll log the status change
            self.logger.info(f"Migration status for folder {folder_id}: {status.value}")
            if migrated_project_id:
                self.logger.info(f"Migrated to project: {migrated_project_id}")

            # TODO: Implement actual database update when migration columns are added
            # update_stmt = (
            #     update(Folder)
            #     .where(Folder.id == folder_id)
            #     .values(
            #         migration_status=status.value,
            #         migrated_to_project_id=migrated_project_id
            #     )
            # )
            # await session.exec(update_stmt)

        except Exception as e:
            self.logger.error(f"Error updating migration status: {e}")

    async def get_migration_status(
        self,
        session: AsyncSession,
        folder_id: UUID
    ) -> Dict[str, Any]:
        """Get the migration status of a specific folder"""
        try:
            folder_query = select(Folder).where(Folder.id == folder_id)
            folder_result = await session.exec(folder_query)
            folder = folder_result.first()

            if not folder:
                raise ValueError(f"Folder {folder_id} not found")

            # Get migration status (default to pending if columns don't exist)
            migration_status = getattr(folder, 'migration_status', MigrationStatus.PENDING.value)
            migrated_project_id = getattr(folder, 'migrated_to_project_id', None)

            return {
                "folder_id": str(folder_id),
                "migration_status": migration_status,
                "migrated_to_project_id": migrated_project_id
            }

        except Exception as e:
            self.logger.error(f"Error getting migration status: {e}")
            raise

    async def rollback_migration(
        self,
        session: AsyncSession,
        folder_id: UUID,
        project_id: UUID
    ) -> bool:
        """
        Rollback a migration by moving flows back to folder and removing RBAC project.

        Args:
            session: Database session
            folder_id: Original folder ID
            project_id: RBAC project ID to rollback

        Returns:
            True if rollback successful
        """
        try:
            # Step 1: Move flows back to folder
            flow_update = (
                update(Flow)
                .where(Flow.project_id == str(project_id))
                .values(
                    folder_id=str(folder_id),
                    project_id=None,
                    environment_id=None
                )
            )
            await session.exec(flow_update)

            # Step 2: Delete environments
            env_query = select(Environment).where(Environment.project_id == str(project_id))
            env_result = await session.exec(env_query)
            environments = env_result.all()

            for env in environments:
                await session.delete(env)

            # Step 3: Delete project
            project_query = select(Project).where(Project.id == str(project_id))
            project_result = await session.exec(project_query)
            project = project_result.first()

            if project:
                await session.delete(project)

            # Step 4: Update migration status
            await self.update_migration_status(session, folder_id, MigrationStatus.ROLLBACK)

            await session.commit()

            self.logger.info(f"Successfully rolled back migration for folder {folder_id}")
            return True

        except Exception as e:
            await session.rollback()
            self.logger.error(f"Error rolling back migration: {e}")
            raise
