"""RBAC validation utilities and business logic."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import HTTPException, status
from sqlmodel import select

if TYPE_CHECKING:
    from uuid import UUID

    from sqlmodel.ext.asyncio.session import AsyncSession

    from langflow.services.database.models.rbac.environment import Environment
    from langflow.services.database.models.rbac.project import Project
    from langflow.services.database.models.rbac.role import Role
    from langflow.services.database.models.rbac.workspace import Workspace
    from langflow.services.database.models.user.model import User


class RBACValidator:
    """Centralized validation logic for RBAC operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def validate_workspace_exists(self, workspace_id: UUID) -> Workspace:
        """Validate that a workspace exists and is active."""
        from langflow.services.database.models.rbac.workspace import Workspace

        workspace = await self.session.get(Workspace, workspace_id)
        if not workspace or workspace.is_deleted:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Workspace not found or has been deleted"
            )
        return workspace

    async def validate_project_exists(self, project_id: UUID) -> Project:
        """Validate that a project exists and is active."""
        from langflow.services.database.models.rbac.project import Project

        project = await self.session.get(Project, project_id)
        if not project or not project.is_active:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found or is inactive"
            )
        return project

    async def validate_role_exists(self, role_id: UUID) -> Role:
        """Validate that a role exists and is active."""
        from langflow.services.database.models.rbac.role import Role

        role = await self.session.get(Role, role_id)
        if not role or not role.is_active:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found or is inactive"
            )
        return role

    async def validate_environment_exists(self, environment_id: UUID) -> Environment:
        """Validate that an environment exists and is active."""
        from langflow.services.database.models.rbac.environment import Environment

        environment = await self.session.get(Environment, environment_id)
        if not environment or not environment.is_active:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Environment not found or is inactive"
            )
        return environment

    async def validate_unique_workspace_name(
        self, name: str, owner_id: UUID, exclude_id: UUID | None = None
    ):
        """Validate that workspace name is unique for the owner."""
        from langflow.services.database.models.rbac.workspace import Workspace

        statement = select(Workspace).where(
            Workspace.owner_id == owner_id,
            Workspace.name == name,
            ~Workspace.is_deleted,
        )

        if exclude_id:
            statement = statement.where(Workspace.id != exclude_id)

        result = await self.session.exec(statement)
        if result.first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Workspace with name '{name}' already exists"
            )

    async def validate_unique_project_name(
        self, name: str, workspace_id: UUID, exclude_id: UUID | None = None
    ):
        """Validate that project name is unique within workspace."""
        from langflow.services.database.models.rbac.project import Project

        statement = select(Project).where(
            Project.workspace_id == workspace_id,
            Project.name == name,
            Project.is_active,
        )

        if exclude_id:
            statement = statement.where(Project.id != exclude_id)

        result = await self.session.exec(statement)
        if result.first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Project with name '{name}' already exists in workspace"
            )

    async def validate_unique_environment_name(
        self, name: str, project_id: UUID, exclude_id: UUID | None = None
    ):
        """Validate that environment name is unique within project."""
        from langflow.services.database.models.rbac.environment import Environment

        statement = select(Environment).where(
            Environment.project_id == project_id,
            Environment.name == name,
            Environment.is_active,
        )

        if exclude_id:
            statement = statement.where(Environment.id != exclude_id)

        result = await self.session.exec(statement)
        if result.first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Environment with name '{name}' already exists in project"
            )

    async def validate_unique_role_name(
        self, name: str, workspace_id: UUID | None = None, exclude_id: UUID | None = None
    ):
        """Validate that role name is unique within workspace (or globally for system roles)."""
        from langflow.services.database.models.rbac.role import Role

        statement = select(Role).where(
            Role.workspace_id == workspace_id,
            Role.name == name,
            Role.is_active,
        )

        if exclude_id:
            statement = statement.where(Role.id != exclude_id)

        result = await self.session.exec(statement)
        if result.first():
            scope = "workspace" if workspace_id else "system"
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Role with name '{name}' already exists in this {scope}"
            )

    async def validate_role_hierarchy(self, role_id: UUID, parent_role_id: UUID | None):
        """Validate role hierarchy to prevent circular dependencies."""
        if not parent_role_id:
            return

        if role_id == parent_role_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Role cannot be its own parent"
            )

        # Check for circular dependency by traversing parent chain
        current_parent_id = parent_role_id
        visited = {role_id}
        max_depth = 10  # Prevent infinite loops

        for _ in range(max_depth):
            if current_parent_id in visited:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Circular dependency detected in role hierarchy"
                )

            parent_role = await self.validate_role_exists(current_parent_id)
            if not parent_role.parent_role_id:
                break

            visited.add(current_parent_id)
            current_parent_id = parent_role.parent_role_id
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Role hierarchy is too deep (max 10 levels)"
            )

    async def validate_role_assignment_constraints(
        self,
        user_id: UUID,
        role_id: UUID,
        workspace_id: UUID,
        exclude_assignment_id: UUID | None = None
    ):
        """Validate role assignment constraints and conflicts."""
        from langflow.services.database.models.rbac.role_assignment import RoleAssignment

        # Check for duplicate active assignment
        statement = select(RoleAssignment).where(
            RoleAssignment.user_id == user_id,
            RoleAssignment.role_id == role_id,
            RoleAssignment.workspace_id == workspace_id,
            RoleAssignment.is_active,
        )

        if exclude_assignment_id:
            statement = statement.where(RoleAssignment.id != exclude_assignment_id)

        result = await self.session.exec(statement)
        if result.first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User already has an active assignment for this role in this workspace"
            )

    async def validate_workspace_ownership(self, workspace: Workspace, user: User):
        """Validate that user can perform operations as workspace owner."""
        if workspace.owner_id != user.id and not user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only workspace owners or superusers can perform this operation"
            )

    async def validate_workspace_limits(self, owner_id: UUID):
        """Validate workspace creation limits per user."""
        from langflow.services.database.models.rbac.workspace import Workspace

        # Count active workspaces for user
        statement = select(Workspace).where(
            Workspace.owner_id == owner_id,
            ~Workspace.is_deleted,
        )
        result = await self.session.exec(statement)
        workspace_count = len(result.all())

        # Default limit - could be configurable per user/plan
        max_workspaces = 50
        if workspace_count >= max_workspaces:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Maximum number of workspaces ({max_workspaces}) reached"
            )

    async def validate_project_limits(self, workspace_id: UUID):
        """Validate project creation limits per workspace."""
        from langflow.services.database.models.rbac.project import Project

        statement = select(Project).where(
            Project.workspace_id == workspace_id,
            Project.is_active,
        )
        result = await self.session.exec(statement)
        project_count = len(result.all())

        max_projects = 100  # Could be configurable per workspace/plan
        if project_count >= max_projects:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Maximum number of projects ({max_projects}) reached for this workspace"
            )

    async def validate_environment_limits(self, project_id: UUID):
        """Validate environment creation limits per project."""
        from langflow.services.database.models.rbac.environment import Environment

        statement = select(Environment).where(
            Environment.project_id == project_id,
            Environment.is_active,
        )
        result = await self.session.exec(statement)
        environment_count = len(result.all())

        max_environments = 20  # Could be configurable per project/plan
        if environment_count >= max_environments:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Maximum number of environments ({max_environments}) reached for this project"
            )


def get_validator(session: AsyncSession) -> RBACValidator:
    """Get an RBAC validator instance."""
    return RBACValidator(session)
