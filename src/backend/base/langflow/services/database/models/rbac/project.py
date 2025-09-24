from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Union, List
from uuid import uuid4

from pydantic import BaseModel, field_validator
from sqlalchemy import CHAR, JSON, Column, Text, UniqueConstraint
from sqlmodel import Field, Relationship, SQLModel

from langflow.schema.serialize import UUIDstr, UUIDAsString

if TYPE_CHECKING:
    from langflow.services.database.models.flow.model import Flow
    from langflow.services.database.models.rbac.environment import Environment
    from langflow.services.database.models.rbac.role_assignment import RoleAssignment
    from langflow.services.database.models.rbac.workspace import Workspace
    from langflow.services.database.models.user.model import User


class ProjectStatus(str, Enum):
    """Project status enumeration."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    ARCHIVED = "archived"
    DRAFT = "draft"
    DEPLOYED = "deployed"
    MAINTENANCE = "maintenance"


class ProjectBase(SQLModel):
    """Base project model for organizing flows within a workspace."""

    name: str = Field(index=True)
    description: Union[str, None] = Field(default=None, sa_column=Column(Text))

    # Project metadata
    repository_url: Union[str, None] = Field(default=None)
    documentation_url: Union[str, None] = Field(default=None)
    tags: Union[List[str], None] = Field(default=[], sa_column=Column(JSON))
    project_metadata: Union[dict, None] = Field(default={}, sa_column=Column(JSON))

    # Project settings
    default_environment_id: Union[UUIDstr, None] = Field(default=None, sa_type=UUIDAsString)
    auto_deploy_enabled: bool = Field(default=False)
    retention_days: int = Field(default=30)  # Data retention policy

    # Status
    is_active: bool = Field(default=True, index=True)
    is_archived: bool = Field(default=False)
    archived_at: Union[datetime, None] = Field(default=None)

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Project name cannot be empty")
        if len(v) > 255:
            raise ValueError("Project name cannot exceed 255 characters")
        # Validate project name format (alphanumeric, hyphens, underscores, spaces)
        import re
        if not re.match(r"^[a-zA-Z0-9_\-\s]+$", v):
            raise ValueError("Project name must contain only letters, numbers, hyphens, underscores, and spaces")
        return v.strip()


class Project(ProjectBase, table=True):  # type: ignore[call-arg]
    """Project table for organizing flows and environments."""

    __tablename__ = "project"

    id: UUIDstr = Field(default_factory=uuid4, primary_key=True, sa_type=UUIDAsString)

    # Workspace relationship
    workspace_id: UUIDstr = Field(foreign_key="workspace.id", sa_type=UUIDAsString)
    workspace: "Workspace" = Relationship(back_populates="projects")

    # Owner relationship
    owner_id: UUIDstr = Field(foreign_key="user.id", sa_type=UUIDAsString)
    owner: "User" = Relationship(back_populates="owned_projects")

    # Relationships
    environments: List["Environment"] = Relationship(
        back_populates="project",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )
    flows: List["Flow"] = Relationship(
        back_populates="project",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )
    role_assignments: List["RoleAssignment"] = Relationship(
        back_populates="project",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )

    # Unique constraints
    __table_args__ = (
        UniqueConstraint("workspace_id", "name", name="unique_project_name_per_workspace"),
    )


class ProjectCreate(SQLModel):
    """Schema for creating a project."""

    name: str
    description: Union[str, None] = None
    workspace_id: UUIDstr
    repository_url: Union[str, None] = None
    documentation_url: Union[str, None] = None
    tags: Union[List[str], None] = None
    project_metadata: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
    auto_deploy_enabled: bool = False
    retention_days: int = 30


class ProjectRead(ProjectBase):
    """Schema for reading project data."""

    id: UUIDstr
    workspace_id: UUIDstr
    owner_id: UUIDstr
    environment_count: Union[int, None] = None
    flow_count: Union[int, None] = None
    last_deployed_at: Union[datetime, None] = None


class ProjectUpdate(SQLModel):
    """Schema for updating project data."""

    name: Union[str, None] = None
    description: Union[str, None] = None
    repository_url: Union[str, None] = None
    documentation_url: Union[str, None] = None
    tags: Union[List[str], None] = None
    project_metadata: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
    default_environment_id: Union[UUIDstr, None] = None
    auto_deploy_enabled: Union[bool, None] = None
    retention_days: Union[int, None] = None
    is_active: Union[bool, None] = None
    is_archived: Union[bool, None] = None


class ProjectListResponse(BaseModel):
    """Schema for paginated project list response."""

    projects: List[ProjectRead]
    total_count: int
    page: int = 1
    page_size: int = 50
    has_next: bool = False
    has_previous: bool = False


class ProjectStatistics(BaseModel):
    """Project statistics and metrics."""

    project_id: UUIDstr
    total_flows: int = 0
    active_flows: int = 0
    total_environments: int = 0
    active_environments: int = 0
    total_deployments: int = 0
    successful_deployments: int = 0
    failed_deployments: int = 0
    last_deployment_at: Union[datetime, None] = None
    total_executions: int = 0
    successful_executions: int = 0
    failed_executions: int = 0
    average_execution_time_ms: Union[float, None] = None
    storage_used_bytes: int = 0
    api_calls_count: int = 0
    unique_users_count: int = 0
