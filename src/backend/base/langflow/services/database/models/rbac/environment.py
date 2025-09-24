from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Union, List
from uuid import uuid4

from pydantic import field_validator
from sqlalchemy import CHAR, JSON, Column, Text, UniqueConstraint
from sqlmodel import Field, Relationship, SQLModel

from langflow.schema.serialize import UUIDstr, UUIDAsString

if TYPE_CHECKING:
    from langflow.services.database.models.flow.model import Flow
    from langflow.services.database.models.rbac.project import Project
    from langflow.services.database.models.rbac.role_assignment import RoleAssignment
    from langflow.services.database.models.user.model import User
    from langflow.services.database.models.variable.model import Variable


class EnvironmentType(str, Enum):
    """Environment type enumeration."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    TESTING = "testing"
    PREVIEW = "preview"


class EnvironmentBase(SQLModel):
    """Base environment model for deployment contexts."""

    name: str = Field(index=True)
    description: Union[str, None] = Field(default=None, sa_column=Column(Text))
    type: EnvironmentType = Field(default=EnvironmentType.DEVELOPMENT, index=True)

    # Environment configuration
    api_endpoint: Union[str, None] = Field(default=None)
    deployment_url: Union[str, None] = Field(default=None)
    config: Union[dict, None] = Field(default={}, sa_column=Column(JSON))
    secrets: Union[dict, None] = Field(default={}, sa_column=Column(JSON))  # Encrypted in practice

    # Resource limits
    max_instances: int = Field(default=1)
    max_memory_mb: int = Field(default=512)
    max_cpu_cores: float = Field(default=0.5)
    timeout_seconds: int = Field(default=300)

    # Deployment settings
    auto_scaling_enabled: bool = Field(default=False)
    min_instances: int = Field(default=0)
    scale_to_zero: bool = Field(default=True)

    # Status and lifecycle
    is_active: bool = Field(default=True, index=True)
    is_locked: bool = Field(default=False)  # Prevent modifications in production
    locked_at: Union[datetime, None] = Field(default=None)
    locked_by_id: Union[UUIDstr, None] = Field(default=None, sa_type=UUIDAsString)

    # Deployment tracking
    last_deployed_at: Union[datetime, None] = Field(default=None)
    last_deployed_by_id: Union[UUIDstr, None] = Field(default=None, sa_type=UUIDAsString)
    deployment_count: int = Field(default=0)

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Environment name cannot be empty")
        if len(v) > 100:
            raise ValueError("Environment name cannot exceed 100 characters")
        # Validate environment name format (allow uppercase, lowercase, numbers, hyphens, underscores, spaces)
        import re
        if not re.match(r"^[a-zA-Z0-9\-_ ]+$", v):
            raise ValueError("Environment name can only contain letters, numbers, hyphens, underscores, and spaces")
        return v.strip()

    @field_validator("max_instances")
    @classmethod
    def validate_max_instances(cls, v: int) -> int:
        if v < 0 or v > 100:
            raise ValueError("Max instances must be between 0 and 100")
        return v


class Environment(EnvironmentBase, table=True):  # type: ignore[call-arg]
    """Environment table for deployment contexts."""

    __tablename__ = "environment"

    id: UUIDstr = Field(default_factory=uuid4, primary_key=True, sa_type=UUIDAsString)

    # Project relationship
    project_id: UUIDstr = Field(foreign_key="project.id", sa_type=UUIDAsString)
    project: "Project" = Relationship(back_populates="environments")

    # Owner relationship
    owner_id: UUIDstr = Field(foreign_key="user.id", sa_type=UUIDAsString)
    owner: "User" = Relationship(back_populates="owned_environments")

    # Relationships
    flows: List["Flow"] = Relationship(
        back_populates="environment",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )
    variables: List["Variable"] = Relationship(
        back_populates="environment",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )
    role_assignments: List["RoleAssignment"] = Relationship(
        back_populates="environment",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )

    # User relationships for tracking
    locked_by: Union["User", None] = Relationship(
        sa_relationship_kwargs={
            "foreign_keys": "[Environment.locked_by_id]",
            "primaryjoin": "Environment.locked_by_id == User.id"
        }
    )
    last_deployed_by: Union["User", None] = Relationship(
        sa_relationship_kwargs={
            "foreign_keys": "[Environment.last_deployed_by_id]",
            "primaryjoin": "Environment.last_deployed_by_id == User.id"
        }
    )

    # Unique constraints
    __table_args__ = (
        UniqueConstraint("project_id", "name", name="unique_environment_name_per_project"),
        UniqueConstraint("project_id", "type", name="unique_environment_type_per_project"),
    )


class EnvironmentCreate(SQLModel):
    """Schema for creating an environment."""

    name: str
    description: Union[str, None] = None
    type: EnvironmentType
    project_id: UUIDstr
    api_endpoint: Union[str, None] = None
    deployment_url: Union[str, None] = None
    config: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
    max_instances: int = 1
    max_memory_mb: int = 512
    max_cpu_cores: float = 0.5
    timeout_seconds: int = 300
    auto_scaling_enabled: bool = False
    min_instances: int = 0
    scale_to_zero: bool = True


class EnvironmentRead(EnvironmentBase):
    """Schema for reading environment data."""

    id: UUIDstr
    project_id: UUIDstr
    owner_id: UUIDstr
    flow_count: Union[int, None] = None
    variable_count: Union[int, None] = None
    is_deployed: Union[bool, None] = None


class EnvironmentUpdate(SQLModel):
    """Schema for updating environment data."""

    name: Union[str, None] = None
    description: Union[str, None] = None
    api_endpoint: Union[str, None] = None
    deployment_url: Union[str, None] = None
    config: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
    secrets: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
    max_instances: Union[int, None] = None
    max_memory_mb: Union[int, None] = None
    max_cpu_cores: Union[float, None] = None
    timeout_seconds: Union[int, None] = None
    auto_scaling_enabled: Union[bool, None] = None
    min_instances: Union[int, None] = None
    scale_to_zero: Union[bool, None] = None
    is_active: Union[bool, None] = None
    is_locked: Union[bool, None] = None


class EnvironmentDeployment(SQLModel, table=True):  # type: ignore[call-arg]
    """Track environment deployments for audit and rollback."""

    __tablename__ = "environment_deployment"

    id: UUIDstr = Field(default_factory=uuid4, primary_key=True, sa_type=UUIDAsString)
    environment_id: UUIDstr = Field(foreign_key="environment.id", index=True, sa_type=UUIDAsString)

    # Deployment details
    version: str = Field(index=True)
    commit_hash: Union[str, None] = Field(default=None)
    deployment_type: str = Field(default="manual")  # manual, auto, rollback

    # Status
    status: str = Field(default="pending", index=True)  # pending, in_progress, success, failed, rolled_back
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Union[datetime, None] = Field(default=None)
    error_message: Union[str, None] = Field(default=None, sa_column=Column(Text))

    # Deployment metadata
    deployed_by_id: UUIDstr = Field(foreign_key="user.id", sa_type=UUIDAsString)
    deployment_config: Union[dict, None] = Field(default={}, sa_column=Column(JSON))
    artifacts: Union[dict, None] = Field(default={}, sa_column=Column(JSON))

    # Relationships
    environment: "Environment" = Relationship()
    deployed_by: "User" = Relationship()
