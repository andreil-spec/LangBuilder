
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Union, List
from uuid import UUID, uuid4

from pydantic import BaseModel, field_validator
from sqlalchemy import CHAR, JSON, Column, Text, UniqueConstraint
# from sqlalchemy.orm import Mapped  # Removed - use quoted strings for SQLModel relationships
from sqlmodel import Field, Relationship, SQLModel

from langflow.schema.serialize import UUIDstr, UUIDAsString

if TYPE_CHECKING:
    from langflow.services.database.models.rbac.audit_log import AuditLog
    from langflow.services.database.models.rbac.project import Project
    from langflow.services.database.models.rbac.role import Role
    from langflow.services.database.models.rbac.role_assignment import RoleAssignment
    from langflow.services.database.models.rbac.service_account import ServiceAccount
    from langflow.services.database.models.rbac.sso_configuration import SSOConfiguration
    from langflow.services.database.models.rbac.user_group import UserGroup
    from langflow.services.database.models.user.model import User


class WorkspaceSettings(BaseModel):
    """Workspace-specific settings and configurations."""

    sso_enabled: bool = False
    sso_provider: Union[str, None] = None
    scim_enabled: bool = False
    max_projects: Union[int, None] = None
    max_users: Union[int, None] = None
    allowed_domains: List[str] = []
    default_role_id: Union[UUID, None] = None
    session_timeout_minutes: int = 1440  # 24 hours default
    ip_allowlist: List[str] = []
    features_enabled: dict[str, bool] = {}
    compliance_settings: dict[str, Any] = {}


class WorkspaceBase(SQLModel):
    """Base workspace model for RBAC hierarchical organization."""

    name: str = Field(index=True, sa_column_kwargs={"unique": False})
    description: Union[str, None] = Field(default=None, sa_column=Column(Text))
    organization: Union[str, None] = Field(default=None, index=True)

    # Settings and metadata
    settings: Union[dict, None] = Field(default_factory=lambda: WorkspaceSettings().model_dump(), sa_column=Column(JSON))
    workspace_metadata: Union[dict, None] = Field(default={}, sa_column=Column(JSON))
    tags: Union[List[str], None] = Field(default=[], sa_column=Column(JSON))

    # Status and lifecycle
    is_active: bool = Field(default=True, index=True)
    is_deleted: bool = Field(default=False)
    deletion_requested_at: Union[datetime, None] = Field(default=None)

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate workspace name is not empty and within length limits."""
        if not v or not v.strip():
            msg = "Workspace name cannot be empty"
            raise ValueError(msg)
        if len(v) > 255:
            msg = "Workspace name cannot exceed 255 characters"
            raise ValueError(msg)
        return v.strip()

    @field_validator("settings", mode="before")
    @classmethod
    def validate_settings(cls, v: Union[dict, None]) -> dict:
        """Validate and normalize workspace settings."""
        if v is None:
            return WorkspaceSettings().model_dump()
        # Validate settings structure
        if not isinstance(v, dict):
            msg = "Settings must be a dictionary"
            raise ValueError(msg)
        return v


class Workspace(WorkspaceBase, table=True):  # type: ignore[call-arg]
    """Workspace table for multi-tenant RBAC system."""

    __tablename__ = "workspace"

    id: UUIDstr = Field(default_factory=uuid4, primary_key=True, sa_type=UUIDAsString)

    # Owner relationship
    owner_id: UUIDstr = Field(foreign_key="user.id", index=True, sa_type=UUIDAsString)
    owner: "User" = Relationship(back_populates="owned_workspaces")

    # Relationships
    projects: List["Project"] = Relationship(
        back_populates="workspace",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )
    roles: List["Role"] = Relationship(
        back_populates="workspace",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )
    role_assignments: List["RoleAssignment"] = Relationship(
        back_populates="workspace",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )
    audit_logs: List["AuditLog"] = Relationship(
        back_populates="workspace",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )
    user_groups: List["UserGroup"] = Relationship(
        back_populates="workspace",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )
    service_accounts: List["ServiceAccount"] = Relationship(
        back_populates="workspace",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )

    # SSO Configurations
    sso_configurations: List["SSOConfiguration"] = Relationship(
        back_populates="workspace",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )

    # Unique constraints
    __table_args__ = (UniqueConstraint("owner_id", "name", name="unique_workspace_name_per_owner"),)


class WorkspaceCreate(SQLModel):
    """Schema for creating a workspace."""

    name: str
    description: Union[str, None] = None
    organization: Union[str, None] = None
    settings: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
    workspace_metadata: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
    tags: Union[List[str], None] = None


class WorkspaceRead(WorkspaceBase):
    """Schema for reading workspace data."""

    id: UUID
    owner_id: UUID
    project_count: Union[int, None] = None
    user_count: Union[int, None] = None
    role_count: Union[int, None] = None

    # Frontend compatibility fields - provide both naming conventions
    @property
    def created_by_id(self) -> UUID:
        """Alias for owner_id to match frontend expectations."""
        return self.owner_id

    @property
    def member_count(self) -> Union[int, None]:
        """Alias for user_count to match frontend expectations."""
        return self.user_count


class WorkspaceListResponse(BaseModel):
    """Schema for paginated workspace list response."""

    workspaces: List[WorkspaceRead]
    total_count: int
    page: int = 1
    page_size: int = 50
    has_next: bool = False
    has_previous: bool = False


class WorkspaceUpdate(SQLModel):
    """Schema for updating workspace data."""

    name: Union[str, None] = None
    description: Union[str, None] = None
    organization: Union[str, None] = None
    settings: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
    workspace_metadata: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
    tags: Union[List[str], None] = None
    is_active: Union[bool, None] = None


class WorkspaceInvitation(SQLModel, table=True):  # type: ignore[call-arg]
    """Workspace invitation model for user onboarding."""

    __tablename__ = "workspace_invitation"

    id: UUIDstr = Field(default_factory=uuid4, primary_key=True, sa_type=UUIDAsString)
    workspace_id: UUIDstr = Field(foreign_key="workspace.id", index=True, sa_type=UUIDAsString)
    email: str = Field(index=True)
    role_id: Union[UUIDstr, None] = Field(foreign_key="role.id", sa_type=UUIDAsString)

    # Invitation details
    invited_by_id: UUIDstr = Field(foreign_key="user.id", sa_type=UUIDAsString)
    invitation_code: str = Field(index=True, unique=True)
    expires_at: datetime = Field()

    # Status
    is_accepted: bool = Field(default=False)
    accepted_at: Union[datetime, None] = Field(default=None)
    accepted_by_id: Union[UUIDstr, None] = Field(foreign_key="user.id", default=None, sa_type=UUIDAsString)

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Relationships
    workspace: "Workspace" = Relationship()
    role: Union["Role", None] = Relationship()
    invited_by: "User" = Relationship(
        sa_relationship_kwargs={
            "foreign_keys": "[WorkspaceInvitation.invited_by_id]",
            "primaryjoin": "WorkspaceInvitation.invited_by_id == User.id"
        }
    )
    accepted_by: Union["User", None] = Relationship(
        sa_relationship_kwargs={
            "foreign_keys": "[WorkspaceInvitation.accepted_by_id]",
            "primaryjoin": "WorkspaceInvitation.accepted_by_id == User.id"
        }
    )
