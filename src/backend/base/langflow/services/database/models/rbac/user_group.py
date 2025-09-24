
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Union, List
from uuid import uuid4

from pydantic import field_validator
from sqlalchemy import CHAR, JSON, Column, Text, UniqueConstraint
from sqlmodel import Field, Relationship, SQLModel

from langflow.schema.serialize import UUIDstr, UUIDAsString

if TYPE_CHECKING:
    from langflow.services.database.models.rbac.role_assignment import RoleAssignment
    from langflow.services.database.models.rbac.workspace import Workspace
    from langflow.services.database.models.user.model import User


class GroupType(str, Enum):
    """Type of user group."""

    LOCAL = "local"        # Manually managed group
    SYNCED = "synced"      # SCIM/SSO synced group
    DYNAMIC = "dynamic"    # Rule-based dynamic group
    TEAM = "team"          # Team/department group
    PROJECT = "project"    # Project-specific group


class UserGroupBase(SQLModel):
    """Base model for user groups."""

    name: str = Field(index=True)
    description: Union[str, None] = Field(default=None, sa_column=Column(Text))
    type: GroupType = Field(default=GroupType.LOCAL, index=True)

    # Group metadata
    external_id: Union[str, None] = Field(default=None, index=True)  # External ID for SCIM/SSO
    external_provider: Union[str, None] = Field(default=None)  # SSO provider name

    # Dynamic group rules
    membership_rules: Union[dict, None] = Field(default={}, sa_column=Column(JSON))  # Rules for dynamic membership
    auto_assign_roles: Union[List[str], None] = Field(default=[], sa_column=Column(JSON))  # Auto-assign these role IDs

    # Group settings
    is_active: bool = Field(default=True, index=True)
    is_system: bool = Field(default=False)  # System groups cannot be deleted
    max_members: Union[int, None] = Field(default=None)

    # Metadata
    group_metadata: Union[dict, None] = Field(default={}, sa_column=Column(JSON))
    tags: Union[List[str], None] = Field(default=[], sa_column=Column(JSON))

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_synced_at: Union[datetime, None] = Field(default=None)  # For SCIM groups

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Group name cannot be empty")
        if len(v) > 255:
            raise ValueError("Group name cannot exceed 255 characters")
        return v.strip()


class UserGroup(UserGroupBase, table=True):  # type: ignore[call-arg]
    """User group table for managing collections of users."""

    __tablename__ = "user_group"

    id: UUIDstr = Field(default_factory=uuid4, primary_key=True, sa_type=UUIDAsString)

    # Workspace relationship
    workspace_id: UUIDstr = Field(foreign_key="workspace.id", sa_type=UUIDAsString)
    workspace: "Workspace" = Relationship(back_populates="user_groups")

    # Creator relationship
    created_by_id: UUIDstr = Field(foreign_key="user.id", sa_type=UUIDAsString)
    created_by: "User" = Relationship(back_populates="created_groups")

    # SSO/SCIM provider relationship
    sso_provider_id: Union[UUIDstr, None] = Field(foreign_key="sso_configuration.id", default=None, sa_type=UUIDAsString)

    # Relationships
    members: List["UserGroupMembership"] = Relationship(
        back_populates="group",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )
    role_assignments: List["RoleAssignment"] = Relationship(
        back_populates="group",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )

    # Parent group for nested groups
    parent_group_id: Union[UUIDstr, None] = Field(foreign_key="user_group.id", default=None, sa_type=UUIDAsString)
    parent_group: Union["UserGroup", None] = Relationship(
        sa_relationship_kwargs={
            "remote_side": "UserGroup.id",
            "foreign_keys": "[UserGroup.parent_group_id]"
        }
    )

    # Unique constraints
    __table_args__ = (
        UniqueConstraint("workspace_id", "name", name="unique_group_name_per_workspace"),
        UniqueConstraint("external_id", "external_provider", name="unique_external_group"),
    )


class UserGroupMembership(SQLModel, table=True):  # type: ignore[call-arg]
    """Junction table for user-group many-to-many relationship."""

    __tablename__ = "user_group_membership"

    id: UUIDstr = Field(default_factory=uuid4, primary_key=True, sa_type=UUIDAsString)

    # Foreign keys
    user_id: UUIDstr = Field(foreign_key="user.id", sa_type=UUIDAsString)
    group_id: UUIDstr = Field(foreign_key="user_group.id", sa_type=UUIDAsString)

    # Membership details
    role: Union[str, None] = Field(default=None)  # Role within the group (e.g., "leader", "member")
    is_active: bool = Field(default=True)
    joined_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Union[datetime, None] = Field(default=None)

    # Added by
    added_by_id: UUIDstr = Field(foreign_key="user.id", sa_type=UUIDAsString)
    added_via: Union[str, None] = Field(default="manual")  # manual, scim, rule, invitation

    # Relationships
    user: "User" = Relationship(
        sa_relationship_kwargs={
            "foreign_keys": "[UserGroupMembership.user_id]",
            "primaryjoin": "UserGroupMembership.user_id == User.id"
        }
    )
    group: "UserGroup" = Relationship(back_populates="members")
    added_by: "User" = Relationship(
        sa_relationship_kwargs={
            "foreign_keys": "[UserGroupMembership.added_by_id]",
            "primaryjoin": "UserGroupMembership.added_by_id == User.id"
        }
    )

    # Unique constraints
    __table_args__ = (
        UniqueConstraint("user_id", "group_id", name="unique_user_group_membership"),
    )


class UserGroupCreate(SQLModel):
    """Schema for creating a user group."""

    name: str
    description: Union[str, None] = None
    type: GroupType = GroupType.LOCAL
    workspace_id: UUIDstr
    parent_group_id: Union[UUIDstr, None] = None
    external_id: Union[str, None] = None
    external_provider: Union[str, None] = None
    membership_rules: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
    auto_assign_roles: Union[List[str], None] = None
    max_members: Union[int, None] = None
    group_metadata: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
    tags: Union[List[str], None] = None


class UserGroupRead(UserGroupBase):
    """Schema for reading user group data."""

    id: UUIDstr
    workspace_id: UUIDstr
    created_by_id: UUIDstr
    parent_group_id: Union[UUIDstr, None]
    member_count: Union[int, None] = None
    role_assignment_count: Union[int, None] = None


class UserGroupUpdate(SQLModel):
    """Schema for updating user group data."""

    name: Union[str, None] = None
    description: Union[str, None] = None
    parent_group_id: Union[UUIDstr, None] = None
    membership_rules: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
    auto_assign_roles: Union[List[str], None] = None
    max_members: Union[int, None] = None
    group_metadata: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
    tags: Union[List[str], None] = None
    is_active: Union[bool, None] = None


class UserGroupMembershipCreate(SQLModel):
    """Schema for adding a user to a group."""

    user_id: UUIDstr
    group_id: UUIDstr
    role: Union[str, None] = None
    expires_at: Union[datetime, None] = None


class UserGroupMembershipRead(SQLModel):
    """Schema for reading group membership."""

    id: UUIDstr
    user_id: UUIDstr
    user_name: Union[str, None] = None
    group_id: UUIDstr
    group_name: Union[str, None] = None
    role: Union[str, None]
    is_active: bool
    joined_at: datetime
    expires_at: Union[datetime, None]
    added_by_id: UUIDstr
    added_by_name: Union[str, None] = None
    added_via: Union[str, None]


class UserGroupSync(SQLModel):
    """Schema for SCIM group sync operations."""

    external_id: str
    external_provider: str
    name: str
    description: Union[str, None] = None
    members: list[str]  # External user IDs
    group_metadata: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
