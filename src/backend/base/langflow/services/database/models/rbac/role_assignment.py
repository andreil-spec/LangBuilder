from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Union, List
from uuid import uuid4

from sqlalchemy import CHAR, JSON, Column, Index, Text, UniqueConstraint
from sqlmodel import Field, Relationship, SQLModel

from langflow.schema.serialize import UUIDstr, UUIDAsString

if TYPE_CHECKING:
    from langflow.services.database.models.flow.model import Flow
    from langflow.services.database.models.rbac.environment import Environment
    from langflow.services.database.models.rbac.project import Project
    from langflow.services.database.models.rbac.role import Role
    from langflow.services.database.models.rbac.service_account import ServiceAccount
    from langflow.services.database.models.rbac.user_group import UserGroup
    from langflow.services.database.models.rbac.workspace import Workspace
    from langflow.services.database.models.user.model import User


class AssignmentType(str, Enum):
    """Type of role assignment."""

    USER = "user"
    GROUP = "group"
    SERVICE_ACCOUNT = "service_account"
    API_TOKEN = "api_token"


class AssignmentScope(str, Enum):
    """Scope level for role assignment."""

    WORKSPACE = "workspace"
    PROJECT = "project"
    ENVIRONMENT = "environment"
    FLOW = "flow"
    COMPONENT = "component"


class RoleAssignmentBase(SQLModel):
    """Base model for role assignments."""

    # Assignment type and scope
    assignment_type: AssignmentType = Field(index=True)
    scope_type: AssignmentScope = Field(index=True)

    # Assignment metadata
    is_active: bool = Field(default=True, index=True)
    is_inherited: bool = Field(default=False)  # Inherited from parent scope

    # Temporal constraints
    valid_from: Union[datetime, None] = Field(default=None)
    valid_until: Union[datetime, None] = Field(default=None)

    # Conditions and restrictions
    conditions: Union[dict, None] = Field(default={}, sa_column=Column(JSON))
    ip_restrictions: Union[List[str], None] = Field(default=[], sa_column=Column(JSON))
    time_restrictions: Union[dict, None] = Field(default={}, sa_column=Column(JSON))  # e.g., business hours only

    # Assignment details
    reason: Union[str, None] = Field(default=None, sa_column=Column(Text))
    approved_by_id: Union[UUIDstr, None] = Field(default=None, sa_type=UUIDAsString)
    approval_date: Union[datetime, None] = Field(default=None)

    # Timestamps
    assigned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Note: Cross-field validation for valid_until vs valid_from will be handled in business logic


class RoleAssignment(RoleAssignmentBase, table=True):  # type: ignore[call-arg]
    """Role assignment table linking users/groups to roles with scope."""

    __tablename__ = "role_assignment"

    id: UUIDstr = Field(default_factory=uuid4, primary_key=True, sa_type=UUIDAsString)

    # Role relationship
    role_id: UUIDstr = Field(foreign_key="role.id", sa_type=UUIDAsString)
    role: "Role" = Relationship(back_populates="role_assignments")

    # Assignee (user, group, or service account)
    user_id: Union[UUIDstr, None] = Field(foreign_key="user.id", sa_type=UUIDAsString)
    group_id: Union[UUIDstr, None] = Field(foreign_key="user_group.id", sa_type=UUIDAsString)
    service_account_id: Union[UUIDstr, None] = Field(foreign_key="service_account.id", sa_type=UUIDAsString)

    # Scope relationships (hierarchical)
    workspace_id: Union[UUIDstr, None] = Field(foreign_key="workspace.id", sa_type=UUIDAsString)
    project_id: Union[UUIDstr, None] = Field(foreign_key="project.id", sa_type=UUIDAsString)
    environment_id: Union[UUIDstr, None] = Field(foreign_key="environment.id", sa_type=UUIDAsString)
    flow_id: Union[UUIDstr, None] = Field(foreign_key="flow.id", sa_type=UUIDAsString)
    component_id: Union[UUIDstr, None] = Field(default=None, sa_type=UUIDAsString)  # Component doesn't have a table yet

    # Assignment tracking
    assigned_by_id: UUIDstr = Field(foreign_key="user.id", sa_type=UUIDAsString)

    # Relationships
    user: Union["User", None] = Relationship(
        sa_relationship_kwargs={
            "foreign_keys": "[RoleAssignment.user_id]",
            "primaryjoin": "RoleAssignment.user_id == User.id"
        }
    )
    group: Union["UserGroup", None] = Relationship(back_populates="role_assignments")
    service_account: Union["ServiceAccount", None] = Relationship(back_populates="role_assignments")
    workspace: Union["Workspace", None] = Relationship(back_populates="role_assignments")
    project: Union["Project", None] = Relationship(back_populates="role_assignments")
    environment: Union["Environment", None] = Relationship(back_populates="role_assignments")
    flow: Union["Flow", None] = Relationship(back_populates="role_assignments")

    assigned_by: "User" = Relationship(
        sa_relationship_kwargs={
            "foreign_keys": "[RoleAssignment.assigned_by_id]",
            "primaryjoin": "RoleAssignment.assigned_by_id == User.id"
        }
    )
    approved_by: Union["User", None] = Relationship(
        sa_relationship_kwargs={
            "foreign_keys": "[RoleAssignment.approved_by_id]",
            "primaryjoin": "RoleAssignment.approved_by_id == User.id"
        }
    )

    # Indexes for performance
    __table_args__ = (
        # Unique constraint to prevent duplicate assignments
        UniqueConstraint(
            "role_id", "user_id", "workspace_id", "project_id",
            "environment_id", "flow_id", "component_id",
            name="unique_role_assignment"
        ),
        # Performance indexes
        Index("idx_user_workspace", "user_id", "workspace_id"),
        Index("idx_user_project", "user_id", "project_id"),
        Index("idx_group_workspace", "group_id", "workspace_id"),
        Index("idx_active_assignments", "is_active", "assignment_type"),
    )


class RoleAssignmentCreate(SQLModel):
    """Schema for creating a role assignment."""

    role_id: UUIDstr
    assignment_type: AssignmentType
    scope_type: AssignmentScope

    # Assignee (one of these must be provided)
    user_id: Union[UUIDstr, None] = None
    group_id: Union[UUIDstr, None] = None
    service_account_id: Union[UUIDstr, None] = None

    # Scope (based on scope_type)
    workspace_id: Union[UUIDstr, None] = None
    project_id: Union[UUIDstr, None] = None
    environment_id: Union[UUIDstr, None] = None
    flow_id: Union[UUIDstr, None] = None
    component_id: Union[UUIDstr, None] = None

    # Optional fields
    valid_from: Union[datetime, None] = None
    valid_until: Union[datetime, None] = None
    conditions: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
    ip_restrictions: Union[List[str], None] = None
    time_restrictions: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
    reason: Union[str, None] = None

    # Note: Removed complex validation to prevent issues
    # Backend will validate that user exists when creating assignment


class RoleAssignmentRead(RoleAssignmentBase):
    """Schema for reading role assignment data."""

    id: UUIDstr
    role_id: UUIDstr
    role_name: Union[str, None] = None

    # Assignee
    user_id: Union[UUIDstr, None]
    user_name: Union[str, None] = None
    group_id: Union[UUIDstr, None]
    group_name: Union[str, None] = None
    service_account_id: Union[UUIDstr, None]
    service_account_name: Union[str, None] = None

    # Scope
    workspace_id: Union[UUIDstr, None]
    workspace_name: Union[str, None] = None
    project_id: Union[UUIDstr, None]
    project_name: Union[str, None] = None
    environment_id: Union[UUIDstr, None]
    environment_name: Union[str, None] = None
    flow_id: Union[UUIDstr, None]
    flow_name: Union[str, None] = None
    component_id: Union[UUIDstr, None]

    # Assignment info
    assigned_by_id: UUIDstr
    assigned_by_name: Union[str, None] = None
    approved_by_id: Union[UUIDstr, None]
    approved_by_name: Union[str, None] = None


class RoleAssignmentUpdate(SQLModel):
    """Schema for updating a role assignment."""

    is_active: Union[bool, None] = None
    valid_from: Union[datetime, None] = None
    valid_until: Union[datetime, None] = None
    conditions: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
    ip_restrictions: Union[List[str], None] = None
    time_restrictions: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
    reason: Union[str, None] = None
    approved_by_id: Union[UUIDstr, None] = None
    approval_date: Union[datetime, None] = None


class RoleAssignmentApproval(SQLModel):
    """Schema for approving a role assignment."""

    assignment_id: UUIDstr
    approved: bool
    reason: Union[str, None] = None
    conditions: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
    valid_until: Union[datetime, None] = None
