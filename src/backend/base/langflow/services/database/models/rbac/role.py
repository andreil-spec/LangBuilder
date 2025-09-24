
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Union, List
from uuid import uuid4

from pydantic import field_validator
from sqlalchemy import CHAR, JSON, Column, Text, UniqueConstraint
from sqlmodel import Field, Relationship, SQLModel

from langflow.schema.serialize import UUIDstr, UUIDAsString

if TYPE_CHECKING:
    from langflow.services.database.models.rbac.permission import RolePermission
    from langflow.services.database.models.rbac.role_assignment import RoleAssignment
    from langflow.services.database.models.rbac.workspace import Workspace
    from langflow.services.database.models.user.model import User


class RoleType(str, Enum):
    """Role type enumeration."""

    SYSTEM = "system"      # Built-in system roles
    CUSTOM = "custom"      # User-defined custom roles
    WORKSPACE = "workspace"  # Workspace-scoped roles
    PROJECT = "project"    # Project-specific roles


class RoleBase(SQLModel):
    """Base role model for RBAC system."""

    name: str = Field(index=True)
    description: Union[str, None] = Field(default=None, sa_column=Column(Text))
    type: RoleType = Field(default=RoleType.CUSTOM, index=True)

    # Role hierarchy
    parent_role_id: Union[UUIDstr, None] = Field(default=None, foreign_key="role.id", sa_type=UUIDAsString)
    priority: int = Field(default=0)  # Higher priority overrides lower

    # Role configuration
    is_system: bool = Field(default=False)  # Cannot be modified/deleted
    is_default: bool = Field(default=False)  # Default role for new users
    is_active: bool = Field(default=True, index=True)

    # Scope definition
    scope_type: Union[str, None] = Field(default="workspace")  # workspace, project, environment, flow, component
    scope_id: Union[UUIDstr, None] = Field(default=None, sa_type=UUIDAsString)  # ID of the scoped resource

    # Metadata
    role_metadata: Union[dict, None] = Field(default={}, sa_column=Column(JSON))
    tags: Union[List[str], None] = Field(default=[], sa_column=Column(JSON))

    # Versioning
    version: int = Field(default=1)

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Role name cannot be empty")
        if len(v) > 100:
            raise ValueError("Role name cannot exceed 100 characters")
        return v.strip()

    @field_validator("priority")
    @classmethod
    def validate_priority(cls, v: int) -> int:
        if v < 0 or v > 1000:
            raise ValueError("Priority must be between 0 and 1000")
        return v


class Role(RoleBase, table=True):  # type: ignore[call-arg]
    """Role table for defining access permissions."""

    __tablename__ = "role"

    id: UUIDstr = Field(default_factory=uuid4, primary_key=True, sa_type=UUIDAsString)

    # Workspace relationship (null for system roles)
    workspace_id: Union[UUIDstr, None] = Field(foreign_key="workspace.id", sa_type=UUIDAsString)
    workspace: Union["Workspace", None] = Relationship(back_populates="roles")

    # Creator relationship
    created_by_id: UUIDstr = Field(foreign_key="user.id", sa_type=UUIDAsString)
    created_by: "User" = Relationship(back_populates="created_roles")

    # Parent role relationship (for hierarchy)
    parent_role: Union["Role", None] = Relationship(
        sa_relationship_kwargs={
            "remote_side": "Role.id",
#            "foreign_keys": "[Role.parent_role_id]"
        }
    )

    # Relationships
    permissions: List["RolePermission"] = Relationship(
        back_populates="role",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )
    role_assignments: List["RoleAssignment"] = Relationship(
        back_populates="role",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )

    # Unique constraints
    __table_args__ = (
        UniqueConstraint("workspace_id", "name", name="unique_role_name_per_workspace"),
    )


# System role definitions
SYSTEM_ROLES = {
    "super_admin": {
        "name": "Super Admin",
        "description": "Full system access with all permissions",
        "type": RoleType.SYSTEM,
        "is_system": True,
        "priority": 1000
    },
    "workspace_admin": {
        "name": "Workspace Admin",
        "description": "Full workspace administration capabilities",
        "type": RoleType.WORKSPACE,
        "is_system": True,
        "priority": 900
    },
    "workspace_owner": {
        "name": "Workspace Owner",
        "description": "Workspace owner with full control",
        "type": RoleType.WORKSPACE,
        "is_system": True,
        "priority": 950
    },
    "project_admin": {
        "name": "Project Admin",
        "description": "Full project administration capabilities",
        "type": RoleType.PROJECT,
        "is_system": True,
        "priority": 800
    },
    "developer": {
        "name": "Developer",
        "description": "Create, edit, and deploy flows",
        "type": RoleType.WORKSPACE,
        "is_system": True,
        "priority": 600
    },
    "editor": {
        "name": "Editor",
        "description": "Edit existing flows and components",
        "type": RoleType.WORKSPACE,
        "is_system": True,
        "priority": 500
    },
    "viewer": {
        "name": "Viewer",
        "description": "Read-only access to resources",
        "type": RoleType.WORKSPACE,
        "is_system": True,
        "priority": 300
    },
    "guest": {
        "name": "Guest",
        "description": "Limited guest access",
        "type": RoleType.WORKSPACE,
        "is_system": True,
        "is_default": True,
        "priority": 100
    }
}


class RoleCreate(SQLModel):
    """Schema for creating a role."""

    name: str
    description: Union[str, None] = None
    type: RoleType = RoleType.CUSTOM
    workspace_id: Union[UUIDstr, None] = None
    parent_role_id: Union[UUIDstr, None] = None
    priority: int = 0
    scope_type: str | None = "workspace"
    scope_id: Union[UUIDstr, None] = None
    role_metadata: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
    tags: Union[List[str], None] = None


class RoleRead(RoleBase):
    """Schema for reading role data."""

    id: UUIDstr
    workspace_id: UUIDstr | None
    created_by_id: UUIDstr
    permission_count: Union[int, None] = None
    assignment_count: Union[int, None] = None
    is_inherited: Union[bool, None] = None


class RoleUpdate(SQLModel):
    """Schema for updating role data."""

    name: Union[str, None] = None
    description: Union[str, None] = None
    parent_role_id: Union[UUIDstr, None] = None
    priority: Union[int, None] = None
    scope_type: Union[str, None] = None
    scope_id: Union[UUIDstr, None] = None
    role_metadata: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
    tags: Union[List[str], None] = None
    is_active: Union[bool, None] = None
    is_default: Union[bool, None] = None


class RoleHierarchy(SQLModel):
    """Role hierarchy for inheritance calculation."""

    role_id: UUIDstr
    role_name: str
    parent_role_id: UUIDstr | None
    depth: int
    path: List[UUIDstr]
    inherited_permissions: List[str]
    effective_priority: int
