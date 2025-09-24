
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Union, List
from uuid import uuid4

from pydantic import field_validator
from sqlalchemy import CHAR, JSON, Column, Text, UniqueConstraint
from sqlmodel import Field, Relationship, SQLModel

from langflow.schema.serialize import UUIDstr, UUIDAsString

if TYPE_CHECKING:
    from langflow.services.database.models.rbac.role import Role


class PermissionAction(str, Enum):
    """Permission actions based on CRUD + extended operations."""

    # Basic CRUD
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"

    # Extended permissions
    EXECUTE = "execute"
    DEPLOY = "deploy"
    EXPORT = "export"
    IMPORT = "import"
    SHARE = "share"
    PUBLISH = "publish"
    ARCHIVE = "archive"
    RESTORE = "restore"

    # Administrative
    MANAGE = "manage"  # Full control
    GRANT = "grant"    # Grant permissions to others
    REVOKE = "revoke"  # Revoke permissions from others
    AUDIT = "audit"    # View audit logs

    # Special permissions
    BREAK_GLASS = "break_glass"  # Emergency access
    IMPERSONATE = "impersonate"  # Act as another user

    # Extended actions from PRD (Story 1.1)
    EXPORT_FLOW = "export_flow"
    DEPLOY_ENVIRONMENT = "deploy_environment"
    INVITE_USERS = "invite_users"
    MODIFY_COMPONENT_SETTINGS = "modify_component_settings"
    MANAGE_TOKENS = "manage_tokens"


class ResourceType(str, Enum):
    """Resource types that can be protected."""

    WORKSPACE = "workspace"
    PROJECT = "project"
    ENVIRONMENT = "environment"
    FLOW = "flow"
    COMPONENT = "component"
    VARIABLE = "variable"
    SECRET = "secret"
    API_KEY = "api_key"
    USER = "user"
    ROLE = "role"
    AUDIT_LOG = "audit_log"
    SYSTEM = "system"
    FILE = "file"
    FOLDER = "folder"


class PermissionBase(SQLModel):
    """Base permission model for defining access rights."""

    name: str = Field(index=True)
    description: Union[str, None] = Field(default=None, sa_column=Column(Text))

    # Permission definition
    resource_type: ResourceType = Field(index=True)
    action: PermissionAction = Field(index=True)

    # Scope and conditions
    scope: Union[str, None] = Field(default="*")  # Glob pattern for resource matching
    conditions: Union[dict, None] = Field(default={}, sa_column=Column(JSON))  # Additional conditions

    # Permission metadata
    category: Union[str, None] = Field(default=None, index=True)  # Grouping for UI
    is_system: bool = Field(default=False)  # System permissions cannot be modified
    is_dangerous: bool = Field(default=False)  # Requires additional confirmation
    requires_mfa: bool = Field(default=False)  # Requires MFA for this action

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Permission name cannot be empty")
        if len(v) > 200:
            raise ValueError("Permission name cannot exceed 200 characters")
        return v.strip()

    @field_validator("scope")
    @classmethod
    def validate_scope(cls, v: Union[str, None]) -> str:
        if v is None:
            return "*"
        # Validate glob pattern
        import re
        if not re.match(r"^[\w\*\?\[\]\-\./]+$", v):
            raise ValueError("Invalid scope pattern")
        return v


class Permission(PermissionBase, table=True):  # type: ignore[call-arg]
    """Permission table for defining granular access rights."""

    __tablename__ = "permission"

    id: UUIDstr = Field(default_factory=uuid4, primary_key=True, sa_type=UUIDAsString)

    # Permission code for fast lookup
    code: str = Field(index=True, unique=True)  # e.g., "flow:create", "workspace:manage"

    # Relationships
    role_permissions: List["RolePermission"] = Relationship(
        back_populates="permission",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )

    # Unique constraints
    __table_args__ = (
        UniqueConstraint("resource_type", "action", "scope", name="unique_permission_definition"),
    )


class RolePermission(SQLModel, table=True):  # type: ignore[call-arg]
    """Junction table for role-permission many-to-many relationship."""

    __tablename__ = "role_permission"

    id: UUIDstr = Field(default_factory=uuid4, primary_key=True, sa_type=UUIDAsString)

    # Foreign keys
    role_id: UUIDstr = Field(foreign_key="role.id", sa_type=UUIDAsString)
    permission_id: UUIDstr = Field(foreign_key="permission.id", sa_type=UUIDAsString)

    # Permission modifiers
    is_granted: bool = Field(default=True)  # True for grant, False for explicit deny
    conditions: Union[dict, None] = Field(default={}, sa_column=Column(JSON))  # Runtime conditions
    expires_at: Union[datetime, None] = Field(default=None)  # Temporary permissions

    # Metadata
    granted_by_id: UUIDstr = Field(foreign_key="user.id", sa_type=UUIDAsString)
    granted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reason: Union[str, None] = Field(default=None, sa_column=Column(Text))

    # Relationships
    role: "Role" = Relationship(back_populates="permissions")
    permission: "Permission" = Relationship(back_populates="role_permissions")

    # Unique constraints
    __table_args__ = (
        UniqueConstraint("role_id", "permission_id", name="unique_role_permission"),
    )


# System permission definitions
SYSTEM_PERMISSIONS = [
    # Workspace permissions
    {"code": "workspace:create", "name": "Create Workspace", "resource_type": ResourceType.WORKSPACE, "action": PermissionAction.CREATE},
    {"code": "workspace:read", "name": "View Workspace", "resource_type": ResourceType.WORKSPACE, "action": PermissionAction.READ},
    {"code": "workspace:update", "name": "Update Workspace", "resource_type": ResourceType.WORKSPACE, "action": PermissionAction.UPDATE},
    {"code": "workspace:delete", "name": "Delete Workspace", "resource_type": ResourceType.WORKSPACE, "action": PermissionAction.DELETE},
    {"code": "workspace:manage", "name": "Manage Workspace", "resource_type": ResourceType.WORKSPACE, "action": PermissionAction.MANAGE},

    # Project permissions
    {"code": "project:create", "name": "Create Project", "resource_type": ResourceType.PROJECT, "action": PermissionAction.CREATE},
    {"code": "project:read", "name": "View Project", "resource_type": ResourceType.PROJECT, "action": PermissionAction.READ},
    {"code": "project:update", "name": "Update Project", "resource_type": ResourceType.PROJECT, "action": PermissionAction.UPDATE},
    {"code": "project:delete", "name": "Delete Project", "resource_type": ResourceType.PROJECT, "action": PermissionAction.DELETE},
    {"code": "project:deploy", "name": "Deploy Project", "resource_type": ResourceType.PROJECT, "action": PermissionAction.DEPLOY},

    # Environment permissions
    {"code": "environment:create", "name": "Create Environment", "resource_type": ResourceType.ENVIRONMENT, "action": PermissionAction.CREATE},
    {"code": "environment:read", "name": "View Environment", "resource_type": ResourceType.ENVIRONMENT, "action": PermissionAction.READ},
    {"code": "environment:update", "name": "Update Environment", "resource_type": ResourceType.ENVIRONMENT, "action": PermissionAction.UPDATE},
    {"code": "environment:delete", "name": "Delete Environment", "resource_type": ResourceType.ENVIRONMENT, "action": PermissionAction.DELETE},
    {"code": "environment:deploy", "name": "Deploy to Environment", "resource_type": ResourceType.ENVIRONMENT, "action": PermissionAction.DEPLOY},

    # Flow permissions
    {"code": "flow:create", "name": "Create Flow", "resource_type": ResourceType.FLOW, "action": PermissionAction.CREATE},
    {"code": "flow:read", "name": "View Flow", "resource_type": ResourceType.FLOW, "action": PermissionAction.READ},
    {"code": "flow:update", "name": "Update Flow", "resource_type": ResourceType.FLOW, "action": PermissionAction.UPDATE},
    {"code": "flow:delete", "name": "Delete Flow", "resource_type": ResourceType.FLOW, "action": PermissionAction.DELETE},
    {"code": "flow:execute", "name": "Execute Flow", "resource_type": ResourceType.FLOW, "action": PermissionAction.EXECUTE},
    {"code": "flow:export", "name": "Export Flow", "resource_type": ResourceType.FLOW, "action": PermissionAction.EXPORT},
    {"code": "flow:import", "name": "Import Flow", "resource_type": ResourceType.FLOW, "action": PermissionAction.IMPORT},
    {"code": "flow:share", "name": "Share Flow", "resource_type": ResourceType.FLOW, "action": PermissionAction.SHARE},
    {"code": "flow:publish", "name": "Publish Flow", "resource_type": ResourceType.FLOW, "action": PermissionAction.PUBLISH},

    # Component permissions
    {"code": "component:create", "name": "Create Component", "resource_type": ResourceType.COMPONENT, "action": PermissionAction.CREATE},
    {"code": "component:read", "name": "View Component", "resource_type": ResourceType.COMPONENT, "action": PermissionAction.READ},
    {"code": "component:update", "name": "Update Component", "resource_type": ResourceType.COMPONENT, "action": PermissionAction.UPDATE},
    {"code": "component:delete", "name": "Delete Component", "resource_type": ResourceType.COMPONENT, "action": PermissionAction.DELETE},
    {"code": "component:execute", "name": "Execute Component", "resource_type": ResourceType.COMPONENT, "action": PermissionAction.EXECUTE},

    # User management permissions
    {"code": "user:create", "name": "Create User", "resource_type": ResourceType.USER, "action": PermissionAction.CREATE},
    {"code": "user:read", "name": "View User", "resource_type": ResourceType.USER, "action": PermissionAction.READ},
    {"code": "user:update", "name": "Update User", "resource_type": ResourceType.USER, "action": PermissionAction.UPDATE},
    {"code": "user:delete", "name": "Delete User", "resource_type": ResourceType.USER, "action": PermissionAction.DELETE},
    {"code": "user:impersonate", "name": "Impersonate User", "resource_type": ResourceType.USER, "action": PermissionAction.IMPERSONATE, "is_dangerous": True, "requires_mfa": True},

    # Role management permissions
    {"code": "role:create", "name": "Create Role", "resource_type": ResourceType.ROLE, "action": PermissionAction.CREATE},
    {"code": "role:read", "name": "View Role", "resource_type": ResourceType.ROLE, "action": PermissionAction.READ},
    {"code": "role:update", "name": "Update Role", "resource_type": ResourceType.ROLE, "action": PermissionAction.UPDATE},
    {"code": "role:delete", "name": "Delete Role", "resource_type": ResourceType.ROLE, "action": PermissionAction.DELETE},
    {"code": "role:grant", "name": "Grant Role", "resource_type": ResourceType.ROLE, "action": PermissionAction.GRANT},
    {"code": "role:revoke", "name": "Revoke Role", "resource_type": ResourceType.ROLE, "action": PermissionAction.REVOKE},

    # Audit permissions
    {"code": "audit:read", "name": "View Audit Logs", "resource_type": ResourceType.AUDIT_LOG, "action": PermissionAction.READ},
    {"code": "audit:export", "name": "Export Audit Logs", "resource_type": ResourceType.AUDIT_LOG, "action": PermissionAction.EXPORT},

    # System permissions
    {"code": "system:manage", "name": "System Management", "resource_type": ResourceType.SYSTEM, "action": PermissionAction.MANAGE, "is_dangerous": True},
    {"code": "system:break_glass", "name": "Break Glass Access", "resource_type": ResourceType.SYSTEM, "action": PermissionAction.BREAK_GLASS, "is_dangerous": True, "requires_mfa": True},

    # Extended actions from PRD (Story 1.1)
    {"code": "flow:export_flow", "name": "Export Flow", "resource_type": ResourceType.FLOW, "action": PermissionAction.EXPORT_FLOW, "category": "Extended Actions"},
    {"code": "environment:deploy_environment", "name": "Deploy Environment", "resource_type": ResourceType.ENVIRONMENT, "action": PermissionAction.DEPLOY_ENVIRONMENT, "category": "Extended Actions"},
    {"code": "user:invite_users", "name": "Invite Users", "resource_type": ResourceType.USER, "action": PermissionAction.INVITE_USERS, "category": "Extended Actions"},
    {"code": "component:modify_component_settings", "name": "Modify Component Settings", "resource_type": ResourceType.COMPONENT, "action": PermissionAction.MODIFY_COMPONENT_SETTINGS, "category": "Extended Actions"},
    {"code": "api_key:manage_tokens", "name": "Manage Tokens", "resource_type": ResourceType.API_KEY, "action": PermissionAction.MANAGE_TOKENS, "category": "Extended Actions"},
]


class PermissionCreate(SQLModel):
    """Schema for creating a permission."""

    name: str
    description: Union[str, None] = None
    code: str
    resource_type: ResourceType
    action: PermissionAction
    scope: Union[str, None] = "*"
    conditions: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
    category: Union[str, None] = None
    is_dangerous: bool = False
    requires_mfa: bool = False


class PermissionRead(PermissionBase):
    """Schema for reading permission data."""

    id: UUIDstr
    code: str
    role_count: Union[int, None] = None


class PermissionUpdate(SQLModel):
    """Schema for updating permission data."""

    name: Union[str, None] = None
    description: Union[str, None] = None
    is_dangerous: Union[bool, None] = None
    requires_mfa: Union[bool, None] = None
    category: Union[str, None] = None


class PermissionCheck(SQLModel):
    """Schema for permission check requests."""

    user_id: UUIDstr
    resource_type: ResourceType
    resource_id: Union[UUIDstr, None] = None
    action: PermissionAction
    context: Union[dict, None] = Field(default=None, sa_column=Column(JSON))


class RolePermissionCreate(SQLModel):
    """Schema for creating a role-permission assignment."""

    permission_id: UUIDstr
    is_granted: bool = True
    conditions: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
    expires_at: Union[datetime, None] = None
    metadata: Union[dict, None] = Field(default=None, sa_column=Column(JSON))


class RolePermissionRead(SQLModel):
    """Schema for reading role-permission assignment data."""

    id: UUIDstr
    role_id: UUIDstr
    permission_id: UUIDstr
    is_granted: bool
    conditions: Union[dict, None] = None
    expires_at: Union[datetime, None] = None
    metadata: Union[dict, None] = None
    created_at: datetime
    updated_at: Union[datetime, None] = None

    # Nested permission data
    permission: Union[PermissionRead, None] = None
