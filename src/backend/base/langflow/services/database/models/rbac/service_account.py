from datetime import datetime, timezone
from typing import TYPE_CHECKING, Union, List
from uuid import UUID, uuid4

from pydantic import field_validator
from sqlalchemy import CHAR, JSON, Column, Text, UniqueConstraint
# from sqlalchemy.orm import Mapped  # Removed - use quoted strings for SQLModel relationships
from sqlmodel import Field, Relationship, SQLModel

from langflow.schema.serialize import UUIDstr, UUIDAsString

if TYPE_CHECKING:
    from langflow.services.database.models.api_key.model import ApiKey
    from langflow.services.database.models.rbac.role_assignment import RoleAssignment
    from langflow.services.database.models.rbac.workspace import Workspace
    from langflow.services.database.models.user.model import User


class ServiceAccountBase(SQLModel):
    """Base model for service accounts."""

    name: str = Field(index=True)
    description: Union[str, None] = Field(default=None, sa_column=Column(Text))

    # Service account metadata
    service_type: Union[str, None] = Field(default="api", index=True)  # api, webhook, integration, bot
    integration_name: Union[str, None] = Field(default=None)  # e.g., "github", "slack", "jenkins"

    # Token configuration
    token_prefix: Union[str, None] = Field(default="sa_")  # Prefix for generated tokens
    max_tokens: int = Field(default=5)  # Maximum number of active tokens
    token_expiry_days: Union[int, None] = Field(default=365)  # Token expiry in days

    # Security settings
    allowed_ips: Union[List[str], None] = Field(default=[], sa_column=Column(JSON))
    allowed_origins: Union[List[str], None] = Field(default=[], sa_column=Column(JSON))
    rate_limit_per_minute: Union[int, None] = Field(default=None)

    # Scoping
    default_scope_type: Union[str, None] = Field(default="workspace")
    default_scope_id: Union[UUIDstr, None] = Field(default=None, sa_type=UUIDAsString)
    allowed_permissions: Union[List[str], None] = Field(default=[], sa_column=Column(JSON))

    # Status
    is_active: bool = Field(default=True, index=True)
    is_locked: bool = Field(default=False)
    locked_reason: Union[str, None] = Field(default=None, sa_column=Column(Text))
    locked_at: Union[datetime, None] = Field(default=None)

    # Usage tracking
    last_used_at: Union[datetime, None] = Field(default=None)
    usage_count: int = Field(default=0)

    # Metadata
    service_metadata: Union[dict, None] = Field(default={}, sa_column=Column(JSON))
    tags: Union[List[str], None] = Field(default=[], sa_column=Column(JSON))

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Union[datetime, None] = Field(default=None)

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Service account name cannot be empty")
        if len(v) > 255:
            raise ValueError("Service account name cannot exceed 255 characters")
        # Validate service account name format
        import re
        if not re.match(r"^[a-zA-Z0-9_\s-]+$", v):
            raise ValueError("Service account name must contain only letters, numbers, hyphens, underscores, and spaces")
        return v.strip()


class ServiceAccount(ServiceAccountBase, table=True):  # type: ignore[call-arg]
    """Service account table for automated access."""

    __tablename__ = "service_account"

    id: UUIDstr = Field(default_factory=uuid4, primary_key=True, sa_type=UUIDAsString)

    # Workspace relationship
    workspace_id: UUIDstr = Field(foreign_key="workspace.id", sa_type=UUIDAsString)
    workspace: "Workspace" = Relationship(back_populates="service_accounts")

    # Creator/owner relationship
    created_by_id: UUIDstr = Field(foreign_key="user.id", sa_type=UUIDAsString)
    created_by: "User" = Relationship(back_populates="created_service_accounts")

    # Relationships
    api_keys: List["ApiKey"] = Relationship(
        back_populates="service_account",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )
    role_assignments: List["RoleAssignment"] = Relationship(
        back_populates="service_account",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )

    # Unique constraints
    __table_args__ = (
        UniqueConstraint("workspace_id", "name", name="unique_service_account_name_per_workspace"),
    )


class ServiceAccountToken(SQLModel, table=True):  # type: ignore[call-arg]
    """Service account token table for authentication."""

    __tablename__ = "service_account_token"

    id: UUIDstr = Field(default_factory=uuid4, primary_key=True, sa_type=UUIDAsString)
    service_account_id: UUIDstr = Field(foreign_key="service_account.id", sa_type=UUIDAsString)

    # Token details
    name: str = Field(index=True)
    token_hash: str = Field(unique=True, index=True)  # Hashed token value
    token_prefix: str = Field()  # First 8 chars for identification

    # Scoping
    scoped_permissions: Union[List[str], None] = Field(default=[], sa_column=Column(JSON))
    scope_type: Union[str, None] = Field(default=None)
    scope_id: Union[UUIDstr, None] = Field(default=None, sa_type=UUIDAsString)

    # Security
    allowed_ips: Union[List[str], None] = Field(default=[], sa_column=Column(JSON))

    # Status and usage
    is_active: bool = Field(default=True, index=True)
    last_used_at: Union[datetime, None] = Field(default=None)
    usage_count: int = Field(default=0)

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Union[datetime, None] = Field(default=None)
    revoked_at: Union[datetime, None] = Field(default=None)
    revoked_by_id: Union[UUIDstr, None] = Field(foreign_key="user.id", default=None, sa_type=UUIDAsString)
    revoke_reason: Union[str, None] = Field(default=None, sa_column=Column(Text))

    # Created by
    created_by_id: UUIDstr = Field(foreign_key="user.id", sa_type=UUIDAsString)

    # Relationships
    service_account: "ServiceAccount" = Relationship()
    created_by: "User" = Relationship(
        sa_relationship_kwargs={
            "foreign_keys": "[ServiceAccountToken.created_by_id]",
            "primaryjoin": "ServiceAccountToken.created_by_id == User.id"
        }
    )
    revoked_by: Union["User", None] = Relationship(
        sa_relationship_kwargs={
            "foreign_keys": "[ServiceAccountToken.revoked_by_id]",
            "primaryjoin": "ServiceAccountToken.revoked_by_id == User.id"
        }
    )

    # Unique constraints
    __table_args__ = (
        UniqueConstraint("service_account_id", "name", name="unique_token_name_per_service_account"),
    )


class ServiceAccountCreate(SQLModel):
    """Schema for creating a service account."""

    name: str
    description: Union[str, None] = None
    workspace_id: UUID
    service_type: Union[str, None] = "api"
    integration_name: Union[str, None] = None
    token_prefix: Union[str, None] = "sa_"
    max_tokens: int = 5
    token_expiry_days: Union[int, None] = 365
    allowed_ips: Union[List[str], None] = None
    allowed_origins: Union[List[str], None] = None
    rate_limit_per_minute: Union[int, None] = None
    default_scope_type: Union[str, None] = "workspace"
    default_scope_id: Union[UUID, None] = None
    allowed_permissions: Union[List[str], None] = None
    service_metadata: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
    tags: Union[List[str], None] = None
    expires_at: Union[datetime, None] = None


class ServiceAccountRead(ServiceAccountBase):
    """Schema for reading service account data."""

    id: UUID
    workspace_id: UUID
    created_by_id: UUID
    active_token_count: Union[int, None] = None
    total_token_count: Union[int, None] = None
    role_count: Union[int, None] = None


class ServiceAccountUpdate(SQLModel):
    """Schema for updating service account data."""

    name: Union[str, None] = None
    description: Union[str, None] = None
    service_type: Union[str, None] = None
    integration_name: Union[str, None] = None
    max_tokens: Union[int, None] = None
    token_expiry_days: Union[int, None] = None
    allowed_ips: Union[List[str], None] = None
    allowed_origins: Union[List[str], None] = None
    rate_limit_per_minute: Union[int, None] = None
    default_scope_type: Union[str, None] = None
    default_scope_id: Union[UUID, None] = None
    allowed_permissions: Union[List[str], None] = None
    service_metadata: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
    tags: Union[List[str], None] = None
    is_active: Union[bool, None] = None
    expires_at: Union[datetime, None] = None


class ServiceAccountTokenCreate(SQLModel):
    """Schema for creating a service account token."""

    service_account_id: UUID
    name: str
    scoped_permissions: Union[List[str], None] = None
    scope_type: Union[str, None] = None
    scope_id: Union[UUID, None] = None
    allowed_ips: Union[List[str], None] = None
    expires_at: Union[datetime, None] = None


class ServiceAccountTokenRead(SQLModel):
    """Schema for reading service account token data."""

    id: UUID
    service_account_id: UUID
    name: str
    token_prefix: str
    scoped_permissions: Union[List[str], None]
    scope_type: Union[str, None]
    scope_id: Union[UUID, None]
    allowed_ips: Union[List[str], None]
    is_active: bool
    last_used_at: Union[datetime, None]
    usage_count: int
    created_at: datetime
    expires_at: Union[datetime, None]
    created_by_id: UUID


class ServiceAccountTokenResponse(SQLModel):
    """Response when creating a new token."""

    id: UUID
    name: str
    token: str  # Full token (only shown once)
    token_prefix: str
    expires_at: Union[datetime, None]
    created_at: datetime
