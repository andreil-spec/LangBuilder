from datetime import datetime, timezone
from typing import TYPE_CHECKING, Union, List
from uuid import uuid4

from pydantic import field_validator
from sqlalchemy import CHAR, JSON, Column
# from sqlalchemy.orm import Mapped  # Removed - use quoted strings for SQLModel relationships
from sqlmodel import DateTime, Field, Relationship, SQLModel, func

from langflow.schema.serialize import UUIDstr, UUIDAsString

# from langflow.services.database.models.rbac.service_account import ServiceAccount

if TYPE_CHECKING:
    from langflow.services.database.models.rbac.service_account import ServiceAccount
    from langflow.services.database.models.user.model import User


def utc_now():
    return datetime.now(timezone.utc)


class ApiKeyBase(SQLModel):
    name: Union[str, None] = Field(index=True, nullable=True, default=None)
    last_used_at: Union[datetime, None] = Field(default=None, nullable=True)
    total_uses: int = Field(default=0)
    is_active: bool = Field(default=True)


class ApiKey(ApiKeyBase, table=True):  # type: ignore[call-arg]

    id: UUIDstr = Field(default_factory=uuid4, primary_key=True, unique=True, sa_type=UUIDAsString)
    created_at: Union[datetime, None] = Field(
        default=None, sa_column=Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    )
    api_key: str = Field(index=True, unique=True)
    # User relationship
    # Delete API keys when user is deleted
    user_id: UUIDstr = Field(index=True, foreign_key="user.id", sa_type=UUIDAsString)
    user: "User" = Relationship(back_populates="api_keys")
#    user_id: UUIDstr = Field(sa_column=Column(CHAR(32), ForeignKey("user.id"), index=True, nullable=False))
#    user: User = Relationship(
#        back_populates="api_keys"
#    )

    # RBAC - Service account relationship (for service account tokens)
    service_account_id: Union[UUIDstr, None] = Field(
        default=None, foreign_key="service_account.id", nullable=True, index=True, sa_type=UUIDAsString
    )
    service_account: Union["ServiceAccount", None] = Relationship(back_populates="api_keys")

    # Token scoping for RBAC
    scoped_permissions: Union[List[str], None] = Field(default=[], sa_column=Column(JSON))
    scope_type: Union[str, None] = Field(default=None)  # workspace, project, environment, flow, component
    scope_id: Union[UUIDstr, None] = Field(default=None, sa_type=UUIDAsString)  # ID of the scoped resource
    workspace_id: Union[UUIDstr, None] = Field(default=None, foreign_key="workspace.id", nullable=True, index=True, sa_type=UUIDAsString)


class ApiKeyCreate(ApiKeyBase):
    api_key: Union[str, None] = None
    user_id: Union[UUIDstr, None] = None
    created_at: Union[datetime, None] = Field(default_factory=utc_now)

    @field_validator("created_at", mode="before")
    @classmethod
    def set_created_at(cls, v):
        return v or utc_now()


class UnmaskedApiKeyRead(ApiKeyBase):
    id: UUIDstr
    api_key: str = Field()
    user_id: UUIDstr = Field()


class ApiKeyRead(ApiKeyBase):
    id: UUIDstr
    api_key: str = Field(schema_extra={"validate_default": True})
    user_id: UUIDstr = Field()
    created_at: datetime = Field()

    @field_validator("api_key")
    @classmethod
    def mask_api_key(cls, v) -> str:
        # This validator will always run, and will mask the API key
        return f"{v[:8]}{'*' * (len(v) - 8)}"
