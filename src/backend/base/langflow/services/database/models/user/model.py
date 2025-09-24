from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, Union, List
from uuid import UUID, uuid4

from pydantic import BaseModel
from sqlalchemy import CHAR, JSON, Column
from sqlmodel import Field, Relationship, SQLModel

from langflow.schema.serialize import UUIDstr, UUIDAsString

if TYPE_CHECKING:
    from langflow.services.database.models.api_key.model import ApiKey
    from langflow.services.database.models.flow.model import Flow
    from langflow.services.database.models.folder.model import Folder
    from langflow.services.database.models.rbac.environment import Environment
    from langflow.services.database.models.rbac.project import Project
    from langflow.services.database.models.rbac.role import Role
    from langflow.services.database.models.rbac.role_assignment import RoleAssignment
    from langflow.services.database.models.rbac.service_account import ServiceAccount
    from langflow.services.database.models.rbac.user_group import UserGroup, UserGroupMembership
    from langflow.services.database.models.rbac.workspace import Workspace
    from langflow.services.database.models.variable.model import Variable


class UserOptin(BaseModel):
    github_starred: bool = Field(default=False)
    dialog_dismissed: bool = Field(default=False)
    discord_clicked: bool = Field(default=False)
    # Add more opt-in actions as needed


class User(SQLModel, table=True):  # type: ignore[call-arg]

    id: UUIDstr = Field(default_factory=uuid4, primary_key=True, unique=True, nullable=False)
#    id: UUIDstr = Field(default_factory=uuid4, sa_column=Column(CHAR(32), primary_key=True, unique=True, nullable=False))
    username: str = Field(index=True, unique=True)
    password: str = Field()
    profile_image: Union[str, None] = Field(default=None, nullable=True)
    is_active: bool = Field(default=False)
    is_superuser: bool = Field(default=False)
    create_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_login_at: Union[datetime, None] = Field(default=None, nullable=True)

    api_keys: List["ApiKey"] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={"cascade": "delete"},
    )
    store_api_key: Union[str, None] = Field(default=None, nullable=True)
    flows: List["Flow"] = Relationship(back_populates="user")
    variables: List["Variable"] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={"cascade": "delete"},
    )
    folders: List["Folder"] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={"cascade": "delete"},
    )
    optins: Union[Dict[str, Any], None] = Field(
        sa_column=Column(JSON, default=lambda: UserOptin().model_dump(), nullable=True)
    )

    # RBAC relationships
    owned_workspaces: List["Workspace"] = Relationship(
        back_populates="owner", sa_relationship_kwargs={"cascade": "delete"}
    )
    owned_projects: List["Project"] = Relationship(back_populates="owner", sa_relationship_kwargs={"cascade": "delete"})
    owned_environments: List["Environment"] = Relationship(
        back_populates="owner", sa_relationship_kwargs={"cascade": "delete"}
    )
    created_roles: List["Role"] = Relationship(back_populates="created_by", sa_relationship_kwargs={"cascade": "delete"})
    role_assignments: List["RoleAssignment"] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={
            "cascade": "delete",
            "foreign_keys": "[RoleAssignment.user_id]",
            "primaryjoin": "RoleAssignment.user_id == User.id",
        },
    )
    group_memberships: List["UserGroupMembership"] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={
            "cascade": "delete",
            "foreign_keys": "[UserGroupMembership.user_id]",
            "primaryjoin": "UserGroupMembership.user_id == User.id",
        },
    )
    created_groups: List["UserGroup"] = Relationship(
        back_populates="created_by", sa_relationship_kwargs={"cascade": "delete"}
    )
    created_service_accounts: List["ServiceAccount"] = Relationship(
        back_populates="created_by", sa_relationship_kwargs={"cascade": "delete"}
    )



class UserCreate(SQLModel):
    username: str = Field()
    password: str = Field()
    optins: Union[Dict[str, Any], None] = Field(
        default={"github_starred": False, "dialog_dismissed": False, "discord_clicked": False}
    )


class UserRead(SQLModel):
    id: UUID = Field(default_factory=uuid4)
    username: str = Field()
    profile_image: Union[str, None] = Field()
    store_api_key: Union[str, None] = Field(nullable=True)
    is_active: bool = Field()
    is_superuser: bool = Field()
    create_at: datetime = Field()
    updated_at: datetime = Field()
    last_login_at: Union[datetime, None] = Field(nullable=True)
    optins: Union[Dict[str, Any], None] = Field(default=None)


class UserUpdate(SQLModel):
    username: Union[str, None] = None
    profile_image: Union[str, None] = None
    password: Union[str, None] = None
    is_active: Union[bool, None] = None
    is_superuser: Union[bool, None] = None
    last_login_at: Union[datetime, None] = None
    optins: Union[Dict[str, Any], None] = None
