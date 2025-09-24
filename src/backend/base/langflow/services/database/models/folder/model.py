from typing import TYPE_CHECKING, Union, List
from uuid import UUID, uuid4

from sqlalchemy import Text, UniqueConstraint
# from sqlalchemy.orm import Mapped  # Removed - use quoted strings for SQLModel relationships
from sqlmodel import JSON, Column, Field, Relationship, SQLModel

from langflow.schema.serialize import UUIDstr

if TYPE_CHECKING:
    from langflow.services.database.models.flow.model import Flow, FlowRead
    from langflow.services.database.models.user.model import User
else:
    from langflow.services.database.models.flow.model import FlowRead



class FolderBase(SQLModel):
    name: str = Field(index=True)
    description: Union[str, None] = Field(default=None, sa_column=Column(Text))
    auth_settings: Union[dict, None] = Field(
        default=None,
        sa_column=Column(JSON, nullable=True),
        description="Authentication settings for the folder/project",
    )


class Folder(FolderBase, table=True):  # type: ignore[call-arg]
    id: Union[UUID, None] = Field(default_factory=uuid4, primary_key=True)
    parent_id: Union[UUID, None] = Field(default=None, foreign_key="folder.id")

    parent: Union["Folder", None] = Relationship(
        back_populates="children",
        sa_relationship_kwargs={"remote_side": "Folder.id"},
    )
    children: List["Folder"] = Relationship(back_populates="parent")
    user_id: Union[UUIDstr, None] = Field(default=None, foreign_key="user.id")
    user: "User" = Relationship(back_populates="folders")
    flows: List["Flow"] = Relationship(
        back_populates="folder", sa_relationship_kwargs={"cascade": "all, delete, delete-orphan"}
    )

    __table_args__ = (UniqueConstraint("user_id", "name", name="unique_folder_name"),)


class FolderCreate(FolderBase):
    components_list: Union[List[UUID], None] = None
    flows_list: Union[List[UUID], None] = None


class FolderRead(FolderBase):
    id: UUID
    parent_id: Union[UUID, None] = Field()


class FolderReadWithFlows(FolderBase):
    id: UUID
    parent_id: Union[UUID, None] = Field()
    flows: List[FlowRead] = Field(default=[])


class FolderUpdate(SQLModel):
    name: Union[str, None] = None
    description: Union[str, None] = None
    parent_id: Union[UUID, None] = None
    components: List[UUID] = Field(default_factory=list)
    flows: List[UUID] = Field(default_factory=list)
    auth_settings: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
