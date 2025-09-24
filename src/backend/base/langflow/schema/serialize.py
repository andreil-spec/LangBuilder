from typing import Annotated
from uuid import UUID

from pydantic import BeforeValidator, field_serializer
from sqlalchemy import TypeDecorator, CHAR


def str_to_uuid(v: str | UUID) -> UUID:
    if isinstance(v, str):
        return UUID(v)
    return v


class UUIDAsString(TypeDecorator):
    """SQLAlchemy type that stores UUIDs as 32-character strings in the database."""
    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        return dialect.type_descriptor(CHAR(32))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        if isinstance(value, UUID):
            return value.hex
        if isinstance(value, str):
            return UUID(value).hex
        return value

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        return UUID(value)


UUIDstr = Annotated[UUID, BeforeValidator(str_to_uuid)]
