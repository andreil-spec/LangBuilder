"""Custom exceptions and error handling for RBAC system."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import HTTPException, status


class RBACException(Exception):
    """Base exception for RBAC-related errors."""

    def __init__(self, message: str, details: dict[str, Any] | None = None):
        self.message = message
        self.details = details or {}
        super().__init__(message)


class PermissionDeniedException(RBACException):
    """Raised when a user lacks required permissions."""

    def __init__(
        self,
        user_id: UUID | None = None,
        resource_type: str | None = None,
        action: str | None = None,
        resource_id: UUID | None = None,
        reason: str | None = None
    ):
        self.user_id = user_id
        self.resource_type = resource_type
        self.action = action
        self.resource_id = resource_id
        self.reason = reason

        message = "Insufficient permissions"
        if resource_type and action:
            message = f"Insufficient permissions for {action} on {resource_type}"
        if reason:
            message += f": {reason}"

        details = {
            "user_id": str(user_id) if user_id else None,
            "resource_type": resource_type,
            "action": action,
            "resource_id": str(resource_id) if resource_id else None,
            "reason": reason,
        }

        super().__init__(message, details)


class ResourceNotFoundException(RBACException):
    """Raised when a requested resource is not found."""

    def __init__(self, resource_type: str, resource_id: UUID | str):
        self.resource_type = resource_type
        self.resource_id = resource_id

        message = f"{resource_type.capitalize()} not found"
        details = {
            "resource_type": resource_type,
            "resource_id": str(resource_id),
        }

        super().__init__(message, details)


class ValidationException(RBACException):
    """Raised when input validation fails."""

    def __init__(self, field: str, value: Any, constraint: str):
        self.field = field
        self.value = value
        self.constraint = constraint

        message = f"Validation failed for field '{field}': {constraint}"
        details = {
            "field": field,
            "value": str(value),
            "constraint": constraint,
        }

        super().__init__(message, details)


class ConflictException(RBACException):
    """Raised when an operation conflicts with existing data."""

    def __init__(self, resource_type: str, conflict_reason: str):
        self.resource_type = resource_type
        self.conflict_reason = conflict_reason

        message = f"Conflict in {resource_type}: {conflict_reason}"
        details = {
            "resource_type": resource_type,
            "conflict_reason": conflict_reason,
        }

        super().__init__(message, details)


class LimitExceededException(RBACException):
    """Raised when a resource limit is exceeded."""

    def __init__(self, resource_type: str, limit: int, current: int):
        self.resource_type = resource_type
        self.limit = limit
        self.current = current

        message = f"Limit exceeded for {resource_type}: {current}/{limit}"
        details = {
            "resource_type": resource_type,
            "limit": limit,
            "current": current,
        }

        super().__init__(message, details)


class CircularDependencyException(RBACException):
    """Raised when a circular dependency is detected."""

    def __init__(self, resource_type: str, dependency_chain: list[str]):
        self.resource_type = resource_type
        self.dependency_chain = dependency_chain

        message = f"Circular dependency detected in {resource_type}: {' -> '.join(dependency_chain)}"
        details = {
            "resource_type": resource_type,
            "dependency_chain": dependency_chain,
        }

        super().__init__(message, details)


def rbac_exception_handler(exc: RBACException) -> HTTPException:
    """Convert RBAC exceptions to HTTP exceptions."""
    if isinstance(exc, PermissionDeniedException):
        return HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "message": exc.message,
                "error_type": "permission_denied",
                "details": exc.details,
            }
        )

    if isinstance(exc, ResourceNotFoundException):
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "message": exc.message,
                "error_type": "resource_not_found",
                "details": exc.details,
            }
        )

    if isinstance(exc, ValidationException):
        return HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": exc.message,
                "error_type": "validation_error",
                "details": exc.details,
            }
        )

    if isinstance(exc, ConflictException):
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "message": exc.message,
                "error_type": "conflict",
                "details": exc.details,
            }
        )

    if isinstance(exc, LimitExceededException):
        return HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": exc.message,
                "error_type": "limit_exceeded",
                "details": exc.details,
            }
        )

    if isinstance(exc, CircularDependencyException):
        return HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": exc.message,
                "error_type": "circular_dependency",
                "details": exc.details,
            }
        )

    # Generic RBAC exception
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail={
            "message": exc.message,
            "error_type": "rbac_error",
            "details": exc.details,
        }
    )


def handle_database_errors(func):
    """Decorator to handle common database errors in RBAC operations."""
    import functools

    from sqlalchemy.exc import IntegrityError, SQLAlchemyError
    from sqlmodel.exc import SQLModelError

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except IntegrityError as e:
            # Handle foreign key violations, unique constraints, etc.
            if "foreign key" in str(e).lower():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Operation failed due to missing referenced resource"
                )
            if "unique" in str(e).lower():
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Operation failed due to duplicate data"
                )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Database constraint violation"
            )
        except (SQLAlchemyError, SQLModelError):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Database operation failed"
            )
        except RBACException as e:
            raise rbac_exception_handler(e)
        except Exception as e:
            # Log unexpected errors
            import traceback

            from loguru import logger

            logger.error(f"Unexpected error in RBAC operation: {e}", exc_info=True)
            logger.debug(f"Traceback: {traceback.format_exc()}")

            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An unexpected error occurred"
            )

    return wrapper
