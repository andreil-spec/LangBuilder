"""RBAC services for LangBuilder.

This module provides business logic and services for Role-Based Access Control,
including permission checking, role management, and audit logging.
"""

from __future__ import annotations

from .permission_engine import PermissionEngine

__all__ = [
    "PermissionEngine",
]
