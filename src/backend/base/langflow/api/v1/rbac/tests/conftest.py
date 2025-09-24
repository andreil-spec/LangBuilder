"""Test configuration and fixtures for RBAC API tests."""

import asyncio
from collections.abc import AsyncGenerator
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.services.database.models.rbac.project import Project
from langflow.services.database.models.rbac.role import Role
from langflow.services.database.models.rbac.workspace import Workspace
from langflow.services.database.models.user.model import User
from langflow.services.rbac.permission_engine import PermissionEngine


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture
async def async_session() -> AsyncGenerator[AsyncSession, None]:
    """Create an async database session for testing."""
    # This would typically connect to a test database
    # For now, this is a placeholder that would need proper implementation
    # with database setup and teardown

    # Placeholder implementation
    yield None  # type: ignore


@pytest.fixture
def test_user() -> User:
    """Create a test user."""
    return User(
        id=uuid4(),
        username="testuser",
        email="test@example.com",
        is_active=True,
        is_superuser=False,
    )


@pytest.fixture
def superuser() -> User:
    """Create a test superuser."""
    return User(
        id=uuid4(),
        username="superuser",
        email="super@example.com",
        is_active=True,
        is_superuser=True,
    )


@pytest.fixture
def test_workspace(test_user: User) -> Workspace:
    """Create a test workspace."""
    return Workspace(
        id=uuid4(),
        name="Test Workspace",
        description="A workspace for testing",
        organization="Test Org",
        owner_id=test_user.id,
        is_active=True,
        is_deleted=False,
    )


@pytest.fixture
def test_project(test_workspace: Workspace, test_user: User) -> Project:
    """Create a test project."""
    return Project(
        id=uuid4(),
        name="Test Project",
        description="A project for testing",
        workspace_id=test_workspace.id,
        owner_id=test_user.id,
        is_active=True,
        is_archived=False,
    )


@pytest.fixture
def test_role(test_workspace: Workspace, test_user: User) -> Role:
    """Create a test role."""
    return Role(
        id=uuid4(),
        name="Test Role",
        description="A role for testing",
        workspace_id=test_workspace.id,
        type="custom",
        created_by_id=test_user.id,
        is_active=True,
        is_system=False,
    )


@pytest.fixture
def permission_engine() -> PermissionEngine:
    """Create a permission engine instance for testing."""
    return PermissionEngine()


@pytest.fixture
def client() -> TestClient:
    """Create a test client."""
    # This would need to be implemented with proper app setup
    # For now, this is a placeholder


# Test data constants
TEST_WORKSPACE_DATA = {
    "name": "Test Workspace",
    "description": "A workspace for testing",
    "organization": "Test Organization",
    "settings": {},
}

TEST_PROJECT_DATA = {
    "name": "Test Project",
    "description": "A project for testing",
    "tags": ["test"],
    "metadata": {},
}

TEST_ROLE_DATA = {
    "name": "Test Role",
    "description": "A role for testing",
    "type": "custom",
    "permissions": ["workspace:read", "project:read"],
}

TEST_PERMISSION_CHECK = {
    "resource_type": "workspace",
    "action": "read",
}
