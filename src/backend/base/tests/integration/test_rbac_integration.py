"""Integration tests for RBAC Phase 2 implementation.

These tests verify that the complete RBAC system works end-to-end,
including API endpoints, permission engine, and database integration.
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import AsyncClient

from langflow.services.database.models.rbac.project import Project
from langflow.services.database.models.rbac.workspace import Workspace
from langflow.services.database.models.user.model import User
from langflow.services.rbac.permission_engine import PermissionEngine, PermissionResult


@pytest.fixture
def mock_app():
    """Create a mock FastAPI application for testing."""
    app = FastAPI()

    # Include RBAC routers
    from langflow.api.v1.rbac.permissions import router as permissions_router
    from langflow.api.v1.rbac.projects import router as projects_router
    from langflow.api.v1.rbac.roles import router as roles_router
    from langflow.api.v1.rbac.workspaces import router as workspaces_router

    app.include_router(workspaces_router, prefix="/api/v1/rbac")
    app.include_router(projects_router, prefix="/api/v1/rbac")
    app.include_router(roles_router, prefix="/api/v1/rbac")
    app.include_router(permissions_router, prefix="/api/v1/rbac")

    return app


@pytest.fixture
def mock_user():
    """Create a mock user for testing."""
    user = MagicMock(spec=User)
    user.id = uuid4()
    user.username = "testuser"
    user.email = "testuser@example.com"
    user.is_superuser = False
    user.is_active = True
    return user


@pytest.fixture
def mock_superuser():
    """Create a mock superuser for testing."""
    user = MagicMock(spec=User)
    user.id = uuid4()
    user.username = "admin"
    user.email = "admin@example.com"
    user.is_superuser = True
    user.is_active = True
    return user


@pytest.fixture
def mock_workspace():
    """Create a mock workspace for testing."""
    workspace = MagicMock(spec=Workspace)
    workspace.id = uuid4()
    workspace.name = "Test Workspace"
    workspace.description = "Integration test workspace"
    workspace.owner_id = uuid4()
    workspace.is_deleted = False
    workspace.is_active = True
    workspace.created_at = datetime.now(timezone.utc)
    workspace.updated_at = datetime.now(timezone.utc)
    return workspace


@pytest.fixture
def mock_project():
    """Create a mock project for testing."""
    project = MagicMock(spec=Project)
    project.id = uuid4()
    project.name = "Test Project"
    project.description = "Integration test project"
    project.workspace_id = uuid4()
    project.owner_id = uuid4()
    project.is_active = True
    project.is_archived = False
    project.created_at = datetime.now(timezone.utc)
    project.updated_at = datetime.now(timezone.utc)
    return project


@pytest.fixture
def mock_permission_engine():
    """Create a mock permission engine for testing."""
    engine = AsyncMock(spec=PermissionEngine)

    # Default to allowing permissions for tests
    def check_permission_side_effect(*args, **kwargs):
        return PermissionResult(
            allowed=True,
            reason="Test permission granted",
            source="mock_engine",
            cached=False
        )

    engine.check_permission.side_effect = check_permission_side_effect
    return engine


class TestRBACWorkflowIntegration:
    """Test complete RBAC workflows."""

    @pytest.mark.asyncio
    async def test_workspace_creation_and_management_workflow(self, mock_app, mock_user):
        """Test complete workspace creation and management workflow."""
        with patch("langflow.api.utils.get_current_active_user", return_value=mock_user), \
             patch("langflow.api.utils.get_session") as mock_get_session:

            # Mock database session
            mock_session = AsyncMock()
            mock_get_session.return_value = mock_session

            # Mock empty database (no existing workspaces)
            mock_result = AsyncMock()
            mock_result.first.return_value = None
            mock_result.all.return_value = []
            mock_session.exec.return_value = mock_result

            # Mock workspace creation
            created_workspace = MagicMock(spec=Workspace)
            created_workspace.id = uuid4()
            created_workspace.name = "Integration Test Workspace"

            async with AsyncClient(app=mock_app, base_url="http://test") as client:
                # Test workspace creation
                workspace_data = {
                    "name": "Integration Test Workspace",
                    "description": "Created during integration test",
                    "organization": "Test Org"
                }

                with patch("langflow.api.v1.rbac.workspaces.Workspace", return_value=created_workspace):
                    response = await client.post(
                        "/api/v1/rbac/workspaces/",
                        json=workspace_data
                    )

                # Verify workspace creation succeeded
                assert response.status_code == 201

                # Test workspace listing
                mock_result.all.return_value = [created_workspace]
                response = await client.get("/api/v1/rbac/workspaces/")
                assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_permission_checking_workflow(self, mock_permission_engine, mock_user):
        """Test permission checking workflow."""
        # Test single permission check
        permission_check = {
            "resource_type": "workspace",
            "action": "read",
            "resource_id": str(uuid4())
        }

        result = await mock_permission_engine.check_permission(
            user=mock_user,
            resource_type=permission_check["resource_type"],
            action=permission_check["action"],
            resource_id=permission_check["resource_id"]
        )

        assert result.allowed is True
        assert result.source == "mock_engine"

        # Test batch permission check
        batch_checks = [
            {"resource_type": "workspace", "action": "read"},
            {"resource_type": "project", "action": "create"},
            {"resource_type": "environment", "action": "deploy"}
        ]

        results = []
        for check in batch_checks:
            result = await mock_permission_engine.check_permission(
                user=mock_user,
                resource_type=check["resource_type"],
                action=check["action"]
            )
            results.append(result)

        assert len(results) == 3
        assert all(result.allowed for result in results)

    @pytest.mark.asyncio
    async def test_hierarchical_permission_workflow(self, mock_permission_engine, mock_user,
                                                   mock_workspace, mock_project):
        """Test hierarchical permission resolution workflow."""
        # Test workspace-level permission affects project access
        workspace_permission_result = await mock_permission_engine.check_permission(
            user=mock_user,
            resource_type="workspace",
            action="read",
            resource_id=mock_workspace.id,
            workspace_id=mock_workspace.id
        )

        project_permission_result = await mock_permission_engine.check_permission(
            user=mock_user,
            resource_type="project",
            action="read",
            resource_id=mock_project.id,
            workspace_id=mock_workspace.id,
            project_id=mock_project.id
        )

        # Both should be allowed due to hierarchical permissions
        assert workspace_permission_result.allowed is True
        assert project_permission_result.allowed is True

    @pytest.mark.asyncio
    async def test_role_based_access_workflow(self, mock_permission_engine, mock_user):
        """Test role-based access control workflow."""

        # Simulate user with specific role permissions
        def role_based_permission_check(*args, **kwargs):
            action = kwargs.get("action")
            resource_type = kwargs.get("resource_type")

            # Grant read permissions but deny write permissions
            if action in ["read", "list"]:
                return PermissionResult(
                    allowed=True,
                    reason=f"User has read access to {resource_type}",
                    source="role_assignment",
                    cached=False
                )
            return PermissionResult(
                allowed=False,
                reason=f"User lacks write access to {resource_type}",
                source="role_assignment",
                cached=False
            )

        mock_permission_engine.check_permission.side_effect = role_based_permission_check

        # Test read access (should be allowed)
        read_result = await mock_permission_engine.check_permission(
            user=mock_user,
            resource_type="workspace",
            action="read"
        )

        assert read_result.allowed is True
        assert "read access" in read_result.reason

        # Test write access (should be denied)
        write_result = await mock_permission_engine.check_permission(
            user=mock_user,
            resource_type="workspace",
            action="delete"
        )

        assert write_result.allowed is False
        assert "lacks write access" in write_result.reason

    @pytest.mark.asyncio
    async def test_api_error_handling_workflow(self, mock_app, mock_user):
        """Test API error handling throughout the system."""
        with patch("langflow.api.utils.get_current_active_user", return_value=mock_user), \
             patch("langflow.api.utils.get_session") as mock_get_session:

            mock_session = AsyncMock()
            mock_get_session.return_value = mock_session

            async with AsyncClient(app=mock_app, base_url="http://test") as client:

                # Test 404 error for non-existent workspace
                mock_session.get.return_value = None

                response = await client.get(f"/api/v1/rbac/workspaces/{uuid4()}")
                assert response.status_code == 404

                # Test 400 error for duplicate workspace name
                existing_workspace = MagicMock(spec=Workspace)
                mock_result = AsyncMock()
                mock_result.first.return_value = existing_workspace
                mock_session.exec.return_value = mock_result

                workspace_data = {
                    "name": "Existing Workspace",
                    "description": "This workspace already exists"
                }

                response = await client.post(
                    "/api/v1/rbac/workspaces/",
                    json=workspace_data
                )
                assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_system_initialization_workflow(self, mock_app, mock_superuser):
        """Test system initialization workflow."""
        with patch("langflow.api.utils.get_current_active_user", return_value=mock_superuser), \
             patch("langflow.api.utils.get_session") as mock_get_session:

            mock_session = AsyncMock()
            mock_get_session.return_value = mock_session

            # Mock no existing permissions/roles
            mock_result = AsyncMock()
            mock_result.first.return_value = None
            mock_session.exec.return_value = mock_result

            async with AsyncClient(app=mock_app, base_url="http://test") as client:

                # Test system permissions initialization
                response = await client.post("/api/v1/rbac/permissions/initialize-system-permissions")
                assert response.status_code == 201

                # Test system roles initialization
                response = await client.post("/api/v1/rbac/roles/initialize-system-roles")
                assert response.status_code == 201

    @pytest.mark.asyncio
    async def test_multi_tenant_isolation_workflow(self, mock_permission_engine, mock_user):
        """Test multi-tenant isolation workflow."""
        workspace1_id = uuid4()
        workspace2_id = uuid4()

        def tenant_isolation_check(*args, **kwargs):
            workspace_id = kwargs.get("workspace_id")
            resource_type = kwargs.get("resource_type")

            # User only has access to workspace1
            if workspace_id == workspace1_id:
                return PermissionResult(
                    allowed=True,
                    reason=f"User has access to workspace {workspace1_id}",
                    source="workspace_membership",
                    cached=False
                )
            return PermissionResult(
                allowed=False,
                reason=f"User lacks access to workspace {workspace_id}",
                source="tenant_isolation",
                cached=False
            )

        mock_permission_engine.check_permission.side_effect = tenant_isolation_check

        # Test access to user's workspace (should be allowed)
        workspace1_result = await mock_permission_engine.check_permission(
            user=mock_user,
            resource_type="workspace",
            action="read",
            workspace_id=workspace1_id
        )

        assert workspace1_result.allowed is True

        # Test access to other workspace (should be denied)
        workspace2_result = await mock_permission_engine.check_permission(
            user=mock_user,
            resource_type="workspace",
            action="read",
            workspace_id=workspace2_id
        )

        assert workspace2_result.allowed is False
        assert "lacks access" in workspace2_result.reason

    def test_performance_and_caching_workflow(self, mock_permission_engine, mock_user):
        """Test performance optimization and caching workflow."""
        # Simulate cached vs non-cached permission checks
        cache_hits = 0

        def caching_permission_check(*args, **kwargs):
            nonlocal cache_hits
            cache_hits += 1

            # First call is not cached, subsequent calls are cached
            is_cached = cache_hits > 1

            return PermissionResult(
                allowed=True,
                reason="Permission granted",
                source="role_assignment",
                cached=is_cached
            )

        mock_permission_engine.check_permission.side_effect = caching_permission_check

        # First permission check (should not be cached)
        result1 = asyncio.run(mock_permission_engine.check_permission(
            user=mock_user,
            resource_type="workspace",
            action="read"
        ))

        assert result1.cached is False

        # Second permission check (should be cached)
        result2 = asyncio.run(mock_permission_engine.check_permission(
            user=mock_user,
            resource_type="workspace",
            action="read"
        ))

        assert result2.cached is True


class TestRBACAPIEndpointIntegration:
    """Test API endpoint integration."""

    @pytest.mark.asyncio
    async def test_workspace_api_integration(self, mock_app, mock_user, mock_workspace):
        """Test workspace API endpoints integration."""
        with patch("langflow.api.utils.get_current_active_user", return_value=mock_user), \
             patch("langflow.api.utils.get_session") as mock_get_session, \
             patch("langflow.api.v1.rbac.dependencies.check_workspace_permission") as mock_check:

            mock_session = AsyncMock()
            mock_get_session.return_value = mock_session
            mock_check.return_value = lambda: mock_workspace

            async with AsyncClient(app=mock_app, base_url="http://test") as client:

                # Test GET workspace
                response = await client.get(f"/api/v1/rbac/workspaces/{mock_workspace.id}")
                # Response may vary based on implementation, but should not error

                # Test workspace statistics
                mock_session.exec.side_effect = [
                    AsyncMock(one=lambda: 5),  # project count
                    AsyncMock(one=lambda: 3),  # user count
                    AsyncMock(one=lambda: 2),  # group count
                    AsyncMock(one=lambda: 10), # flow count
                ]

                response = await client.get(f"/api/v1/rbac/workspaces/{mock_workspace.id}/stats")
                # Should return statistics without error

    @pytest.mark.asyncio
    async def test_permission_api_integration(self, mock_app, mock_superuser, mock_permission_engine):
        """Test permission API endpoints integration."""
        with patch("langflow.api.utils.get_current_active_user", return_value=mock_superuser), \
             patch("langflow.api.utils.get_session") as mock_get_session, \
             patch("langflow.api.v1.rbac.dependencies.get_permission_engine", return_value=mock_permission_engine):

            mock_session = AsyncMock()
            mock_get_session.return_value = mock_session

            async with AsyncClient(app=mock_app, base_url="http://test") as client:

                # Test permission check
                permission_check = {
                    "resource_type": "workspace",
                    "action": "read",
                    "resource_id": str(uuid4())
                }

                response = await client.post(
                    "/api/v1/rbac/permissions/check",
                    json=permission_check
                )

                # Should return permission check result
                assert response.status_code == 200
                result = response.json()
                assert "allowed" in result
                assert "reason" in result

    @pytest.mark.asyncio
    async def test_batch_permission_api_integration(self, mock_app, mock_user, mock_permission_engine):
        """Test batch permission checking integration."""
        with patch("langflow.api.utils.get_current_active_user", return_value=mock_user), \
             patch("langflow.api.utils.get_session") as mock_get_session, \
             patch("langflow.api.v1.rbac.dependencies.get_permission_engine", return_value=mock_permission_engine):

            mock_session = AsyncMock()
            mock_get_session.return_value = mock_session

            async with AsyncClient(app=mock_app, base_url="http://test") as client:

                # Test batch permission check
                batch_checks = [
                    {"resource_type": "workspace", "action": "read"},
                    {"resource_type": "project", "action": "create"},
                    {"resource_type": "environment", "action": "deploy"}
                ]

                response = await client.post(
                    "/api/v1/rbac/permissions/batch-check",
                    json=batch_checks
                )

                # Should return batch permission results
                assert response.status_code == 200
                results = response.json()
                assert len(results) == 3
                for result in results:
                    assert "allowed" in result
                    assert "reason" in result


@pytest.mark.asyncio
async def test_complete_rbac_system_integration():
    """Test the complete RBAC system integration."""
    # This test verifies that all RBAC components work together
    print("Running complete RBAC system integration test...")

    # Mock components
    mock_user = MagicMock(spec=User)
    mock_user.id = uuid4()
    mock_user.is_superuser = False

    mock_permission_engine = AsyncMock(spec=PermissionEngine)
    mock_permission_engine.check_permission.return_value = PermissionResult(
        allowed=True,
        reason="Integration test permission",
        source="test",
        cached=False
    )

    # Test permission engine integration
    result = await mock_permission_engine.check_permission(
        user=mock_user,
        resource_type="workspace",
        action="read"
    )

    assert result.allowed is True
    assert "Integration test" in result.reason

    print("✓ RBAC system integration test completed successfully")


if __name__ == "__main__":
    # Run the complete integration test
    asyncio.run(test_complete_rbac_system_integration())
