"""Integration tests for RBAC API endpoints.

This module tests the complete RBAC system including:
- Permission enforcement across all endpoints
- Business logic validation
- Error handling
- Authentication integration
"""

from datetime import datetime
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from httpx import AsyncClient
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.main import create_app
from langflow.services.database.models.rbac.project import Project
from langflow.services.database.models.rbac.role import Role
from langflow.services.database.models.rbac.workspace import Workspace
from langflow.services.database.models.user.model import User


@pytest.fixture
def app():
    """Create test FastAPI app."""
    return create_app()


@pytest.fixture
def client(app):
    """Create test client."""
    return TestClient(app)


@pytest.fixture
async def async_client(app):
    """Create async test client."""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac


@pytest.fixture
async def test_users(session: AsyncSession):
    """Create test users with different roles."""
    # Create superuser
    superuser = User(
        id=uuid4(),
        username="superuser",
        email="superuser@test.com",
        password="hashed_password",
        is_active=True,
        is_superuser=True
    )

    # Create regular user (workspace owner)
    owner = User(
        id=uuid4(),
        username="workspace_owner",
        email="owner@test.com",
        password="hashed_password",
        is_active=True,
        is_superuser=False
    )

    # Create regular user (member)
    member = User(
        id=uuid4(),
        username="member",
        email="member@test.com",
        password="hashed_password",
        is_active=True,
        is_superuser=False
    )

    session.add(superuser)
    session.add(owner)
    session.add(member)
    await session.commit()

    return {
        "superuser": superuser,
        "owner": owner,
        "member": member
    }


@pytest.fixture
async def test_workspace(session: AsyncSession, test_users):
    """Create test workspace."""
    workspace = Workspace(
        id=uuid4(),
        name="Test Workspace",
        description="Test workspace for integration tests",
        owner_id=test_users["owner"].id,
        organization="Test Org",
        settings={"test": True}
    )

    session.add(workspace)
    await session.commit()
    await session.refresh(workspace)

    return workspace


@pytest.fixture
async def test_project(session: AsyncSession, test_workspace):
    """Create test project."""
    project = Project(
        id=uuid4(),
        name="Test Project",
        description="Test project for integration tests",
        workspace_id=test_workspace.id,
        settings={"test": True}
    )

    session.add(project)
    await session.commit()
    await session.refresh(project)

    return project


class TestWorkspaceAPI:
    """Test workspace API endpoints."""

    async def test_create_workspace_success(self, async_client: AsyncClient, test_users):
        """Test successful workspace creation."""
        # Mock authentication for owner user
        headers = {"Authorization": f"Bearer {test_users['owner'].id}"}

        workspace_data = {
            "name": "New Workspace",
            "description": "A new test workspace",
            "organization": "Test Company"
        }

        response = await async_client.post(
            "/api/v1/rbac/workspaces/",
            json=workspace_data,
            headers=headers
        )

        assert response.status_code == 201
        data = response.json()
        assert data["name"] == workspace_data["name"]
        assert data["owner_id"] == str(test_users["owner"].id)

    async def test_create_workspace_duplicate_name(self, async_client: AsyncClient, test_users, test_workspace):
        """Test workspace creation with duplicate name fails."""
        headers = {"Authorization": f"Bearer {test_users['owner'].id}"}

        workspace_data = {
            "name": test_workspace.name,  # Duplicate name
            "description": "Another workspace",
        }

        response = await async_client.post(
            "/api/v1/rbac/workspaces/",
            json=workspace_data,
            headers=headers
        )

        assert response.status_code == 400
        assert "already exists" in response.json()["detail"]

    async def test_create_workspace_invalid_name(self, async_client: AsyncClient, test_users):
        """Test workspace creation with invalid name fails."""
        headers = {"Authorization": f"Bearer {test_users['owner'].id}"}

        workspace_data = {
            "name": "x",  # Too short
            "description": "Test workspace",
        }

        response = await async_client.post(
            "/api/v1/rbac/workspaces/",
            json=workspace_data,
            headers=headers
        )

        assert response.status_code == 400
        assert "at least 3 characters" in response.json()["detail"]

    async def test_list_workspaces_owner_access(self, async_client: AsyncClient, test_users, test_workspace):
        """Test workspace listing shows only owned workspaces."""
        headers = {"Authorization": f"Bearer {test_users['owner'].id}"}

        response = await async_client.get(
            "/api/v1/rbac/workspaces/",
            headers=headers
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 1
        assert any(w["id"] == str(test_workspace.id) for w in data)

    async def test_list_workspaces_no_access(self, async_client: AsyncClient, test_users):
        """Test workspace listing for user with no workspaces."""
        headers = {"Authorization": f"Bearer {test_users['member'].id}"}

        response = await async_client.get(
            "/api/v1/rbac/workspaces/",
            headers=headers
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 0  # Member has no workspaces

    async def test_get_workspace_success(self, async_client: AsyncClient, test_users, test_workspace):
        """Test getting workspace by ID."""
        headers = {"Authorization": f"Bearer {test_users['owner'].id}"}

        response = await async_client.get(
            f"/api/v1/rbac/workspaces/{test_workspace.id}",
            headers=headers
        )

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == str(test_workspace.id)
        assert data["name"] == test_workspace.name

    async def test_get_workspace_permission_denied(self, async_client: AsyncClient, test_users, test_workspace):
        """Test getting workspace without permission fails."""
        headers = {"Authorization": f"Bearer {test_users['member'].id}"}

        response = await async_client.get(
            f"/api/v1/rbac/workspaces/{test_workspace.id}",
            headers=headers
        )

        assert response.status_code == 403
        assert "Insufficient permissions" in response.json()["detail"]

    async def test_update_workspace_success(self, async_client: AsyncClient, test_users, test_workspace):
        """Test workspace update."""
        headers = {"Authorization": f"Bearer {test_users['owner'].id}"}

        update_data = {
            "description": "Updated description",
            "organization": "Updated Org"
        }

        response = await async_client.put(
            f"/api/v1/rbac/workspaces/{test_workspace.id}",
            json=update_data,
            headers=headers
        )

        assert response.status_code == 200
        data = response.json()
        assert data["description"] == update_data["description"]

    async def test_delete_workspace_success(self, async_client: AsyncClient, test_users, test_workspace):
        """Test workspace deletion."""
        headers = {"Authorization": f"Bearer {test_users['owner'].id}"}

        response = await async_client.delete(
            f"/api/v1/rbac/workspaces/{test_workspace.id}",
            headers=headers
        )

        assert response.status_code == 204


class TestProjectAPI:
    """Test project API endpoints."""

    async def test_create_project_success(self, async_client: AsyncClient, test_users, test_workspace):
        """Test successful project creation."""
        headers = {"Authorization": f"Bearer {test_users['owner'].id}"}

        project_data = {
            "name": "New Project",
            "description": "A new test project",
            "workspace_id": str(test_workspace.id),
            "settings": {"test": True}
        }

        response = await async_client.post(
            "/api/v1/rbac/projects/",
            json=project_data,
            headers=headers
        )

        assert response.status_code == 201
        data = response.json()
        assert data["name"] == project_data["name"]
        assert data["workspace_id"] == str(test_workspace.id)

    async def test_create_project_permission_denied(self, async_client: AsyncClient, test_users, test_workspace):
        """Test project creation without workspace permission fails."""
        headers = {"Authorization": f"Bearer {test_users['member'].id}"}

        project_data = {
            "name": "Unauthorized Project",
            "workspace_id": str(test_workspace.id)
        }

        response = await async_client.post(
            "/api/v1/rbac/projects/",
            json=project_data,
            headers=headers
        )

        assert response.status_code == 403

    async def test_list_projects_in_workspace(self, async_client: AsyncClient, test_users, test_project):
        """Test listing projects in workspace."""
        headers = {"Authorization": f"Bearer {test_users['owner'].id}"}

        response = await async_client.get(
            "/api/v1/rbac/projects/",
            params={"workspace_id": str(test_project.workspace_id)},
            headers=headers
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 1
        assert any(p["id"] == str(test_project.id) for p in data)


class TestRoleAssignmentAPI:
    """Test role assignment API endpoints."""

    async def test_create_role_assignment_success(self, async_client: AsyncClient, test_users, test_workspace):
        """Test successful role assignment creation."""
        # First create a role
        role = Role(
            id=uuid4(),
            name="Test Role",
            workspace_id=test_workspace.id,
            permissions=["workspace:read"]
        )

        headers = {"Authorization": f"Bearer {test_users['owner'].id}"}

        assignment_data = {
            "user_id": str(test_users["member"].id),
            "role_id": str(role.id),
            "workspace_id": str(test_workspace.id),
            "assignment_type": "direct",
            "scope": "workspace"
        }

        response = await async_client.post(
            "/api/v1/rbac/role-assignments/",
            json=assignment_data,
            headers=headers
        )

        assert response.status_code == 201
        data = response.json()
        assert data["user_id"] == assignment_data["user_id"]
        assert data["role_id"] == assignment_data["role_id"]

    async def test_list_role_assignments(self, async_client: AsyncClient, test_users, test_workspace):
        """Test listing role assignments in workspace."""
        headers = {"Authorization": f"Bearer {test_users['owner'].id}"}

        response = await async_client.get(
            "/api/v1/rbac/role-assignments/",
            params={"workspace_id": str(test_workspace.id)},
            headers=headers
        )

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)


class TestPermissionEnforcement:
    """Test permission enforcement across endpoints."""

    async def test_superuser_access(self, async_client: AsyncClient, test_users, test_workspace):
        """Test superuser has access to all resources."""
        headers = {"Authorization": f"Bearer {test_users['superuser'].id}"}

        # Superuser should be able to access any workspace
        response = await async_client.get(
            f"/api/v1/rbac/workspaces/{test_workspace.id}",
            headers=headers
        )

        assert response.status_code == 200

    async def test_unauthenticated_access_denied(self, async_client: AsyncClient, test_workspace):
        """Test unauthenticated requests are denied."""
        response = await async_client.get(
            f"/api/v1/rbac/workspaces/{test_workspace.id}"
        )

        assert response.status_code == 401

    async def test_permission_check_caching(self, async_client: AsyncClient, test_users, test_workspace):
        """Test permission checks are properly cached for performance."""
        headers = {"Authorization": f"Bearer {test_users['owner'].id}"}

        # Make multiple requests to same resource
        start_time = datetime.now()

        for _ in range(5):
            response = await async_client.get(
                f"/api/v1/rbac/workspaces/{test_workspace.id}",
                headers=headers
            )
            assert response.status_code == 200

        elapsed = (datetime.now() - start_time).total_seconds()

        # Should be fast due to caching (under 1 second for 5 requests)
        assert elapsed < 1.0


class TestErrorHandling:
    """Test error handling across RBAC endpoints."""

    async def test_not_found_error(self, async_client: AsyncClient, test_users):
        """Test 404 error for non-existent resources."""
        headers = {"Authorization": f"Bearer {test_users['superuser'].id}"}

        response = await async_client.get(
            f"/api/v1/rbac/workspaces/{uuid4()}",
            headers=headers
        )

        assert response.status_code == 404
        assert "not found" in response.json()["detail"]

    async def test_validation_error(self, async_client: AsyncClient, test_users):
        """Test validation error handling."""
        headers = {"Authorization": f"Bearer {test_users['owner'].id}"}

        # Invalid data (missing required fields)
        response = await async_client.post(
            "/api/v1/rbac/workspaces/",
            json={},  # Missing required name field
            headers=headers
        )

        assert response.status_code == 422  # Unprocessable Entity

    async def test_permission_denied_error_format(self, async_client: AsyncClient, test_users, test_workspace):
        """Test permission denied error includes proper details."""
        headers = {"Authorization": f"Bearer {test_users['member'].id}"}

        response = await async_client.delete(
            f"/api/v1/rbac/workspaces/{test_workspace.id}",
            headers=headers
        )

        assert response.status_code == 403
        error_detail = response.json()["detail"]
        assert "Insufficient permissions" in error_detail


class TestServiceAccountAPI:
    """Test service account API endpoints."""

    async def test_create_service_account_success(self, async_client: AsyncClient, test_users, test_workspace):
        """Test successful service account creation."""
        headers = {"Authorization": f"Bearer {test_users['owner'].id}"}

        service_account_data = {
            "name": "Test Service Account",
            "description": "A test service account",
            "workspace_id": str(test_workspace.id),
            "is_active": True
        }

        response = await async_client.post(
            "/api/v1/rbac/service-accounts/",
            json=service_account_data,
            headers=headers
        )

        assert response.status_code == 201
        data = response.json()
        assert data["name"] == service_account_data["name"]
        assert data["workspace_id"] == str(test_workspace.id)

    async def test_list_service_accounts(self, async_client: AsyncClient, test_users, test_workspace):
        """Test listing service accounts in workspace."""
        headers = {"Authorization": f"Bearer {test_users['owner'].id}"}

        response = await async_client.get(
            "/api/v1/rbac/service-accounts/",
            params={"workspace_id": str(test_workspace.id)},
            headers=headers
        )

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    async def test_service_account_permission_denied(self, async_client: AsyncClient, test_users, test_workspace):
        """Test service account access denied for non-member."""
        headers = {"Authorization": f"Bearer {test_users['member'].id}"}

        response = await async_client.get(
            "/api/v1/rbac/service-accounts/",
            params={"workspace_id": str(test_workspace.id)},
            headers=headers
        )

        assert response.status_code == 403


class TestUserGroupAPI:
    """Test user group API endpoints."""

    async def test_create_user_group_success(self, async_client: AsyncClient, test_users, test_workspace):
        """Test successful user group creation."""
        headers = {"Authorization": f"Bearer {test_users['owner'].id}"}

        group_data = {
            "name": "Test Group",
            "description": "A test user group",
            "workspace_id": str(test_workspace.id),
            "type": "manual",
            "is_active": True
        }

        response = await async_client.post(
            "/api/v1/rbac/user-groups/",
            json=group_data,
            headers=headers
        )

        assert response.status_code == 201
        data = response.json()
        assert data["name"] == group_data["name"]
        assert data["workspace_id"] == str(test_workspace.id)

    async def test_list_user_groups(self, async_client: AsyncClient, test_users, test_workspace):
        """Test listing user groups in workspace."""
        headers = {"Authorization": f"Bearer {test_users['owner'].id}"}

        response = await async_client.get(
            "/api/v1/rbac/user-groups/",
            params={"workspace_id": str(test_workspace.id)},
            headers=headers
        )

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    async def test_user_group_permission_denied(self, async_client: AsyncClient, test_users, test_workspace):
        """Test user group access denied for non-member."""
        headers = {"Authorization": f"Bearer {test_users['member'].id}"}

        response = await async_client.get(
            "/api/v1/rbac/user-groups/",
            params={"workspace_id": str(test_workspace.id)},
            headers=headers
        )

        assert response.status_code == 403


class TestAuditLogging:
    """Test audit logging functionality."""

    async def test_workspace_audit_log_creation(self, async_client: AsyncClient, test_users, test_workspace):
        """Test that workspace operations create audit logs."""
        headers = {"Authorization": f"Bearer {test_users['owner'].id}"}

        # Perform an operation that should be audited
        response = await async_client.put(
            f"/api/v1/rbac/workspaces/{test_workspace.id}",
            json={"description": "Updated for audit test"},
            headers=headers
        )

        assert response.status_code == 200

        # Check audit logs
        response = await async_client.get(
            "/api/v1/rbac/audit/logs",
            params={"workspace_id": str(test_workspace.id)},
            headers=headers
        )

        assert response.status_code == 200
        logs = response.json()

        # Should have audit log for the update operation
        assert len(logs) > 0

    async def test_role_audit_log_creation(self, async_client: AsyncClient, test_users, test_workspace):
        """Test that role operations create audit logs."""
        headers = {"Authorization": f"Bearer {test_users['owner'].id}"}

        # Create a role that should be audited
        role_data = {
            "name": "Test Audit Role",
            "description": "A role for testing audit logging",
            "workspace_id": str(test_workspace.id),
            "type": "custom",
            "permissions": ["workspace:read"]
        }

        response = await async_client.post(
            "/api/v1/rbac/roles/",
            json=role_data,
            headers=headers
        )

        assert response.status_code == 201
        role = response.json()

        # Check audit logs for role creation
        response = await async_client.get(
            "/api/v1/rbac/audit/logs",
            params={"workspace_id": str(test_workspace.id)},
            headers=headers
        )

        assert response.status_code == 200
        logs = response.json()

        # Should have audit log for the role creation
        assert len(logs) > 0
        # Check if there's a log entry for create_role action
        create_role_logs = [log for log in logs if log.get("action") == "create_role"]
        assert len(create_role_logs) > 0

    async def test_project_audit_log_creation(self, async_client: AsyncClient, test_users, test_workspace):
        """Test that project operations create audit logs."""
        headers = {"Authorization": f"Bearer {test_users['owner'].id}"}

        # Create a project that should be audited
        project_data = {
            "name": "Test Audit Project",
            "description": "A project for testing audit logging",
            "workspace_id": str(test_workspace.id)
        }

        response = await async_client.post(
            "/api/v1/rbac/projects/",
            json=project_data,
            headers=headers
        )

        assert response.status_code == 201
        project = response.json()

        # Check audit logs for project creation
        response = await async_client.get(
            "/api/v1/rbac/audit/logs",
            params={"workspace_id": str(test_workspace.id)},
            headers=headers
        )

        assert response.status_code == 200
        logs = response.json()

        # Should have audit log for the project creation
        assert len(logs) > 0
        # Check if there's a log entry for create_project action
        create_project_logs = [log for log in logs if log.get("action") == "create_project"]
        assert len(create_project_logs) > 0


class TestRoleAssignmentWorkflows:
    """Test role assignment workflows and automation."""

    async def test_project_owner_role_assignment(self, async_client: AsyncClient, test_users, test_workspace):
        """Test that project owners automatically get project admin role."""
        headers = {"Authorization": f"Bearer {test_users['owner'].id}"}

        # Create a project
        project_data = {
            "name": "Test Role Assignment Project",
            "description": "A project for testing role assignments",
            "workspace_id": str(test_workspace.id)
        }

        response = await async_client.post(
            "/api/v1/rbac/projects/",
            json=project_data,
            headers=headers
        )

        assert response.status_code == 201
        project = response.json()
        project_id = project["id"]

        # Check role assignments for the project creator
        response = await async_client.get(
            "/api/v1/rbac/role-assignments/",
            params={"workspace_id": str(test_workspace.id)},
            headers=headers
        )

        assert response.status_code == 200
        assignments = response.json()

        # Should have a project admin assignment for the creator
        project_assignments = [
            a for a in assignments
            if a.get("scope_type") == "project" and a.get("scope_id") == project_id
        ]
        assert len(project_assignments) > 0

        # Check that the assignment is for project admin role
        project_admin_assignment = project_assignments[0]
        assert project_admin_assignment["user_id"] == str(test_users["owner"].id)
        assert "admin" in project_admin_assignment.get("role_name", "").lower()

    async def test_workspace_user_listing_with_roles(self, async_client: AsyncClient, test_users, test_workspace):
        """Test that workspace user listing includes role information."""
        headers = {"Authorization": f"Bearer {test_users['owner'].id}"}

        # List users in workspace
        response = await async_client.get(
            f"/api/v1/rbac/workspaces/{test_workspace.id}/users",
            headers=headers
        )

        assert response.status_code == 200
        users = response.json()

        # Should include at least the workspace owner
        assert len(users) >= 1

        # Find the workspace owner in the list
        owner_user = next(
            (u for u in users if u["user_id"] == str(test_users["owner"].id)),
            None
        )
        assert owner_user is not None

        # Should have workspace owner role
        assert len(owner_user["roles"]) >= 1
        workspace_owner_role = next(
            (r for r in owner_user["roles"] if "owner" in r["role_name"].lower()),
            None
        )
        assert workspace_owner_role is not None
        assert workspace_owner_role["assignment_type"] == "ownership"

    async def test_workspace_access_with_role_assignments(self, async_client: AsyncClient, test_users, test_workspace):
        """Test that users with role assignments can access workspaces."""
        headers = {"Authorization": f"Bearer {test_users['owner'].id}"}

        # List workspaces as owner
        response = await async_client.get(
            "/api/v1/rbac/workspaces/",
            headers=headers
        )

        assert response.status_code == 200
        workspaces = response.json()

        # Owner should see their workspace
        owner_workspaces = [w for w in workspaces if w["id"] == str(test_workspace.id)]
        assert len(owner_workspaces) == 1

        # Test that members without role assignments don't see the workspace
        member_headers = {"Authorization": f"Bearer {test_users['member'].id}"}
        response = await async_client.get(
            "/api/v1/rbac/workspaces/",
            headers=member_headers
        )

        assert response.status_code == 200
        member_workspaces = response.json()

        # Member should not see the workspace (no role assignments yet)
        member_workspace_access = [w for w in member_workspaces if w["id"] == str(test_workspace.id)]
        assert len(member_workspace_access) == 0


@pytest.mark.integration
class TestEndToEndWorkflows:
    """Test complete end-to-end workflows."""

    async def test_complete_workspace_lifecycle(self, async_client: AsyncClient, test_users):
        """Test complete workspace creation, usage, and deletion workflow."""
        headers = {"Authorization": f"Bearer {test_users['owner'].id}"}

        # 1. Create workspace
        workspace_data = {
            "name": "E2E Test Workspace",
            "description": "End-to-end test workspace"
        }

        response = await async_client.post(
            "/api/v1/rbac/workspaces/",
            json=workspace_data,
            headers=headers
        )
        assert response.status_code == 201
        workspace = response.json()
        workspace_id = workspace["id"]

        # 2. Create project in workspace
        project_data = {
            "name": "E2E Test Project",
            "workspace_id": workspace_id
        }

        response = await async_client.post(
            "/api/v1/rbac/projects/",
            json=project_data,
            headers=headers
        )
        assert response.status_code == 201
        project = response.json()

        # 3. List projects in workspace
        response = await async_client.get(
            "/api/v1/rbac/projects/",
            params={"workspace_id": workspace_id},
            headers=headers
        )
        assert response.status_code == 200
        projects = response.json()
        assert len(projects) >= 1

        # 4. Delete workspace (should cascade delete projects)
        response = await async_client.delete(
            f"/api/v1/rbac/workspaces/{workspace_id}",
            headers=headers
        )
        assert response.status_code == 204

    async def test_role_assignment_workflow(self, async_client: AsyncClient, test_users, test_workspace):
        """Test complete role assignment workflow."""
        owner_headers = {"Authorization": f"Bearer {test_users['owner'].id}"}
        member_headers = {"Authorization": f"Bearer {test_users['member'].id}"}

        # 1. Member initially can't access workspace
        response = await async_client.get(
            f"/api/v1/rbac/workspaces/{test_workspace.id}",
            headers=member_headers
        )
        assert response.status_code == 403

        # 2. Owner creates role assignment for member
        # (This would need a role to exist first)

        # 3. Member can now access workspace (after role assignment)
        # This would be tested after implementing the role assignment

        # 4. Owner removes role assignment
        # Member loses access again


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])
