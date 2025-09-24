"""Tests for RBAC workspaces API endpoints."""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import status
from httpx import AsyncClient


class TestWorkspacesAPI:
    """Test workspace API endpoints."""

    @pytest.mark.asyncio
    async def test_create_workspace_success(self, client: AsyncClient, logged_in_headers):
        """Test successful workspace creation."""
        workspace_data = {
            "name": "Test Workspace",
            "description": "A test workspace for RBAC",
            "organization": "Test Organization",
            "settings": {
                "sso_enabled": False,
                "max_projects": 50
            },
            "metadata": {
                "department": "engineering",
                "environment": "test"
            },
            "tags": ["test", "development"]
        }

        response = await client.post(
            "/api/v1/rbac/workspaces/",
            json=workspace_data,
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_201_CREATED
        result = response.json()

        # Verify response structure
        assert "id" in result
        assert result["name"] == workspace_data["name"]
        assert result["description"] == workspace_data["description"]
        assert result["organization"] == workspace_data["organization"]
        assert result["settings"]["sso_enabled"] is False
        assert result["settings"]["max_projects"] == 50
        assert result["metadata"]["department"] == "engineering"
        assert result["tags"] == ["test", "development"]
        assert result["is_active"] is True
        assert result["is_deleted"] is False
        assert "owner_id" in result
        assert "created_at" in result
        assert "updated_at" in result

    @pytest.mark.asyncio
    async def test_create_workspace_minimal(self, client: AsyncClient, logged_in_headers):
        """Test workspace creation with minimal required data."""
        workspace_data = {
            "name": "Minimal Workspace"
        }

        response = await client.post(
            "/api/v1/rbac/workspaces/",
            json=workspace_data,
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_201_CREATED
        result = response.json()

        assert result["name"] == "Minimal Workspace"
        assert result["description"] is None
        assert result["organization"] is None
        assert isinstance(result["settings"], dict)
        assert result["metadata"] == {}
        assert result["tags"] == []

    @pytest.mark.asyncio
    async def test_create_workspace_duplicate_name(self, client: AsyncClient, logged_in_headers):
        """Test workspace creation with duplicate name fails."""
        workspace_data = {
            "name": "Duplicate Workspace"
        }

        # Create first workspace
        response1 = await client.post(
            "/api/v1/rbac/workspaces/",
            json=workspace_data,
            headers=logged_in_headers
        )
        assert response1.status_code == status.HTTP_201_CREATED

        # Try to create workspace with same name
        response2 = await client.post(
            "/api/v1/rbac/workspaces/",
            json=workspace_data,
            headers=logged_in_headers
        )
        assert response2.status_code == status.HTTP_400_BAD_REQUEST
        assert "already exists" in response2.json()["detail"]

    @pytest.mark.asyncio
    async def test_create_workspace_invalid_data(self, client: AsyncClient, logged_in_headers):
        """Test workspace creation with invalid data."""
        # Empty name
        response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": ""},
            headers=logged_in_headers
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

        # Missing name
        response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"description": "No name provided"},
            headers=logged_in_headers
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_create_workspace_unauthorized(self, client: AsyncClient):
        """Test workspace creation without authentication."""
        workspace_data = {
            "name": "Unauthorized Workspace"
        }

        response = await client.post(
            "/api/v1/rbac/workspaces/",
            json=workspace_data
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_list_workspaces_success(self, client: AsyncClient, logged_in_headers):
        """Test successful workspace listing."""
        # Create test workspaces
        workspace_names = ["Workspace 1", "Workspace 2", "Workspace 3"]
        created_workspaces = []

        for name in workspace_names:
            response = await client.post(
                "/api/v1/rbac/workspaces/",
                json={"name": name},
                headers=logged_in_headers
            )
            assert response.status_code == status.HTTP_201_CREATED
            created_workspaces.append(response.json())

        # List workspaces
        response = await client.get(
            "/api/v1/rbac/workspaces/",
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_200_OK
        result = response.json()

        assert isinstance(result, list)
        assert len(result) >= len(workspace_names)

        # Verify created workspaces are in the list
        result_names = [workspace["name"] for workspace in result]
        for name in workspace_names:
            assert name in result_names

    @pytest.mark.asyncio
    async def test_list_workspaces_with_pagination(self, client: AsyncClient, logged_in_headers):
        """Test workspace listing with pagination."""
        response = await client.get(
            "/api/v1/rbac/workspaces/?skip=0&limit=5",
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_200_OK
        result = response.json()
        assert isinstance(result, list)
        assert len(result) <= 5

    @pytest.mark.asyncio
    async def test_list_workspaces_with_search(self, client: AsyncClient, logged_in_headers):
        """Test workspace listing with search filter."""
        # Create workspace with specific name
        await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Searchable Workspace", "description": "This is searchable"},
            headers=logged_in_headers
        )

        # Search by name
        response = await client.get(
            "/api/v1/rbac/workspaces/?search=Searchable",
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_200_OK
        result = response.json()
        assert len(result) >= 1
        assert any("Searchable" in workspace["name"] for workspace in result)

    @pytest.mark.asyncio
    async def test_list_workspaces_with_organization_filter(self, client: AsyncClient, logged_in_headers):
        """Test workspace listing with organization filter."""
        # Create workspace with specific organization
        await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Org Workspace", "organization": "Test Corp"},
            headers=logged_in_headers
        )

        # Filter by organization
        response = await client.get(
            "/api/v1/rbac/workspaces/?organization=Test Corp",
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_200_OK
        result = response.json()
        assert all(workspace["organization"] == "Test Corp" for workspace in result if workspace["organization"])

    @pytest.mark.asyncio
    async def test_list_workspaces_unauthorized(self, client: AsyncClient):
        """Test workspace listing without authentication."""
        response = await client.get("/api/v1/rbac/workspaces/")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_get_workspace_success(self, client: AsyncClient, logged_in_headers):
        """Test successful workspace retrieval."""
        # Create workspace
        create_response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Get Test Workspace"},
            headers=logged_in_headers
        )
        assert create_response.status_code == status.HTTP_201_CREATED
        workspace = create_response.json()
        workspace_id = workspace["id"]

        # Get workspace
        response = await client.get(
            f"/api/v1/rbac/workspaces/{workspace_id}",
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_200_OK
        result = response.json()

        assert result["id"] == workspace_id
        assert result["name"] == "Get Test Workspace"
        assert "owner_id" in result
        assert "created_at" in result
        assert "updated_at" in result

    @pytest.mark.asyncio
    async def test_get_workspace_not_found(self, client: AsyncClient, logged_in_headers):
        """Test workspace retrieval with non-existent ID."""
        non_existent_id = str(uuid4())

        response = await client.get(
            f"/api/v1/rbac/workspaces/{non_existent_id}",
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.asyncio
    async def test_get_workspace_invalid_id(self, client: AsyncClient, logged_in_headers):
        """Test workspace retrieval with invalid ID format."""
        response = await client.get(
            "/api/v1/rbac/workspaces/invalid-uuid",
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_update_workspace_success(self, client: AsyncClient, logged_in_headers):
        """Test successful workspace update."""
        # Create workspace
        create_response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Original Workspace", "description": "Original description"},
            headers=logged_in_headers
        )
        assert create_response.status_code == status.HTTP_201_CREATED
        workspace = create_response.json()
        workspace_id = workspace["id"]

        # Update workspace
        update_data = {
            "name": "Updated Workspace",
            "description": "Updated description",
            "organization": "Updated Organization",
            "settings": {
                "sso_enabled": True,
                "max_projects": 100
            },
            "metadata": {
                "updated": True
            },
            "tags": ["updated"]
        }

        response = await client.put(
            f"/api/v1/rbac/workspaces/{workspace_id}",
            json=update_data,
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_200_OK
        result = response.json()

        assert result["id"] == workspace_id
        assert result["name"] == "Updated Workspace"
        assert result["description"] == "Updated description"
        assert result["organization"] == "Updated Organization"
        assert result["settings"]["sso_enabled"] is True
        assert result["settings"]["max_projects"] == 100
        assert result["metadata"]["updated"] is True
        assert result["tags"] == ["updated"]
        assert result["updated_at"] != workspace["updated_at"]

    @pytest.mark.asyncio
    async def test_update_workspace_partial(self, client: AsyncClient, logged_in_headers):
        """Test partial workspace update."""
        # Create workspace
        create_response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Partial Update Workspace", "description": "Original"},
            headers=logged_in_headers
        )
        assert create_response.status_code == status.HTTP_201_CREATED
        workspace = create_response.json()
        workspace_id = workspace["id"]

        # Update only name
        response = await client.put(
            f"/api/v1/rbac/workspaces/{workspace_id}",
            json={"name": "Partially Updated"},
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_200_OK
        result = response.json()

        assert result["name"] == "Partially Updated"
        assert result["description"] == "Original"  # Should remain unchanged

    @pytest.mark.asyncio
    async def test_update_workspace_duplicate_name(self, client: AsyncClient, logged_in_headers):
        """Test workspace update with duplicate name fails."""
        # Create first workspace
        create_response1 = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "First Workspace"},
            headers=logged_in_headers
        )
        assert create_response1.status_code == status.HTTP_201_CREATED

        # Create second workspace
        create_response2 = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Second Workspace"},
            headers=logged_in_headers
        )
        assert create_response2.status_code == status.HTTP_201_CREATED
        workspace2 = create_response2.json()
        workspace2_id = workspace2["id"]

        # Try to update second workspace to have same name as first
        response = await client.put(
            f"/api/v1/rbac/workspaces/{workspace2_id}",
            json={"name": "First Workspace"},
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "already exists" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_delete_workspace_success(self, client: AsyncClient, logged_in_headers):
        """Test successful workspace deletion (soft delete)."""
        # Create workspace
        create_response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Delete Test Workspace"},
            headers=logged_in_headers
        )
        assert create_response.status_code == status.HTTP_201_CREATED
        workspace = create_response.json()
        workspace_id = workspace["id"]

        # Delete workspace
        response = await client.delete(
            f"/api/v1/rbac/workspaces/{workspace_id}",
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_204_NO_CONTENT

        # Verify workspace is soft deleted (should not appear in normal listing)
        list_response = await client.get(
            "/api/v1/rbac/workspaces/",
            headers=logged_in_headers
        )
        assert list_response.status_code == status.HTTP_200_OK
        workspaces = list_response.json()
        workspace_ids = [ws["id"] for ws in workspaces]
        assert workspace_id not in workspace_ids

    @pytest.mark.asyncio
    async def test_delete_workspace_not_found(self, client: AsyncClient, logged_in_headers):
        """Test workspace deletion with non-existent ID."""
        non_existent_id = str(uuid4())

        response = await client.delete(
            f"/api/v1/rbac/workspaces/{non_existent_id}",
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND


class TestWorkspaceInvitations:
    """Test workspace invitation endpoints."""

    @pytest.mark.asyncio
    async def test_invite_user_success(self, client: AsyncClient, logged_in_headers):
        """Test successful user invitation to workspace."""
        # Create workspace
        create_response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Invitation Test Workspace"},
            headers=logged_in_headers
        )
        assert create_response.status_code == status.HTTP_201_CREATED
        workspace = create_response.json()
        workspace_id = workspace["id"]

        # Invite user
        invitation_data = {
            "email": "newuser@example.com",
            "role_id": str(uuid4())  # Would be a valid role ID in real scenario
        }

        response = await client.post(
            f"/api/v1/rbac/workspaces/{workspace_id}/invite",
            json=invitation_data,
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_200_OK
        result = response.json()

        assert "message" in result
        assert "invitation_id" in result
        assert "expires_at" in result
        assert result["message"] == "Invitation sent successfully"

    @pytest.mark.asyncio
    async def test_invite_user_missing_email(self, client: AsyncClient, logged_in_headers):
        """Test user invitation without email fails."""
        # Create workspace
        create_response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Invitation Test Workspace"},
            headers=logged_in_headers
        )
        assert create_response.status_code == status.HTTP_201_CREATED
        workspace = create_response.json()
        workspace_id = workspace["id"]

        # Try to invite without email
        response = await client.post(
            f"/api/v1/rbac/workspaces/{workspace_id}/invite",
            json={"role_id": str(uuid4())},
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Email is required" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_invite_user_duplicate_invitation(self, client: AsyncClient, logged_in_headers):
        """Test duplicate invitation to same user fails."""
        # Create workspace
        create_response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Invitation Test Workspace"},
            headers=logged_in_headers
        )
        assert create_response.status_code == status.HTTP_201_CREATED
        workspace = create_response.json()
        workspace_id = workspace["id"]

        invitation_data = {
            "email": "duplicate@example.com",
            "role_id": str(uuid4())
        }

        # First invitation
        response1 = await client.post(
            f"/api/v1/rbac/workspaces/{workspace_id}/invite",
            json=invitation_data,
            headers=logged_in_headers
        )
        assert response1.status_code == status.HTTP_200_OK

        # Duplicate invitation
        response2 = await client.post(
            f"/api/v1/rbac/workspaces/{workspace_id}/invite",
            json=invitation_data,
            headers=logged_in_headers
        )
        assert response2.status_code == status.HTTP_400_BAD_REQUEST
        assert "pending invitation" in response2.json()["detail"]


class TestWorkspaceUsers:
    """Test workspace user management endpoints."""

    @pytest.mark.asyncio
    async def test_list_workspace_users(self, client: AsyncClient, logged_in_headers):
        """Test listing users in workspace."""
        # Create workspace
        create_response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Users Test Workspace"},
            headers=logged_in_headers
        )
        assert create_response.status_code == status.HTTP_201_CREATED
        workspace = create_response.json()
        workspace_id = workspace["id"]

        # List users
        response = await client.get(
            f"/api/v1/rbac/workspaces/{workspace_id}/users",
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_200_OK
        result = response.json()

        assert isinstance(result, list)
        assert len(result) >= 1  # At least the owner

        # Verify owner is in the list
        user = result[0]
        assert "user_id" in user
        assert "username" in user
        assert "roles" in user
        assert "joined_at" in user
        assert "is_active" in user
        assert "workspace_owner" in user["roles"]


class TestWorkspaceProjects:
    """Test workspace project management endpoints."""

    @pytest.mark.asyncio
    async def test_list_workspace_projects(self, client: AsyncClient, logged_in_headers):
        """Test listing projects in workspace."""
        # Create workspace
        create_response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Projects Test Workspace"},
            headers=logged_in_headers
        )
        assert create_response.status_code == status.HTTP_201_CREATED
        workspace = create_response.json()
        workspace_id = workspace["id"]

        # List projects
        response = await client.get(
            f"/api/v1/rbac/workspaces/{workspace_id}/projects",
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_200_OK
        result = response.json()

        assert isinstance(result, list)
        # May be empty if no projects created yet


class TestWorkspaceStatistics:
    """Test workspace statistics endpoints."""

    @pytest.mark.asyncio
    async def test_get_workspace_statistics(self, client: AsyncClient, logged_in_headers):
        """Test getting workspace statistics."""
        # Create workspace
        create_response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Stats Test Workspace"},
            headers=logged_in_headers
        )
        assert create_response.status_code == status.HTTP_201_CREATED
        workspace = create_response.json()
        workspace_id = workspace["id"]

        # Get statistics
        response = await client.get(
            f"/api/v1/rbac/workspaces/{workspace_id}/stats",
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_200_OK
        result = response.json()

        assert "workspace_id" in result
        assert "project_count" in result
        assert "user_count" in result
        assert "group_count" in result
        assert "flow_count" in result
        assert "created_at" in result
        assert "last_updated" in result

        assert result["workspace_id"] == workspace_id
        assert isinstance(result["project_count"], int)
        assert isinstance(result["user_count"], int)
        assert isinstance(result["group_count"], int)
        assert isinstance(result["flow_count"], int)
        assert result["user_count"] >= 1  # At least the owner
