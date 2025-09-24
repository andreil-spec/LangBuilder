"""Tests for RBAC roles API endpoints."""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import status
from httpx import AsyncClient
from langflow.services.database.models.rbac.role import RoleType


class TestRolesAPI:
    """Test role API endpoints."""

    @pytest.mark.asyncio
    async def test_create_role_success(self, client: AsyncClient, logged_in_headers):
        """Test successful role creation."""
        # First create a workspace
        workspace_response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Role Test Workspace"},
            headers=logged_in_headers
        )
        assert workspace_response.status_code == status.HTTP_201_CREATED
        workspace = workspace_response.json()
        workspace_id = workspace["id"]

        # Create role
        role_data = {
            "name": "Test Role",
            "description": "A test role for RBAC",
            "role_type": RoleType.CUSTOM.value,
            "is_system": False,
            "is_immutable": False,
            "metadata": {
                "department": "engineering",
                "level": "intermediate"
            },
            "tags": ["test", "custom"]
        }

        response = await client.post(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/",
            json=role_data,
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_201_CREATED
        result = response.json()

        # Verify response structure
        assert "id" in result
        assert result["name"] == role_data["name"]
        assert result["description"] == role_data["description"]
        assert result["role_type"] == role_data["role_type"]
        assert result["is_system"] == role_data["is_system"]
        assert result["is_immutable"] == role_data["is_immutable"]
        assert result["metadata"]["department"] == "engineering"
        assert result["tags"] == ["test", "custom"]
        assert result["is_active"] is True
        assert result["workspace_id"] == workspace_id
        assert "created_by_id" in result
        assert "created_at" in result
        assert "updated_at" in result

    @pytest.mark.asyncio
    async def test_create_role_minimal(self, client: AsyncClient, logged_in_headers):
        """Test role creation with minimal required data."""
        # Create workspace
        workspace_response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Minimal Role Workspace"},
            headers=logged_in_headers
        )
        assert workspace_response.status_code == status.HTTP_201_CREATED
        workspace = workspace_response.json()
        workspace_id = workspace["id"]

        role_data = {
            "name": "Minimal Role"
        }

        response = await client.post(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/",
            json=role_data,
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_201_CREATED
        result = response.json()

        assert result["name"] == "Minimal Role"
        assert result["description"] is None
        assert result["role_type"] == RoleType.CUSTOM.value  # Default
        assert result["is_system"] is False  # Default
        assert result["is_immutable"] is False  # Default
        assert result["metadata"] == {}
        assert result["tags"] == []

    @pytest.mark.asyncio
    async def test_create_role_duplicate_name(self, client: AsyncClient, logged_in_headers):
        """Test role creation with duplicate name fails."""
        # Create workspace
        workspace_response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Duplicate Role Workspace"},
            headers=logged_in_headers
        )
        assert workspace_response.status_code == status.HTTP_201_CREATED
        workspace = workspace_response.json()
        workspace_id = workspace["id"]

        role_data = {
            "name": "Duplicate Role"
        }

        # Create first role
        response1 = await client.post(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/",
            json=role_data,
            headers=logged_in_headers
        )
        assert response1.status_code == status.HTTP_201_CREATED

        # Try to create role with same name
        response2 = await client.post(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/",
            json=role_data,
            headers=logged_in_headers
        )
        assert response2.status_code == status.HTTP_400_BAD_REQUEST
        assert "already exists" in response2.json()["detail"]

    @pytest.mark.asyncio
    async def test_create_role_invalid_data(self, client: AsyncClient, logged_in_headers):
        """Test role creation with invalid data."""
        # Create workspace
        workspace_response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Invalid Role Workspace"},
            headers=logged_in_headers
        )
        assert workspace_response.status_code == status.HTTP_201_CREATED
        workspace = workspace_response.json()
        workspace_id = workspace["id"]

        # Empty name
        response = await client.post(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/",
            json={"name": ""},
            headers=logged_in_headers
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

        # Missing name
        response = await client.post(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/",
            json={"description": "No name provided"},
            headers=logged_in_headers
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_create_role_unauthorized(self, client: AsyncClient):
        """Test role creation without authentication."""
        workspace_id = str(uuid4())
        role_data = {
            "name": "Unauthorized Role"
        }

        response = await client.post(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/",
            json=role_data
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_list_roles_success(self, client: AsyncClient, logged_in_headers):
        """Test successful role listing."""
        # Create workspace
        workspace_response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "List Roles Workspace"},
            headers=logged_in_headers
        )
        assert workspace_response.status_code == status.HTTP_201_CREATED
        workspace = workspace_response.json()
        workspace_id = workspace["id"]

        # Create test roles
        role_names = ["Role 1", "Role 2", "Role 3"]
        created_roles = []

        for name in role_names:
            response = await client.post(
                f"/api/v1/rbac/workspaces/{workspace_id}/roles/",
                json={"name": name},
                headers=logged_in_headers
            )
            assert response.status_code == status.HTTP_201_CREATED
            created_roles.append(response.json())

        # List roles
        response = await client.get(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/",
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_200_OK
        result = response.json()

        assert isinstance(result, list)
        assert len(result) >= len(role_names)

        # Verify created roles are in the list
        result_names = [role["name"] for role in result]
        for name in role_names:
            assert name in result_names

    @pytest.mark.asyncio
    async def test_list_roles_with_pagination(self, client: AsyncClient, logged_in_headers):
        """Test role listing with pagination."""
        # Create workspace
        workspace_response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Pagination Workspace"},
            headers=logged_in_headers
        )
        assert workspace_response.status_code == status.HTTP_201_CREATED
        workspace = workspace_response.json()
        workspace_id = workspace["id"]

        response = await client.get(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/?skip=0&limit=5",
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_200_OK
        result = response.json()
        assert isinstance(result, list)
        assert len(result) <= 5

    @pytest.mark.asyncio
    async def test_list_roles_with_filters(self, client: AsyncClient, logged_in_headers):
        """Test role listing with filters."""
        # Create workspace
        workspace_response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Filter Workspace"},
            headers=logged_in_headers
        )
        assert workspace_response.status_code == status.HTTP_201_CREATED
        workspace = workspace_response.json()
        workspace_id = workspace["id"]

        # Create roles with different types
        await client.post(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/",
            json={"name": "System Role", "role_type": RoleType.SYSTEM.value, "is_system": True},
            headers=logged_in_headers
        )

        await client.post(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/",
            json={"name": "Custom Role", "role_type": RoleType.CUSTOM.value},
            headers=logged_in_headers
        )

        # Filter by role type
        response = await client.get(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/?role_type={RoleType.SYSTEM.value}",
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_200_OK
        result = response.json()
        assert all(role["role_type"] == RoleType.SYSTEM.value for role in result)

        # Filter by is_system
        response = await client.get(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/?is_system=true",
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_200_OK
        result = response.json()
        assert all(role["is_system"] is True for role in result)

    @pytest.mark.asyncio
    async def test_get_role_success(self, client: AsyncClient, logged_in_headers):
        """Test successful role retrieval."""
        # Create workspace
        workspace_response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Get Role Workspace"},
            headers=logged_in_headers
        )
        assert workspace_response.status_code == status.HTTP_201_CREATED
        workspace = workspace_response.json()
        workspace_id = workspace["id"]

        # Create role
        create_response = await client.post(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/",
            json={"name": "Get Test Role", "description": "Role for testing get endpoint"},
            headers=logged_in_headers
        )
        assert create_response.status_code == status.HTTP_201_CREATED
        role = create_response.json()
        role_id = role["id"]

        # Get role
        response = await client.get(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/{role_id}",
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_200_OK
        result = response.json()

        assert result["id"] == role_id
        assert result["name"] == "Get Test Role"
        assert result["description"] == "Role for testing get endpoint"
        assert result["workspace_id"] == workspace_id
        assert "created_by_id" in result
        assert "created_at" in result
        assert "updated_at" in result

    @pytest.mark.asyncio
    async def test_get_role_not_found(self, client: AsyncClient, logged_in_headers):
        """Test role retrieval with non-existent ID."""
        # Create workspace
        workspace_response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Not Found Workspace"},
            headers=logged_in_headers
        )
        assert workspace_response.status_code == status.HTTP_201_CREATED
        workspace = workspace_response.json()
        workspace_id = workspace["id"]

        non_existent_id = str(uuid4())

        response = await client.get(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/{non_existent_id}",
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.asyncio
    async def test_update_role_success(self, client: AsyncClient, logged_in_headers):
        """Test successful role update."""
        # Create workspace
        workspace_response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Update Role Workspace"},
            headers=logged_in_headers
        )
        assert workspace_response.status_code == status.HTTP_201_CREATED
        workspace = workspace_response.json()
        workspace_id = workspace["id"]

        # Create role
        create_response = await client.post(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/",
            json={"name": "Original Role", "description": "Original description"},
            headers=logged_in_headers
        )
        assert create_response.status_code == status.HTTP_201_CREATED
        role = create_response.json()
        role_id = role["id"]

        # Update role
        update_data = {
            "name": "Updated Role",
            "description": "Updated description",
            "role_type": RoleType.WORKSPACE.value,
            "metadata": {
                "updated": True,
                "version": "2.0"
            },
            "tags": ["updated", "v2"]
        }

        response = await client.put(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/{role_id}",
            json=update_data,
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_200_OK
        result = response.json()

        assert result["id"] == role_id
        assert result["name"] == "Updated Role"
        assert result["description"] == "Updated description"
        assert result["role_type"] == RoleType.WORKSPACE.value
        assert result["metadata"]["updated"] is True
        assert result["metadata"]["version"] == "2.0"
        assert result["tags"] == ["updated", "v2"]
        assert result["updated_at"] != role["updated_at"]

    @pytest.mark.asyncio
    async def test_update_role_partial(self, client: AsyncClient, logged_in_headers):
        """Test partial role update."""
        # Create workspace
        workspace_response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Partial Update Workspace"},
            headers=logged_in_headers
        )
        assert workspace_response.status_code == status.HTTP_201_CREATED
        workspace = workspace_response.json()
        workspace_id = workspace["id"]

        # Create role
        create_response = await client.post(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/",
            json={"name": "Partial Update Role", "description": "Original"},
            headers=logged_in_headers
        )
        assert create_response.status_code == status.HTTP_201_CREATED
        role = create_response.json()
        role_id = role["id"]

        # Update only name
        response = await client.put(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/{role_id}",
            json={"name": "Partially Updated"},
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_200_OK
        result = response.json()

        assert result["name"] == "Partially Updated"
        assert result["description"] == "Original"  # Should remain unchanged

    @pytest.mark.asyncio
    async def test_update_role_duplicate_name(self, client: AsyncClient, logged_in_headers):
        """Test role update with duplicate name fails."""
        # Create workspace
        workspace_response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Duplicate Update Workspace"},
            headers=logged_in_headers
        )
        assert workspace_response.status_code == status.HTTP_201_CREATED
        workspace = workspace_response.json()
        workspace_id = workspace["id"]

        # Create first role
        create_response1 = await client.post(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/",
            json={"name": "First Role"},
            headers=logged_in_headers
        )
        assert create_response1.status_code == status.HTTP_201_CREATED

        # Create second role
        create_response2 = await client.post(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/",
            json={"name": "Second Role"},
            headers=logged_in_headers
        )
        assert create_response2.status_code == status.HTTP_201_CREATED
        role2 = create_response2.json()
        role2_id = role2["id"]

        # Try to update second role to have same name as first
        response = await client.put(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/{role2_id}",
            json={"name": "First Role"},
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "already exists" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_update_immutable_role_fails(self, client: AsyncClient, logged_in_headers):
        """Test updating immutable role fails."""
        # Create workspace
        workspace_response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Immutable Role Workspace"},
            headers=logged_in_headers
        )
        assert workspace_response.status_code == status.HTTP_201_CREATED
        workspace = workspace_response.json()
        workspace_id = workspace["id"]

        # Create immutable role
        create_response = await client.post(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/",
            json={"name": "Immutable Role", "is_immutable": True},
            headers=logged_in_headers
        )
        assert create_response.status_code == status.HTTP_201_CREATED
        role = create_response.json()
        role_id = role["id"]

        # Try to update immutable role
        response = await client.put(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/{role_id}",
            json={"name": "Updated Immutable Role"},
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "immutable" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_delete_role_success(self, client: AsyncClient, logged_in_headers):
        """Test successful role deletion."""
        # Create workspace
        workspace_response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Delete Role Workspace"},
            headers=logged_in_headers
        )
        assert workspace_response.status_code == status.HTTP_201_CREATED
        workspace = workspace_response.json()
        workspace_id = workspace["id"]

        # Create role
        create_response = await client.post(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/",
            json={"name": "Delete Test Role"},
            headers=logged_in_headers
        )
        assert create_response.status_code == status.HTTP_201_CREATED
        role = create_response.json()
        role_id = role["id"]

        # Delete role
        response = await client.delete(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/{role_id}",
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_204_NO_CONTENT

        # Verify role is deleted (should not appear in listing)
        list_response = await client.get(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/",
            headers=logged_in_headers
        )
        assert list_response.status_code == status.HTTP_200_OK
        roles = list_response.json()
        role_ids = [r["id"] for r in roles]
        assert role_id not in role_ids

    @pytest.mark.asyncio
    async def test_delete_role_not_found(self, client: AsyncClient, logged_in_headers):
        """Test role deletion with non-existent ID."""
        # Create workspace
        workspace_response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Delete Not Found Workspace"},
            headers=logged_in_headers
        )
        assert workspace_response.status_code == status.HTTP_201_CREATED
        workspace = workspace_response.json()
        workspace_id = workspace["id"]

        non_existent_id = str(uuid4())

        response = await client.delete(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/{non_existent_id}",
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.asyncio
    async def test_delete_immutable_role_fails(self, client: AsyncClient, logged_in_headers):
        """Test deleting immutable role fails."""
        # Create workspace
        workspace_response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Delete Immutable Workspace"},
            headers=logged_in_headers
        )
        assert workspace_response.status_code == status.HTTP_201_CREATED
        workspace = workspace_response.json()
        workspace_id = workspace["id"]

        # Create immutable role
        create_response = await client.post(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/",
            json={"name": "Immutable Delete Role", "is_immutable": True},
            headers=logged_in_headers
        )
        assert create_response.status_code == status.HTTP_201_CREATED
        role = create_response.json()
        role_id = role["id"]

        # Try to delete immutable role
        response = await client.delete(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/{role_id}",
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "immutable" in response.json()["detail"].lower()


class TestRolePermissions:
    """Test role permission management endpoints."""

    @pytest.mark.asyncio
    async def test_list_role_permissions(self, client: AsyncClient, logged_in_headers):
        """Test listing permissions for a role."""
        # Create workspace
        workspace_response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Role Permissions Workspace"},
            headers=logged_in_headers
        )
        assert workspace_response.status_code == status.HTTP_201_CREATED
        workspace = workspace_response.json()
        workspace_id = workspace["id"]

        # Create role
        create_response = await client.post(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/",
            json={"name": "Permissions Test Role"},
            headers=logged_in_headers
        )
        assert create_response.status_code == status.HTTP_201_CREATED
        role = create_response.json()
        role_id = role["id"]

        # List role permissions
        response = await client.get(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/{role_id}/permissions",
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_200_OK
        result = response.json()

        assert isinstance(result, list)
        # May be empty if no permissions assigned yet

    @pytest.mark.asyncio
    async def test_assign_permission_to_role(self, client: AsyncClient, logged_in_headers):
        """Test assigning permission to role."""
        # Create workspace
        workspace_response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Assign Permission Workspace"},
            headers=logged_in_headers
        )
        assert workspace_response.status_code == status.HTTP_201_CREATED
        workspace = workspace_response.json()
        workspace_id = workspace["id"]

        # Create role
        role_response = await client.post(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/",
            json={"name": "Permission Assignment Role"},
            headers=logged_in_headers
        )
        assert role_response.status_code == status.HTTP_201_CREATED
        role = role_response.json()
        role_id = role["id"]

        # Create permission (this would typically exist in the system)
        permission_response = await client.post(
            f"/api/v1/rbac/workspaces/{workspace_id}/permissions/",
            json={
                "code": "workspace:read",
                "name": "Read Workspace",
                "resource_type": "workspace",
                "action": "read"
            },
            headers=logged_in_headers
        )
        assert permission_response.status_code == status.HTTP_201_CREATED
        permission = permission_response.json()
        permission_id = permission["id"]

        # Assign permission to role
        assignment_data = {
            "permission_id": permission_id,
            "is_granted": True
        }

        response = await client.post(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/{role_id}/permissions",
            json=assignment_data,
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_201_CREATED
        result = response.json()

        assert result["permission_id"] == permission_id
        assert result["is_granted"] is True
        assert "granted_at" in result

    @pytest.mark.asyncio
    async def test_revoke_permission_from_role(self, client: AsyncClient, logged_in_headers):
        """Test revoking permission from role."""
        # Create workspace
        workspace_response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Revoke Permission Workspace"},
            headers=logged_in_headers
        )
        assert workspace_response.status_code == status.HTTP_201_CREATED
        workspace = workspace_response.json()
        workspace_id = workspace["id"]

        # Create role
        role_response = await client.post(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/",
            json={"name": "Permission Revocation Role"},
            headers=logged_in_headers
        )
        assert role_response.status_code == status.HTTP_201_CREATED
        role = role_response.json()
        role_id = role["id"]

        # Create permission
        permission_response = await client.post(
            f"/api/v1/rbac/workspaces/{workspace_id}/permissions/",
            json={
                "code": "project:update",
                "name": "Update Project",
                "resource_type": "project",
                "action": "update"
            },
            headers=logged_in_headers
        )
        assert permission_response.status_code == status.HTTP_201_CREATED
        permission = permission_response.json()
        permission_id = permission["id"]

        # Assign permission first
        assignment_response = await client.post(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/{role_id}/permissions",
            json={"permission_id": permission_id, "is_granted": True},
            headers=logged_in_headers
        )
        assert assignment_response.status_code == status.HTTP_201_CREATED
        assignment = assignment_response.json()
        assignment_id = assignment["id"]

        # Revoke permission
        response = await client.delete(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/{role_id}/permissions/{assignment_id}",
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_204_NO_CONTENT


class TestRoleAssignments:
    """Test role assignment management endpoints."""

    @pytest.mark.asyncio
    async def test_list_role_assignments(self, client: AsyncClient, logged_in_headers):
        """Test listing assignments for a role."""
        # Create workspace
        workspace_response = await client.post(
            "/api/v1/rbac/workspaces/",
            json={"name": "Role Assignments Workspace"},
            headers=logged_in_headers
        )
        assert workspace_response.status_code == status.HTTP_201_CREATED
        workspace = workspace_response.json()
        workspace_id = workspace["id"]

        # Create role
        role_response = await client.post(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/",
            json={"name": "Assignments Test Role"},
            headers=logged_in_headers
        )
        assert role_response.status_code == status.HTTP_201_CREATED
        role = role_response.json()
        role_id = role["id"]

        # List role assignments
        response = await client.get(
            f"/api/v1/rbac/workspaces/{workspace_id}/roles/{role_id}/assignments",
            headers=logged_in_headers
        )

        assert response.status_code == status.HTTP_200_OK
        result = response.json()

        assert isinstance(result, list)
        # May be empty if no assignments yet
