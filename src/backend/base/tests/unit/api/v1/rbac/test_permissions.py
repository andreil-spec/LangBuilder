"""Test suite for permissions RBAC API endpoints."""

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import HTTPException, status
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.api.v1.rbac.permissions import (
    batch_check_permissions,
    check_permission,
    get_permission,
    initialize_system_permissions,
    list_actions,
    list_permissions,
    list_resource_types,
)
from langflow.services.database.models.rbac.permission import Permission
from langflow.services.database.models.user.model import User
from langflow.services.rbac.permission_engine import PermissionEngine, PermissionResult


@pytest.fixture
def mock_user():
    """Create a mock regular user for testing."""
    user = MagicMock(spec=User)
    user.id = uuid4()
    user.username = "testuser"
    user.is_superuser = False
    return user


@pytest.fixture
def mock_superuser():
    """Create a mock superuser for testing."""
    user = MagicMock(spec=User)
    user.id = uuid4()
    user.username = "admin"
    user.is_superuser = True
    return user


@pytest.fixture
def mock_session():
    """Create a mock database session."""
    return AsyncMock(spec=AsyncSession)


@pytest.fixture
def mock_permission_engine():
    """Create a mock permission engine."""
    return AsyncMock(spec=PermissionEngine)


@pytest.fixture
def sample_permission():
    """Create a sample permission for testing."""
    permission = MagicMock(spec=Permission)
    permission.id = uuid4()
    permission.name = "Read Workspace"
    permission.code = "workspace:read"
    permission.resource_type = "workspace"
    permission.action = "read"
    permission.description = "Allows reading workspace information"
    permission.is_system = True
    return permission


class TestListPermissions:
    """Test permissions listing endpoint."""

    @pytest.mark.asyncio
    async def test_list_permissions_as_superuser(self, mock_session, mock_superuser, sample_permission):
        """Test listing permissions as superuser."""
        # Mock database query result
        mock_result = AsyncMock()
        mock_result.all.return_value = [sample_permission]
        mock_session.exec.return_value = mock_result

        result = await list_permissions(
            session=mock_session,
            current_user=mock_superuser,
            skip=0,
            limit=100
        )

        # Verify query was executed
        mock_session.exec.assert_called_once()
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_list_permissions_as_regular_user(self, mock_session, mock_user):
        """Test that regular users cannot list permissions."""
        with pytest.raises(HTTPException) as exc_info:
            await list_permissions(
                session=mock_session,
                current_user=mock_user,
                skip=0,
                limit=100
            )

        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "Only superusers" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_list_permissions_with_filters(self, mock_session, mock_superuser):
        """Test listing permissions with search filters."""
        mock_result = AsyncMock()
        mock_result.all.return_value = []
        mock_session.exec.return_value = mock_result

        result = await list_permissions(
            session=mock_session,
            current_user=mock_superuser,
            search="workspace",
            resource_type="workspace",
            action="read",
            skip=0,
            limit=50
        )

        mock_session.exec.assert_called_once()
        assert result == []


class TestGetPermission:
    """Test get permission endpoint."""

    @pytest.mark.asyncio
    async def test_get_permission_as_superuser(self, mock_session, mock_superuser, sample_permission):
        """Test getting permission as superuser."""
        permission_id = sample_permission.id
        mock_session.get.return_value = sample_permission

        result = await get_permission(
            permission_id=permission_id,
            session=mock_session,
            current_user=mock_superuser
        )

        # Verify permission was retrieved
        mock_session.get.assert_called_once_with(Permission, permission_id)
        assert result.id == str(sample_permission.id)

    @pytest.mark.asyncio
    async def test_get_permission_as_regular_user(self, mock_session, mock_user):
        """Test that regular users cannot get permission details."""
        permission_id = uuid4()

        with pytest.raises(HTTPException) as exc_info:
            await get_permission(
                permission_id=permission_id,
                session=mock_session,
                current_user=mock_user
            )

        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.asyncio
    async def test_get_permission_not_found(self, mock_session, mock_superuser):
        """Test getting non-existent permission."""
        permission_id = uuid4()
        mock_session.get.return_value = None

        with pytest.raises(HTTPException) as exc_info:
            await get_permission(
                permission_id=permission_id,
                session=mock_session,
                current_user=mock_superuser
            )

        assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
        assert "Permission not found" in exc_info.value.detail


class TestCheckPermission:
    """Test permission checking endpoint."""

    @pytest.mark.asyncio
    async def test_check_permission_success(self, mock_session, mock_user, mock_permission_engine):
        """Test successful permission check."""
        permission_check = {
            "resource_type": "workspace",
            "action": "read",
            "resource_id": str(uuid4())
        }

        # Mock permission engine result
        permission_result = PermissionResult(
            allowed=True,
            reason="User has direct permission",
            source="role_assignment",
            cached=False
        )
        mock_permission_engine.check_permission.return_value = permission_result

        result = await check_permission(
            permission_check=permission_check,
            session=mock_session,
            current_user=mock_user,
            permission_engine=mock_permission_engine
        )

        # Verify permission check was called
        mock_permission_engine.check_permission.assert_called_once()
        assert result["allowed"] is True
        assert result["reason"] == "User has direct permission"
        assert result["source"] == "role_assignment"

    @pytest.mark.asyncio
    async def test_check_permission_denied(self, mock_session, mock_user, mock_permission_engine):
        """Test permission check that is denied."""
        permission_check = {
            "resource_type": "workspace",
            "action": "delete",
            "resource_id": str(uuid4())
        }

        # Mock permission engine result
        permission_result = PermissionResult(
            allowed=False,
            reason="User lacks required permissions",
            source="default_deny",
            cached=False
        )
        mock_permission_engine.check_permission.return_value = permission_result

        result = await check_permission(
            permission_check=permission_check,
            session=mock_session,
            current_user=mock_user,
            permission_engine=mock_permission_engine
        )

        assert result["allowed"] is False
        assert result["reason"] == "User lacks required permissions"

    @pytest.mark.asyncio
    async def test_check_permission_missing_required_fields(self, mock_session, mock_user, mock_permission_engine):
        """Test permission check with missing required fields."""
        permission_check = {
            "resource_type": "workspace"
            # Missing 'action' field
        }

        with pytest.raises(HTTPException) as exc_info:
            await check_permission(
                permission_check=permission_check,
                session=mock_session,
                current_user=mock_user,
                permission_engine=mock_permission_engine
            )

        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert "resource_type and action are required" in exc_info.value.detail


class TestBatchCheckPermissions:
    """Test batch permission checking endpoint."""

    @pytest.mark.asyncio
    async def test_batch_check_permissions_success(self, mock_session, mock_user, mock_permission_engine):
        """Test successful batch permission check."""
        permission_checks = [
            {
                "resource_type": "workspace",
                "action": "read",
                "resource_id": str(uuid4())
            },
            {
                "resource_type": "project",
                "action": "create",
                "workspace_id": str(uuid4())
            }
        ]

        # Mock permission engine results
        results = [
            PermissionResult(allowed=True, reason="Allowed", source="role", cached=False),
            PermissionResult(allowed=False, reason="Denied", source="default", cached=False)
        ]
        mock_permission_engine.check_permission.side_effect = results

        result = await batch_check_permissions(
            permission_checks=permission_checks,
            session=mock_session,
            current_user=mock_user,
            permission_engine=mock_permission_engine
        )

        # Verify both checks were performed
        assert len(result) == 2
        assert result[0]["allowed"] is True
        assert result[1]["allowed"] is False
        assert mock_permission_engine.check_permission.call_count == 2

    @pytest.mark.asyncio
    async def test_batch_check_permissions_too_many(self, mock_session, mock_user, mock_permission_engine):
        """Test batch permission check with too many requests."""
        permission_checks = [{"resource_type": "workspace", "action": "read"}] * 51

        with pytest.raises(HTTPException) as exc_info:
            await batch_check_permissions(
                permission_checks=permission_checks,
                session=mock_session,
                current_user=mock_user,
                permission_engine=mock_permission_engine
            )

        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert "Maximum 50 permission checks" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_batch_check_permissions_invalid_request(self, mock_session, mock_user, mock_permission_engine):
        """Test batch permission check with invalid request."""
        permission_checks = [
            {
                "resource_type": "workspace",
                "action": "read"
            },
            {
                "resource_type": "project"
                # Missing 'action' field
            }
        ]

        # Mock first successful check
        permission_result = PermissionResult(allowed=True, reason="OK", source="role", cached=False)
        mock_permission_engine.check_permission.return_value = permission_result

        result = await batch_check_permissions(
            permission_checks=permission_checks,
            session=mock_session,
            current_user=mock_user,
            permission_engine=mock_permission_engine
        )

        # Verify first check succeeded, second failed validation
        assert len(result) == 2
        assert result[0]["allowed"] is True
        assert result[1]["allowed"] is False
        assert "Invalid request" in result[1]["reason"]

    @pytest.mark.asyncio
    async def test_batch_check_permissions_engine_error(self, mock_session, mock_user, mock_permission_engine):
        """Test batch permission check with engine error."""
        permission_checks = [
            {
                "resource_type": "workspace",
                "action": "read",
                "resource_id": str(uuid4())
            }
        ]

        # Mock permission engine error
        mock_permission_engine.check_permission.side_effect = Exception("Database error")

        result = await batch_check_permissions(
            permission_checks=permission_checks,
            session=mock_session,
            current_user=mock_user,
            permission_engine=mock_permission_engine
        )

        # Verify error is handled gracefully
        assert len(result) == 1
        assert result[0]["allowed"] is False
        assert "Error checking permission" in result[0]["reason"]
        assert result[0]["source"] == "error"


class TestInitializeSystemPermissions:
    """Test system permissions initialization endpoint."""

    @pytest.mark.asyncio
    async def test_initialize_system_permissions_as_superuser(self, mock_session, mock_superuser):
        """Test system permissions initialization as superuser."""
        # Mock no existing permissions
        mock_result = AsyncMock()
        mock_result.first.return_value = None
        mock_session.exec.return_value = mock_result

        with patch("langflow.api.v1.rbac.permissions.SYSTEM_PERMISSIONS", [
            {"code": "workspace:read", "name": "Read Workspace", "resource_type": "workspace", "action": "read"},
            {"code": "project:create", "name": "Create Project", "resource_type": "project", "action": "create"}
        ]):
            result = await initialize_system_permissions(
                session=mock_session,
                current_user=mock_superuser
            )

        # Verify permissions were created
        assert result["permissions_created"] == 2
        assert "initialized" in result["message"]
        mock_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_initialize_system_permissions_as_regular_user(self, mock_session, mock_user):
        """Test that regular users cannot initialize system permissions."""
        with pytest.raises(HTTPException) as exc_info:
            await initialize_system_permissions(
                session=mock_session,
                current_user=mock_user
            )

        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "Only superusers" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_initialize_system_permissions_already_exist(self, mock_session, mock_superuser):
        """Test system permissions initialization when permissions already exist."""
        # Mock existing permissions
        existing_permission = MagicMock(spec=Permission)
        mock_result = AsyncMock()
        mock_result.first.return_value = existing_permission
        mock_session.exec.return_value = mock_result

        result = await initialize_system_permissions(
            session=mock_session,
            current_user=mock_superuser
        )

        # Verify no new permissions were created
        assert result["permissions_created"] == 0


class TestListResourceTypes:
    """Test resource types listing endpoint."""

    @pytest.mark.asyncio
    async def test_list_resource_types_success(self, mock_session, mock_user):
        """Test successful resource types listing."""
        # Mock database query result
        mock_result = AsyncMock()
        mock_result.all.return_value = ["workspace", "project", "environment", "flow"]
        mock_session.exec.return_value = mock_result

        result = await list_resource_types(
            session=mock_session,
            current_user=mock_user
        )

        # Verify query was executed and results sorted
        mock_session.exec.assert_called_once()
        assert result == ["environment", "flow", "project", "workspace"]

    @pytest.mark.asyncio
    async def test_list_resource_types_empty(self, mock_session, mock_user):
        """Test resource types listing with no results."""
        mock_result = AsyncMock()
        mock_result.all.return_value = []
        mock_session.exec.return_value = mock_result

        result = await list_resource_types(
            session=mock_session,
            current_user=mock_user
        )

        assert result == []


class TestListActions:
    """Test actions listing endpoint."""

    @pytest.mark.asyncio
    async def test_list_actions_success(self, mock_session, mock_user):
        """Test successful actions listing."""
        # Mock database query result
        mock_result = AsyncMock()
        mock_result.all.return_value = ["read", "create", "update", "delete"]
        mock_session.exec.return_value = mock_result

        result = await list_actions(
            session=mock_session,
            current_user=mock_user
        )

        # Verify query was executed and results sorted
        mock_session.exec.assert_called_once()
        assert result == ["create", "delete", "read", "update"]

    @pytest.mark.asyncio
    async def test_list_actions_with_resource_type_filter(self, mock_session, mock_user):
        """Test actions listing with resource type filter."""
        mock_result = AsyncMock()
        mock_result.all.return_value = ["read", "update"]
        mock_session.exec.return_value = mock_result

        result = await list_actions(
            session=mock_session,
            current_user=mock_user,
            resource_type="workspace"
        )

        mock_session.exec.assert_called_once()
        assert result == ["read", "update"]

    @pytest.mark.asyncio
    async def test_list_actions_empty(self, mock_session, mock_user):
        """Test actions listing with no results."""
        mock_result = AsyncMock()
        mock_result.all.return_value = []
        mock_session.exec.return_value = mock_result

        result = await list_actions(
            session=mock_session,
            current_user=mock_user,
            resource_type="nonexistent"
        )

        assert result == []
