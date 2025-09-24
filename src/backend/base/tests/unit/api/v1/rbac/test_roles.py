"""Test suite for roles RBAC API endpoints."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import HTTPException, status
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.api.v1.rbac.roles import (
    assign_permission_to_role,
    create_role,
    delete_role,
    get_role,
    initialize_system_roles,
    list_role_permissions,
    list_roles,
    remove_permission_from_role,
    update_role,
)
from langflow.services.database.models.rbac.permission import Permission, RolePermission
from langflow.services.database.models.rbac.role import (
    Role,
    RoleCreate,
    RoleUpdate,
)
from langflow.services.database.models.rbac.workspace import Workspace
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
    engine = AsyncMock(spec=PermissionEngine)
    engine.check_permission.return_value = PermissionResult(
        allowed=True,
        reason="Test permission granted",
        source="test",
        cached=False
    )
    return engine


@pytest.fixture
def sample_workspace():
    """Create a sample workspace for testing."""
    workspace = MagicMock(spec=Workspace)
    workspace.id = uuid4()
    workspace.name = "Test Workspace"
    workspace.is_deleted = False
    return workspace


@pytest.fixture
def sample_role():
    """Create a sample role for testing."""
    role = MagicMock(spec=Role)
    role.id = uuid4()
    role.name = "Test Role"
    role.description = "A test role"
    role.workspace_id = uuid4()
    role.type = "custom"
    role.is_system = False
    role.is_active = True
    role.created_at = datetime.now(timezone.utc)
    role.updated_at = datetime.now(timezone.utc)
    role.version = 1
    return role


@pytest.fixture
def role_create_data():
    """Create role creation data."""
    return RoleCreate(
        name="New Role",
        description="A new role for testing",
        workspace_id=uuid4(),
        type="custom"
    )


class TestCreateRole:
    """Test role creation endpoint."""

    @pytest.mark.asyncio
    async def test_create_role_success(self, mock_session, mock_user, mock_permission_engine,
                                      role_create_data, sample_workspace):
        """Test successful role creation."""
        # Mock workspace lookup
        mock_session.get.return_value = sample_workspace

        # Mock no existing role
        mock_result = AsyncMock()
        mock_result.first.return_value = None
        mock_session.exec.return_value = mock_result

        # Mock role creation
        created_role = MagicMock(spec=Role)
        created_role.id = uuid4()
        created_role.name = role_create_data.name
        created_role.created_by_id = mock_user.id

        mock_session.refresh = AsyncMock()

        with patch("langflow.api.v1.rbac.roles.Role") as MockRole:
            MockRole.return_value = created_role

            result = await create_role(
                role_data=role_create_data,
                session=mock_session,
                current_user=mock_user,
                permission_engine=mock_permission_engine
            )

            # Verify role was created
            mock_session.add.assert_called_once()
            mock_session.commit.assert_called_once()
            mock_session.refresh.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_role_workspace_not_found(self, mock_session, mock_user,
                                                  mock_permission_engine, role_create_data):
        """Test role creation with non-existent workspace."""
        # Mock no workspace found
        mock_session.get.return_value = None

        with pytest.raises(HTTPException) as exc_info:
            await create_role(
                role_data=role_create_data,
                session=mock_session,
                current_user=mock_user,
                permission_engine=mock_permission_engine
            )

        assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
        assert "Workspace not found" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_create_role_permission_denied(self, mock_session, mock_user,
                                                mock_permission_engine, role_create_data,
                                                sample_workspace):
        """Test role creation with insufficient permissions."""
        # Mock workspace lookup
        mock_session.get.return_value = sample_workspace

        # Mock permission denied
        mock_permission_engine.check_permission.return_value = PermissionResult(
            allowed=False,
            reason="Insufficient permissions",
            source="test",
            cached=False
        )

        with pytest.raises(HTTPException) as exc_info:
            await create_role(
                role_data=role_create_data,
                session=mock_session,
                current_user=mock_user,
                permission_engine=mock_permission_engine
            )

        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "Insufficient permissions" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_create_system_role_as_regular_user(self, mock_session, mock_user,
                                                     mock_permission_engine):
        """Test that regular users cannot create system-level roles."""
        role_data = RoleCreate(
            name="System Role",
            description="A system role",
            workspace_id=None,  # System role
            type="system"
        )

        with pytest.raises(HTTPException) as exc_info:
            await create_role(
                role_data=role_data,
                session=mock_session,
                current_user=mock_user,
                permission_engine=mock_permission_engine
            )

        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "Only superusers" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_create_role_duplicate_name(self, mock_session, mock_user,
                                             mock_permission_engine, role_create_data,
                                             sample_workspace):
        """Test role creation with duplicate name."""
        # Mock workspace lookup
        mock_session.get.return_value = sample_workspace

        # Mock existing role
        existing_role = MagicMock(spec=Role)
        mock_result = AsyncMock()
        mock_result.first.return_value = existing_role
        mock_session.exec.return_value = mock_result

        with pytest.raises(HTTPException) as exc_info:
            await create_role(
                role_data=role_create_data,
                session=mock_session,
                current_user=mock_user,
                permission_engine=mock_permission_engine
            )

        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert "already exists" in exc_info.value.detail


class TestListRoles:
    """Test role listing endpoint."""

    @pytest.mark.asyncio
    async def test_list_roles_success(self, mock_session, mock_user, mock_permission_engine,
                                     sample_role):
        """Test successful role listing."""
        # Mock database query result
        mock_result = AsyncMock()
        mock_result.all.return_value = [sample_role]
        mock_session.exec.return_value = mock_result

        result = await list_roles(
            session=mock_session,
            current_user=mock_user,
            permission_engine=mock_permission_engine,
            workspace_id=None,
            skip=0,
            limit=100
        )

        # Verify query was executed
        mock_session.exec.assert_called()
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_list_roles_as_superuser(self, mock_session, mock_superuser,
                                          mock_permission_engine, sample_role):
        """Test role listing as superuser (can see all roles)."""
        # Mock database query result
        mock_result = AsyncMock()
        mock_result.all.return_value = [sample_role]
        mock_session.exec.return_value = mock_result

        result = await list_roles(
            session=mock_session,
            current_user=mock_superuser,
            permission_engine=mock_permission_engine,
            workspace_id=None,
            skip=0,
            limit=100
        )

        # Superusers should see all roles
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_list_roles_with_filters(self, mock_session, mock_user, mock_permission_engine):
        """Test role listing with search filters."""
        mock_result = AsyncMock()
        mock_result.all.return_value = []
        mock_session.exec.return_value = mock_result

        result = await list_roles(
            session=mock_session,
            current_user=mock_user,
            permission_engine=mock_permission_engine,
            search="admin",
            type="system",
            is_system=True,
            is_active=True,
            skip=0,
            limit=50
        )

        mock_session.exec.assert_called_once()
        assert result == []


class TestGetRole:
    """Test get role endpoint."""

    @pytest.mark.asyncio
    async def test_get_role_success(self, mock_session, mock_user, sample_role):
        """Test successful role retrieval."""
        role_id = sample_role.id
        mock_session.get.return_value = sample_role

        # Mock workspace for permission check
        sample_role.workspace_id = uuid4()
        mock_workspace = MagicMock()
        mock_session.get.side_effect = [sample_role, mock_workspace]

        with patch("langflow.api.v1.rbac.dependencies.PermissionChecker") as MockChecker:
            mock_checker = MockChecker.return_value
            mock_checker.has_workspace_permission.return_value = True

            result = await get_role(
                role_id=role_id,
                session=mock_session,
                current_user=mock_user
            )

            assert result.id == str(sample_role.id)

    @pytest.mark.asyncio
    async def test_get_role_not_found(self, mock_session, mock_user):
        """Test getting non-existent role."""
        role_id = uuid4()
        mock_session.get.return_value = None

        with pytest.raises(HTTPException) as exc_info:
            await get_role(
                role_id=role_id,
                session=mock_session,
                current_user=mock_user
            )

        assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
        assert "Role not found" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_get_system_role_as_regular_user(self, mock_session, mock_user, sample_role):
        """Test that regular users cannot view system roles."""
        role_id = sample_role.id
        sample_role.workspace_id = None  # System role
        mock_session.get.return_value = sample_role

        with pytest.raises(HTTPException) as exc_info:
            await get_role(
                role_id=role_id,
                session=mock_session,
                current_user=mock_user
            )

        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "Access denied to system roles" in exc_info.value.detail


class TestUpdateRole:
    """Test role update endpoint."""

    @pytest.mark.asyncio
    async def test_update_role_success(self, mock_session, mock_user, sample_role):
        """Test successful role update."""
        role_id = sample_role.id
        update_data = RoleUpdate(
            name="Updated Role",
            description="Updated description"
        )

        mock_session.get.return_value = sample_role

        # Mock workspace for permission check
        mock_workspace = MagicMock()
        mock_session.get.side_effect = [sample_role, mock_workspace]

        with patch("langflow.api.v1.rbac.dependencies.PermissionChecker") as MockChecker:
            mock_checker = MockChecker.return_value
            mock_checker.has_workspace_permission.return_value = True

            result = await update_role(
                role_id=role_id,
                role_data=update_data,
                session=mock_session,
                current_user=mock_user
            )

            # Verify update was committed
            mock_session.commit.assert_called_once()
            mock_session.refresh.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_system_role(self, mock_session, mock_user, sample_role):
        """Test that system roles cannot be modified."""
        role_id = sample_role.id
        sample_role.is_system = True  # System role
        update_data = RoleUpdate(name="Updated System Role")

        mock_session.get.return_value = sample_role

        with pytest.raises(HTTPException) as exc_info:
            await update_role(
                role_id=role_id,
                role_data=update_data,
                session=mock_session,
                current_user=mock_user
            )

        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert "System roles cannot be modified" in exc_info.value.detail


class TestDeleteRole:
    """Test role deletion endpoint."""

    @pytest.mark.asyncio
    async def test_delete_role_success(self, mock_session, mock_user, sample_role):
        """Test successful role deletion (deactivation)."""
        role_id = sample_role.id
        mock_session.get.return_value = sample_role

        # Mock workspace for permission check
        mock_workspace = MagicMock()
        mock_session.get.side_effect = [sample_role, mock_workspace]

        # Mock no active assignments
        with patch("langflow.api.v1.rbac.dependencies.PermissionChecker") as MockChecker:
            mock_checker = MockChecker.return_value
            mock_checker.has_workspace_permission.return_value = True

            mock_session.query.return_value.filter.return_value.count.return_value = 0

            await delete_role(
                role_id=role_id,
                session=mock_session,
                current_user=mock_user
            )

            # Verify role was deactivated
            assert sample_role.is_active is False
            mock_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_system_role(self, mock_session, mock_user, sample_role):
        """Test that system roles cannot be deleted."""
        role_id = sample_role.id
        sample_role.is_system = True  # System role
        mock_session.get.return_value = sample_role

        with pytest.raises(HTTPException) as exc_info:
            await delete_role(
                role_id=role_id,
                session=mock_session,
                current_user=mock_user
            )

        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert "System roles cannot be deleted" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_delete_role_with_active_assignments(self, mock_session, mock_user, sample_role):
        """Test deleting role with active assignments."""
        role_id = sample_role.id
        mock_session.get.return_value = sample_role

        # Mock workspace for permission check
        mock_workspace = MagicMock()
        mock_session.get.side_effect = [sample_role, mock_workspace]

        with patch("langflow.api.v1.rbac.dependencies.PermissionChecker") as MockChecker:
            mock_checker = MockChecker.return_value
            mock_checker.has_workspace_permission.return_value = True

            # Mock active assignments
            mock_session.query.return_value.filter.return_value.count.return_value = 3

            with pytest.raises(HTTPException) as exc_info:
                await delete_role(
                    role_id=role_id,
                    session=mock_session,
                    current_user=mock_user
                )

            assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
            assert "active assignments" in exc_info.value.detail


class TestRolePermissions:
    """Test role permission management endpoints."""

    @pytest.mark.asyncio
    async def test_list_role_permissions_success(self, mock_session, mock_user, sample_role):
        """Test listing role permissions."""
        role_id = sample_role.id
        mock_session.get.return_value = sample_role

        # Mock role permissions
        mock_permission = MagicMock(spec=Permission)
        mock_role_permission = MagicMock(spec=RolePermission)
        mock_role_permission.permission_id = mock_permission.id

        mock_session.query.return_value.filter.return_value.all.return_value = [mock_role_permission]
        mock_session.get.side_effect = [sample_role, mock_permission]

        result = await list_role_permissions(
            role_id=role_id,
            session=mock_session,
            current_user=mock_user
        )

        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_assign_permission_to_role_success(self, mock_session, mock_user, sample_role):
        """Test assigning permission to role."""
        role_id = sample_role.id
        permission_id = uuid4()
        permission_data = {"permission_id": str(permission_id)}

        # Mock role and permission lookup
        mock_permission = MagicMock(spec=Permission)
        mock_session.get.side_effect = [sample_role, mock_permission]

        # Mock no existing assignment
        mock_session.query.return_value.filter.return_value.first.return_value = None

        result = await assign_permission_to_role(
            role_id=role_id,
            permission_data=permission_data,
            session=mock_session,
            current_user=mock_user
        )

        # Verify permission assignment
        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()
        assert "assigned successfully" in result["message"]

    @pytest.mark.asyncio
    async def test_assign_permission_already_assigned(self, mock_session, mock_user, sample_role):
        """Test assigning permission that's already assigned."""
        role_id = sample_role.id
        permission_id = uuid4()
        permission_data = {"permission_id": str(permission_id)}

        # Mock role and permission lookup
        mock_permission = MagicMock(spec=Permission)
        mock_session.get.side_effect = [sample_role, mock_permission]

        # Mock existing assignment
        existing_assignment = MagicMock(spec=RolePermission)
        mock_session.query.return_value.filter.return_value.first.return_value = existing_assignment

        with pytest.raises(HTTPException) as exc_info:
            await assign_permission_to_role(
                role_id=role_id,
                permission_data=permission_data,
                session=mock_session,
                current_user=mock_user
            )

        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert "already assigned" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_remove_permission_from_role_success(self, mock_session, mock_user):
        """Test removing permission from role."""
        role_id = uuid4()
        permission_id = uuid4()

        # Mock existing assignment
        role_permission = MagicMock(spec=RolePermission)
        mock_session.query.return_value.filter.return_value.first.return_value = role_permission

        await remove_permission_from_role(
            role_id=role_id,
            permission_id=permission_id,
            session=mock_session,
            current_user=mock_user
        )

        # Verify permission removal
        mock_session.delete.assert_called_once_with(role_permission)
        mock_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_remove_permission_not_found(self, mock_session, mock_user):
        """Test removing non-existent permission assignment."""
        role_id = uuid4()
        permission_id = uuid4()

        # Mock no existing assignment
        mock_session.query.return_value.filter.return_value.first.return_value = None

        with pytest.raises(HTTPException) as exc_info:
            await remove_permission_from_role(
                role_id=role_id,
                permission_id=permission_id,
                session=mock_session,
                current_user=mock_user
            )

        assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
        assert "assignment not found" in exc_info.value.detail


class TestInitializeSystemRoles:
    """Test system roles initialization endpoint."""

    @pytest.mark.asyncio
    async def test_initialize_system_roles_as_superuser(self, mock_session, mock_superuser):
        """Test system roles initialization as superuser."""
        # Mock no existing roles/permissions
        mock_session.query.return_value.filter.return_value.first.return_value = None

        with patch("langflow.api.v1.rbac.roles.SYSTEM_PERMISSIONS", [
            {"code": "workspace:read", "name": "Read Workspace"}
        ]), patch("langflow.api.v1.rbac.roles.SYSTEM_ROLES", {
            "admin": {"name": "Administrator", "description": "System administrator"}
        }):
            result = await initialize_system_roles(
                session=mock_session,
                current_user=mock_superuser
            )

        # Verify roles and permissions were created
        assert result["permissions_created"] == 1
        assert result["roles_created"] == 1
        mock_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_initialize_system_roles_as_regular_user(self, mock_session, mock_user):
        """Test that regular users cannot initialize system roles."""
        with pytest.raises(HTTPException) as exc_info:
            await initialize_system_roles(
                session=mock_session,
                current_user=mock_user
            )

        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "Only superusers" in exc_info.value.detail
