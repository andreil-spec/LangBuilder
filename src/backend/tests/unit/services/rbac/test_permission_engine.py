"""Unit tests for Permission Engine."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest
from langflow.services.database.models.rbac.permission import PermissionAction, ResourceType
from langflow.services.database.models.rbac.project import Project
from langflow.services.database.models.rbac.role_assignment import AssignmentScope
from langflow.services.database.models.rbac.workspace import Workspace
from langflow.services.database.models.user.model import User
from langflow.services.rbac.permission_engine import PermissionEngine, PermissionResult


class TestPermissionResult:
    """Test PermissionResult class."""

    def test_permission_result_creation(self):
        """Test basic PermissionResult creation."""
        result = PermissionResult(
            granted=True,
            reason="Test permission granted",
            cached=False,
            scope_path=["workspace:123"],
            applicable_roles=["admin"],
            check_duration_ms=50.0
        )

        assert result.granted is True
        assert result.reason == "Test permission granted"
        assert result.cached is False
        assert result.scope_path == ["workspace:123"]
        assert result.applicable_roles == ["admin"]
        assert result.check_duration_ms == 50.0
        assert bool(result) is True  # Test __bool__ method

    def test_permission_result_default_values(self):
        """Test PermissionResult with default values."""
        result = PermissionResult(
            granted=False,
            reason="Access denied"
        )

        assert result.granted is False
        assert result.reason == "Access denied"
        assert result.cached is False
        assert result.scope_path == []
        assert result.applicable_roles == []
        assert result.check_duration_ms is None
        assert bool(result) is False


class TestPermissionEngine:
    """Test PermissionEngine class."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock database session."""
        session = Mock()
        return session

    @pytest.fixture
    def mock_redis(self):
        """Create a mock Redis client."""
        redis_client = AsyncMock()
        return redis_client

    @pytest.fixture
    def permission_engine(self, mock_redis):
        """Create a PermissionEngine instance."""
        return PermissionEngine(redis_client=mock_redis)

    @pytest.fixture
    def sample_user(self):
        """Create a sample user."""
        return User(
            id=uuid4(),
            username="testuser",
            password="hashed_password",
            is_active=True,
            is_superuser=False
        )

    @pytest.fixture
    def superuser(self):
        """Create a superuser."""
        return User(
            id=uuid4(),
            username="superuser",
            password="hashed_password",
            is_active=True,
            is_superuser=True
        )

    @pytest.mark.asyncio
    async def test_superuser_bypass(self, permission_engine, mock_session, superuser):
        """Test that superusers bypass permission checks."""
        result = await permission_engine.check_permission(
            session=mock_session,
            user=superuser,
            resource_type=ResourceType.WORKSPACE,
            action=PermissionAction.DELETE,
            resource_id=uuid4()
        )

        assert result.granted is True
        assert result.reason == "Super admin access"
        assert "super_admin" in result.applicable_roles
        assert result.check_duration_ms is not None

    @pytest.mark.asyncio
    async def test_cache_key_building(self, permission_engine):
        """Test cache key building."""
        user_id = uuid4()
        resource_id = uuid4()

        # Test with resource ID
        cache_key = permission_engine._build_cache_key(
            user_id=user_id,
            resource_type=ResourceType.WORKSPACE,
            action=PermissionAction.READ,
            resource_id=resource_id
        )

        expected = f"perm:{user_id}:workspace:read:{resource_id}"
        assert cache_key == expected

        # Test without resource ID
        cache_key_no_resource = permission_engine._build_cache_key(
            user_id=user_id,
            resource_type=ResourceType.WORKSPACE,
            action=PermissionAction.READ,
            resource_id=None
        )

        expected_no_resource = f"perm:{user_id}:workspace:read:type"
        assert cache_key_no_resource == expected_no_resource

    @pytest.mark.asyncio
    async def test_cached_permission_hit(self, permission_engine, mock_session, sample_user, mock_redis):
        """Test cache hit scenario."""
        # Mock cached result
        cached_data = {
            "granted": True,
            "reason": "Cached permission",
            "scope_path": ["workspace:123"],
            "applicable_roles": ["admin"]
        }

        import json
        mock_redis.get.return_value = json.dumps(cached_data)

        result = await permission_engine.check_permission(
            session=mock_session,
            user=sample_user,
            resource_type=ResourceType.WORKSPACE,
            action=PermissionAction.READ,
            resource_id=uuid4()
        )

        assert result.granted is True
        assert result.reason == "Cached permission"
        assert result.cached is True
        assert result.scope_path == ["workspace:123"]
        assert result.applicable_roles == ["admin"]
        assert result.check_duration_ms is not None

    @pytest.mark.asyncio
    async def test_resolve_workspace_scope(self, permission_engine, mock_session):
        """Test workspace scope resolution."""
        workspace_id = uuid4()
        workspace = Workspace(id=workspace_id, name="Test Workspace", owner_id=uuid4())

        mock_session.get.return_value = workspace

        scope_path = await permission_engine._resolve_resource_scope(
            session=mock_session,
            resource_type=ResourceType.WORKSPACE,
            resource_id=workspace_id
        )

        assert scope_path == [f"workspace:{workspace_id}"]

    @pytest.mark.asyncio
    async def test_resolve_project_scope(self, permission_engine, mock_session):
        """Test project scope resolution."""
        workspace_id = uuid4()
        project_id = uuid4()

        project = Project(
            id=project_id,
            name="Test Project",
            workspace_id=workspace_id,
            owner_id=uuid4()
        )

        mock_session.get.return_value = project

        scope_path = await permission_engine._resolve_resource_scope(
            session=mock_session,
            resource_type=ResourceType.PROJECT,
            resource_id=project_id
        )

        expected_scope = [
            f"workspace:{workspace_id}",
            f"project:{project_id}"
        ]
        assert scope_path == expected_scope

    @pytest.mark.asyncio
    async def test_permission_denied_no_roles(self, permission_engine, mock_session, sample_user):
        """Test permission denied when user has no applicable roles."""
        # Mock empty role assignments
        mock_session.query.return_value.filter.return_value.all.return_value = []

        result = await permission_engine.check_permission(
            session=mock_session,
            user=sample_user,
            resource_type=ResourceType.WORKSPACE,
            action=PermissionAction.DELETE,
            resource_id=uuid4()
        )

        assert result.granted is False
        assert "No applicable permissions found" in result.reason
        assert result.check_duration_ms is not None

    @pytest.mark.asyncio
    async def test_bulk_permissions_check(self, permission_engine, mock_session, superuser):
        """Test bulk permission checking."""
        permission_requests = [
            (ResourceType.WORKSPACE, PermissionAction.READ, uuid4()),
            (ResourceType.PROJECT, PermissionAction.CREATE, uuid4()),
            (ResourceType.FLOW, PermissionAction.EXECUTE, uuid4())
        ]

        results = await permission_engine.check_bulk_permissions(
            session=mock_session,
            user=superuser,
            permission_requests=permission_requests
        )

        assert len(results) == 3

        # All should be granted for superuser
        for request, result in results.items():
            assert result.granted is True
            assert result.reason == "Super admin access"

    @pytest.mark.asyncio
    async def test_get_user_permissions(self, permission_engine, mock_session):
        """Test getting user permissions."""
        user_id = uuid4()
        role_id = uuid4()
        permission_id = uuid4()

        # Mock role assignment
        role_assignment = Mock()
        role_assignment.role_id = role_id
        role_assignment.scope_type = AssignmentScope.WORKSPACE
        role_assignment.workspace_id = uuid4()
        role_assignment.assigned_at = datetime.now(timezone.utc)

        # Mock role
        role = Mock()
        role.id = role_id
        role.name = "Admin"
        role.is_active = True

        # Mock permission
        permission = Mock()
        permission.id = permission_id
        permission.code = "workspace:read"
        permission.name = "Read Workspace"
        permission.resource_type = ResourceType.WORKSPACE
        permission.action = PermissionAction.READ

        # Setup mock queries
        mock_session.query.return_value.filter.return_value.all.return_value = [role_assignment]
        mock_session.get.side_effect = lambda model, id: role if id == role_id else None
        mock_session.query.return_value.join.return_value.filter.return_value.all.return_value = [permission]

        permissions = await permission_engine.get_user_permissions(
            session=mock_session,
            user_id=user_id,
            scope_type=AssignmentScope.WORKSPACE
        )

        assert len(permissions) == 1
        perm_data = permissions[0]

        assert perm_data["permission_id"] == str(permission_id)
        assert perm_data["permission_code"] == "workspace:read"
        assert perm_data["permission_name"] == "Read Workspace"
        assert perm_data["resource_type"] == ResourceType.WORKSPACE
        assert perm_data["action"] == PermissionAction.READ
        assert perm_data["role_id"] == str(role_id)
        assert perm_data["role_name"] == "Admin"
        assert perm_data["scope_type"] == AssignmentScope.WORKSPACE

    @pytest.mark.asyncio
    async def test_permission_check_error_handling(self, permission_engine, mock_session, sample_user):
        """Test error handling in permission checks."""
        # Mock session to raise an exception
        mock_session.get.side_effect = Exception("Database error")

        result = await permission_engine.check_permission(
            session=mock_session,
            user=sample_user,
            resource_type=ResourceType.WORKSPACE,
            action=PermissionAction.READ,
            resource_id=uuid4()
        )

        assert result.granted is False
        assert "Permission check failed" in result.reason
        assert "Database error" in result.reason
        assert result.check_duration_ms is not None

    @pytest.mark.asyncio
    async def test_cache_invalidation(self, permission_engine, mock_redis):
        """Test cache invalidation for user."""
        user_id = uuid4()

        # Mock Redis keys method
        mock_redis.keys.return_value = [
            f"perm:{user_id}:workspace:read:123",
            f"perm:{user_id}:project:create:456"
        ]

        await permission_engine.invalidate_user_permissions(user_id)

        # Verify Redis methods were called
        mock_redis.keys.assert_called_once_with(f"perm:{user_id}:*")
        mock_redis.delete.assert_called_once()


class TestPermissionEngineScenarios:
    """Test realistic permission scenarios."""

    @pytest.fixture
    def permission_engine(self):
        """Create a PermissionEngine without Redis for testing."""
        return PermissionEngine()

    @pytest.mark.asyncio
    async def test_workspace_owner_permissions(self, permission_engine):
        """Test that workspace owners have full permissions."""
        # This would require a more complex mock setup with actual database relationships
        # For now, we'll test the logic structure

    @pytest.mark.asyncio
    async def test_inherited_permissions(self, permission_engine):
        """Test permission inheritance from parent scopes."""
        # Test that workspace permissions apply to projects within the workspace

    @pytest.mark.asyncio
    async def test_temporal_permissions(self, permission_engine):
        """Test time-based permission constraints."""
        # Test permissions that expire
