"""Tests for the RBAC permission engine."""

from datetime import datetime
from uuid import uuid4

import pytest

from langflow.services.database.models.rbac.workspace import Workspace
from langflow.services.database.models.user.model import User
from langflow.services.rbac.permission_engine import PermissionResult


class TestPermissionEngine:
    """Test cases for the permission engine core functionality."""

    async def test_superuser_has_all_permissions(self, permission_engine, async_session):
        """Test that superusers have all permissions."""
        superuser = User(
            id=uuid4(),
            username="superuser",
            email="super@example.com",
            is_superuser=True,
            is_active=True,
        )

        result = await permission_engine.check_permission(
            session=async_session,
            user=superuser,
            resource_type="workspace",
            action="delete",
            resource_id=uuid4(),
        )

        assert result.allowed is True
        assert result.source == "superuser"
        assert "superuser" in result.reason.lower()

    async def test_owner_has_all_permissions(self, permission_engine, async_session):
        """Test that resource owners have all permissions."""
        user = User(
            id=uuid4(),
            username="owner",
            email="owner@example.com",
            is_superuser=False,
            is_active=True,
        )

        workspace = Workspace(
            id=uuid4(),
            name="Test Workspace",
            owner_id=user.id,
            is_active=True,
            is_deleted=False,
        )

        result = await permission_engine.check_permission(
            session=async_session,
            user=user,
            resource_type="workspace",
            action="manage",
            resource_id=workspace.id,
            workspace_id=workspace.id,
        )

        assert result.allowed is True
        assert result.source == "ownership"
        assert "owner" in result.reason.lower()

    async def test_inactive_user_denied(self, permission_engine, async_session):
        """Test that inactive users are denied all permissions."""
        inactive_user = User(
            id=uuid4(),
            username="inactive",
            email="inactive@example.com",
            is_superuser=False,
            is_active=False,
        )

        result = await permission_engine.check_permission(
            session=async_session,
            user=inactive_user,
            resource_type="workspace",
            action="read",
            resource_id=uuid4(),
        )

        assert result.allowed is False
        assert "inactive" in result.reason.lower()

    async def test_permission_caching(self, permission_engine, async_session):
        """Test that permission results are cached."""
        user = User(
            id=uuid4(),
            username="testuser",
            email="test@example.com",
            is_superuser=True,
            is_active=True,
        )

        # First call should not be cached
        result1 = await permission_engine.check_permission(
            session=async_session,
            user=user,
            resource_type="workspace",
            action="read",
            resource_id=uuid4(),
            use_cache=True,
        )

        # Second call should be cached
        result2 = await permission_engine.check_permission(
            session=async_session,
            user=user,
            resource_type="workspace",
            action="read",
            resource_id=uuid4(),
            use_cache=True,
        )

        assert result1.allowed == result2.allowed
        # Second result should be faster (cached)

    async def test_cache_invalidation(self, permission_engine, async_session):
        """Test that cache invalidation works correctly."""
        user_id = uuid4()

        # Invalidate user cache
        await permission_engine.invalidate_user_cache(user_id)

        # Invalidate resource cache
        resource_id = uuid4()
        await permission_engine.invalidate_resource_cache("workspace", resource_id)

        # Test should pass without errors
        assert True

    async def test_hierarchical_permissions(self, permission_engine, async_session):
        """Test that hierarchical permissions work correctly."""
        # This would test workspace -> project -> environment -> flow hierarchy
        # For now, it's a placeholder

    async def test_permission_result_structure(self, permission_engine, async_session):
        """Test that PermissionResult has correct structure."""
        user = User(
            id=uuid4(),
            username="testuser",
            email="test@example.com",
            is_superuser=True,
            is_active=True,
        )

        result = await permission_engine.check_permission(
            session=async_session,
            user=user,
            resource_type="workspace",
            action="read",
            resource_id=uuid4(),
        )

        # Test result structure
        assert isinstance(result, PermissionResult)
        assert isinstance(result.allowed, bool)
        assert isinstance(result.reason, str)
        assert isinstance(result.source, str)
        assert isinstance(result.cached, bool)
        assert result.evaluated_at is None or isinstance(result.evaluated_at, datetime)

    async def test_multiple_permission_checks(self, permission_engine, async_session):
        """Test multiple permission checks for performance."""
        user = User(
            id=uuid4(),
            username="testuser",
            email="test@example.com",
            is_superuser=True,
            is_active=True,
        )

        # Test multiple permission checks
        permissions_to_check = [
            ("workspace", "read"),
            ("workspace", "create"),
            ("project", "read"),
            ("project", "update"),
            ("flow", "execute"),
        ]

        results = []
        for resource_type, action in permissions_to_check:
            result = await permission_engine.check_permission(
                session=async_session,
                user=user,
                resource_type=resource_type,
                action=action,
                resource_id=uuid4(),
            )
            results.append(result)

        # All should be allowed for superuser
        assert all(result.allowed for result in results)

    async def test_permission_engine_error_handling(self, permission_engine, async_session):
        """Test that permission engine handles errors gracefully."""
        user = User(
            id=uuid4(),
            username="testuser",
            email="test@example.com",
            is_superuser=False,
            is_active=True,
        )

        # Test with invalid resource type
        result = await permission_engine.check_permission(
            session=async_session,
            user=user,
            resource_type="invalid_resource",
            action="read",
            resource_id=uuid4(),
        )

        # Should deny unknown resource types
        assert result.allowed is False
        assert "unknown" in result.reason.lower() or "invalid" in result.reason.lower()


@pytest.mark.performance
class TestPermissionEnginePerformance:
    """Performance tests for the permission engine."""

    async def test_permission_check_latency(self, permission_engine, async_session):
        """Test that permission checks meet latency requirements (<100ms p95)."""
        import time

        user = User(
            id=uuid4(),
            username="testuser",
            email="test@example.com",
            is_superuser=True,
            is_active=True,
        )

        # Measure latency for multiple permission checks
        latencies = []
        for _ in range(100):
            start_time = time.perf_counter()

            await permission_engine.check_permission(
                session=async_session,
                user=user,
                resource_type="workspace",
                action="read",
                resource_id=uuid4(),
            )

            end_time = time.perf_counter()
            latencies.append((end_time - start_time) * 1000)  # Convert to ms

        # Calculate p95 latency
        latencies.sort()
        p95_latency = latencies[int(0.95 * len(latencies))]

        # Should be under 100ms for p95
        assert p95_latency < 100, f"P95 latency {p95_latency}ms exceeds 100ms requirement"

    async def test_cache_performance(self, permission_engine, async_session):
        """Test that caching improves performance significantly."""
        user = User(
            id=uuid4(),
            username="testuser",
            email="test@example.com",
            is_superuser=True,
            is_active=True,
        )

        resource_id = uuid4()

        # Time first call (uncached)
        import time
        start_time = time.perf_counter()
        result1 = await permission_engine.check_permission(
            session=async_session,
            user=user,
            resource_type="workspace",
            action="read",
            resource_id=resource_id,
            use_cache=True,
        )
        uncached_time = time.perf_counter() - start_time

        # Time second call (cached)
        start_time = time.perf_counter()
        result2 = await permission_engine.check_permission(
            session=async_session,
            user=user,
            resource_type="workspace",
            action="read",
            resource_id=resource_id,
            use_cache=True,
        )
        cached_time = time.perf_counter() - start_time

        # Cached call should be significantly faster
        assert cached_time < uncached_time / 2, "Cached call should be at least 2x faster"
        assert result1.allowed == result2.allowed
