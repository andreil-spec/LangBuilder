"""Unit tests for RBAC service business logic."""

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from langflow.services.rbac.permission_engine import PermissionDecision, PermissionResult
from langflow.services.rbac.service import RBACService


class TestRBACService:
    """Test cases for RBAC service."""

    @pytest.fixture
    def mock_cache_service(self):
        """Mock cache service."""
        cache_service = MagicMock()
        cache_service._client = MagicMock()
        return cache_service

    @pytest.fixture
    def rbac_service(self, mock_cache_service):
        """Create RBAC service instance."""
        return RBACService(cache_service=mock_cache_service)

    @pytest.fixture
    def mock_session(self):
        """Mock database session."""
        session = AsyncMock()
        return session

    @pytest.fixture
    def mock_user(self):
        """Mock user object."""
        user = MagicMock()
        user.id = uuid4()
        user.username = "test_user"
        user.email = "test@example.com"
        user.is_superuser = False
        return user

    @pytest.mark.asyncio
    async def test_evaluate_permission_success(self, rbac_service, mock_session, mock_user):
        """Test successful permission evaluation."""
        # Mock permission engine result
        expected_result = PermissionResult(
            decision=PermissionDecision.ALLOW,
            reason="Permission granted via role: editor",
            cached=False,
            evaluation_time_ms=50.0,
        )

        with patch.object(rbac_service.permission_engine, "check_permission", return_value=expected_result):
            with patch.object(rbac_service, "_log_permission_check", return_value=None):
                result = await rbac_service.evaluate_permission(
                    session=mock_session,
                    user=mock_user,
                    resource_type="flow",
                    action="read",
                    workspace_id="ws-123",
                )

        assert result.allowed is True
        assert result.decision == PermissionDecision.ALLOW
        assert result.reason == "Permission granted via role: editor"
        assert rbac_service._performance_metrics["permission_checks"] == 1
        assert rbac_service._performance_metrics["cache_misses"] == 1

    @pytest.mark.asyncio
    async def test_evaluate_permission_denied(self, rbac_service, mock_session, mock_user):
        """Test permission denial."""
        expected_result = PermissionResult(
            decision=PermissionDecision.DENY,
            reason="No applicable permissions found",
            cached=False,
            evaluation_time_ms=25.0,
        )

        with patch.object(rbac_service.permission_engine, "check_permission", return_value=expected_result):
            with patch.object(rbac_service, "_log_permission_check", return_value=None):
                result = await rbac_service.evaluate_permission(
                    session=mock_session,
                    user=mock_user,
                    resource_type="flow",
                    action="delete",
                )

        assert result.allowed is False
        assert result.decision == PermissionDecision.DENY

    @pytest.mark.asyncio
    async def test_evaluate_permission_cached(self, rbac_service, mock_session, mock_user):
        """Test cached permission evaluation."""
        cached_result = PermissionResult(
            decision=PermissionDecision.ALLOW,
            reason="Permission granted via role: editor",
            cached=True,
            evaluation_time_ms=5.0,
        )

        with patch.object(rbac_service.permission_engine, "check_permission", return_value=cached_result):
            with patch.object(rbac_service, "_log_permission_check", return_value=None):
                result = await rbac_service.evaluate_permission(
                    session=mock_session,
                    user=mock_user,
                    resource_type="flow",
                    action="read",
                )

        assert result.cached is True
        assert rbac_service._performance_metrics["cache_hits"] == 1

    @pytest.mark.asyncio
    async def test_batch_evaluate_permissions(self, rbac_service, mock_session, mock_user):
        """Test batch permission evaluation."""
        permission_requests = [
            {"resource_type": "flow", "action": "read"},
            {"resource_type": "flow", "action": "update"},
            {"resource_type": "environment", "action": "deploy"},
        ]

        expected_results = [
            PermissionResult(decision=PermissionDecision.ALLOW, reason="Allowed", cached=False),
            PermissionResult(decision=PermissionDecision.ALLOW, reason="Allowed", cached=False),
            PermissionResult(decision=PermissionDecision.DENY, reason="Denied", cached=False),
        ]

        with patch.object(rbac_service.permission_engine, "batch_check_permissions", return_value=expected_results):
            with patch.object(rbac_service, "_log_permission_check", return_value=None):
                results = await rbac_service.batch_evaluate_permissions(
                    session=mock_session,
                    user=mock_user,
                    permission_requests=permission_requests,
                )

        assert len(results) == 3
        assert results[0].allowed is True
        assert results[1].allowed is True
        assert results[2].allowed is False
        assert rbac_service._performance_metrics["permission_checks"] == 3

    @pytest.mark.asyncio
    async def test_assign_role_to_user_success(self, rbac_service, mock_session, mock_user):
        """Test successful role assignment."""
        from langflow.services.database.models.rbac.role import Role
        from langflow.services.database.models.user.model import User

        role_id = str(uuid4())
        user_id = str(uuid4())

        # Mock role and user
        mock_role = MagicMock(spec=Role)
        mock_role.id = role_id
        mock_role.is_active = True

        mock_target_user = MagicMock(spec=User)
        mock_target_user.id = user_id

        mock_session.get.side_effect = lambda model, id: {
            (Role, role_id): mock_role,
            (User, user_id): mock_target_user,
        }[(model, id)]

        # Mock no existing assignment
        mock_session.exec.return_value.first.return_value = None

        with patch.object(rbac_service, "_validate_role_assignment_scope", return_value=None):
            with patch.object(rbac_service.permission_engine, "invalidate_user_cache", return_value=None):
                with patch.object(rbac_service, "_log_role_assignment", return_value=None):
                    assignment = await rbac_service.assign_role_to_user(
                        session=mock_session,
                        user_id=user_id,
                        role_id=role_id,
                        scope_type="workspace",
                        scope_id="ws-123",
                        assigned_by=mock_user,
                    )

        assert assignment is not None
        mock_session.add.assert_called_once()
        mock_session.commit.assert_called()

    @pytest.mark.asyncio
    async def test_assign_role_duplicate_assignment(self, rbac_service, mock_session, mock_user):
        """Test duplicate role assignment error."""
        from langflow.services.database.models.rbac.role import Role
        from langflow.services.database.models.rbac.role_assignment import RoleAssignment
        from langflow.services.database.models.user.model import User

        role_id = str(uuid4())
        user_id = str(uuid4())

        # Mock role and user
        mock_role = MagicMock(spec=Role)
        mock_role.id = role_id
        mock_role.is_active = True

        mock_target_user = MagicMock(spec=User)
        mock_target_user.id = user_id

        mock_session.get.side_effect = lambda model, id: {
            (Role, role_id): mock_role,
            (User, user_id): mock_target_user,
        }[(model, id)]

        # Mock existing assignment
        existing_assignment = MagicMock(spec=RoleAssignment)
        mock_session.exec.return_value.first.return_value = existing_assignment

        with patch.object(rbac_service, "_validate_role_assignment_scope", return_value=None):
            with pytest.raises(ValueError, match="Role assignment already exists"):
                await rbac_service.assign_role_to_user(
                    session=mock_session,
                    user_id=user_id,
                    role_id=role_id,
                    scope_type="workspace",
                    scope_id="ws-123",
                    assigned_by=mock_user,
                )

    @pytest.mark.asyncio
    async def test_revoke_role_from_user(self, rbac_service, mock_session, mock_user):
        """Test role revocation."""
        from langflow.services.database.models.rbac.role_assignment import RoleAssignment

        assignment_id = str(uuid4())
        user_id = uuid4()

        # Mock assignment
        mock_assignment = MagicMock(spec=RoleAssignment)
        mock_assignment.id = assignment_id
        mock_assignment.user_id = user_id
        mock_assignment.is_active = True

        mock_session.get.return_value = mock_assignment

        with patch.object(rbac_service.permission_engine, "invalidate_user_cache", return_value=None):
            with patch.object(rbac_service, "_log_role_assignment", return_value=None):
                await rbac_service.revoke_role_from_user(
                    session=mock_session,
                    assignment_id=assignment_id,
                    revoked_by=mock_user,
                )

        assert mock_assignment.is_active is False
        assert mock_assignment.revoked_at is not None
        assert mock_assignment.revoked_by_id == mock_user.id
        mock_session.commit.assert_called()

    @pytest.mark.asyncio
    async def test_check_workspace_access_allowed(self, rbac_service, mock_session, mock_user):
        """Test workspace access check - allowed."""
        workspace_id = "ws-123"

        with patch.object(rbac_service, "evaluate_permission") as mock_evaluate:
            mock_evaluate.return_value = PermissionResult(
                decision=PermissionDecision.ALLOW,
                reason="User owns workspace",
                cached=False,
            )

            has_access = await rbac_service.check_workspace_access(
                session=mock_session,
                user=mock_user,
                workspace_id=workspace_id,
                required_action="read",
            )

        assert has_access is True
        mock_evaluate.assert_called_once_with(
            session=mock_session,
            user=mock_user,
            resource_type="workspace",
            action="read",
            resource_id=workspace_id,
            workspace_id=workspace_id,
        )

    @pytest.mark.asyncio
    async def test_validate_break_glass_access_success(self, rbac_service, mock_session, mock_user):
        """Test successful break-glass access validation."""
        justification = "Emergency production issue requires immediate access"
        target_resource_type = "environment"
        target_resource_id = "env-123"

        with patch.object(rbac_service, "evaluate_permission") as mock_evaluate:
            mock_evaluate.return_value = PermissionResult(
                decision=PermissionDecision.ALLOW,
                reason="User has break-glass permission",
                cached=False,
            )

            with patch.object(rbac_service, "_log_break_glass_access", return_value=None):
                result = await rbac_service.validate_break_glass_access(
                    session=mock_session,
                    user=mock_user,
                    justification=justification,
                    target_resource_type=target_resource_type,
                    target_resource_id=target_resource_id,
                )

        assert result is True

    @pytest.mark.asyncio
    async def test_validate_break_glass_access_insufficient_justification(self, rbac_service, mock_session, mock_user):
        """Test break-glass access with insufficient justification."""
        justification = "help"  # Too short

        with pytest.raises(ValueError, match="Break-glass access requires detailed justification"):
            await rbac_service.validate_break_glass_access(
                session=mock_session,
                user=mock_user,
                justification=justification,
                target_resource_type="environment",
                target_resource_id="env-123",
            )

    def test_get_performance_metrics(self, rbac_service):
        """Test performance metrics retrieval."""
        # Simulate some activity
        rbac_service._performance_metrics = {
            "permission_checks": 100,
            "cache_hits": 80,
            "cache_misses": 20,
            "avg_evaluation_time_ms": 25.5,
        }

        metrics = rbac_service.get_performance_metrics()

        assert metrics["permission_checks"] == 100
        assert metrics["cache_hits"] == 80
        assert metrics["cache_misses"] == 20
        assert metrics["avg_evaluation_time_ms"] == 25.5
        assert metrics["cache_hit_ratio"] == 0.8  # 80/100

    @pytest.mark.asyncio
    async def test_get_user_workspaces(self, rbac_service, mock_session, mock_user):
        """Test getting user's accessible workspaces."""
        from langflow.services.database.models.rbac.workspace import Workspace

        # Mock owned workspaces
        owned_workspace = MagicMock(spec=Workspace)
        owned_workspace.id = uuid4()
        owned_workspace.name = "Owned Workspace"

        # Mock assigned workspaces
        assigned_workspace = MagicMock(spec=Workspace)
        assigned_workspace.id = uuid4()
        assigned_workspace.name = "Assigned Workspace"

        mock_session.exec.side_effect = [
            MagicMock(all=lambda: [owned_workspace]),  # Owner query
            MagicMock(all=lambda: [assigned_workspace]),  # Assignment query
        ]

        workspaces = await rbac_service.get_user_workspaces(
            session=mock_session,
            user=mock_user,
        )

        assert len(workspaces) == 2
        workspace_names = [ws.name for ws in workspaces]
        assert "Owned Workspace" in workspace_names
        assert "Assigned Workspace" in workspace_names
