"""Tests for ConditionalPermissionService."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from langflow.services.rbac.conditional_permissions import (
    ConditionalPermission,
    ConditionalPermissionService,
    ConditionOperator,
    ConditionType,
    PermissionContext,
)


class TestConditionalPermissionService:
    """Test cases for ConditionalPermissionService."""

    @pytest.fixture
    def permission_service(self):
        """Create a ConditionalPermissionService instance."""
        service = ConditionalPermissionService()
        # Mock the policy manager to avoid real database calls
        service._policy_manager = AsyncMock()
        return service

    @pytest.fixture
    def mock_session(self):
        """Create a mock database session."""
        return AsyncMock()

    @pytest.fixture
    def sample_context(self):
        """Create a sample permission context."""
        return PermissionContext(
            user_id=str(uuid4()),
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0 (Test Browser)",
            session_id="test-session-123",
            timestamp=datetime(2024, 1, 15, 14, 30, 0, tzinfo=timezone.utc),  # Monday 2:30 PM UTC
            environment_type="production",
            workspace_id=str(uuid4()),
            mfa_verified=True,
            vpn_detected=False
        )

    @pytest.fixture
    def business_hours_condition(self):
        """Business hours time condition."""
        return {
            "type": ConditionType.TIME_WINDOW,
            "operator": ConditionOperator.BETWEEN,
            "value": {"start": "09:00", "end": "17:00"},
            "timezone": "UTC"
        }

    @pytest.fixture
    def ip_restriction_condition(self):
        """IP address restriction condition."""
        return {
            "type": ConditionType.IP_ADDRESS,
            "operator": ConditionOperator.IN,
            "value": ["192.168.1.0/24", "10.0.0.0/8"]
        }

    @pytest.fixture
    def mfa_required_condition(self):
        """MFA requirement condition."""
        return {
            "type": ConditionType.MFA_REQUIRED,
            "operator": ConditionOperator.EQUALS,
            "value": True
        }

    async def test_evaluate_conditional_permission_no_policies(self, permission_service, mock_session, sample_context):
        """Test evaluation when no conditional policies exist."""
        # Mock no policies found
        permission_service._policy_manager.get_policies_for_permission.return_value = []

        result = await permission_service.evaluate_conditional_permission(
            mock_session,
            "test.permission",
            sample_context
        )

        assert result["allowed"] is True
        assert result["reason"] == "No conditional restrictions"

    async def test_evaluate_conditional_permission_all_conditions_pass(
        self, permission_service, mock_session, sample_context,
        business_hours_condition, ip_restriction_condition, mfa_required_condition
    ):
        """Test evaluation when all conditions pass."""
        # Create conditional permission with multiple conditions
        conditional_perm = ConditionalPermission(
            permission="test.permission",
            conditions=[business_hours_condition, ip_restriction_condition, mfa_required_condition],
            enabled=True,
            priority=100,
            description="Test policy",
            failure_action="deny"
        )

        # Mock policy manager to return our test policy
        mock_policy = MagicMock()
        mock_policy.permission = "test.permission"
        mock_policy.conditions = {"conditions": conditional_perm.conditions}
        mock_policy.enabled = True
        mock_policy.priority = 100
        mock_policy.description = "Test policy"
        mock_policy.failure_action = "deny"
        mock_policy.bypass_roles = []

        permission_service._policy_manager.get_policies_for_permission.return_value = [mock_policy]

        # Mock bypass role check to return False
        with patch.object(permission_service, "_has_bypass_role", return_value=False):
            result = await permission_service.evaluate_conditional_permission(
                mock_session,
                "test.permission",
                sample_context
            )

        assert result["allowed"] is True
        assert result["reason"] == "All conditional restrictions satisfied"

    async def test_evaluate_conditional_permission_time_condition_fail(
        self, permission_service, mock_session, sample_context
    ):
        """Test evaluation when time condition fails."""
        # Create a condition that requires access outside business hours
        after_hours_condition = {
            "type": ConditionType.TIME_WINDOW,
            "operator": ConditionOperator.BETWEEN,
            "value": {"start": "18:00", "end": "08:00"},  # 6 PM to 8 AM
            "timezone": "UTC"
        }

        conditional_perm = ConditionalPermission(
            permission="test.permission",
            conditions=[after_hours_condition],
            enabled=True,
            priority=100,
            failure_action="deny"
        )

        # Mock policy
        mock_policy = MagicMock()
        mock_policy.permission = "test.permission"
        mock_policy.conditions = {"conditions": conditional_perm.conditions}
        mock_policy.enabled = True
        mock_policy.priority = 100
        mock_policy.description = "After hours only"
        mock_policy.failure_action = "deny"
        mock_policy.bypass_roles = []

        permission_service._policy_manager.get_policies_for_permission.return_value = [mock_policy]

        with patch.object(permission_service, "_has_bypass_role", return_value=False):
            result = await permission_service.evaluate_conditional_permission(
                mock_session,
                "test.permission",
                sample_context
            )

        assert result["allowed"] is False
        assert "Conditional restriction failed" in result["reason"]
        assert result["failure_action"] == "deny"

    async def test_evaluate_conditional_permission_require_approval(
        self, permission_service, mock_session, sample_context, ip_restriction_condition
    ):
        """Test evaluation when conditions fail but action is require_approval."""
        # Use IP that doesn't match the restriction
        context_with_external_ip = PermissionContext(
            user_id=sample_context.user_id,
            ip_address="203.0.113.1",  # External IP not in allowed ranges
            timestamp=sample_context.timestamp,
            mfa_verified=True
        )

        conditional_perm = ConditionalPermission(
            permission="test.permission",
            conditions=[ip_restriction_condition],
            enabled=True,
            priority=100,
            failure_action="require_approval"
        )

        # Mock policy
        mock_policy = MagicMock()
        mock_policy.permission = "test.permission"
        mock_policy.conditions = {"conditions": conditional_perm.conditions}
        mock_policy.enabled = True
        mock_policy.priority = 100
        mock_policy.description = "IP restriction policy"
        mock_policy.failure_action = "require_approval"
        mock_policy.bypass_roles = []

        permission_service._policy_manager.get_policies_for_permission.return_value = [mock_policy]

        with patch.object(permission_service, "_has_bypass_role", return_value=False):
            result = await permission_service.evaluate_conditional_permission(
                mock_session,
                "test.permission",
                context_with_external_ip
            )

        assert result["allowed"] is False
        assert result["require_approval"] is True
        assert "Approval required" in result["reason"]

    async def test_evaluate_conditional_permission_with_bypass_role(
        self, permission_service, mock_session, sample_context, business_hours_condition
    ):
        """Test evaluation when user has bypass role."""
        conditional_perm = ConditionalPermission(
            permission="test.permission",
            conditions=[business_hours_condition],
            enabled=True,
            priority=100,
            failure_action="deny",
            bypass_roles=["admin", "emergency_access"]
        )

        # Mock policy
        mock_policy = MagicMock()
        mock_policy.permission = "test.permission"
        mock_policy.conditions = {"conditions": conditional_perm.conditions}
        mock_policy.enabled = True
        mock_policy.priority = 100
        mock_policy.failure_action = "deny"
        mock_policy.bypass_roles = ["admin", "emergency_access"]

        permission_service._policy_manager.get_policies_for_permission.return_value = [mock_policy]

        # Mock bypass role check to return True
        with patch.object(permission_service, "_has_bypass_role", return_value=True):
            result = await permission_service.evaluate_conditional_permission(
                mock_session,
                "test.permission",
                sample_context
            )

        assert result["allowed"] is True
        assert result["reason"] == "User has bypass role"

    async def test_evaluate_time_condition_within_business_hours(self, permission_service, sample_context):
        """Test time condition evaluation during business hours."""
        condition = {
            "type": ConditionType.TIME_WINDOW,
            "operator": ConditionOperator.BETWEEN,
            "value": {"start": "09:00", "end": "17:00"},
            "timezone": "UTC"
        }

        result = await permission_service.evaluate_time_condition(condition, sample_context)

        assert result["met"] is True
        assert "within allowed window" in result["details"]

    async def test_evaluate_time_condition_outside_business_hours(self, permission_service):
        """Test time condition evaluation outside business hours."""
        # Create context for 8 PM (20:00)
        evening_context = PermissionContext(
            user_id=str(uuid4()),
            timestamp=datetime(2024, 1, 15, 20, 0, 0, tzinfo=timezone.utc)
        )

        condition = {
            "type": ConditionType.TIME_WINDOW,
            "operator": ConditionOperator.BETWEEN,
            "value": {"start": "09:00", "end": "17:00"},
            "timezone": "UTC"
        }

        result = await permission_service.evaluate_time_condition(condition, evening_context)

        assert result["met"] is False
        assert "outside allowed window" in result["details"]

    async def test_evaluate_time_condition_overnight_range(self, permission_service):
        """Test time condition with overnight range (e.g., 22:00-06:00)."""
        # Test at 2 AM (within overnight range)
        night_context = PermissionContext(
            user_id=str(uuid4()),
            timestamp=datetime(2024, 1, 15, 2, 0, 0, tzinfo=timezone.utc)
        )

        condition = {
            "type": ConditionType.TIME_WINDOW,
            "operator": ConditionOperator.BETWEEN,
            "value": {"start": "22:00", "end": "06:00"},  # Overnight range
            "timezone": "UTC"
        }

        result = await permission_service.evaluate_time_condition(condition, night_context)

        assert result["met"] is True
        assert "within allowed window" in result["details"]

    async def test_evaluate_ip_condition_allowed_ip(self, permission_service, sample_context):
        """Test IP condition with allowed IP address."""
        condition = {
            "type": ConditionType.IP_ADDRESS,
            "operator": ConditionOperator.IN,
            "value": ["192.168.1.0/24", "10.0.0.0/8"]
        }

        result = await permission_service.evaluate_ip_condition(condition, sample_context)

        assert result["met"] is True
        assert "allowed by rule" in result["details"]

    async def test_evaluate_ip_condition_blocked_ip(self, permission_service):
        """Test IP condition with blocked IP address."""
        external_context = PermissionContext(
            user_id=str(uuid4()),
            ip_address="203.0.113.1"  # External IP
        )

        condition = {
            "type": ConditionType.IP_ADDRESS,
            "operator": ConditionOperator.IN,
            "value": ["192.168.1.0/24", "10.0.0.0/8"]
        }

        result = await permission_service.evaluate_ip_condition(condition, external_context)

        assert result["met"] is False
        assert "denied by rule" in result["details"]

    async def test_evaluate_ip_condition_no_ip_provided(self, permission_service):
        """Test IP condition when no IP address is provided."""
        no_ip_context = PermissionContext(
            user_id=str(uuid4()),
            ip_address=None
        )

        condition = {
            "type": ConditionType.IP_ADDRESS,
            "operator": ConditionOperator.IN,
            "value": ["192.168.1.0/24"]
        }

        result = await permission_service.evaluate_ip_condition(condition, no_ip_context)

        assert result["met"] is False
        assert "No IP address provided" in result["details"]

    async def test_evaluate_geolocation_condition_allowed_country(self, permission_service):
        """Test geolocation condition with allowed country."""
        geo_context = PermissionContext(
            user_id=str(uuid4()),
            geolocation={"country": "US", "region": "California"}
        )

        condition = {
            "type": ConditionType.GEOLOCATION,
            "operator": ConditionOperator.IN,
            "value": ["US", "CA", "GB"]
        }

        result = await permission_service.evaluate_geolocation_condition(condition, geo_context)

        assert result["met"] is True
        assert "allowed by rule" in result["details"]

    async def test_evaluate_geolocation_condition_blocked_country(self, permission_service):
        """Test geolocation condition with blocked country."""
        geo_context = PermissionContext(
            user_id=str(uuid4()),
            geolocation={"country": "CN", "region": "Beijing"}
        )

        condition = {
            "type": ConditionType.GEOLOCATION,
            "operator": ConditionOperator.IN,
            "value": ["US", "CA", "GB"]
        }

        result = await permission_service.evaluate_geolocation_condition(condition, geo_context)

        assert result["met"] is False
        assert "denied by rule" in result["details"]

    async def test_evaluate_mfa_condition_verified(self, permission_service, sample_context):
        """Test MFA condition when MFA is verified."""
        condition = {
            "type": ConditionType.MFA_REQUIRED,
            "operator": ConditionOperator.EQUALS,
            "value": True
        }

        result = await permission_service.evaluate_mfa_condition(condition, sample_context)

        assert result["met"] is True
        assert "MFA verified" in result["details"]

    async def test_evaluate_mfa_condition_not_verified(self, permission_service):
        """Test MFA condition when MFA is not verified."""
        no_mfa_context = PermissionContext(
            user_id=str(uuid4()),
            mfa_verified=False
        )

        condition = {
            "type": ConditionType.MFA_REQUIRED,
            "operator": ConditionOperator.EQUALS,
            "value": True
        }

        result = await permission_service.evaluate_mfa_condition(condition, no_mfa_context)

        assert result["met"] is False
        assert "MFA not verified" in result["details"]

    async def test_evaluate_rate_limit_condition_within_limit(self, permission_service, mock_session, sample_context):
        """Test rate limit condition when within allowed limits."""
        condition = {
            "type": ConditionType.REQUEST_RATE,
            "operator": ConditionOperator.LESS_EQUAL,
            "value": 10,
            "window": 3600
        }

        # Mock recent request count to be within limit
        with patch.object(permission_service, "_get_recent_request_count", return_value=5):
            result = await permission_service.evaluate_rate_limit_condition(
                mock_session, condition, sample_context
            )

        assert result["met"] is True
        assert "Recent requests: 5/10" in result["details"]

    async def test_evaluate_rate_limit_condition_over_limit(self, permission_service, mock_session, sample_context):
        """Test rate limit condition when over allowed limits."""
        condition = {
            "type": ConditionType.REQUEST_RATE,
            "operator": ConditionOperator.LESS_EQUAL,
            "value": 5,
            "window": 3600
        }

        # Mock recent request count to be over limit
        with patch.object(permission_service, "_get_recent_request_count", return_value=10):
            result = await permission_service.evaluate_rate_limit_condition(
                mock_session, condition, sample_context
            )

        assert result["met"] is False
        assert "Recent requests: 10/5" in result["details"]

    async def test_add_conditional_permission(self, permission_service, mock_session, business_hours_condition):
        """Test adding a new conditional permission."""
        # Mock policy manager create_policy method
        mock_policy = MagicMock()
        mock_policy.id = str(uuid4())
        permission_service._policy_manager.create_policy.return_value = mock_policy

        result = await permission_service.add_conditional_permission(
            session=mock_session,
            workspace_id=str(uuid4()),
            permission="test.permission",
            conditions=[business_hours_condition],
            priority=100,
            description="Test policy",
            failure_action="deny",
            created_by=str(uuid4())
        )

        assert result["success"] is True
        assert "policy_id" in result
        permission_service._policy_manager.create_policy.assert_called_once()

    async def test_multiple_policies_priority_ordering(self, permission_service, mock_session, sample_context):
        """Test that policies are evaluated in priority order."""
        # Create policies with different priorities
        high_priority_policy = MagicMock()
        high_priority_policy.permission = "test.permission"
        high_priority_policy.conditions = {"conditions": []}
        high_priority_policy.enabled = True
        high_priority_policy.priority = 200
        high_priority_policy.description = "High priority"
        high_priority_policy.failure_action = "deny"
        high_priority_policy.bypass_roles = []

        low_priority_policy = MagicMock()
        low_priority_policy.permission = "test.permission"
        low_priority_policy.conditions = {"conditions": []}
        low_priority_policy.enabled = True
        low_priority_policy.priority = 100
        low_priority_policy.description = "Low priority"
        low_priority_policy.failure_action = "log_only"
        low_priority_policy.bypass_roles = []

        # Return policies in reverse priority order to test sorting
        permission_service._policy_manager.get_policies_for_permission.return_value = [
            low_priority_policy, high_priority_policy
        ]

        with patch.object(permission_service, "_has_bypass_role", return_value=False):
            result = await permission_service.evaluate_conditional_permission(
                mock_session,
                "test.permission",
                sample_context
            )

        # Should succeed because policies with empty conditions always pass
        assert result["allowed"] is True

    async def test_caching_mechanism(self, permission_service, mock_session, sample_context):
        """Test that results are cached and reused."""
        # Mock no policies
        permission_service._policy_manager.get_policies_for_permission.return_value = []

        # First call
        result1 = await permission_service.evaluate_conditional_permission(
            mock_session,
            "test.permission",
            sample_context
        )

        # Second call with same context should use cache
        result2 = await permission_service.evaluate_conditional_permission(
            mock_session,
            "test.permission",
            sample_context
        )

        assert result1 == result2
        # Policy manager should only be called once due to caching
        assert permission_service._policy_manager.get_policies_for_permission.call_count == 1

    async def test_error_handling(self, permission_service, mock_session, sample_context):
        """Test error handling in evaluation."""
        # Mock policy manager to raise an exception
        permission_service._policy_manager.get_policies_for_permission.side_effect = Exception("Database error")

        result = await permission_service.evaluate_conditional_permission(
            mock_session,
            "test.permission",
            sample_context
        )

        assert result["allowed"] is False
        assert "Evaluation error" in result["reason"]

    def test_validate_conditions_success(self, permission_service):
        """Test successful condition validation."""
        conditions = [
            {
                "type": "time_window",
                "operator": "between",
                "value": {"start": "09:00", "end": "17:00"}
            }
        ]

        result = permission_service._validate_conditions(conditions)
        assert result["valid"] is True

    def test_validate_conditions_missing_type(self, permission_service):
        """Test condition validation with missing type."""
        conditions = [
            {
                "operator": "between",
                "value": {"start": "09:00", "end": "17:00"}
            }
        ]

        result = permission_service._validate_conditions(conditions)
        assert result["valid"] is False
        assert "missing 'type' field" in result["error"]

    def test_validate_conditions_invalid_type(self, permission_service):
        """Test condition validation with invalid type."""
        conditions = [
            {
                "type": "invalid_type",
                "operator": "equals",
                "value": "test"
            }
        ]

        result = permission_service._validate_conditions(conditions)
        assert result["valid"] is False
        assert "Invalid condition type" in result["error"]

    def test_validate_conditions_invalid_operator(self, permission_service):
        """Test condition validation with invalid operator."""
        conditions = [
            {
                "type": "time_window",
                "operator": "invalid_operator",
                "value": {"start": "09:00", "end": "17:00"}
            }
        ]

        result = permission_service._validate_conditions(conditions)
        assert result["valid"] is False
        assert "Invalid operator" in result["error"]
