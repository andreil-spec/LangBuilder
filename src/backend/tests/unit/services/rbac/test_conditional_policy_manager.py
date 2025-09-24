"""Tests for ConditionalPolicyManager service."""

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from langflow.services.database.models.rbac.conditional_policy import (
    ConditionalPolicy,
    ConditionalPolicyEvaluation,
)
from langflow.services.rbac.conditional_policy_manager import ConditionalPolicyManager


class TestConditionalPolicyManager:
    """Test cases for ConditionalPolicyManager."""

    @pytest.fixture
    def policy_manager(self):
        """Create a ConditionalPolicyManager instance."""
        return ConditionalPolicyManager()

    @pytest.fixture
    def mock_session(self):
        """Create a mock database session."""
        session = AsyncMock()
        return session

    @pytest.fixture
    def sample_conditions(self):
        """Sample conditions for testing."""
        return [
            {
                "type": "time_window",
                "operator": "between",
                "value": {"start": "09:00", "end": "17:00"},
                "timezone": "UTC"
            },
            {
                "type": "ip_address",
                "operator": "in",
                "value": ["10.0.0.0/8", "172.16.0.0/12"]
            }
        ]

    @pytest.fixture
    def sample_policy_data(self, sample_conditions):
        """Sample policy data for testing."""
        return {
            "name": "Test Business Hours Policy",
            "description": "Test policy for business hours access",
            "permission": "flows.deploy",
            "workspace_id": str(uuid4()),
            "conditions": sample_conditions,
            "priority": 100,
            "failure_action": "require_approval",
            "enabled": True
        }

    async def test_create_policy_success(self, policy_manager, mock_session, sample_policy_data):
        """Test successful policy creation."""
        # Mock the database operations
        mock_session.add = MagicMock()
        mock_session.commit = AsyncMock()
        mock_session.refresh = AsyncMock()

        # Mock policy validation
        with patch.object(policy_manager, "_validate_conditions", return_value={"valid": True}):
            # Create policy
            policy = await policy_manager.create_policy(
                session=mock_session,
                created_by_id=str(uuid4()),
                **sample_policy_data
            )

            # Verify policy creation
            assert policy is not None
            assert policy.name == sample_policy_data["name"]
            assert policy.permission == sample_policy_data["permission"]
            assert policy.enabled == sample_policy_data["enabled"]
            assert policy.priority == sample_policy_data["priority"]
            assert policy.conditions["conditions"] == sample_policy_data["conditions"]

            # Verify database operations were called
            mock_session.add.assert_called()
            mock_session.commit.assert_called_once()

    async def test_create_policy_invalid_conditions(self, policy_manager, mock_session, sample_policy_data):
        """Test policy creation with invalid conditions."""
        # Mock validation to return error
        with patch.object(policy_manager, "_validate_conditions",
                         return_value={"valid": False, "error": "Invalid condition type"}):

            with pytest.raises(ValueError, match="Invalid condition type"):
                await policy_manager.create_policy(
                    session=mock_session,
                    created_by_id=str(uuid4()),
                    **sample_policy_data
                )

    async def test_get_policy_by_id_exists(self, policy_manager, mock_session):
        """Test getting an existing policy by ID."""
        # Mock policy
        policy_id = str(uuid4())
        mock_policy = ConditionalPolicy(
            id=policy_id,
            name="Test Policy",
            permission="test.permission",
            conditions={"conditions": []},
            enabled=True
        )

        # Mock database query
        mock_result = MagicMock()
        mock_result.first.return_value = mock_policy
        mock_session.exec.return_value = mock_result

        # Get policy
        result = await policy_manager.get_policy_by_id(mock_session, policy_id)

        # Verify result
        assert result == mock_policy
        mock_session.exec.assert_called_once()

    async def test_get_policy_by_id_not_exists(self, policy_manager, mock_session):
        """Test getting a non-existent policy by ID."""
        # Mock empty result
        mock_result = MagicMock()
        mock_result.first.return_value = None
        mock_session.exec.return_value = mock_result

        # Get policy
        result = await policy_manager.get_policy_by_id(mock_session, str(uuid4()))

        # Verify result
        assert result is None

    async def test_get_policies_for_permission(self, policy_manager, mock_session):
        """Test getting policies for a specific permission."""
        # Mock policies
        policies = [
            ConditionalPolicy(
                id=str(uuid4()),
                name="Policy 1",
                permission="test.permission",
                conditions={"conditions": []},
                enabled=True,
                priority=100
            ),
            ConditionalPolicy(
                id=str(uuid4()),
                name="Policy 2",
                permission="test.permission",
                conditions={"conditions": []},
                enabled=True,
                priority=200
            )
        ]

        # Mock database query
        mock_result = MagicMock()
        mock_result.all.return_value = policies
        mock_session.exec.return_value = mock_result

        # Get policies
        result = await policy_manager.get_policies_for_permission(
            mock_session,
            "test.permission",
            enabled_only=True
        )

        # Verify result
        assert len(result) == 2
        assert result[0].priority == 200  # Should be sorted by priority descending
        assert result[1].priority == 100

    async def test_update_policy_success(self, policy_manager, mock_session):
        """Test successful policy update."""
        # Mock existing policy
        policy_id = str(uuid4())
        mock_policy = ConditionalPolicy(
            id=policy_id,
            name="Old Name",
            permission="test.permission",
            conditions={"conditions": []},
            enabled=True,
            version=1
        )

        mock_result = MagicMock()
        mock_result.first.return_value = mock_policy
        mock_session.exec.return_value = mock_result
        mock_session.commit = AsyncMock()
        mock_session.refresh = AsyncMock()

        # Update policy
        updated_policy = await policy_manager.update_policy(
            session=mock_session,
            policy_id=policy_id,
            name="New Name",
            enabled=False,
            updated_by_id=str(uuid4())
        )

        # Verify update
        assert updated_policy.name == "New Name"
        assert updated_policy.enabled is False
        assert updated_policy.version == 2  # Version should be incremented
        mock_session.commit.assert_called_once()

    async def test_delete_policy_success(self, policy_manager, mock_session):
        """Test successful policy deletion."""
        # Mock existing policy
        policy_id = str(uuid4())
        mock_policy = ConditionalPolicy(
            id=policy_id,
            name="Test Policy",
            permission="test.permission",
            conditions={"conditions": []},
            enabled=True
        )

        mock_result = MagicMock()
        mock_result.first.return_value = mock_policy
        mock_session.exec.return_value = mock_result
        mock_session.delete = MagicMock()
        mock_session.commit = AsyncMock()

        # Delete policy
        success = await policy_manager.delete_policy(mock_session, policy_id)

        # Verify deletion
        assert success is True
        mock_session.delete.assert_called_once_with(mock_policy)
        mock_session.commit.assert_called_once()

    async def test_toggle_policy_status(self, policy_manager, mock_session):
        """Test toggling policy enabled status."""
        # Mock existing policy
        policy_id = str(uuid4())
        mock_policy = ConditionalPolicy(
            id=policy_id,
            name="Test Policy",
            permission="test.permission",
            conditions={"conditions": []},
            enabled=True
        )

        mock_result = MagicMock()
        mock_result.first.return_value = mock_policy
        mock_session.exec.return_value = mock_result
        mock_session.commit = AsyncMock()
        mock_session.refresh = AsyncMock()

        # Toggle policy
        updated_policy = await policy_manager.toggle_policy_status(
            session=mock_session,
            policy_id=policy_id,
            updated_by_id=str(uuid4())
        )

        # Verify toggle
        assert updated_policy.enabled is False  # Should be toggled from True to False
        mock_session.commit.assert_called_once()

    async def test_log_policy_evaluation(self, policy_manager, mock_session):
        """Test logging policy evaluation."""
        mock_session.add = MagicMock()
        mock_session.commit = AsyncMock()

        # Log evaluation
        await policy_manager.log_policy_evaluation(
            session=mock_session,
            policy_id=str(uuid4()),
            user_id=str(uuid4()),
            permission="test.permission",
            evaluation_context={"ip_address": "192.168.1.1"},
            conditions_evaluated={"time_check": True},
            result="allowed",
            decision_reason="All conditions met",
            execution_time_ms=15.5
        )

        # Verify logging
        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()

        # Check the logged evaluation object
        call_args = mock_session.add.call_args[0]
        evaluation = call_args[0]
        assert isinstance(evaluation, ConditionalPolicyEvaluation)
        assert evaluation.result == "allowed"
        assert evaluation.execution_time_ms == 15.5

    async def test_get_policy_analytics(self, policy_manager, mock_session):
        """Test getting policy analytics."""
        policy_id = str(uuid4())

        # Mock policy
        mock_policy = ConditionalPolicy(
            id=policy_id,
            name="Test Policy",
            permission="test.permission",
            conditions={"conditions": []},
            enabled=True,
            evaluation_count=100
        )

        # Mock evaluations
        mock_evaluations = [
            ConditionalPolicyEvaluation(result="allowed", execution_time_ms=10.0),
            ConditionalPolicyEvaluation(result="denied", execution_time_ms=15.0),
            ConditionalPolicyEvaluation(result="allowed", execution_time_ms=12.0),
        ]

        # Mock database queries
        mock_session.exec.side_effect = [
            MagicMock(first=lambda: mock_policy),  # Policy query
            MagicMock(all=lambda: mock_evaluations)  # Evaluations query
        ]

        # Get analytics
        analytics = await policy_manager.get_policy_analytics(mock_session, policy_id)

        # Verify analytics
        assert analytics.policy_id == policy_id
        assert analytics.policy_name == "Test Policy"
        assert analytics.evaluation_count == 100
        assert analytics.allow_rate == 2/3  # 2 allowed out of 3 total
        assert analytics.deny_rate == 1/3   # 1 denied out of 3 total
        assert analytics.avg_execution_time_ms == (10.0 + 15.0 + 12.0) / 3

    def test_validate_conditions_valid(self, policy_manager):
        """Test condition validation with valid conditions."""
        conditions = [
            {
                "type": "time_window",
                "operator": "between",
                "value": {"start": "09:00", "end": "17:00"}
            }
        ]

        result = policy_manager._validate_conditions(conditions)
        assert result["valid"] is True

    def test_validate_conditions_invalid_type(self, policy_manager):
        """Test condition validation with invalid condition type."""
        conditions = [
            {
                "type": "invalid_type",
                "operator": "equals",
                "value": "test"
            }
        ]

        result = policy_manager._validate_conditions(conditions)
        assert result["valid"] is False
        assert "Invalid condition type" in result["error"]

    def test_validate_conditions_missing_field(self, policy_manager):
        """Test condition validation with missing required field."""
        conditions = [
            {
                "type": "time_window",
                # Missing operator
                "value": {"start": "09:00", "end": "17:00"}
            }
        ]

        result = policy_manager._validate_conditions(conditions)
        assert result["valid"] is False
        assert "missing 'operator' field" in result["error"]

    def test_validate_conditions_invalid_operator(self, policy_manager):
        """Test condition validation with invalid operator."""
        conditions = [
            {
                "type": "time_window",
                "operator": "invalid_operator",
                "value": {"start": "09:00", "end": "17:00"}
            }
        ]

        result = policy_manager._validate_conditions(conditions)
        assert result["valid"] is False
        assert "Invalid operator" in result["error"]

    async def test_create_template_success(self, policy_manager, mock_session):
        """Test successful template creation."""
        mock_session.add = MagicMock()
        mock_session.commit = AsyncMock()
        mock_session.refresh = AsyncMock()

        # Create template
        template = await policy_manager.create_template(
            session=mock_session,
            name="Business Hours Template",
            description="Template for business hours restrictions",
            category="security",
            conditions_template=[
                {
                    "type": "time_window",
                    "operator": "between",
                    "value": {"start": "09:00", "end": "17:00"}
                }
            ],
            default_priority=100,
            default_failure_action="require_approval",
            created_by_id=str(uuid4())
        )

        # Verify template creation
        assert template is not None
        assert template.name == "Business Hours Template"
        assert template.category == "security"
        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()

    async def test_bulk_operations(self, policy_manager, mock_session):
        """Test bulk policy operations."""
        policy_ids = [str(uuid4()), str(uuid4()), str(uuid4())]

        # Mock policies
        policies = [
            ConditionalPolicy(id=pid, enabled=True, name=f"Policy {i}")
            for i, pid in enumerate(policy_ids)
        ]

        # Mock database queries for each policy
        mock_session.exec.side_effect = [
            MagicMock(first=lambda: policy) for policy in policies
        ]
        mock_session.commit = AsyncMock()

        # Test bulk disable
        results = []
        for policy_id in policy_ids:
            success = await policy_manager.disable_policy(
                session=mock_session,
                policy_id=policy_id,
                updated_by_id=str(uuid4())
            )
            results.append(success)

        # Verify all operations succeeded
        assert all(results)
        assert mock_session.commit.call_count == len(policy_ids)

    async def test_error_handling(self, policy_manager, mock_session):
        """Test error handling in policy operations."""
        # Mock database error
        mock_session.commit.side_effect = Exception("Database error")

        with pytest.raises(Exception, match="Database error"):
            await policy_manager.create_policy(
                session=mock_session,
                name="Test Policy",
                permission="test.permission",
                conditions=[],
                created_by_id=str(uuid4())
            )
