"""Tests for conditional policy API endpoints."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import HTTPException
from langflow.api.v1.schemas.conditional_policy_schemas import (
    ConditionalPolicyCreate,
    ConditionalPolicyRead,
    ConditionalPolicyUpdate,
    PolicyEvaluationRequest,
    PolicyEvaluationResult,
)
from langflow.services.database.models.rbac.conditional_policy import ConditionalPolicy


class TestConditionalPolicyAPI:
    """Test cases for conditional policy API endpoints."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock database session."""
        return AsyncMock()

    @pytest.fixture
    def mock_user(self):
        """Create a mock authenticated user."""
        user = MagicMock()
        user.id = str(uuid4())
        user.is_active = True
        return user

    @pytest.fixture
    def sample_policy_data(self):
        """Sample policy creation data."""
        return {
            "name": "Test Business Hours Policy",
            "description": "Test policy for business hours access",
            "permission": "flows.deploy",
            "workspace_id": str(uuid4()),
            "conditions": [
                {
                    "type": "time_window",
                    "operator": "between",
                    "value": {"start": "09:00", "end": "17:00"},
                    "timezone": "UTC"
                }
            ],
            "enabled": True,
            "priority": 100,
            "failure_action": "require_approval",
            "bypass_roles": ["admin"]
        }

    @pytest.fixture
    def sample_policy(self, sample_policy_data):
        """Sample policy object."""
        policy = ConditionalPolicy(
            id=str(uuid4()),
            name=sample_policy_data["name"],
            description=sample_policy_data["description"],
            permission=sample_policy_data["permission"],
            workspace_id=sample_policy_data["workspace_id"],
            conditions={"conditions": sample_policy_data["conditions"]},
            enabled=sample_policy_data["enabled"],
            priority=sample_policy_data["priority"],
            failure_action=sample_policy_data["failure_action"],
            bypass_roles=sample_policy_data["bypass_roles"],
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            version=1,
            evaluation_count=0
        )
        return policy

    @patch("langflow.api.v1.rbac_advanced.ConditionalPolicyManager")
    @patch("langflow.api.v1.rbac_advanced.get_current_active_user")
    @patch("langflow.api.v1.rbac_advanced.get_session")
    async def test_create_conditional_policy_success(
        self, mock_get_session, mock_get_user, mock_policy_manager_class,
        sample_policy_data, sample_policy, mock_session, mock_user
    ):
        """Test successful policy creation."""
        # Setup mocks
        mock_get_session.return_value = mock_session
        mock_get_user.return_value = mock_user
        mock_policy_manager = AsyncMock()
        mock_policy_manager.create_policy.return_value = sample_policy
        mock_policy_manager_class.return_value = mock_policy_manager

        # Import the endpoint function
        from langflow.api.v1.rbac_advanced import create_conditional_policy

        # Create policy request
        policy_request = ConditionalPolicyCreate(**sample_policy_data)

        # Call endpoint
        result = await create_conditional_policy(
            policy_data=policy_request,
            current_user=mock_user,
            session=mock_session
        )

        # Verify result
        assert isinstance(result, ConditionalPolicyRead)
        assert result.name == sample_policy_data["name"]
        assert result.permission == sample_policy_data["permission"]

        # Verify policy manager was called
        mock_policy_manager.create_policy.assert_called_once()

    @patch("langflow.api.v1.rbac_advanced.ConditionalPolicyManager")
    @patch("langflow.api.v1.rbac_advanced.get_current_active_user")
    @patch("langflow.api.v1.rbac_advanced.get_session")
    async def test_create_conditional_policy_error(
        self, mock_get_session, mock_get_user, mock_policy_manager_class,
        sample_policy_data, mock_session, mock_user
    ):
        """Test policy creation error handling."""
        # Setup mocks
        mock_get_session.return_value = mock_session
        mock_get_user.return_value = mock_user
        mock_policy_manager = AsyncMock()
        mock_policy_manager.create_policy.side_effect = Exception("Database error")
        mock_policy_manager_class.return_value = mock_policy_manager

        # Import the endpoint function
        from langflow.api.v1.rbac_advanced import create_conditional_policy

        # Create policy request
        policy_request = ConditionalPolicyCreate(**sample_policy_data)

        # Call endpoint and expect error
        with pytest.raises(HTTPException) as exc_info:
            await create_conditional_policy(
                policy_data=policy_request,
                current_user=mock_user,
                session=mock_session
            )

        assert exc_info.value.status_code == 500
        assert "Internal error creating conditional policy" in str(exc_info.value.detail)

    @patch("langflow.api.v1.rbac_advanced.ConditionalPolicyManager")
    @patch("langflow.api.v1.rbac_advanced.get_current_active_user")
    @patch("langflow.api.v1.rbac_advanced.get_session")
    async def test_list_conditional_policies_success(
        self, mock_get_session, mock_get_user, mock_policy_manager_class,
        sample_policy, mock_session, mock_user
    ):
        """Test successful policy listing."""
        # Setup mocks
        mock_get_session.return_value = mock_session
        mock_get_user.return_value = mock_user
        mock_policy_manager = AsyncMock()
        mock_policy_manager.get_all_policies.return_value = [sample_policy]
        mock_policy_manager_class.return_value = mock_policy_manager

        # Import the endpoint function
        from langflow.api.v1.rbac_advanced import list_conditional_policies

        # Call endpoint
        result = await list_conditional_policies(
            permission=None,
            workspace_id=None,
            enabled_only=True,
            current_user=mock_user,
            session=mock_session
        )

        # Verify result
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], ConditionalPolicyRead)
        assert result[0].name == sample_policy.name

    @patch("langflow.api.v1.rbac_advanced.ConditionalPolicyManager")
    @patch("langflow.api.v1.rbac_advanced.get_current_active_user")
    @patch("langflow.api.v1.rbac_advanced.get_session")
    async def test_list_conditional_policies_with_permission_filter(
        self, mock_get_session, mock_get_user, mock_policy_manager_class,
        sample_policy, mock_session, mock_user
    ):
        """Test policy listing with permission filter."""
        # Setup mocks
        mock_get_session.return_value = mock_session
        mock_get_user.return_value = mock_user
        mock_policy_manager = AsyncMock()
        mock_policy_manager.get_policies_for_permission.return_value = [sample_policy]
        mock_policy_manager_class.return_value = mock_policy_manager

        # Import the endpoint function
        from langflow.api.v1.rbac_advanced import list_conditional_policies

        # Call endpoint with permission filter
        result = await list_conditional_policies(
            permission="flows.deploy",
            workspace_id=None,
            enabled_only=True,
            current_user=mock_user,
            session=mock_session
        )

        # Verify result
        assert len(result) == 1
        mock_policy_manager.get_policies_for_permission.assert_called_once_with(
            session=mock_session,
            permission="flows.deploy",
            workspace_id=None,
            enabled_only=True
        )

    @patch("langflow.api.v1.rbac_advanced.ConditionalPolicyManager")
    @patch("langflow.api.v1.rbac_advanced.get_current_active_user")
    @patch("langflow.api.v1.rbac_advanced.get_session")
    async def test_get_conditional_policy_success(
        self, mock_get_session, mock_get_user, mock_policy_manager_class,
        sample_policy, mock_session, mock_user
    ):
        """Test successful policy retrieval."""
        # Setup mocks
        mock_get_session.return_value = mock_session
        mock_get_user.return_value = mock_user
        mock_policy_manager = AsyncMock()
        mock_policy_manager.get_policy_by_id.return_value = sample_policy
        mock_policy_manager_class.return_value = mock_policy_manager

        # Import the endpoint function
        from langflow.api.v1.rbac_advanced import get_conditional_policy

        # Call endpoint
        result = await get_conditional_policy(
            policy_id=sample_policy.id,
            current_user=mock_user,
            session=mock_session
        )

        # Verify result
        assert isinstance(result, ConditionalPolicyRead)
        assert result.id == sample_policy.id
        assert result.name == sample_policy.name

    @patch("langflow.api.v1.rbac_advanced.ConditionalPolicyManager")
    @patch("langflow.api.v1.rbac_advanced.get_current_active_user")
    @patch("langflow.api.v1.rbac_advanced.get_session")
    async def test_get_conditional_policy_not_found(
        self, mock_get_session, mock_get_user, mock_policy_manager_class,
        mock_session, mock_user
    ):
        """Test policy retrieval when policy not found."""
        # Setup mocks
        mock_get_session.return_value = mock_session
        mock_get_user.return_value = mock_user
        mock_policy_manager = AsyncMock()
        mock_policy_manager.get_policy_by_id.return_value = None
        mock_policy_manager_class.return_value = mock_policy_manager

        # Import the endpoint function
        from langflow.api.v1.rbac_advanced import get_conditional_policy

        # Call endpoint and expect 404
        with pytest.raises(HTTPException) as exc_info:
            await get_conditional_policy(
                policy_id=str(uuid4()),
                current_user=mock_user,
                session=mock_session
            )

        assert exc_info.value.status_code == 404
        assert "Conditional policy not found" in str(exc_info.value.detail)

    @patch("langflow.api.v1.rbac_advanced.ConditionalPolicyManager")
    @patch("langflow.api.v1.rbac_advanced.get_current_active_user")
    @patch("langflow.api.v1.rbac_advanced.get_session")
    async def test_update_conditional_policy_success(
        self, mock_get_session, mock_get_user, mock_policy_manager_class,
        sample_policy, mock_session, mock_user
    ):
        """Test successful policy update."""
        # Setup mocks
        mock_get_session.return_value = mock_session
        mock_get_user.return_value = mock_user

        # Create updated policy
        updated_policy = ConditionalPolicy(**sample_policy.__dict__)
        updated_policy.name = "Updated Policy Name"
        updated_policy.priority = 200

        mock_policy_manager = AsyncMock()
        mock_policy_manager.update_policy.return_value = updated_policy
        mock_policy_manager_class.return_value = mock_policy_manager

        # Import the endpoint function
        from langflow.api.v1.rbac_advanced import update_conditional_policy

        # Create update request
        update_request = ConditionalPolicyUpdate(
            name="Updated Policy Name",
            priority=200
        )

        # Call endpoint
        result = await update_conditional_policy(
            policy_id=sample_policy.id,
            policy_updates=update_request,
            current_user=mock_user,
            session=mock_session
        )

        # Verify result
        assert isinstance(result, ConditionalPolicyRead)
        assert result.name == "Updated Policy Name"
        assert result.priority == 200

    @patch("langflow.api.v1.rbac_advanced.ConditionalPolicyManager")
    @patch("langflow.api.v1.rbac_advanced.get_current_active_user")
    @patch("langflow.api.v1.rbac_advanced.get_session")
    async def test_delete_conditional_policy_success(
        self, mock_get_session, mock_get_user, mock_policy_manager_class,
        sample_policy, mock_session, mock_user
    ):
        """Test successful policy deletion."""
        # Setup mocks
        mock_get_session.return_value = mock_session
        mock_get_user.return_value = mock_user
        mock_policy_manager = AsyncMock()
        mock_policy_manager.delete_policy.return_value = True
        mock_policy_manager_class.return_value = mock_policy_manager

        # Import the endpoint function
        from langflow.api.v1.rbac_advanced import delete_conditional_policy

        # Call endpoint
        result = await delete_conditional_policy(
            policy_id=sample_policy.id,
            current_user=mock_user,
            session=mock_session
        )

        # Verify no exception and policy manager was called
        assert result is None  # 204 No Content
        mock_policy_manager.delete_policy.assert_called_once_with(
            session=mock_session,
            policy_id=sample_policy.id
        )

    @patch("langflow.api.v1.rbac_advanced.ConditionalPolicyManager")
    @patch("langflow.api.v1.rbac_advanced.get_current_active_user")
    @patch("langflow.api.v1.rbac_advanced.get_session")
    async def test_delete_conditional_policy_not_found(
        self, mock_get_session, mock_get_user, mock_policy_manager_class,
        mock_session, mock_user
    ):
        """Test policy deletion when policy not found."""
        # Setup mocks
        mock_get_session.return_value = mock_session
        mock_get_user.return_value = mock_user
        mock_policy_manager = AsyncMock()
        mock_policy_manager.delete_policy.return_value = False
        mock_policy_manager_class.return_value = mock_policy_manager

        # Import the endpoint function
        from langflow.api.v1.rbac_advanced import delete_conditional_policy

        # Call endpoint and expect 404
        with pytest.raises(HTTPException) as exc_info:
            await delete_conditional_policy(
                policy_id=str(uuid4()),
                current_user=mock_user,
                session=mock_session
            )

        assert exc_info.value.status_code == 404
        assert "Conditional policy not found" in str(exc_info.value.detail)

    @patch("langflow.api.v1.rbac_advanced.ConditionalPolicyManager")
    @patch("langflow.api.v1.rbac_advanced.get_current_active_user")
    @patch("langflow.api.v1.rbac_advanced.get_session")
    async def test_toggle_policy_status_success(
        self, mock_get_session, mock_get_user, mock_policy_manager_class,
        sample_policy, mock_session, mock_user
    ):
        """Test successful policy status toggle."""
        # Setup mocks
        mock_get_session.return_value = mock_session
        mock_get_user.return_value = mock_user

        # Create toggled policy
        toggled_policy = ConditionalPolicy(**sample_policy.__dict__)
        toggled_policy.enabled = not sample_policy.enabled

        mock_policy_manager = AsyncMock()
        mock_policy_manager.toggle_policy_status.return_value = toggled_policy
        mock_policy_manager_class.return_value = mock_policy_manager

        # Import the endpoint function
        from langflow.api.v1.rbac_advanced import toggle_policy_status

        # Call endpoint
        result = await toggle_policy_status(
            policy_id=sample_policy.id,
            current_user=mock_user,
            session=mock_session
        )

        # Verify result
        assert isinstance(result, ConditionalPolicyRead)
        assert result.enabled != sample_policy.enabled

    @patch("langflow.api.v1.rbac_advanced.ConditionalPermissionService")
    @patch("langflow.api.v1.rbac_advanced.get_current_active_user")
    @patch("langflow.api.v1.rbac_advanced.get_session")
    async def test_evaluate_conditional_policies_success(
        self, mock_get_session, mock_get_user, mock_conditional_service_class,
        mock_session, mock_user
    ):
        """Test successful policy evaluation."""
        # Setup mocks
        mock_get_session.return_value = mock_session
        mock_get_user.return_value = mock_user
        mock_conditional_service = AsyncMock()
        mock_conditional_service.evaluate_conditional_permission.return_value = {
            "allowed": True,
            "policies_evaluated": 2,
            "failing_policies": [],
            "require_approval": False,
            "reason": "All conditions met"
        }
        mock_conditional_service_class.return_value = mock_conditional_service

        # Import the endpoint function
        from langflow.api.v1.rbac_advanced import evaluate_conditional_policies

        # Create evaluation request
        evaluation_request = PolicyEvaluationRequest(
            permission="flows.deploy",
            user_id=str(uuid4()),
            ip_address="192.168.1.100",
            mfa_verified=True
        )

        # Mock request object
        mock_request = MagicMock()
        mock_request.client.host = "192.168.1.100"
        mock_request.headers.get.return_value = "Mozilla/5.0"

        # Call endpoint
        result = await evaluate_conditional_policies(
            request=mock_request,
            evaluation_request=evaluation_request,
            current_user=mock_user,
            session=mock_session
        )

        # Verify result
        assert isinstance(result, PolicyEvaluationResult)
        assert result.allowed is True
        assert result.policies_evaluated == 2
        assert result.require_approval is False

    @patch("langflow.api.v1.rbac_advanced.ConditionalPolicyManager")
    @patch("langflow.api.v1.rbac_advanced.get_current_active_user")
    @patch("langflow.api.v1.rbac_advanced.get_session")
    async def test_get_policy_analytics_success(
        self, mock_get_session, mock_get_user, mock_policy_manager_class,
        sample_policy, mock_session, mock_user
    ):
        """Test successful policy analytics retrieval."""
        # Setup mocks
        mock_get_session.return_value = mock_session
        mock_get_user.return_value = mock_user

        # Create mock analytics
        from langflow.api.v1.schemas.conditional_policy_schemas import PolicyAnalytics
        mock_analytics = PolicyAnalytics(
            policy_id=sample_policy.id,
            policy_name=sample_policy.name,
            evaluation_count=100,
            allow_rate=0.8,
            deny_rate=0.15,
            approval_rate=0.05,
            avg_execution_time_ms=12.5,
            last_evaluation=datetime.now(timezone.utc),
            top_failing_conditions=["time_window", "ip_address"]
        )

        mock_policy_manager = AsyncMock()
        mock_policy_manager.get_policy_analytics.return_value = mock_analytics
        mock_policy_manager_class.return_value = mock_policy_manager

        # Import the endpoint function
        from langflow.api.v1.rbac_advanced import get_policy_analytics

        # Call endpoint
        result = await get_policy_analytics(
            policy_id=sample_policy.id,
            current_user=mock_user,
            session=mock_session
        )

        # Verify result
        assert isinstance(result, PolicyAnalytics)
        assert result.policy_id == sample_policy.id
        assert result.evaluation_count == 100
        assert result.allow_rate == 0.8

    @patch("langflow.api.v1.rbac_advanced.ConditionalPolicyManager")
    @patch("langflow.api.v1.rbac_advanced.get_current_active_user")
    @patch("langflow.api.v1.rbac_advanced.get_session")
    async def test_execute_bulk_policy_operation_enable(
        self, mock_get_session, mock_get_user, mock_policy_manager_class,
        mock_session, mock_user
    ):
        """Test bulk enable operation."""
        # Setup mocks
        mock_get_session.return_value = mock_session
        mock_get_user.return_value = mock_user
        mock_policy_manager = AsyncMock()
        mock_policy_manager.enable_policy.return_value = True
        mock_policy_manager_class.return_value = mock_policy_manager

        # Import the endpoint function
        from langflow.api.v1.rbac_advanced import execute_bulk_policy_operation
        from langflow.api.v1.schemas.conditional_policy_schemas import BulkPolicyOperation

        # Create bulk operation request
        policy_ids = [str(uuid4()), str(uuid4()), str(uuid4())]
        bulk_operation = BulkPolicyOperation(
            operation="enable",
            policy_ids=policy_ids
        )

        # Call endpoint
        result = await execute_bulk_policy_operation(
            bulk_operation=bulk_operation,
            current_user=mock_user,
            session=mock_session
        )

        # Verify result
        assert result["operation"] == "enable"
        assert result["total_policies"] == 3
        assert result["successful_operations"] == 3
        assert result["failed_operations"] == 0
        assert len(result["results"]) == 3

    @patch("langflow.api.v1.rbac_advanced.ConditionalPolicyManager")
    @patch("langflow.api.v1.rbac_advanced.get_current_active_user")
    @patch("langflow.api.v1.rbac_advanced.get_session")
    async def test_execute_bulk_policy_operation_invalid_operation(
        self, mock_get_session, mock_get_user, mock_policy_manager_class,
        mock_session, mock_user
    ):
        """Test bulk operation with invalid operation type."""
        # Setup mocks
        mock_get_session.return_value = mock_session
        mock_get_user.return_value = mock_user
        mock_policy_manager = AsyncMock()
        mock_policy_manager_class.return_value = mock_policy_manager

        # Import the endpoint function
        from langflow.api.v1.rbac_advanced import execute_bulk_policy_operation
        from langflow.api.v1.schemas.conditional_policy_schemas import BulkPolicyOperation

        # Create bulk operation with invalid operation
        bulk_operation = BulkPolicyOperation(
            operation="invalid_operation",
            policy_ids=[str(uuid4())]
        )

        # Call endpoint and expect error
        with pytest.raises(HTTPException) as exc_info:
            await execute_bulk_policy_operation(
                bulk_operation=bulk_operation,
                current_user=mock_user,
                session=mock_session
            )

        assert exc_info.value.status_code == 400
        assert "Unsupported bulk operation" in str(exc_info.value.detail)

    async def test_policy_evaluation_integration(self, mock_session, mock_user):
        """Integration test for policy evaluation flow."""
        # This test would verify the complete flow from API to service
        # In a real implementation, this would use actual test database
        # and verify end-to-end functionality

    async def test_api_permission_checks(self, mock_session, mock_user):
        """Test that API endpoints properly check user permissions."""
        # This test would verify that only users with appropriate roles
        # (like RBACAdmin) can access certain endpoints

    async def test_input_validation(self):
        """Test that API endpoints properly validate input data."""
        # Test cases for invalid condition types, operators, etc.
        # These would be handled by Pydantic validation in the schemas
