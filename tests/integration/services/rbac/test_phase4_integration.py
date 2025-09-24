"""Integration tests for RBAC Phase 4: Integration & Middleware.

These tests verify the complete integration of RBAC middleware and
authentication enhancement with the existing LangBuilder system.

Test coverage:
- RBAC middleware integration with FastAPI
- Authentication enhancement with existing auth system
- Flow execution permission integration
- Dependency injection with RBAC context
- Backward compatibility with existing functionality
"""

# NO future annotations per Phase 1 requirements
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from langflow.services.rbac.dependencies import RBACPermissionChecker, check_custom_permission
from langflow.services.rbac.flow_integration import FlowExecutionContext, RBACFlowExecutionGuard
from langflow.services.rbac.integration import RBACIntegrationConfig, RBACIntegrationService
from langflow.services.rbac.middleware import RBACMiddleware


class TestRBACMiddlewareIntegration:
    """Test RBAC middleware integration with FastAPI."""

    @pytest.fixture
    def mock_rbac_service(self):
        """Mock RBAC service for testing."""
        service = AsyncMock()
        # Mock successful permission evaluation
        service.evaluate_permission.return_value = AsyncMock(
            granted=True,
            reason="test_permission_granted",
            evaluation_time=0.005
        )
        return service

    @pytest.fixture
    def mock_user(self):
        """Mock user for testing."""
        user = MagicMock()
        user.id = uuid4()
        user.is_active = True
        user.is_superuser = False
        return user

    @pytest.fixture
    def test_app(self, mock_rbac_service):
        """Create test FastAPI app with RBAC middleware."""
        app = FastAPI()

        # Add RBAC middleware
        rbac_middleware = RBACMiddleware(
            app=app,
            rbac_service=mock_rbac_service,
            enforce_rbac=True,
            protected_patterns=["/api/v1/flows/"],
            bypass_patterns=["/health", "/docs"]
        )
        app.add_middleware(type(rbac_middleware), **rbac_middleware.__dict__)

        # Add test endpoints
        @app.get("/health")
        async def health():
            return {"status": "ok"}

        @app.get("/api/v1/flows/{flow_id}")
        async def get_flow(flow_id: str):
            return {"flow_id": flow_id}

        @app.post("/api/v1/flows/")
        async def create_flow():
            return {"message": "flow created"}

        return app

    @pytest.mark.asyncio
    async def test_middleware_bypass_public_endpoints(self, test_app):
        """Test that public endpoints bypass RBAC middleware."""
        client = TestClient(test_app)

        # Health endpoint should bypass RBAC
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    @pytest.mark.asyncio
    async def test_middleware_protects_api_endpoints(self, test_app, mock_user):
        """Test that API endpoints are protected by RBAC middleware."""
        client = TestClient(test_app)

        # Protected endpoint without authentication should return 403
        with patch("langflow.services.rbac.middleware.get_current_user_by_jwt") as mock_auth:
            mock_auth.side_effect = Exception("No token")
            with patch("langflow.services.rbac.middleware.api_key_security") as mock_api:
                mock_api.side_effect = Exception("No API key")

                response = client.get("/api/v1/flows/test-flow-id")
                assert response.status_code == 403
                assert "Insufficient permissions" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_middleware_allows_authorized_access(self, test_app, mock_user):
        """Test that middleware allows access for authorized users."""
        client = TestClient(test_app)

        # Mock successful authentication
        with patch("langflow.services.rbac.middleware.get_current_user_by_jwt") as mock_auth:
            mock_auth.return_value = mock_user
            with patch("langflow.services.deps.get_session") as mock_session:
                mock_session.return_value.__aenter__.return_value = AsyncMock()

                response = client.get(
                    "/api/v1/flows/test-flow-id",
                    headers={"Authorization": "Bearer test-token"}
                )
                assert response.status_code == 200
                assert response.json() == {"flow_id": "test-flow-id"}

    @pytest.mark.asyncio
    async def test_middleware_performance_tracking(self, test_app, mock_user):
        """Test that middleware tracks performance metrics."""
        client = TestClient(test_app)

        # Get middleware instance for metrics
        middleware_layer = None
        for middleware in test_app.user_middleware:
            if hasattr(middleware.cls, "get_metrics"):
                middleware_layer = middleware.cls(**middleware.kwargs)
                break

        assert middleware_layer is not None

        # Make some requests to generate metrics
        with patch("langflow.services.rbac.middleware.get_current_user_by_jwt") as mock_auth:
            mock_auth.return_value = mock_user
            with patch("langflow.services.deps.get_session") as mock_session:
                mock_session.return_value.__aenter__.return_value = AsyncMock()

                # Make several requests
                for i in range(3):
                    response = client.get(
                        f"/api/v1/flows/test-flow-{i}",
                        headers={"Authorization": "Bearer test-token"}
                    )
                    assert response.status_code == 200

        # Check metrics
        metrics = middleware_layer.get_metrics()
        assert metrics["request_count"] >= 3
        assert metrics["average_processing_time"] > 0


class TestRBACDependencies:
    """Test RBAC dependency injection integration."""

    @pytest.fixture
    def mock_session(self):
        """Mock database session."""
        return AsyncMock()

    @pytest.fixture
    def mock_user(self):
        """Mock user for testing."""
        user = MagicMock()
        user.id = uuid4()
        user.is_active = True
        user.is_superuser = False
        return user

    @pytest.fixture
    def mock_request(self):
        """Mock FastAPI request."""
        request = MagicMock()
        request.path_params = {"flow_id": "test-flow-id"}
        request.query_params = {}
        return request

    @pytest.mark.asyncio
    async def test_permission_checker_allows_superuser(self, mock_request, mock_session):
        """Test that permission checker allows superuser access."""
        superuser = MagicMock()
        superuser.id = uuid4()
        superuser.is_active = True
        superuser.is_superuser = True

        checker = RBACPermissionChecker(
            resource_type="flow",
            action="read",
            resource_id_param="flow_id"
        )

        result = await checker(mock_request, superuser, mock_session)
        assert result == superuser

    @pytest.mark.asyncio
    async def test_permission_checker_evaluates_permissions(self, mock_request, mock_user, mock_session):
        """Test that permission checker evaluates RBAC permissions."""
        checker = RBACPermissionChecker(
            resource_type="flow",
            action="read",
            resource_id_param="flow_id",
            allow_superuser_bypass=False
        )

        # Mock RBAC service with granted permission
        with patch.object(checker, "_get_rbac_service") as mock_get_service:
            mock_rbac_service = AsyncMock()
            mock_rbac_service.evaluate_permission.return_value = AsyncMock(
                granted=True,
                reason="test_granted"
            )
            mock_get_service.return_value = mock_rbac_service

            result = await checker(mock_request, mock_user, mock_session)
            assert result == mock_user

            # Verify permission was evaluated
            mock_rbac_service.evaluate_permission.assert_called_once()

    @pytest.mark.asyncio
    async def test_permission_checker_denies_insufficient_permissions(self, mock_request, mock_user, mock_session):
        """Test that permission checker denies access for insufficient permissions."""
        from fastapi import HTTPException

        checker = RBACPermissionChecker(
            resource_type="flow",
            action="write",
            resource_id_param="flow_id",
            allow_superuser_bypass=False
        )

        # Mock RBAC service with denied permission
        with patch.object(checker, "_get_rbac_service") as mock_get_service:
            mock_rbac_service = AsyncMock()
            mock_rbac_service.evaluate_permission.return_value = AsyncMock(
                granted=False,
                reason="insufficient_role"
            )
            mock_get_service.return_value = mock_rbac_service

            with pytest.raises(HTTPException) as exc_info:
                await checker(mock_request, mock_user, mock_session)

            assert exc_info.value.status_code == 403
            assert "Insufficient permissions" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_custom_permission_check(self, mock_user, mock_session):
        """Test custom permission checking function."""
        # Mock RBAC service
        with patch("langflow.services.rbac.dependencies.RBACService") as mock_rbac_class:
            mock_rbac_service = AsyncMock()
            mock_rbac_service.evaluate_permission.return_value = AsyncMock(
                granted=True,
                reason="test_granted"
            )
            mock_rbac_class.return_value = mock_rbac_service

            result = await check_custom_permission(
                user=mock_user,
                session=mock_session,
                resource_type="project",
                action="read",
                resource_id="test-project-id"
            )

            assert result is True
            mock_rbac_service.evaluate_permission.assert_called_once()


class TestFlowExecutionIntegration:
    """Test Flow execution integration with RBAC."""

    @pytest.fixture
    def mock_rbac_service(self):
        """Mock RBAC service for testing."""
        service = AsyncMock()
        service.evaluate_permission.return_value = AsyncMock(
            granted=True,
            reason="test_permission_granted",
            evaluation_time=0.005
        )
        return service

    @pytest.fixture
    def mock_user(self):
        """Mock user for testing."""
        user = MagicMock()
        user.id = uuid4()
        user.is_active = True
        user.is_superuser = False
        return user

    @pytest.fixture
    def mock_session(self):
        """Mock database session."""
        return AsyncMock()

    @pytest.fixture
    def mock_graph(self):
        """Mock Flow graph for testing."""
        graph = AsyncMock()
        graph.arun.return_value = {"result": "test_execution_result"}
        return graph

    @pytest.mark.asyncio
    async def test_flow_execution_permission_check(self, mock_rbac_service, mock_user, mock_session):
        """Test Flow execution permission checking."""
        guard = RBACFlowExecutionGuard(mock_rbac_service)

        context = await guard.check_execution_permission(
            session=mock_session,
            user=mock_user,
            flow_id="test-flow-id",
            execution_type="execute"
        )

        assert isinstance(context, FlowExecutionContext)
        assert context.permission_granted is True
        assert context.user == mock_user
        assert context.flow_id == "test-flow-id"
        assert context.execution_type == "execute"

    @pytest.mark.asyncio
    async def test_flow_execution_with_rbac(self, mock_rbac_service, mock_user, mock_session, mock_graph):
        """Test complete Flow execution with RBAC protection."""
        guard = RBACFlowExecutionGuard(mock_rbac_service)

        result = await guard.execute_flow_with_rbac(
            session=mock_session,
            user=mock_user,
            flow_id="test-flow-id",
            graph=mock_graph,
            inputs={"test_input": "test_value"}
        )

        assert result == {"result": "test_execution_result"}

        # Verify permission was checked
        mock_rbac_service.evaluate_permission.assert_called()

        # Verify graph was executed with RBAC context
        mock_graph.arun.assert_called_once()
        call_args = mock_graph.arun.call_args
        inputs = call_args[1]["inputs"]
        assert "_rbac_context" in inputs
        assert inputs["_rbac_context"]["user_id"] == str(mock_user.id)

    @pytest.mark.asyncio
    async def test_flow_execution_permission_denied(self, mock_rbac_service, mock_user, mock_session):
        """Test Flow execution with denied permissions."""
        # Configure RBAC service to deny permission
        mock_rbac_service.evaluate_permission.return_value = AsyncMock(
            granted=False,
            reason="insufficient_role"
        )

        guard = RBACFlowExecutionGuard(mock_rbac_service)

        with pytest.raises(PermissionError) as exc_info:
            await guard.check_execution_permission(
                session=mock_session,
                user=mock_user,
                flow_id="test-flow-id",
                execution_type="execute"
            )

        assert "insufficient_role" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_flow_execution_caching(self, mock_rbac_service, mock_user, mock_session):
        """Test Flow execution permission caching."""
        guard = RBACFlowExecutionGuard(mock_rbac_service)

        # First execution - should call RBAC service
        context1 = await guard.check_execution_permission(
            session=mock_session,
            user=mock_user,
            flow_id="test-flow-id",
            execution_type="execute",
            use_cache=True
        )

        assert context1.permission_granted is True
        assert mock_rbac_service.evaluate_permission.call_count == 1

        # Second execution - should use cache
        context2 = await guard.check_execution_permission(
            session=mock_session,
            user=mock_user,
            flow_id="test-flow-id",
            execution_type="execute",
            use_cache=True
        )

        assert context2.permission_granted is True
        # Should still be 1 call (cached)
        assert mock_rbac_service.evaluate_permission.call_count == 1


class TestRBACIntegrationService:
    """Test RBAC integration service."""

    @pytest.mark.asyncio
    async def test_integration_service_initialization(self):
        """Test RBAC integration service initialization."""
        config = RBACIntegrationConfig(
            enable_rbac=True,
            enable_middleware=True,
            enable_flow_integration=True
        )

        service = RBACIntegrationService(config)

        # Mock the service dependencies to avoid actual initialization
        with patch("langflow.services.rbac.integration.RBACService") as mock_rbac:
            mock_rbac.return_value = AsyncMock()
            with patch("langflow.services.rbac.integration.RBACMiddlewareService") as mock_middleware:
                mock_middleware.return_value = AsyncMock()
                with patch("langflow.services.rbac.integration.RBACFlowIntegrationService") as mock_flow:
                    mock_flow.return_value = AsyncMock()

                    await service.initialize_service()

                    assert service.is_rbac_enabled() is True
                    assert service.rbac_service is not None
                    assert service.middleware_service is not None
                    assert service.flow_integration_service is not None

    @pytest.mark.asyncio
    async def test_integration_service_degraded_mode(self):
        """Test RBAC integration service degraded mode."""
        config = RBACIntegrationConfig(enable_rbac=False)
        service = RBACIntegrationService(config)

        await service.initialize_service()

        assert service.is_rbac_enabled() is False
        assert service.rbac_service is None

    @pytest.mark.asyncio
    async def test_middleware_setup(self):
        """Test RBAC middleware setup on FastAPI app."""
        app = FastAPI()
        config = RBACIntegrationConfig(enable_rbac=True, enable_middleware=True)
        service = RBACIntegrationService(config)

        # Mock middleware service
        mock_middleware_service = AsyncMock()
        mock_middleware = MagicMock()
        mock_middleware_service.create_middleware.return_value = mock_middleware
        service.middleware_service = mock_middleware_service

        service.setup_middleware(app)

        # Verify middleware was created
        mock_middleware_service.create_middleware.assert_called_once()

    def test_integration_config_from_environment(self):
        """Test RBAC integration config from environment variables."""
        import os

        # Set test environment variables
        test_env = {
            "LANGFLOW_ENABLE_RBAC": "true",
            "LANGFLOW_ENABLE_RBAC_MIDDLEWARE": "false",
            "LANGFLOW_ENFORCE_RBAC_PERMISSIONS": "true"
        }

        with patch.dict(os.environ, test_env):
            config = RBACIntegrationConfig.from_environment()

            assert config.enable_rbac is True
            assert config.enable_middleware is False
            assert config.enforce_permissions is True

    @pytest.mark.asyncio
    async def test_backward_compatibility_functions(self):
        """Test backward compatibility functions."""
        from langflow.services.rbac.integration import check_user_access_to_flow, get_user_accessible_flows

        # Mock user
        user = MagicMock()
        user.id = uuid4()
        user.is_active = True
        user.is_superuser = False

        # Mock session
        session = AsyncMock()

        # Test with RBAC disabled (should use fallback behavior)
        with patch("langflow.services.rbac.integration.get_rbac_integration_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.is_rbac_enabled.return_value = False
            mock_get_service.return_value = mock_service

            # Should allow access for active users when RBAC is disabled
            result = await check_user_access_to_flow(user, "test-flow-id", "read", session)
            assert result is True

            # Should return user flows when RBAC is disabled
            with patch("langflow.services.rbac.integration._get_user_flows") as mock_get_flows:
                mock_get_flows.return_value = ["flow1", "flow2"]

                flows = await get_user_accessible_flows(user, session)
                assert flows == ["flow1", "flow2"]


class TestEndToEndIntegration:
    """End-to-end integration tests."""

    @pytest.mark.asyncio
    async def test_complete_rbac_flow(self):
        """Test complete RBAC integration flow from middleware to Flow execution."""
        # This test simulates a complete request flow through RBAC components

        # Create mock components
        mock_user = MagicMock()
        mock_user.id = uuid4()
        mock_user.is_active = True
        mock_user.is_superuser = False

        mock_session = AsyncMock()

        mock_rbac_service = AsyncMock()
        mock_rbac_service.evaluate_permission.return_value = AsyncMock(
            granted=True,
            reason="test_granted",
            evaluation_time=0.005
        )

        # Test permission checking pipeline
        from langflow.services.rbac.dependencies import check_custom_permission
        from langflow.services.rbac.flow_integration import RBACFlowExecutionGuard

        # 1. Check API access permission
        with patch("langflow.services.rbac.dependencies.RBACService") as mock_rbac_class:
            mock_rbac_class.return_value = mock_rbac_service

            api_access = await check_custom_permission(
                user=mock_user,
                session=mock_session,
                resource_type="flow",
                action="read",
                resource_id="test-flow-id"
            )
            assert api_access is True

        # 2. Check Flow execution permission
        guard = RBACFlowExecutionGuard(mock_rbac_service)
        execution_context = await guard.check_execution_permission(
            session=mock_session,
            user=mock_user,
            flow_id="test-flow-id",
            execution_type="execute"
        )
        assert execution_context.permission_granted is True

        # 3. Verify audit trail (mock)
        assert mock_rbac_service.evaluate_permission.call_count >= 2

    @pytest.mark.asyncio
    async def test_performance_under_load(self):
        """Test RBAC performance under simulated load."""
        # Create RBAC components
        mock_rbac_service = AsyncMock()
        mock_rbac_service.evaluate_permission.return_value = AsyncMock(
            granted=True,
            reason="test_granted",
            evaluation_time=0.001  # Fast evaluation
        )

        guard = RBACFlowExecutionGuard(mock_rbac_service)

        mock_user = MagicMock()
        mock_user.id = uuid4()
        mock_user.is_superuser = False

        mock_session = AsyncMock()

        # Simulate multiple concurrent permission checks
        import time
        start_time = time.perf_counter()

        tasks = []
        for i in range(50):  # 50 concurrent permission checks
            task = guard.check_execution_permission(
                session=mock_session,
                user=mock_user,
                flow_id=f"test-flow-{i}",
                execution_type="execute",
                use_cache=True
            )
            tasks.append(task)

        results = await asyncio.gather(*tasks)
        end_time = time.perf_counter()

        # Verify all permissions were granted
        assert all(result.permission_granted for result in results)

        # Verify reasonable performance (should complete in under 1 second)
        total_time = end_time - start_time
        assert total_time < 1.0

        # Check cache effectiveness
        cache_stats = guard.get_cache_stats()
        assert cache_stats["cached_entries"] > 0
