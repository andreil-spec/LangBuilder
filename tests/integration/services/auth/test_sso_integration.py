"""Integration tests for SSO authentication flows.

These tests verify end-to-end SSO functionality including:
- OIDC provider integration
- OAuth2 provider integration
- User provisioning from SSO claims
- Session management and cleanup
- Error handling for various SSO failure scenarios
"""

# NO future annotations per Phase 1 requirements
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from langflow.services.auth.sso_service import (
    SSOConfiguration,
    SSOFlowState,
    SSOProtocol,
    SSOService,
    SSOUserClaims,
)


class TestSSOIntegrationFlows:
    """Integration tests for complete SSO authentication flows."""

    @pytest.fixture
    async def sso_service(self):
        """Create SSO service instance for integration testing."""
        return SSOService()

    @pytest.fixture
    async def mock_session(self):
        """Mock database session for integration tests."""
        session = AsyncMock()
        return session

    @pytest.fixture
    def oidc_config(self):
        """OIDC configuration for testing."""
        return SSOConfiguration(
            id=str(uuid4()),
            name="Test OIDC Provider",
            protocol=SSOProtocol.OIDC,
            provider_url="https://accounts.google.com",
            client_id="test-client-id",
            client_secret="test-client-secret",
            scopes=["openid", "email", "profile"],
            attribute_mapping={"groups": "custom_groups"},
            is_active=True,
            auto_provision_users=True
        )

    @pytest.fixture
    def oauth2_config(self):
        """OAuth2 configuration for testing."""
        return SSOConfiguration(
            id=str(uuid4()),
            name="Test GitHub OAuth",
            protocol=SSOProtocol.OAUTH2,
            provider_url="https://github.com",
            client_id="github-client-id",
            client_secret="github-client-secret",
            scopes=["read:user", "user:email"],
            attribute_mapping={},
            is_active=True,
            auto_provision_users=True
        )

    @pytest.mark.asyncio
    async def test_complete_oidc_authentication_flow(self, sso_service, mock_session, oidc_config):
        """Test complete OIDC authentication flow from initiation to user provisioning."""
        provider_id = oidc_config.id
        redirect_uri = "https://app.example.com/auth/callback"

        # Mock OIDC discovery document
        discovery_doc = {
            "authorization_endpoint": "https://accounts.google.com/oauth2/v2/auth",
            "token_endpoint": "https://oauth2.googleapis.com/token",
            "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
            "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs"
        }

        # Mock HTTP client responses
        with patch("httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = discovery_doc
            mock_response.status_code = 200
            mock_client.return_value.__aenter__.return_value.get.return_value = mock_response

            with patch.object(sso_service, "get_sso_config", return_value=oidc_config):
                # Step 1: Initiate SSO flow
                auth_url, state = await sso_service.initiate_sso_flow(
                    session=mock_session,
                    provider_id=provider_id,
                    redirect_uri=redirect_uri,
                    client_ip="192.168.1.100",
                    user_agent="Mozilla/5.0 Test Browser"
                )

                # Verify flow initiation
                assert auth_url.startswith("https://accounts.google.com/oauth2/v2/auth")
                assert "client_id=test-client-id" in auth_url
                assert f"state={state}" in auth_url
                assert "scope=openid+email+profile" in auth_url
                assert state in sso_service._active_flows

                # Step 2: Mock successful authorization code exchange
                mock_token_response = {
                    "access_token": "mock-access-token",
                    "id_token": "mock-id-token",
                    "token_type": "Bearer",
                    "expires_in": 3600
                }

                mock_userinfo_response = {
                    "sub": "google-user-123",
                    "email": "testuser@example.com",
                    "name": "Test User",
                    "given_name": "Test",
                    "family_name": "User",
                    "picture": "https://example.com/avatar.jpg",
                    "custom_groups": ["developers", "admins"]
                }

                # Mock token exchange and userinfo requests
                mock_client.return_value.__aenter__.return_value.post.return_value.json.return_value = mock_token_response
                mock_client.return_value.__aenter__.return_value.get.return_value.json.return_value = mock_userinfo_response

                # Step 3: Handle SSO callback
                result = await sso_service.handle_sso_callback(
                    session=mock_session,
                    state=state,
                    authorization_code="mock-auth-code"
                )

                # Verify successful authentication
                assert result.success is True
                assert result.user_claims.email == "testuser@example.com"
                assert result.user_claims.groups == ["developers", "admins"]
                assert result.flow_state == SSOFlowState.COMPLETED

                # Step 4: Verify user provisioning
                assert result.user_claims.sub == "google-user-123"
                assert result.user_claims.name == "Test User"
                assert result.user_claims.given_name == "Test"
                assert result.user_claims.family_name == "User"

                # Verify flow cleanup
                assert state not in sso_service._active_flows

    @pytest.mark.asyncio
    async def test_oauth2_github_integration_flow(self, sso_service, mock_session, oauth2_config):
        """Test OAuth2 integration with GitHub provider."""
        provider_id = oauth2_config.id
        redirect_uri = "https://app.example.com/auth/github/callback"

        with patch.object(sso_service, "get_sso_config", return_value=oauth2_config):
            # Step 1: Initiate OAuth2 flow
            auth_url, state = await sso_service.initiate_sso_flow(
                session=mock_session,
                provider_id=provider_id,
                redirect_uri=redirect_uri,
                client_ip="10.0.0.50",
                user_agent="Mozilla/5.0 Integration Test"
            )

            # Verify GitHub OAuth2 URL structure
            assert auth_url.startswith("https://github.com/login/oauth/authorize")
            assert "client_id=github-client-id" in auth_url
            assert f"state={state}" in auth_url
            assert "scope=read%3Auser+user%3Aemail" in auth_url

            # Step 2: Mock GitHub API responses
            mock_token_response = {
                "access_token": "gho_mock-github-token",
                "token_type": "bearer",
                "scope": "read:user,user:email"
            }

            mock_user_response = {
                "id": 12345678,
                "login": "testuser",
                "name": "GitHub Test User",
                "email": "testuser@github.example.com",
                "avatar_url": "https://github.com/avatar.jpg",
                "bio": "Test user for integration testing"
            }

            mock_emails_response = [
                {
                    "email": "testuser@github.example.com",
                    "primary": True,
                    "verified": True,
                    "visibility": "public"
                }
            ]

            with patch("httpx.AsyncClient") as mock_client:
                mock_client_instance = mock_client.return_value.__aenter__.return_value

                # Mock token exchange
                mock_client_instance.post.return_value.json.return_value = mock_token_response
                mock_client_instance.post.return_value.status_code = 200

                # Mock user info requests
                mock_client_instance.get.side_effect = [
                    MagicMock(json=lambda: mock_user_response, status_code=200),
                    MagicMock(json=lambda: mock_emails_response, status_code=200)
                ]

                # Step 3: Handle OAuth2 callback
                result = await sso_service.handle_sso_callback(
                    session=mock_session,
                    state=state,
                    authorization_code="github-auth-code-123"
                )

                # Verify GitHub integration results
                assert result.success is True
                assert result.user_claims.email == "testuser@github.example.com"
                assert result.user_claims.name == "GitHub Test User"
                assert result.user_claims.sub == "12345678"

    @pytest.mark.asyncio
    async def test_sso_error_handling_invalid_provider(self, sso_service, mock_session):
        """Test error handling for invalid SSO provider configuration."""
        invalid_provider_id = str(uuid4())

        with patch.object(sso_service, "get_sso_config", return_value=None):
            # Test initiation with invalid provider
            with pytest.raises(ValueError, match="SSO provider not found"):
                await sso_service.initiate_sso_flow(
                    session=mock_session,
                    provider_id=invalid_provider_id,
                    redirect_uri="https://app.example.com/callback"
                )

    @pytest.mark.asyncio
    async def test_sso_error_handling_expired_flow(self, sso_service, mock_session, oidc_config):
        """Test error handling for expired SSO flows."""
        provider_id = oidc_config.id

        with patch.object(sso_service, "get_sso_config", return_value=oidc_config):
            # Create an expired flow manually
            expired_state = "expired_flow_state"
            expired_context = MagicMock()
            expired_context.provider_id = provider_id
            expired_context.expires_at = datetime.now(timezone.utc) - timedelta(minutes=30)
            sso_service._active_flows[expired_state] = expired_context

            # Attempt to handle callback with expired flow
            result = await sso_service.handle_sso_callback(
                session=mock_session,
                state=expired_state,
                authorization_code="test-code"
            )

            # Verify error handling
            assert result.success is False
            assert result.error_code == "flow_expired"
            assert "expired" in result.error_message.lower()
            assert expired_state not in sso_service._active_flows

    @pytest.mark.asyncio
    async def test_sso_user_provisioning_integration(self, sso_service, mock_session, oidc_config):
        """Test complete user provisioning from SSO claims."""
        from langflow.services.database.models.user.model import User

        user_claims = SSOUserClaims(
            sub="oidc-user-456",
            email="provision@example.com",
            name="Provision Test User",
            given_name="Provision",
            family_name="User",
            groups=["qa_team", "contractors"],
            custom_attributes={
                "department": "Quality Assurance",
                "employee_id": "EMP-456"
            }
        )

        # Mock database operations for user provisioning
        mock_existing_user = None  # Simulate new user
        mock_session.exec.return_value.first.return_value = mock_existing_user

        new_user = MagicMock(spec=User)
        new_user.id = str(uuid4())
        new_user.username = "provision@example.com"
        new_user.email = "provision@example.com"
        new_user.is_active = True

        with patch.object(sso_service, "_create_user_from_claims", return_value=new_user):
            with patch.object(sso_service, "_provision_user_groups", return_value=None):
                # Test user provisioning
                provisioned_user = await sso_service.provision_user_from_sso(
                    session=mock_session,
                    user_claims=user_claims,
                    provider_id=oidc_config.id
                )

                # Verify provisioning results
                assert provisioned_user is not None
                assert provisioned_user.username == "provision@example.com"
                mock_session.add.assert_called_once()
                mock_session.commit.assert_called()

    @pytest.mark.asyncio
    async def test_sso_concurrent_flows_handling(self, sso_service, mock_session, oidc_config):
        """Test handling of multiple concurrent SSO flows."""
        provider_id = oidc_config.id
        redirect_uri = "https://app.example.com/callback"

        with patch.object(sso_service, "get_sso_config", return_value=oidc_config):
            with patch("httpx.AsyncClient") as mock_client:
                mock_response = MagicMock()
                mock_response.json.return_value = {
                    "authorization_endpoint": "https://test.oidc.com/auth",
                    "token_endpoint": "https://test.oidc.com/token"
                }
                mock_client.return_value.__aenter__.return_value.get.return_value = mock_response

                # Initiate multiple concurrent flows
                flows = []
                for i in range(5):
                    auth_url, state = await sso_service.initiate_sso_flow(
                        session=mock_session,
                        provider_id=provider_id,
                        redirect_uri=redirect_uri,
                        client_ip=f"192.168.1.{100 + i}",
                        user_agent=f"Test Browser {i}"
                    )
                    flows.append((auth_url, state))

                # Verify all flows are tracked
                assert len(sso_service._active_flows) == 5

                # Verify each flow has unique state
                states = [flow[1] for flow in flows]
                assert len(set(states)) == 5  # All states should be unique

                # Test cleanup of individual flows
                for _, state in flows[:3]:
                    if state in sso_service._active_flows:
                        del sso_service._active_flows[state]

                assert len(sso_service._active_flows) == 2

    @pytest.mark.asyncio
    async def test_sso_flow_cleanup_on_service_restart(self, sso_service):
        """Test automatic cleanup of expired flows."""
        # Add some test flows with different expiration times
        current_time = datetime.now(timezone.utc)

        # Active flow (not expired)
        active_context = MagicMock()
        active_context.expires_at = current_time + timedelta(minutes=10)
        sso_service._active_flows["active_flow"] = active_context

        # Expired flows
        for i in range(3):
            expired_context = MagicMock()
            expired_context.expires_at = current_time - timedelta(minutes=5 + i)
            sso_service._active_flows[f"expired_flow_{i}"] = expired_context

        # Run cleanup
        sso_service.cleanup_expired_flows()

        # Verify only active flow remains
        assert len(sso_service._active_flows) == 1
        assert "active_flow" in sso_service._active_flows

        # Verify all expired flows are cleaned up
        for i in range(3):
            assert f"expired_flow_{i}" not in sso_service._active_flows

    @pytest.mark.asyncio
    async def test_sso_provider_discovery_failure_handling(self, sso_service, mock_session, oidc_config):
        """Test handling of OIDC discovery document failures."""
        provider_id = oidc_config.id

        with patch.object(sso_service, "get_sso_config", return_value=oidc_config):
            with patch("httpx.AsyncClient") as mock_client:
                # Mock discovery failure
                mock_client.return_value.__aenter__.return_value.get.side_effect = Exception("Discovery failed")

                # Test that initiation fails gracefully
                with pytest.raises(Exception, match="Discovery failed"):
                    await sso_service.initiate_sso_flow(
                        session=mock_session,
                        provider_id=provider_id,
                        redirect_uri="https://app.example.com/callback"
                    )

    @pytest.mark.asyncio
    async def test_sso_token_exchange_error_handling(self, sso_service, mock_session, oidc_config):
        """Test error handling during token exchange phase."""
        provider_id = oidc_config.id

        # Set up a valid flow first
        state = "test_token_error_state"
        flow_context = MagicMock()
        flow_context.provider_id = provider_id
        flow_context.nonce = "test_nonce"
        flow_context.expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        flow_context.redirect_uri = "https://app.example.com/callback"
        sso_service._active_flows[state] = flow_context

        with patch.object(sso_service, "get_sso_config", return_value=oidc_config):
            with patch("httpx.AsyncClient") as mock_client:
                # Mock token exchange failure
                mock_response = MagicMock()
                mock_response.status_code = 400
                mock_response.json.return_value = {
                    "error": "invalid_grant",
                    "error_description": "Authorization code expired"
                }
                mock_client.return_value.__aenter__.return_value.post.return_value = mock_response

                # Test token exchange error handling
                result = await sso_service.handle_sso_callback(
                    session=mock_session,
                    state=state,
                    authorization_code="invalid-code"
                )

                # Verify error handling
                assert result.success is False
                assert result.error_code == "token_exchange_failed"
                assert "invalid_grant" in result.error_message

                # Verify flow is cleaned up even on error
                assert state not in sso_service._active_flows
