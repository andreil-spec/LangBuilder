"""Unit tests for SSO service."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from langflow.services.auth.sso_service import (
    OAuth2Provider,
    OIDCProvider,
    SSOAuthenticationResult,
    SSOFlowState,
    SSOProtocol,
    SSOService,
    SSOUserClaims,
)


class TestSSOService:
    """Test cases for SSO service."""

    @pytest.fixture
    def sso_service(self):
        """Create SSO service instance."""
        return SSOService()

    @pytest.fixture
    def mock_session(self):
        """Mock database session."""
        session = AsyncMock()
        return session

    @pytest.fixture
    def mock_sso_config(self):
        """Mock SSO configuration."""
        config = MagicMock()
        config.id = uuid4()
        config.protocol = SSOProtocol.OIDC
        config.client_id = "test_client_id"
        config.client_secret = "test_client_secret"
        config.provider_url = "https://oidc.example.com"
        config.scopes = ["openid", "email", "profile"]
        config.attribute_mapping = {"groups": "custom_groups"}
        config.is_active = True
        return config

    @pytest.fixture
    def mock_user(self):
        """Mock user object."""
        user = MagicMock()
        user.id = uuid4()
        user.username = "test_user"
        user.email = "test@example.com"
        return user

    @pytest.mark.asyncio
    async def test_initiate_sso_flow_oidc(self, sso_service, mock_session, mock_sso_config):
        """Test OIDC SSO flow initiation."""
        provider_id = str(mock_sso_config.id)
        redirect_uri = "https://app.example.com/callback"

        with patch.object(sso_service, "get_provider") as mock_get_provider:
            mock_provider = MagicMock(spec=OIDCProvider)
            mock_provider.initiate_flow.return_value = "https://oidc.example.com/auth?client_id=test&state=abc123"
            mock_get_provider.return_value = mock_provider

            auth_url, state = await sso_service.initiate_sso_flow(
                session=mock_session,
                provider_id=provider_id,
                redirect_uri=redirect_uri,
                client_ip="192.168.1.1",
                user_agent="Mozilla/5.0",
            )

        assert auth_url.startswith("https://oidc.example.com/auth")
        assert state is not None
        assert len(state) > 20  # Should be cryptographically secure
        assert state in sso_service._active_flows

        # Check flow context
        flow_context = sso_service._active_flows[state]
        assert flow_context.provider_id == provider_id
        assert flow_context.redirect_uri == redirect_uri
        assert flow_context.client_ip == "192.168.1.1"
        assert flow_context.user_agent == "Mozilla/5.0"

    @pytest.mark.asyncio
    async def test_handle_sso_callback_success(self, sso_service, mock_session, mock_sso_config):
        """Test successful SSO callback handling."""
        # Set up active flow
        state = "test_state_123"
        flow_context = MagicMock()
        flow_context.provider_id = str(mock_sso_config.id)
        flow_context.nonce = "test_nonce"
        flow_context.expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        sso_service._active_flows[state] = flow_context

        # Mock successful authentication result
        user_claims = SSOUserClaims(
            sub="user123",
            email="test@example.com",
            name="Test User",
            groups=["developers", "admins"],
        )

        auth_result = SSOAuthenticationResult(
            success=True,
            user_claims=user_claims,
            flow_state=SSOFlowState.COMPLETED,
        )

        with patch.object(sso_service, "get_provider") as mock_get_provider:
            mock_provider = MagicMock()
            mock_provider.handle_callback.return_value = auth_result
            mock_get_provider.return_value = mock_provider

            result = await sso_service.handle_sso_callback(
                session=mock_session,
                state=state,
                authorization_code="auth_code_123",
            )

        assert result.success is True
        assert result.user_claims.email == "test@example.com"
        assert result.user_claims.groups == ["developers", "admins"]
        assert state not in sso_service._active_flows  # Should be cleaned up

    @pytest.mark.asyncio
    async def test_handle_sso_callback_invalid_state(self, sso_service, mock_session):
        """Test SSO callback with invalid state."""
        result = await sso_service.handle_sso_callback(
            session=mock_session,
            state="invalid_state",
            authorization_code="auth_code_123",
        )

        assert result.success is False
        assert result.error_code == "invalid_state"
        assert "Invalid or expired SSO flow state" in result.error_message

    @pytest.mark.asyncio
    async def test_handle_sso_callback_expired_flow(self, sso_service, mock_session):
        """Test SSO callback with expired flow."""
        state = "expired_state"
        flow_context = MagicMock()
        flow_context.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)  # Expired
        sso_service._active_flows[state] = flow_context

        result = await sso_service.handle_sso_callback(
            session=mock_session,
            state=state,
            authorization_code="auth_code_123",
        )

        assert result.success is False
        assert result.error_code == "flow_expired"
        assert state not in sso_service._active_flows  # Should be cleaned up

    @pytest.mark.asyncio
    async def test_provision_user_from_sso_new_user(self, sso_service, mock_session, mock_sso_config):
        """Test user provisioning for new user."""
        from langflow.services.database.models.user.model import User

        user_claims = SSOUserClaims(
            sub="new_user_123",
            email="newuser@example.com",
            name="New User",
            given_name="New",
            family_name="User",
            groups=["users"],
        )

        # Mock no existing user
        mock_session.exec.return_value.first.return_value = None

        # Mock user creation
        new_user = MagicMock(spec=User)
        new_user.id = uuid4()
        new_user.username = "newuser@example.com"
        new_user.email = "newuser@example.com"

        with patch.object(sso_service, "_provision_user_groups", return_value=None):
            user = await sso_service.provision_user_from_sso(
                session=mock_session,
                user_claims=user_claims,
                provider_id=str(mock_sso_config.id),
            )

        mock_session.add.assert_called_once()
        mock_session.commit.assert_called()

    @pytest.mark.asyncio
    async def test_provision_user_from_sso_existing_user(self, sso_service, mock_session, mock_sso_config, mock_user):
        """Test user provisioning for existing user."""
        user_claims = SSOUserClaims(
            sub="existing_user_123",
            email="test@example.com",
            name="Updated Name",
        )

        # Mock existing user
        mock_session.exec.return_value.first.return_value = mock_user

        with patch.object(sso_service, "_provision_user_groups", return_value=None):
            user = await sso_service.provision_user_from_sso(
                session=mock_session,
                user_claims=user_claims,
                provider_id=str(mock_sso_config.id),
            )

        assert user == mock_user
        assert mock_user.last_login_at is not None
        mock_session.commit.assert_called()

    @pytest.mark.asyncio
    async def test_provision_user_from_sso_missing_email(self, sso_service, mock_session, mock_sso_config):
        """Test user provisioning with missing email."""
        user_claims = SSOUserClaims(
            sub="user_no_email",
            email="",  # Missing email
            name="User No Email",
        )

        with pytest.raises(ValueError, match="Email is required for user provisioning"):
            await sso_service.provision_user_from_sso(
                session=mock_session,
                user_claims=user_claims,
                provider_id=str(mock_sso_config.id),
            )

    def test_cleanup_expired_flows(self, sso_service):
        """Test cleanup of expired SSO flows."""
        # Add active flow (not expired)
        active_state = "active_flow"
        active_context = MagicMock()
        active_context.expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        sso_service._active_flows[active_state] = active_context

        # Add expired flow
        expired_state = "expired_flow"
        expired_context = MagicMock()
        expired_context.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)
        sso_service._active_flows[expired_state] = expired_context

        # Cleanup
        sso_service.cleanup_expired_flows()

        # Check results
        assert active_state in sso_service._active_flows
        assert expired_state not in sso_service._active_flows


class TestOIDCProvider:
    """Test cases for OIDC provider."""

    @pytest.fixture
    def mock_config(self):
        """Mock OIDC configuration."""
        config = MagicMock()
        config.protocol = SSOProtocol.OIDC
        config.client_id = "oidc_client"
        config.client_secret = "oidc_secret"
        config.provider_url = "https://oidc.example.com"
        config.scopes = ["openid", "email", "profile"]
        config.attribute_mapping = {}
        return config

    @pytest.fixture
    def oidc_provider(self, mock_config):
        """Create OIDC provider instance."""
        return OIDCProvider(mock_config)

    @pytest.mark.asyncio
    async def test_initiate_flow(self, oidc_provider):
        """Test OIDC flow initiation."""
        redirect_uri = "https://app.example.com/callback"
        state = "test_state"
        nonce = "test_nonce"

        # Mock discovery document
        discovery_doc = {
            "authorization_endpoint": "https://oidc.example.com/auth",
            "token_endpoint": "https://oidc.example.com/token",
            "userinfo_endpoint": "https://oidc.example.com/userinfo",
        }

        with patch.object(oidc_provider, "_get_discovery_document", return_value=discovery_doc):
            auth_url = await oidc_provider.initiate_flow(redirect_uri, state, nonce)

        assert auth_url.startswith("https://oidc.example.com/auth")
        assert "client_id=oidc_client" in auth_url
        assert f"state={state}" in auth_url
        assert f"nonce={nonce}" in auth_url
        assert "scope=openid+email+profile" in auth_url

    def test_map_attributes_default(self, oidc_provider):
        """Test attribute mapping with default configuration."""
        provider_claims = {
            "sub": "user123",
            "email": "test@example.com",
            "name": "Test User",
            "given_name": "Test",
            "family_name": "User",
            "groups": ["group1", "group2"],
            "custom_field": "custom_value",
        }

        user_claims = oidc_provider.map_attributes(provider_claims)

        assert user_claims.sub == "user123"
        assert user_claims.email == "test@example.com"
        assert user_claims.name == "Test User"
        assert user_claims.given_name == "Test"
        assert user_claims.family_name == "User"
        assert user_claims.groups == ["group1", "group2"]
        assert "custom_field" in user_claims.custom_attributes

    def test_map_attributes_custom_mapping(self, mock_config):
        """Test attribute mapping with custom configuration."""
        mock_config.attribute_mapping = {
            "groups": "custom_groups",
            "email": "mail",
        }

        provider = OIDCProvider(mock_config)

        provider_claims = {
            "sub": "user123",
            "mail": "test@example.com",  # Custom email field
            "name": "Test User",
            "custom_groups": ["admin", "user"],  # Custom groups field
        }

        user_claims = provider.map_attributes(provider_claims)

        assert user_claims.sub == "user123"
        assert user_claims.email == "test@example.com"
        assert user_claims.groups == ["admin", "user"]


class TestOAuth2Provider:
    """Test cases for OAuth2 provider."""

    @pytest.fixture
    def mock_config(self):
        """Mock OAuth2 configuration."""
        config = MagicMock()
        config.protocol = SSOProtocol.OAUTH2
        config.client_id = "oauth2_client"
        config.client_secret = "oauth2_secret"
        config.provider_url = "https://github.com"
        config.scopes = ["read:user", "user:email"]
        config.attribute_mapping = {}
        return config

    @pytest.fixture
    def oauth2_provider(self, mock_config):
        """Create OAuth2 provider instance."""
        return OAuth2Provider(mock_config)

    @pytest.mark.asyncio
    async def test_initiate_flow(self, oauth2_provider):
        """Test OAuth2 flow initiation."""
        redirect_uri = "https://app.example.com/callback"
        state = "test_state"
        nonce = "test_nonce"

        auth_url = await oauth2_provider.initiate_flow(redirect_uri, state, nonce)

        assert auth_url.startswith("https://github.com/oauth/authorize")
        assert "client_id=oauth2_client" in auth_url
        assert f"state={state}" in auth_url
        assert "scope=read%3Auser+user%3Aemail" in auth_url
