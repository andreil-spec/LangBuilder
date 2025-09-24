"""Integration tests for SAML2 and LDAP SSO providers."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from langflow.services.auth.sso_service import SSOAuthenticationResult, SSOFlowState, SSOService
from langflow.services.database.models.rbac.sso_configuration import SSOConfiguration
from sqlmodel.ext.asyncio.session import AsyncSession


@pytest.fixture
async def sso_service():
    """Create SSO service instance."""
    service = SSOService()
    await service.initialize_service()
    return service


@pytest.fixture
def mock_session():
    """Mock database session."""
    return AsyncMock(spec=AsyncSession)


@pytest.fixture
def saml2_config():
    """SAML2 configuration for testing."""
    config = SSOConfiguration(
        id="saml2-test-id",
        name="Test SAML2 Provider",
        protocol="saml2",
        provider_url="https://idp.example.com",
        is_active=True,
        saml2_entity_id="langflow-sp-test",
        saml2_sso_url="https://idp.example.com/sso",
        saml2_slo_url="https://idp.example.com/slo",
        saml2_name_id_format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        saml2_acs_url="https://app.example.com/auth/saml/callback",
        saml2_metadata_url="https://idp.example.com/metadata",
        attribute_mapping={
            "email": "emailAddress",
            "name": "displayName",
            "groups": "memberOf"
        }
    )
    return config


@pytest.fixture
def ldap_config():
    """LDAP configuration for testing."""
    config = SSOConfiguration(
        id="ldap-test-id",
        name="Test LDAP Provider",
        protocol="ldap",
        provider_url="ldap://ldap.example.com",
        is_active=True,
        ldap_server="ldap.example.com",
        ldap_port=389,
        ldap_use_ssl=False,
        ldap_use_tls=False,
        ldap_bind_dn="cn=admin,dc=example,dc=com",
        ldap_bind_password="admin_password",
        ldap_base_dn="dc=example,dc=com",
        ldap_user_search_base="ou=users,dc=example,dc=com",
        ldap_group_search_base="ou=groups,dc=example,dc=com",
        ldap_user_search_filter="(|(uid={username})(mail={username}))",
        ldap_group_search_filter="(&(objectClass=group)(member={user_dn}))",
        ldap_user_attributes=["uid", "cn", "mail", "givenName", "sn", "memberOf"],
        ldap_auth_method="SIMPLE",
        attribute_mapping={
            "email": "mail",
            "name": "cn"
        }
    )
    return config


class TestSSOServiceSAML2Integration:
    """Integration tests for SAML2 SSO functionality."""

    @pytest.mark.asyncio
    async def test_initiate_saml2_flow(self, sso_service, mock_session, saml2_config):
        """Test initiating SAML2 SSO flow."""
        # Mock database session
        mock_session.get.return_value = saml2_config

        # Mock SAML2 provider
        with patch("langflow.services.auth.saml2_provider.SAML2Provider") as mock_provider_class:
            mock_provider = MagicMock()
            mock_provider.initiate_flow.return_value = "https://idp.example.com/sso?SAMLRequest=..."
            mock_provider_class.return_value = mock_provider

            authorization_url, state = await sso_service.initiate_sso_flow(
                session=mock_session,
                provider_id="saml2-test-id",
                redirect_uri="https://app.example.com/auth/callback",
                client_ip="192.168.1.1",
                user_agent="Mozilla/5.0"
            )

        assert authorization_url.startswith("https://idp.example.com/sso")
        assert "SAMLRequest=" in authorization_url
        assert state is not None
        assert len(state) > 0

        # Verify flow context is stored
        assert state in sso_service._active_flows
        flow_context = sso_service._active_flows[state]
        assert flow_context.provider_id == "saml2-test-id"
        assert flow_context.client_ip == "192.168.1.1"

    @pytest.mark.asyncio
    async def test_handle_saml2_callback_success(self, sso_service, mock_session, saml2_config):
        """Test successful SAML2 callback handling."""
        # Set up flow context
        state = "test-state"
        sso_service._active_flows[state] = MagicMock(
            provider_id="saml2-test-id",
            nonce="test-nonce"
        )

        # Mock database session
        mock_session.get.return_value = saml2_config

        # Mock successful SAML2 response
        mock_user_claims = MagicMock()
        mock_user_claims.email = "test@example.com"
        mock_user_claims.name = "Test User"

        with patch("langflow.services.auth.saml2_provider.SAML2Provider") as mock_provider_class:
            mock_provider = MagicMock()
            mock_provider.handle_callback.return_value = SSOAuthenticationResult(
                success=True,
                user_claims=mock_user_claims,
                flow_state=SSOFlowState.COMPLETED
            )
            mock_provider_class.return_value = mock_provider

            result = await sso_service.handle_sso_callback(
                session=mock_session,
                state=state,
                authorization_code="SAMLResponse_base64_encoded"
            )

        assert result.success is True
        assert result.flow_state == SSOFlowState.COMPLETED
        assert result.user_claims.email == "test@example.com"

        # Verify flow context is cleaned up
        assert state not in sso_service._active_flows

    @pytest.mark.asyncio
    async def test_get_saml2_metadata(self, sso_service, mock_session, saml2_config):
        """Test SAML2 metadata generation."""
        # Mock database session
        mock_session.get.return_value = saml2_config

        with patch("langflow.services.auth.saml2_provider.SAML2Provider") as mock_provider_class:
            mock_provider = MagicMock()
            mock_provider.get_metadata.return_value = """<?xml version="1.0"?>
            <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="langflow-sp-test">
                <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                            Location="https://app.example.com/auth/callback" index="0"/>
                </SPSSODescriptor>
            </EntityDescriptor>"""
            mock_provider_class.return_value = mock_provider

            metadata = await sso_service.get_saml2_metadata(
                session=mock_session,
                provider_id="saml2-test-id",
                redirect_uri="https://app.example.com/auth/callback"
            )

        assert "EntityDescriptor" in metadata
        assert "SPSSODescriptor" in metadata
        assert "langflow-sp-test" in metadata
        assert "AssertionConsumerService" in metadata

    @pytest.mark.asyncio
    async def test_validate_saml2_token(self, sso_service, mock_session, saml2_config):
        """Test SAML2 token validation."""
        # Mock database session
        mock_session.get.return_value = saml2_config

        mock_user_claims = MagicMock()
        mock_user_claims.email = "test@example.com"

        with patch("langflow.services.auth.saml2_provider.SAML2Provider") as mock_provider_class:
            mock_provider = MagicMock()
            mock_provider.validate_token.return_value = SSOAuthenticationResult(
                success=True,
                user_claims=mock_user_claims,
                flow_state=SSOFlowState.COMPLETED
            )
            mock_provider_class.return_value = mock_provider

            result = await sso_service.validate_sso_token(
                session=mock_session,
                provider_id="saml2-test-id",
                token="<saml:Assertion>...</saml:Assertion>"
            )

        assert result.success is True
        assert result.user_claims.email == "test@example.com"


class TestSSOServiceLDAPIntegration:
    """Integration tests for LDAP SSO functionality."""

    @pytest.mark.asyncio
    async def test_initiate_ldap_flow(self, sso_service, mock_session, ldap_config):
        """Test initiating LDAP authentication flow."""
        # Mock database session
        mock_session.get.return_value = ldap_config

        with patch("langflow.services.auth.ldap_provider.LDAPProvider") as mock_provider_class:
            mock_provider = MagicMock()
            mock_provider.initiate_flow.return_value = "ldap://authenticate?state=test&nonce=nonce"
            mock_provider_class.return_value = mock_provider

            authorization_url, state = await sso_service.initiate_sso_flow(
                session=mock_session,
                provider_id="ldap-test-id",
                redirect_uri="https://app.example.com/auth/callback"
            )

        assert authorization_url.startswith("ldap://authenticate")
        assert state is not None

    @pytest.mark.asyncio
    async def test_authenticate_ldap_user_success(self, sso_service, mock_session, ldap_config):
        """Test successful LDAP user authentication."""
        # Mock database session
        mock_session.get.return_value = ldap_config

        mock_user_claims = MagicMock()
        mock_user_claims.email = "test@example.com"
        mock_user_claims.name = "Test User"
        mock_user_claims.groups = ["Administrators", "Users"]

        with patch("langflow.services.auth.ldap_provider.LDAPProvider") as mock_provider_class:
            mock_provider = MagicMock()
            mock_provider.authenticate_user.return_value = SSOAuthenticationResult(
                success=True,
                user_claims=mock_user_claims,
                flow_state=SSOFlowState.COMPLETED,
                provider_response={
                    "dn": "uid=testuser,ou=users,dc=example,dc=com",
                    "groups": ["Administrators", "Users"]
                }
            )
            mock_provider_class.return_value = mock_provider

            result = await sso_service.authenticate_ldap_user(
                session=mock_session,
                provider_id="ldap-test-id",
                username="testuser",
                password="testpass"
            )

        assert result.success is True
        assert result.flow_state == SSOFlowState.COMPLETED
        assert result.user_claims.email == "test@example.com"
        assert "Administrators" in result.user_claims.groups

    @pytest.mark.asyncio
    async def test_authenticate_ldap_user_invalid_credentials(self, sso_service, mock_session, ldap_config):
        """Test LDAP authentication with invalid credentials."""
        # Mock database session
        mock_session.get.return_value = ldap_config

        with patch("langflow.services.auth.ldap_provider.LDAPProvider") as mock_provider_class:
            mock_provider = MagicMock()
            mock_provider.authenticate_user.return_value = SSOAuthenticationResult(
                success=False,
                error_code="invalid_credentials",
                error_message="Invalid username or password",
                flow_state=SSOFlowState.FAILED
            )
            mock_provider_class.return_value = mock_provider

            result = await sso_service.authenticate_ldap_user(
                session=mock_session,
                provider_id="ldap-test-id",
                username="testuser",
                password="wrongpass"
            )

        assert result.success is False
        assert result.error_code == "invalid_credentials"
        assert result.flow_state == SSOFlowState.FAILED

    @pytest.mark.asyncio
    async def test_test_ldap_connection_success(self, sso_service, mock_session, ldap_config):
        """Test successful LDAP connection test."""
        # Mock database session
        mock_session.get.return_value = ldap_config

        with patch("langflow.services.auth.ldap_provider.LDAPProvider") as mock_provider_class:
            mock_provider = MagicMock()
            mock_provider.test_connection.return_value = True
            mock_provider_class.return_value = mock_provider

            result = await sso_service.test_ldap_connection(
                session=mock_session,
                provider_id="ldap-test-id"
            )

        assert result is True

    @pytest.mark.asyncio
    async def test_test_ldap_connection_failure(self, sso_service, mock_session, ldap_config):
        """Test failed LDAP connection test."""
        # Mock database session
        mock_session.get.return_value = ldap_config

        with patch("langflow.services.auth.ldap_provider.LDAPProvider") as mock_provider_class:
            mock_provider = MagicMock()
            mock_provider.test_connection.return_value = False
            mock_provider_class.return_value = mock_provider

            result = await sso_service.test_ldap_connection(
                session=mock_session,
                provider_id="ldap-test-id"
            )

        assert result is False

    @pytest.mark.asyncio
    async def test_ldap_validate_token_not_supported(self, sso_service, mock_session, ldap_config):
        """Test LDAP token validation (not supported)."""
        # Mock database session
        mock_session.get.return_value = ldap_config

        with patch("langflow.services.auth.ldap_provider.LDAPProvider") as mock_provider_class:
            mock_provider = MagicMock()
            mock_provider.validate_token.return_value = SSOAuthenticationResult(
                success=False,
                error_code="not_supported",
                error_message="LDAP does not support token validation",
                flow_state=SSOFlowState.FAILED
            )
            mock_provider_class.return_value = mock_provider

            result = await sso_service.validate_sso_token(
                session=mock_session,
                provider_id="ldap-test-id",
                token="some-token"
            )

        assert result.success is False
        assert result.error_code == "not_supported"


class TestSSOServiceErrorHandling:
    """Test error handling scenarios."""

    @pytest.mark.asyncio
    async def test_provider_not_found(self, sso_service, mock_session):
        """Test handling when provider is not found."""
        # Mock database session returning None
        mock_session.get.return_value = None

        result = await sso_service.authenticate_ldap_user(
            session=mock_session,
            provider_id="nonexistent-id",
            username="testuser",
            password="testpass"
        )

        assert result.success is False
        assert result.error_code == "provider_not_found"

    @pytest.mark.asyncio
    async def test_wrong_protocol_for_ldap(self, sso_service, mock_session, saml2_config):
        """Test LDAP authentication with SAML2 provider."""
        # Mock database session returning SAML2 config for LDAP call
        mock_session.get.return_value = saml2_config

        result = await sso_service.authenticate_ldap_user(
            session=mock_session,
            provider_id="saml2-test-id",
            username="testuser",
            password="testpass"
        )

        assert result.success is False
        assert result.error_code == "invalid_protocol"

    @pytest.mark.asyncio
    async def test_wrong_protocol_for_saml2_metadata(self, sso_service, mock_session, ldap_config):
        """Test SAML2 metadata with LDAP provider."""
        # Mock database session returning LDAP config for SAML2 call
        mock_session.get.return_value = ldap_config

        with pytest.raises(ValueError, match="Provider is not a SAML2 provider"):
            await sso_service.get_saml2_metadata(
                session=mock_session,
                provider_id="ldap-test-id",
                redirect_uri="https://app.example.com/auth/callback"
            )

    @pytest.mark.asyncio
    async def test_inactive_provider(self, sso_service, mock_session, saml2_config):
        """Test handling inactive provider."""
        # Make provider inactive
        saml2_config.is_active = False
        mock_session.get.return_value = saml2_config

        with pytest.raises(ValueError, match="provider not found or inactive"):
            await sso_service.get_saml2_metadata(
                session=mock_session,
                provider_id="saml2-test-id",
                redirect_uri="https://app.example.com/auth/callback"
            )

    @pytest.mark.asyncio
    async def test_callback_with_invalid_state(self, sso_service, mock_session):
        """Test callback handling with invalid state."""
        result = await sso_service.handle_sso_callback(
            session=mock_session,
            state="invalid-state",
            authorization_code="some-code"
        )

        assert result.success is False
        assert result.error_code == "invalid_state"

    def test_cleanup_expired_flows(self, sso_service):
        """Test cleanup of expired SSO flows."""
        from datetime import datetime, timedelta, timezone

        # Add some flows with different expiration times
        now = datetime.now(timezone.utc)

        # Expired flow
        expired_context = MagicMock()
        expired_context.expires_at = now - timedelta(hours=1)
        sso_service._active_flows["expired"] = expired_context

        # Valid flow
        valid_context = MagicMock()
        valid_context.expires_at = now + timedelta(hours=1)
        sso_service._active_flows["valid"] = valid_context

        # Run cleanup
        sso_service.cleanup_expired_flows()

        # Check that expired flow is removed and valid flow remains
        assert "expired" not in sso_service._active_flows
        assert "valid" in sso_service._active_flows


class TestSSOServiceProviderFactory:
    """Test SSO provider factory functionality."""

    def test_create_saml2_provider(self, saml2_config):
        """Test creating SAML2 provider via factory."""
        from langflow.services.auth.saml2_provider import SAML2Provider
        from langflow.services.auth.sso_service import SSOProviderFactory

        provider = SSOProviderFactory.create_provider(saml2_config)

        assert isinstance(provider, SAML2Provider)
        assert provider.entity_id == "langflow-sp-test"

    def test_create_ldap_provider(self, ldap_config):
        """Test creating LDAP provider via factory."""
        from langflow.services.auth.ldap_provider import LDAPProvider
        from langflow.services.auth.sso_service import SSOProviderFactory

        provider = SSOProviderFactory.create_provider(ldap_config)

        assert isinstance(provider, LDAPProvider)
        assert provider.ldap_server == "ldap.example.com"

    def test_unsupported_protocol(self):
        """Test error handling for unsupported protocol."""
        from langflow.services.auth.sso_service import SSOProviderFactory

        config = MagicMock()
        config.protocol = "unsupported_protocol"

        with pytest.raises(ValueError, match="Unsupported SSO protocol"):
            SSOProviderFactory.create_provider(config)
