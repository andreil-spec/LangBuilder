"""Tests for SAML2 SSO provider implementation."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from langflow.services.auth.saml2_provider import SAML2_NAMESPACES, SAML2Provider
from langflow.services.auth.sso_service import SSOFlowState
from lxml import etree


@pytest.fixture
def mock_saml2_config():
    """Mock SAML2 configuration."""
    config = MagicMock()
    config.id = "test-provider-id"
    config.protocol = "saml2"
    config.provider_url = "https://idp.example.com"
    config.client_id = "test-client-id"
    config.client_secret = "test-client-secret"
    config.saml2_entity_id = "langflow-sp-test"
    config.saml2_sso_url = "https://idp.example.com/sso"
    config.saml2_slo_url = "https://idp.example.com/slo"
    config.saml2_name_id_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    config.saml2_acs_url = "https://app.example.com/auth/saml/callback"
    config.saml2_metadata_url = "https://idp.example.com/metadata"
    config.saml2_certificate = None
    config.saml2_private_key = None
    config.saml2_idp_certificate = None
    config.saml2_signature_algorithm = "RSA_SHA256"
    config.saml2_digest_algorithm = "SHA256"
    config.attribute_mapping = {
        "email": "emailAddress",
        "name": "displayName",
        "groups": "memberOf"
    }
    return config


@pytest.fixture
def saml2_provider(mock_saml2_config):
    """Create SAML2 provider instance."""
    return SAML2Provider(mock_saml2_config)


class TestSAML2Provider:
    """Test cases for SAML2Provider."""

    def test_initialization(self, saml2_provider, mock_saml2_config):
        """Test SAML2 provider initialization."""
        assert saml2_provider.entity_id == "langflow-sp-test"
        assert saml2_provider.sso_url == "https://idp.example.com/sso"
        assert saml2_provider.slo_url == "https://idp.example.com/slo"
        assert saml2_provider.name_id_format == "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

    @pytest.mark.asyncio
    async def test_initiate_flow(self, saml2_provider):
        """Test SAML2 authentication flow initiation."""
        redirect_uri = "https://app.example.com/auth/callback"
        state = "test-state"
        nonce = "test-nonce"

        authorization_url = await saml2_provider.initiate_flow(redirect_uri, state, nonce)

        assert authorization_url.startswith(saml2_provider.sso_url)
        assert "SAMLRequest=" in authorization_url
        assert "RelayState=" in authorization_url
        assert "test-state:test-nonce" in authorization_url

    def test_create_authn_request(self, saml2_provider):
        """Test SAML authentication request creation."""
        redirect_uri = "https://app.example.com/auth/callback"
        state = "test-state"

        authn_request = saml2_provider._create_authn_request(redirect_uri, state)

        assert authn_request.tag.endswith("AuthnRequest")
        assert authn_request.get("Version") == "2.0"
        assert authn_request.get("Destination") == saml2_provider.sso_url
        assert authn_request.get("AssertionConsumerServiceURL") == redirect_uri

        # Check issuer
        issuer = authn_request.find(".//saml:Issuer", namespaces=SAML2_NAMESPACES)
        assert issuer is not None
        assert issuer.text == saml2_provider.entity_id

    @pytest.mark.asyncio
    async def test_handle_callback_success(self, saml2_provider):
        """Test successful SAML2 callback handling."""
        # Create mock SAML response
        saml_response = self._create_mock_saml_response()
        encoded_response = self._encode_saml_response(saml_response)

        with patch.object(saml2_provider, "_verify_signature", return_value=True), \
             patch.object(saml2_provider, "_validate_conditions", return_value=True):

            result = await saml2_provider.handle_callback(
                encoded_response,
                "test-state",
                "test-nonce"
            )

        assert result.success is True
        assert result.flow_state == SSOFlowState.COMPLETED
        assert result.user_claims is not None
        assert result.user_claims.email == "test@example.com"

    @pytest.mark.asyncio
    async def test_handle_callback_invalid_signature(self, saml2_provider):
        """Test callback handling with invalid signature."""
        saml_response = self._create_mock_saml_response()
        encoded_response = self._encode_saml_response(saml_response)

        # Mock IDP certificate to enable signature verification
        saml2_provider.idp_certificate = "test-cert"

        with patch.object(saml2_provider, "_verify_signature", return_value=False):
            result = await saml2_provider.handle_callback(
                encoded_response,
                "test-state",
                "test-nonce"
            )

        assert result.success is False
        assert result.error_code == "invalid_signature"
        assert result.flow_state == SSOFlowState.FAILED

    @pytest.mark.asyncio
    async def test_handle_callback_no_assertion(self, saml2_provider):
        """Test callback handling with no assertion."""
        # Create SAML response without assertion
        response = etree.Element(
            "{urn:oasis:names:tc:SAML:2.0:protocol}Response",
            nsmap=SAML2_NAMESPACES
        )
        encoded_response = self._encode_saml_response(response)

        result = await saml2_provider.handle_callback(
            encoded_response,
            "test-state",
            "test-nonce"
        )

        assert result.success is False
        assert result.error_code == "no_assertion"
        assert result.flow_state == SSOFlowState.FAILED

    @pytest.mark.asyncio
    async def test_validate_token_success(self, saml2_provider):
        """Test successful token validation."""
        assertion = self._create_mock_assertion()
        assertion_str = etree.tostring(assertion).decode()

        with patch.object(saml2_provider, "_verify_signature", return_value=True), \
             patch.object(saml2_provider, "_validate_conditions", return_value=True):

            result = await saml2_provider.validate_token(assertion_str)

        assert result.success is True
        assert result.flow_state == SSOFlowState.COMPLETED
        assert result.user_claims is not None

    def test_validate_conditions_success(self, saml2_provider):
        """Test successful conditions validation."""
        assertion = self._create_mock_assertion_with_conditions(
            not_before=datetime.now(timezone.utc) - timedelta(minutes=5),
            not_on_or_after=datetime.now(timezone.utc) + timedelta(minutes=30),
            audience=saml2_provider.entity_id
        )

        result = saml2_provider._validate_conditions(assertion)
        assert result is True

    def test_validate_conditions_expired(self, saml2_provider):
        """Test conditions validation with expired assertion."""
        assertion = self._create_mock_assertion_with_conditions(
            not_before=datetime.now(timezone.utc) - timedelta(hours=2),
            not_on_or_after=datetime.now(timezone.utc) - timedelta(hours=1),
            audience=saml2_provider.entity_id
        )

        result = saml2_provider._validate_conditions(assertion)
        assert result is False

    def test_validate_conditions_invalid_audience(self, saml2_provider):
        """Test conditions validation with invalid audience."""
        assertion = self._create_mock_assertion_with_conditions(
            not_before=datetime.now(timezone.utc) - timedelta(minutes=5),
            not_on_or_after=datetime.now(timezone.utc) + timedelta(minutes=30),
            audience="wrong-audience"
        )

        result = saml2_provider._validate_conditions(assertion)
        assert result is False

    def test_extract_user_claims(self, saml2_provider):
        """Test user claims extraction from SAML assertion."""
        assertion = self._create_mock_assertion_with_attributes()

        user_claims = saml2_provider._extract_user_claims(assertion)

        assert user_claims.sub == "test@example.com"
        assert user_claims.email == "test@example.com"
        assert user_claims.name == "Test User"
        assert user_claims.given_name == "Test"
        assert user_claims.family_name == "User"
        assert "Administrators" in user_claims.groups

    @pytest.mark.asyncio
    async def test_get_metadata(self, saml2_provider):
        """Test SAML2 metadata generation."""
        saml2_provider.assertion_consumer_service_url = "https://app.example.com/auth/callback"

        metadata = await saml2_provider.get_metadata()

        assert "EntityDescriptor" in metadata
        assert "SPSSODescriptor" in metadata
        assert saml2_provider.entity_id in metadata
        assert "AssertionConsumerService" in metadata

    @pytest.mark.asyncio
    async def test_fetch_idp_metadata_success(self, saml2_provider):
        """Test successful IDP metadata fetching."""
        mock_metadata = """<?xml version="1.0"?>
        <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
            <IDPSSODescriptor>
                <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                   Location="https://idp.example.com/sso"/>
            </IDPSSODescriptor>
        </EntityDescriptor>"""

        with patch("httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.content = mock_metadata.encode()

            mock_client.return_value.__aenter__.return_value.get.return_value = mock_response

            metadata = await saml2_provider._fetch_idp_metadata()

        assert metadata is not None
        assert metadata.tag.endswith("EntityDescriptor")

    def _create_mock_saml_response(self):
        """Create a mock SAML response."""
        response = etree.Element(
            "{urn:oasis:names:tc:SAML:2.0:protocol}Response",
            nsmap=SAML2_NAMESPACES
        )

        assertion = self._create_mock_assertion()
        response.append(assertion)

        return response

    def _create_mock_assertion(self):
        """Create a mock SAML assertion."""
        assertion = etree.Element(
            "{urn:oasis:names:tc:SAML:2.0:assertion}Assertion",
            nsmap=SAML2_NAMESPACES
        )

        # Add Subject with NameID
        subject = etree.SubElement(assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}Subject")
        name_id = etree.SubElement(subject, "{urn:oasis:names:tc:SAML:2.0:assertion}NameID")
        name_id.text = "test@example.com"

        return assertion

    def _create_mock_assertion_with_conditions(self, not_before, not_on_or_after, audience):
        """Create mock assertion with conditions."""
        assertion = self._create_mock_assertion()

        conditions = etree.SubElement(
            assertion,
            "{urn:oasis:names:tc:SAML:2.0:assertion}Conditions",
            NotBefore=not_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
            NotOnOrAfter=not_on_or_after.strftime("%Y-%m-%dT%H:%M:%SZ")
        )

        audience_restriction = etree.SubElement(
            conditions,
            "{urn:oasis:names:tc:SAML:2.0:assertion}AudienceRestriction"
        )
        audience_elem = etree.SubElement(
            audience_restriction,
            "{urn:oasis:names:tc:SAML:2.0:assertion}Audience"
        )
        audience_elem.text = audience

        return assertion

    def _create_mock_assertion_with_attributes(self):
        """Create mock assertion with attribute statement."""
        assertion = self._create_mock_assertion()

        attr_statement = etree.SubElement(
            assertion,
            "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement"
        )

        # Add attributes
        attributes = [
            ("emailAddress", "test@example.com"),
            ("displayName", "Test User"),
            ("givenName", "Test"),
            ("surname", "User"),
            ("memberOf", "Administrators"),
        ]

        for attr_name, attr_value in attributes:
            attr = etree.SubElement(
                attr_statement,
                "{urn:oasis:names:tc:SAML:2.0:assertion}Attribute",
                Name=attr_name
            )
            attr_value_elem = etree.SubElement(
                attr,
                "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue"
            )
            attr_value_elem.text = attr_value

        return assertion

    def _encode_saml_response(self, response):
        """Encode SAML response for testing."""
        import base64
        import zlib

        xml_str = etree.tostring(response)
        compressed = zlib.compress(xml_str)
        encoded = base64.b64encode(compressed).decode()
        return encoded
