"""SAML2 SSO provider implementation for enterprise authentication.

This module implements SAML2 authentication following LangBuilder patterns,
providing enterprise-grade single sign-on capabilities.
"""

import base64
import uuid
import zlib
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from urllib.parse import urlencode

import httpx
from loguru import logger
from lxml import etree
from signxml import XMLSigner, XMLVerifier

from langflow.services.auth.sso_service import (
    SSOAuthenticationResult,
    SSOFlowState,
    SSOProvider,
    SSOUserClaims,
)

if TYPE_CHECKING:
    from langflow.services.database.models.rbac.sso_configuration import SSOConfiguration

# SAML2 Constants
SAML2_NAMESPACES = {
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "xenc": "http://www.w3.org/2001/04/xmlenc#",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
}

SAML2_BINDINGS = {
    "POST": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
    "REDIRECT": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
    "ARTIFACT": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
}

SAML2_STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"


class SAML2Provider(SSOProvider):
    """SAML2 SSO provider implementation."""

    def __init__(self, configuration: "SSOConfiguration"):
        """Initialize SAML2 provider with configuration.

        Args:
            configuration: SSO configuration object
        """
        super().__init__(configuration)

        # SAML2 specific configuration
        self.entity_id = configuration.saml2_entity_id or f"langflow-sp-{configuration.id}"
        self.sso_url = configuration.saml2_sso_url or f"{self.base_url}/sso"
        self.slo_url = configuration.saml2_slo_url or f"{self.base_url}/slo"
        self.certificate = configuration.saml2_certificate
        self.private_key = configuration.saml2_private_key
        self.idp_certificate = configuration.saml2_idp_certificate

        # Optional settings
        self.name_id_format = (
            configuration.saml2_name_id_format or
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        )
        self.assertion_consumer_service_url = configuration.saml2_acs_url
        self.metadata_url = configuration.saml2_metadata_url
        self.signature_algorithm = configuration.saml2_signature_algorithm or "RSA_SHA256"
        self.digest_algorithm = configuration.saml2_digest_algorithm or "SHA256"

        # Cache for IDP metadata
        self._idp_metadata_cache = None
        self._idp_metadata_cache_time = None
        self._metadata_cache_ttl = 3600  # 1 hour

    async def initiate_flow(
        self,
        redirect_uri: str,
        state: str,
        nonce: str,
    ) -> str:
        """Initiate SAML2 authentication flow.

        Args:
            redirect_uri: Callback URI after authentication
            state: State parameter for CSRF protection
            nonce: Nonce for replay protection (stored as RelayState)

        Returns:
            Authorization URL with SAML Request
        """
        try:
            # Generate SAML authentication request
            authn_request = self._create_authn_request(redirect_uri, state)

            # Sign the request if we have a private key
            if self.private_key:
                authn_request = self._sign_request(authn_request)

            # Encode the request
            encoded_request = base64.b64encode(
                zlib.compress(etree.tostring(authn_request))
            ).decode("utf-8")

            # Create relay state combining state and nonce
            relay_state = f"{state}:{nonce}"

            # Build authorization URL
            params = {
                "SAMLRequest": encoded_request,
                "RelayState": relay_state,
            }

            authorization_url = f"{self.sso_url}?{urlencode(params)}"

            logger.info(
                "SAML2 authentication flow initiated",
                extra={
                    "entity_id": self.entity_id,
                    "sso_url": self.sso_url,
                    "redirect_uri": redirect_uri,
                }
            )

            return authorization_url

        except Exception as e:
            logger.error(f"Failed to initiate SAML2 flow: {e}")
            raise ValueError(f"SAML2 flow initiation failed: {e!s}")

    async def handle_callback(
        self,
        authorization_code: str,  # This will be SAMLResponse
        state: str,
        nonce: str,
    ) -> SSOAuthenticationResult:
        """Handle SAML2 callback and extract user claims.

        Args:
            authorization_code: SAMLResponse from IDP
            state: State parameter for validation
            nonce: Nonce for validation

        Returns:
            Authentication result with user claims
        """
        try:
            # Decode SAML response
            saml_response = base64.b64decode(authorization_code)
            response_doc = etree.fromstring(saml_response)

            # Validate signature if IDP certificate is configured
            if self.idp_certificate:
                if not self._verify_signature(response_doc):
                    return SSOAuthenticationResult(
                        success=False,
                        error_code="invalid_signature",
                        error_message="SAML response signature validation failed",
                        flow_state=SSOFlowState.FAILED,
                    )

            # Extract and validate assertions
            assertions = response_doc.xpath(
                "//saml:Assertion",
                namespaces=SAML2_NAMESPACES
            )

            if not assertions:
                return SSOAuthenticationResult(
                    success=False,
                    error_code="no_assertion",
                    error_message="No assertion found in SAML response",
                    flow_state=SSOFlowState.FAILED,
                )

            assertion = assertions[0]

            # Validate conditions (time bounds, audience)
            if not self._validate_conditions(assertion):
                return SSOAuthenticationResult(
                    success=False,
                    error_code="invalid_conditions",
                    error_message="SAML assertion conditions validation failed",
                    flow_state=SSOFlowState.FAILED,
                )

            # Extract user attributes
            user_claims = self._extract_user_claims(assertion)

            logger.info(
                "SAML2 authentication successful",
                extra={
                    "user_email": user_claims.email,
                    "entity_id": self.entity_id,
                }
            )

            return SSOAuthenticationResult(
                success=True,
                user_claims=user_claims,
                flow_state=SSOFlowState.COMPLETED,
                provider_response={"assertion": etree.tostring(assertion).decode()},
            )

        except Exception as e:
            logger.error(f"SAML2 callback handling failed: {e}")
            return SSOAuthenticationResult(
                success=False,
                error_code="callback_error",
                error_message=str(e),
                flow_state=SSOFlowState.FAILED,
            )

    async def validate_token(
        self,
        token: str,
    ) -> SSOAuthenticationResult:
        """Validate SAML2 token (assertion).

        Args:
            token: SAML assertion to validate

        Returns:
            Authentication result with user claims
        """
        try:
            # Parse the assertion
            assertion_doc = etree.fromstring(token.encode() if isinstance(token, str) else token)

            # Validate signature
            if self.idp_certificate and not self._verify_signature(assertion_doc):
                return SSOAuthenticationResult(
                    success=False,
                    error_code="invalid_signature",
                    error_message="SAML assertion signature validation failed",
                    flow_state=SSOFlowState.FAILED,
                )

            # Validate conditions
            if not self._validate_conditions(assertion_doc):
                return SSOAuthenticationResult(
                    success=False,
                    error_code="invalid_conditions",
                    error_message="SAML assertion conditions validation failed",
                    flow_state=SSOFlowState.FAILED,
                )

            # Extract user claims
            user_claims = self._extract_user_claims(assertion_doc)

            return SSOAuthenticationResult(
                success=True,
                user_claims=user_claims,
                flow_state=SSOFlowState.COMPLETED,
            )

        except Exception as e:
            logger.error(f"SAML2 token validation failed: {e}")
            return SSOAuthenticationResult(
                success=False,
                error_code="validation_error",
                error_message=str(e),
                flow_state=SSOFlowState.FAILED,
            )

    async def get_metadata(self) -> str:
        """Generate service provider metadata.

        Returns:
            SP metadata XML document
        """
        metadata = etree.Element(
            "{urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor",
            entityID=self.entity_id,
            nsmap={"md": "urn:oasis:names:tc:SAML:2.0:metadata"},
        )

        sp_descriptor = etree.SubElement(
            metadata,
            "{urn:oasis:names:tc:SAML:2.0:metadata}SPSSODescriptor",
            protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol",
        )

        # Add key descriptor if certificate is available
        if self.certificate:
            key_descriptor = etree.SubElement(
                sp_descriptor,
                "{urn:oasis:names:tc:SAML:2.0:metadata}KeyDescriptor",
                use="signing",
            )
            key_info = etree.SubElement(
                key_descriptor,
                "{http://www.w3.org/2000/09/xmldsig#}KeyInfo",
            )
            x509_data = etree.SubElement(
                key_info,
                "{http://www.w3.org/2000/09/xmldsig#}X509Data",
            )
            x509_cert = etree.SubElement(
                x509_data,
                "{http://www.w3.org/2000/09/xmldsig#}X509Certificate",
            )
            x509_cert.text = self.certificate.replace("-----BEGIN CERTIFICATE-----", "").replace(
                "-----END CERTIFICATE-----", ""
            ).strip()

        # Add NameID formats
        name_id_format = etree.SubElement(
            sp_descriptor,
            "{urn:oasis:names:tc:SAML:2.0:metadata}NameIDFormat",
        )
        name_id_format.text = self.name_id_format

        # Add Assertion Consumer Service
        acs = etree.SubElement(
            sp_descriptor,
            "{urn:oasis:names:tc:SAML:2.0:metadata}AssertionConsumerService",
            Binding=SAML2_BINDINGS["POST"],
            Location=self.assertion_consumer_service_url or redirect_uri,
            index="0",
            isDefault="true",
        )

        return etree.tostring(metadata, pretty_print=True).decode()

    def _create_authn_request(self, redirect_uri: str, state: str) -> etree.Element:
        """Create SAML authentication request.

        Args:
            redirect_uri: Callback URI
            state: State parameter

        Returns:
            SAML AuthnRequest element
        """
        request_id = f"id-{uuid.uuid4()}"
        issue_instant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        authn_request = etree.Element(
            "{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest",
            ID=request_id,
            Version="2.0",
            IssueInstant=issue_instant,
            Destination=self.sso_url,
            AssertionConsumerServiceURL=redirect_uri,
            ProtocolBinding=SAML2_BINDINGS["POST"],
            nsmap=SAML2_NAMESPACES,
        )

        # Add Issuer
        issuer = etree.SubElement(
            authn_request,
            "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer",
        )
        issuer.text = self.entity_id

        # Add NameIDPolicy
        name_id_policy = etree.SubElement(
            authn_request,
            "{urn:oasis:names:tc:SAML:2.0:protocol}NameIDPolicy",
            Format=self.name_id_format,
            AllowCreate="true",
        )

        # Add RequestedAuthnContext (optional)
        requested_authn_context = etree.SubElement(
            authn_request,
            "{urn:oasis:names:tc:SAML:2.0:protocol}RequestedAuthnContext",
            Comparison="minimum",
        )

        authn_context_class_ref = etree.SubElement(
            requested_authn_context,
            "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextClassRef",
        )
        authn_context_class_ref.text = (
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
        )

        return authn_request

    def _sign_request(self, request: etree.Element) -> etree.Element:
        """Sign SAML request with private key.

        Args:
            request: SAML request to sign

        Returns:
            Signed SAML request
        """
        if not self.private_key or not self.certificate:
            return request

        try:
            signer = XMLSigner(
                method=self.signature_algorithm,
                digest=self.digest_algorithm,
            )
            signed_request = signer.sign(
                request,
                key=self.private_key,
                cert=self.certificate,
            )
            return signed_request
        except Exception as e:
            logger.warning(f"Failed to sign SAML request: {e}")
            return request

    def _verify_signature(self, element: etree.Element) -> bool:
        """Verify XML signature on SAML element.

        Args:
            element: SAML element to verify

        Returns:
            True if signature is valid
        """
        if not self.idp_certificate:
            logger.warning("No IDP certificate configured for signature verification")
            return True

        try:
            verifier = XMLVerifier()
            verifier.verify(element, x509_cert=self.idp_certificate)
            return True
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False

    def _validate_conditions(self, assertion: etree.Element) -> bool:
        """Validate SAML assertion conditions.

        Args:
            assertion: SAML assertion element

        Returns:
            True if conditions are valid
        """
        conditions = assertion.xpath(
            ".//saml:Conditions",
            namespaces=SAML2_NAMESPACES,
        )

        if not conditions:
            return True  # No conditions to validate

        condition = conditions[0]

        # Check NotBefore
        not_before = condition.get("NotBefore")
        if not_before:
            not_before_dt = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
            if datetime.now(timezone.utc) < not_before_dt:
                logger.warning("SAML assertion not yet valid")
                return False

        # Check NotOnOrAfter
        not_on_or_after = condition.get("NotOnOrAfter")
        if not_on_or_after:
            not_on_or_after_dt = datetime.fromisoformat(
                not_on_or_after.replace("Z", "+00:00")
            )
            if datetime.now(timezone.utc) >= not_on_or_after_dt:
                logger.warning("SAML assertion expired")
                return False

        # Check AudienceRestriction
        audience_restrictions = condition.xpath(
            ".//saml:AudienceRestriction/saml:Audience",
            namespaces=SAML2_NAMESPACES,
        )

        if audience_restrictions:
            valid_audience = False
            for audience in audience_restrictions:
                if audience.text == self.entity_id:
                    valid_audience = True
                    break
            if not valid_audience:
                logger.warning("Invalid audience in SAML assertion")
                return False

        return True

    def _extract_user_claims(self, assertion: etree.Element) -> SSOUserClaims:
        """Extract user claims from SAML assertion.

        Args:
            assertion: SAML assertion element

        Returns:
            User claims object
        """
        claims = {}

        # Extract NameID
        name_ids = assertion.xpath(
            ".//saml:Subject/saml:NameID",
            namespaces=SAML2_NAMESPACES,
        )
        if name_ids:
            name_id = name_ids[0]
            claims["sub"] = name_id.text
            if self.name_id_format == "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress":
                claims["email"] = name_id.text

        # Extract attributes
        attribute_statements = assertion.xpath(
            ".//saml:AttributeStatement",
            namespaces=SAML2_NAMESPACES,
        )

        if attribute_statements:
            for attribute_statement in attribute_statements:
                attributes = attribute_statement.xpath(
                    ".//saml:Attribute",
                    namespaces=SAML2_NAMESPACES,
                )

                for attribute in attributes:
                    attr_name = attribute.get("Name")
                    attr_values = attribute.xpath(
                        ".//saml:AttributeValue",
                        namespaces=SAML2_NAMESPACES,
                    )

                    if attr_values:
                        # Handle multiple values
                        if len(attr_values) == 1:
                            claims[attr_name] = attr_values[0].text
                        else:
                            claims[attr_name] = [v.text for v in attr_values]

        # Map to standard claims using provider's attribute mapping
        mapped_claims = self.map_attributes(claims)

        return mapped_claims

    async def _fetch_idp_metadata(self) -> etree.Element | None:
        """Fetch and cache IDP metadata.

        Returns:
            IDP metadata document or None
        """
        if not self.metadata_url:
            return None

        # Check cache
        if (
            self._idp_metadata_cache and
            self._idp_metadata_cache_time and
            (datetime.now() - self._idp_metadata_cache_time).seconds < self._metadata_cache_ttl
        ):
            return self._idp_metadata_cache

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(self.metadata_url)
                if response.status_code == 200:
                    metadata = etree.fromstring(response.content)
                    self._idp_metadata_cache = metadata
                    self._idp_metadata_cache_time = datetime.now()
                    return metadata
        except Exception as e:
            logger.error(f"Failed to fetch IDP metadata: {e}")

        return None
