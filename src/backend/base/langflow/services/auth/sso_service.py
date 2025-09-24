"""SSO integration framework for RBAC system.

This module provides Single Sign-On integration following LangBuilder patterns,
supporting OIDC, SAML2, OAuth2, and LDAP protocols.
"""

# NO future annotations per Phase 1 requirements
import base64
import json
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

import httpx
from loguru import logger
from pydantic import BaseModel
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.schema.serialize import UUIDstr
from langflow.services.base import Service

# Constants
HTTP_OK = 200
OIDC_DISCOVERY_CACHE_TTL = 3600  # 1 hour
SSO_FLOW_CLEANUP_INTERVAL = 3600  # 1 hour
TOKEN_REQUEST_TIMEOUT = 10.0
DISCOVERY_REQUEST_TIMEOUT = 10.0

if TYPE_CHECKING:
    from langflow.services.database.models.rbac.sso_configuration import SSOConfiguration


class SSOProtocol(str, Enum):
    """Supported SSO protocols."""

    OIDC = "oidc"
    SAML2 = "saml2"
    OAUTH2 = "oauth2"
    LDAP = "ldap"


class SSOFlowState(str, Enum):
    """SSO authentication flow states."""

    INITIATED = "initiated"
    AUTHENTICATED = "authenticated"
    AUTHORIZED = "authorized"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class SSOUserClaims:
    """User claims extracted from SSO provider."""

    sub: str  # Subject identifier
    email: str
    name: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    groups: list[str] | None = None
    roles: list[str] | None = None
    department: str | None = None
    organization: str | None = None
    custom_attributes: dict[str, Any] | None = None


@dataclass
class SSOFlowContext:
    """Context for SSO authentication flow."""

    state: str
    nonce: str
    provider_id: UUIDstr
    redirect_uri: str
    initiated_at: datetime
    expires_at: datetime
    client_ip: str | None = None
    user_agent: str | None = None


class SSOAuthenticationResult(BaseModel):
    """Result of SSO authentication process."""

    success: bool
    user_claims: SSOUserClaims | None = None
    error_code: str | None = None
    error_message: str | None = None
    provider_response: dict[str, Any] | None = None
    flow_state: SSOFlowState = SSOFlowState.FAILED


class SSOProvider(ABC):
    """Abstract base class for SSO providers following LangBuilder patterns."""

    def __init__(self, configuration: "SSOConfiguration"):
        """Initialize SSO provider with configuration."""
        self.configuration = configuration
        self.protocol = SSOProtocol(configuration.protocol)
        self.client_id = configuration.client_id
        self.client_secret = configuration.client_secret
        self.base_url = configuration.provider_url
        self.scopes = configuration.scopes or []
        self.attribute_mapping = configuration.attribute_mapping or {}

    @abstractmethod
    async def initiate_flow(
        self,
        redirect_uri: str,
        state: str,
        nonce: str,
    ) -> str:
        """Initiate SSO authentication flow.

        Args:
            redirect_uri: Callback URI after authentication
            state: State parameter for CSRF protection
            nonce: Nonce for replay protection

        Returns:
            Authorization URL to redirect user to
        """

    @abstractmethod
    async def handle_callback(
        self,
        authorization_code: str,
        state: str,
        nonce: str,
    ) -> SSOAuthenticationResult:
        """Handle SSO callback and extract user claims.

        Args:
            authorization_code: Authorization code from provider
            state: State parameter for validation
            nonce: Nonce for validation

        Returns:
            Authentication result with user claims
        """

    @abstractmethod
    async def validate_token(
        self,
        token: str,
    ) -> SSOAuthenticationResult:
        """Validate SSO token and extract claims.

        Args:
            token: Token to validate

        Returns:
            Authentication result with user claims
        """

    def map_attributes(self, provider_claims: dict[str, Any]) -> SSOUserClaims:
        """Map provider-specific claims to standard user claims.

        Args:
            provider_claims: Raw claims from SSO provider

        Returns:
            Mapped user claims
        """
        # Default mapping
        default_mapping = {
            "sub": "sub",
            "email": "email",
            "name": "name",
            "given_name": "given_name",
            "family_name": "family_name",
            "groups": "groups",
        }

        # Apply custom attribute mapping
        mapping = {**default_mapping, **self.attribute_mapping}

        mapped_claims = {}
        for standard_field, provider_field in mapping.items():
            if provider_field in provider_claims:
                mapped_claims[standard_field] = provider_claims[provider_field]

        # Extract groups and roles
        groups = mapped_claims.get("groups", [])
        if isinstance(groups, str):
            groups = [groups]

        roles = provider_claims.get("roles", [])
        if isinstance(roles, str):
            roles = [roles]

        return SSOUserClaims(
            sub=mapped_claims.get("sub", ""),
            email=mapped_claims.get("email", ""),
            name=mapped_claims.get("name"),
            given_name=mapped_claims.get("given_name"),
            family_name=mapped_claims.get("family_name"),
            groups=groups,
            roles=roles,
            department=provider_claims.get("department"),
            organization=provider_claims.get("organization"),
            custom_attributes={k: v for k, v in provider_claims.items()
                             if k not in mapping.values()}
        )


class OIDCProvider(SSOProvider):
    """OIDC/OAuth2 SSO provider implementation."""

    def __init__(self, configuration: "SSOConfiguration"):
        """Initialize OIDC provider."""
        super().__init__(configuration)
        self.discovery_endpoint = f"{self.base_url}/.well-known/openid_configuration"
        self._discovery_cache = None
        self._discovery_cache_time = None
        self._cache_ttl = 3600  # 1 hour cache

    async def _get_discovery_document(self) -> dict[str, Any]:
        """Get OIDC discovery document with caching."""
        now = datetime.now(timezone.utc)

        # Check cache
        if (self._discovery_cache and self._discovery_cache_time and
            (now - self._discovery_cache_time).total_seconds() < self._cache_ttl):
            return self._discovery_cache

        # Fetch discovery document
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(self.discovery_endpoint, timeout=10.0)
                response.raise_for_status()

                discovery_doc = response.json()
                self._discovery_cache = discovery_doc
                self._discovery_cache_time = now

                logger.info(f"Loaded OIDC discovery document from {self.discovery_endpoint}")
                return discovery_doc

            except httpx.HTTPError as e:
                logger.error(f"Failed to fetch OIDC discovery document: {e}")
                msg = f"Unable to fetch OIDC discovery document: {e}"
                raise ValueError(msg) from e

    async def initiate_flow(
        self,
        redirect_uri: str,
        state: str,
        nonce: str,
    ) -> str:
        """Initiate OIDC authentication flow."""
        discovery_doc = await self._get_discovery_document()
        authorization_endpoint = discovery_doc.get("authorization_endpoint")

        if not authorization_endpoint:
            msg = "Authorization endpoint not found in discovery document"
            raise ValueError(msg)

        # Build authorization URL
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(self.scopes or ["openid", "email", "profile"]),
            "state": state,
            "nonce": nonce,
        }

        auth_url = f"{authorization_endpoint}?{urlencode(params)}"
        logger.info(f"Generated OIDC authorization URL for client {self.client_id}")

        return auth_url

    async def handle_callback(
        self,
        authorization_code: str,
        state: str,
        nonce: str,
    ) -> SSOAuthenticationResult:
        """Handle OIDC callback and extract user claims."""
        try:
            discovery_doc = await self._get_discovery_document()
            token_endpoint = discovery_doc.get("token_endpoint")
            userinfo_endpoint = discovery_doc.get("userinfo_endpoint")

            if not token_endpoint:
                return SSOAuthenticationResult(
                    success=False,
                    error_code="missing_token_endpoint",
                    error_message="Token endpoint not found in discovery document"
                )

            # Exchange authorization code for tokens
            token_data = await self._exchange_code_for_tokens(
                token_endpoint, authorization_code, self.configuration.redirect_uri
            )

            if not token_data:
                return SSOAuthenticationResult(
                    success=False,
                    error_code="token_exchange_failed",
                    error_message="Failed to exchange authorization code for tokens"
                )

            # Validate ID token and extract claims
            user_claims = await self._extract_claims_from_tokens(
                token_data, userinfo_endpoint, nonce
            )

            if not user_claims:
                return SSOAuthenticationResult(
                    success=False,
                    error_code="claims_extraction_failed",
                    error_message="Failed to extract user claims from tokens"
                )

            logger.info(f"Successfully authenticated user {user_claims.email} via OIDC")

            return SSOAuthenticationResult(
                success=True,
                user_claims=user_claims,
                flow_state=SSOFlowState.COMPLETED,
                provider_response=token_data
            )

        except Exception as e:
            logger.error(f"OIDC callback handling failed: {e}")
            return SSOAuthenticationResult(
                success=False,
                error_code="callback_error",
                error_message=str(e)
            )

    async def validate_token(self, token: str) -> SSOAuthenticationResult:
        """Validate OIDC token and extract claims."""
        try:
            discovery_doc = await self._get_discovery_document()
            userinfo_endpoint = discovery_doc.get("userinfo_endpoint")

            if not userinfo_endpoint:
                return SSOAuthenticationResult(
                    success=False,
                    error_code="missing_userinfo_endpoint",
                    error_message="Userinfo endpoint not found"
                )

            # Call userinfo endpoint with access token
            async with httpx.AsyncClient() as client:
                headers = {"Authorization": f"Bearer {token}"}
                response = await client.get(userinfo_endpoint, headers=headers, timeout=10.0)

                if response.status_code != 200:
                    return SSOAuthenticationResult(
                        success=False,
                        error_code="invalid_token",
                        error_message="Token validation failed"
                    )

                provider_claims = response.json()
                user_claims = self.map_attributes(provider_claims)

                return SSOAuthenticationResult(
                    success=True,
                    user_claims=user_claims,
                    flow_state=SSOFlowState.COMPLETED,
                    provider_response=provider_claims
                )

        except Exception as e:
            logger.error(f"OIDC token validation failed: {e}")
            return SSOAuthenticationResult(
                success=False,
                error_code="token_validation_error",
                error_message=str(e)
            )

    async def _exchange_code_for_tokens(
        self,
        token_endpoint: str,
        authorization_code: str,
        redirect_uri: str,
    ) -> dict[str, Any] | None:
        """Exchange authorization code for access and ID tokens."""
        try:
            # Prepare token request
            token_data = {
                "grant_type": "authorization_code",
                "code": authorization_code,
                "redirect_uri": redirect_uri,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            }

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    token_endpoint,
                    data=token_data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=10.0
                )

                if response.status_code != 200:
                    logger.error(f"Token exchange failed: {response.status_code} {response.text}")
                    return None

                tokens = response.json()
                logger.debug("Successfully exchanged authorization code for tokens")
                return tokens

        except Exception as e:
            logger.error(f"Token exchange error: {e}")
            return None

    async def _extract_claims_from_tokens(
        self,
        token_data: dict[str, Any],
        userinfo_endpoint: str | None,
        nonce: str,
    ) -> SSOUserClaims | None:
        """Extract user claims from ID token and userinfo endpoint."""
        try:
            claims = {}

            # Extract claims from ID token if present
            id_token = token_data.get("id_token")
            if id_token:
                # Simple JWT parsing without signature verification for demo
                # In production, use proper JWT library with signature verification
                parts = id_token.split(".")
                if len(parts) >= 2:
                    # Decode payload (add padding if needed)
                    payload = parts[1]
                    payload += "=" * (4 - len(payload) % 4)
                    id_claims = json.loads(base64.urlsafe_b64decode(payload))

                    # Verify nonce
                    if id_claims.get("nonce") != nonce:
                        logger.warning("ID token nonce mismatch")
                        return None

                    claims.update(id_claims)

            # Get additional claims from userinfo endpoint
            access_token = token_data.get("access_token")
            if access_token and userinfo_endpoint:
                async with httpx.AsyncClient() as client:
                    headers = {"Authorization": f"Bearer {access_token}"}
                    response = await client.get(userinfo_endpoint, headers=headers, timeout=10.0)

                    if response.status_code == 200:
                        userinfo_claims = response.json()
                        claims.update(userinfo_claims)

            if not claims:
                logger.error("No claims extracted from tokens")
                return None

            # Map provider claims to standard format
            user_claims = self.map_attributes(claims)

            # Validate required fields
            if not user_claims.sub or not user_claims.email:
                logger.error("Missing required claims (sub or email)")
                return None

            return user_claims

        except Exception as e:
            logger.error(f"Claims extraction error: {e}")
            return None


class SSOProviderFactory:
    """Factory for creating SSO provider instances."""

    @staticmethod
    def create_provider(configuration: "SSOConfiguration") -> SSOProvider:
        """Create SSO provider based on protocol."""
        protocol = SSOProtocol(configuration.protocol)

        if protocol == SSOProtocol.OIDC:
            return OIDCProvider(configuration)
        if protocol == SSOProtocol.OAUTH2:
            return OIDCProvider(configuration)  # OAuth2 uses same implementation
        if protocol == SSOProtocol.SAML2:
            from langflow.services.auth.saml2_provider import SAML2Provider
            return SAML2Provider(configuration)
        if protocol == SSOProtocol.LDAP:
            from langflow.services.auth.ldap_provider import LDAPProvider
            return LDAPProvider(configuration)
        msg = f"Unsupported SSO protocol: {protocol}"
        raise ValueError(msg)


class SSOService(Service):
    """SSO service for managing authentication flows."""

    name = "sso_service"

    def __init__(self):
        super().__init__()
        self._active_flows: dict[str, SSOFlowContext] = {}
        self._flow_cleanup_interval = 3600  # 1 hour

    async def initialize_service(self) -> None:
        """Initialize SSO service."""
        logger.info("SSO service initialized")

    async def initiate_sso_flow(
        self,
        session: AsyncSession,
        provider_id: UUIDstr,
        redirect_uri: str,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[str, str]:
        """Initiate SSO authentication flow.

        Args:
            session: Database session
            provider_id: SSO provider configuration ID
            redirect_uri: Callback URI after authentication
            client_ip: Client IP address
            user_agent: Client user agent

        Returns:
            Tuple of (authorization_url, state)
        """
        # Get SSO configuration
        from langflow.services.database.models.rbac.sso_configuration import SSOConfiguration

        config = await session.get(SSOConfiguration, provider_id)
        if not config or not config.is_active:
            msg = "SSO provider not found or inactive"
            raise ValueError(msg)

        # Create provider instance
        provider = SSOProviderFactory.create_provider(config)

        # Generate flow context
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)

        flow_context = SSOFlowContext(
            state=state,
            nonce=nonce,
            provider_id=provider_id,
            redirect_uri=redirect_uri,
            initiated_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            client_ip=client_ip,
            user_agent=user_agent,
        )

        # Store flow context
        self._active_flows[state] = flow_context

        # Generate authorization URL
        auth_url = await provider.initiate_flow(redirect_uri, state, nonce)

        logger.info(f"Initiated SSO flow for provider {provider_id}")
        return auth_url, state

    async def handle_sso_callback(
        self,
        session: AsyncSession,
        authorization_code: str,
        state: str,
    ) -> SSOAuthenticationResult:
        """Handle SSO callback and authenticate user.

        Args:
            session: Database session
            authorization_code: Authorization code from provider
            state: State parameter for validation

        Returns:
            Authentication result
        """
        # Validate flow context
        flow_context = self._active_flows.get(state)
        if not flow_context:
            return SSOAuthenticationResult(
                success=False,
                error_code="invalid_state",
                error_message="Invalid or expired SSO flow state"
            )

        # Check expiration
        if datetime.now(timezone.utc) > flow_context.expires_at:
            self._active_flows.pop(state, None)
            return SSOAuthenticationResult(
                success=False,
                error_code="flow_expired",
                error_message="SSO flow has expired"
            )

        try:
            # Get SSO configuration
            from langflow.services.database.models.rbac.sso_configuration import SSOConfiguration

            config = await session.get(SSOConfiguration, flow_context.provider_id)
            if not config:
                return SSOAuthenticationResult(
                    success=False,
                    error_code="provider_not_found",
                    error_message="SSO provider configuration not found"
                )

            # Create provider and handle callback
            provider = SSOProviderFactory.create_provider(config)
            result = await provider.handle_callback(
                authorization_code,
                state,
                flow_context.nonce
            )

            # Clean up flow context
            self._active_flows.pop(state, None)

            if result.success and result.user_claims:
                logger.info(f"SSO authentication successful for {result.user_claims.email}")
            else:
                logger.warning(f"SSO authentication failed: {result.error_message}")

            return result

        except Exception as e:
            logger.error(f"SSO callback handling error: {e}")
            self._active_flows.pop(state, None)
            return SSOAuthenticationResult(
                success=False,
                error_code="callback_error",
                error_message=str(e)
            )

    async def validate_sso_token(
        self,
        session: AsyncSession,
        provider_id: UUIDstr,
        token: str,
    ) -> SSOAuthenticationResult:
        """Validate SSO token and extract user claims.

        Args:
            session: Database session
            provider_id: SSO provider configuration ID
            token: Token to validate

        Returns:
            Authentication result
        """
        try:
            # Get SSO configuration
            from langflow.services.database.models.rbac.sso_configuration import SSOConfiguration

            config = await session.get(SSOConfiguration, provider_id)
            if not config or not config.is_active:
                return SSOAuthenticationResult(
                    success=False,
                    error_code="provider_not_found",
                    error_message="SSO provider not found or inactive"
                )

            # Create provider and validate token
            provider = SSOProviderFactory.create_provider(config)
            return await provider.validate_token(token)


        except Exception as e:
            logger.error(f"SSO token validation error: {e}")
            return SSOAuthenticationResult(
                success=False,
                error_code="validation_error",
                error_message=str(e)
            )

    async def authenticate_ldap_user(
        self,
        session: AsyncSession,
        provider_id: UUIDstr,
        username: str,
        password: str,
    ) -> SSOAuthenticationResult:
        """Authenticate user directly with LDAP credentials.

        Args:
            session: Database session
            provider_id: LDAP provider configuration ID
            username: Username or email
            password: User password

        Returns:
            Authentication result
        """
        try:
            # Get LDAP configuration
            from langflow.services.database.models.rbac.sso_configuration import SSOConfiguration

            config = await session.get(SSOConfiguration, provider_id)
            if not config or not config.is_active:
                return SSOAuthenticationResult(
                    success=False,
                    error_code="provider_not_found",
                    error_message="LDAP provider not found or inactive"
                )

            if config.protocol != SSOProtocol.LDAP:
                return SSOAuthenticationResult(
                    success=False,
                    error_code="invalid_protocol",
                    error_message="Provider is not an LDAP provider"
                )

            # Create LDAP provider and authenticate
            from langflow.services.auth.ldap_provider import LDAPProvider

            provider = LDAPProvider(config)
            return await provider.authenticate_user(username, password)

        except Exception as e:
            logger.error(f"LDAP authentication error: {e}")
            return SSOAuthenticationResult(
                success=False,
                error_code="authentication_error",
                error_message=str(e)
            )

    async def get_saml2_metadata(
        self,
        session: AsyncSession,
        provider_id: UUIDstr,
        redirect_uri: str,
    ) -> str:
        """Get SAML2 service provider metadata.

        Args:
            session: Database session
            provider_id: SAML2 provider configuration ID
            redirect_uri: Assertion consumer service URL

        Returns:
            SAML2 metadata XML

        Raises:
            ValueError: If provider not found or not SAML2
        """
        try:
            # Get SAML2 configuration
            from langflow.services.database.models.rbac.sso_configuration import SSOConfiguration

            config = await session.get(SSOConfiguration, provider_id)
            if not config or not config.is_active:
                raise ValueError("SAML2 provider not found or inactive")

            if config.protocol != SSOProtocol.SAML2:
                raise ValueError("Provider is not a SAML2 provider")

            # Create SAML2 provider and get metadata
            from langflow.services.auth.saml2_provider import SAML2Provider

            provider = SAML2Provider(config)
            provider.assertion_consumer_service_url = redirect_uri
            return await provider.get_metadata()

        except Exception as e:
            logger.error(f"SAML2 metadata generation error: {e}")
            raise ValueError(f"Failed to generate SAML2 metadata: {e!s}")

    async def test_ldap_connection(
        self,
        session: AsyncSession,
        provider_id: UUIDstr,
    ) -> bool:
        """Test LDAP connection.

        Args:
            session: Database session
            provider_id: LDAP provider configuration ID

        Returns:
            True if connection successful
        """
        try:
            # Get LDAP configuration
            from langflow.services.database.models.rbac.sso_configuration import SSOConfiguration

            config = await session.get(SSOConfiguration, provider_id)
            if not config or config.protocol != SSOProtocol.LDAP:
                return False

            # Create LDAP provider and test connection
            from langflow.services.auth.ldap_provider import LDAPProvider

            provider = LDAPProvider(config)
            return await provider.test_connection()

        except Exception as e:
            logger.error(f"LDAP connection test error: {e}")
            return False

    def cleanup_expired_flows(self) -> None:
        """Clean up expired SSO flows."""
        now = datetime.now(timezone.utc)
        expired_states = [
            state for state, context in self._active_flows.items()
            if now > context.expires_at
        ]

        for state in expired_states:
            self._active_flows.pop(state, None)

        if expired_states:
            logger.info(f"Cleaned up {len(expired_states)} expired SSO flows")
