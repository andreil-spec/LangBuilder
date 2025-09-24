"""LDAP SSO provider implementation for directory service authentication.

This module implements LDAP authentication following LangBuilder patterns,
providing integration with Active Directory and other LDAP servers.
"""

import asyncio
import re
from typing import TYPE_CHECKING, Any

import ldap3
from ldap3 import (
    ALL,
    ANONYMOUS,
    NTLM,
    SASL,
    SIMPLE,
    Connection,
    Server,
    ServerPool,
    Tls,
)
from ldap3.core.exceptions import (
    LDAPException,
    LDAPInvalidCredentialsResult,
)
from loguru import logger

from langflow.services.auth.sso_service import (
    SSOAuthenticationResult,
    SSOFlowState,
    SSOProvider,
    SSOUserClaims,
)

if TYPE_CHECKING:
    from langflow.services.database.models.rbac.sso_configuration import SSOConfiguration

# LDAP Constants
DEFAULT_LDAP_PORT = 389
DEFAULT_LDAPS_PORT = 636
DEFAULT_TIMEOUT = 30
MAX_CONNECTION_LIFETIME = 3600  # 1 hour
CONNECTION_POOL_SIZE = 10


class LDAPProvider(SSOProvider):
    """LDAP SSO provider implementation for directory service authentication."""

    def __init__(self, configuration: "SSOConfiguration"):
        """Initialize LDAP provider with configuration.

        Args:
            configuration: SSO configuration object
        """
        super().__init__(configuration)

        # LDAP specific configuration
        self.ldap_server = configuration.ldap_server or self.base_url
        self.ldap_port = configuration.ldap_port or DEFAULT_LDAP_PORT
        self.use_ssl = configuration.ldap_use_ssl or False
        self.use_tls = configuration.ldap_use_tls or False
        self.bind_dn = configuration.ldap_bind_dn
        self.bind_password = configuration.ldap_bind_password
        self.base_dn = configuration.ldap_base_dn or ""
        self.user_search_base = configuration.ldap_user_search_base or self.base_dn
        self.group_search_base = configuration.ldap_group_search_base or self.base_dn

        # Search filters
        self.user_search_filter = (
            configuration.ldap_user_search_filter or
            "(|(uid={username})(mail={username})(sAMAccountName={username}))"
        )
        self.group_search_filter = (
            configuration.ldap_group_search_filter or
            "(&(objectClass=group)(member={user_dn}))"
        )

        # Attribute mappings
        self.user_attributes = configuration.ldap_user_attributes or [
            "uid",
            "cn",
            "sn",
            "givenName",
            "mail",
            "displayName",
            "memberOf",
            "department",
            "title",
            "telephoneNumber",
        ]

        # Authentication method
        self.auth_method = configuration.ldap_auth_method or "SIMPLE"

        # Connection pool
        self._connection_pool = []
        self._pool_lock = asyncio.Lock()
        self._server_pool = None

        # Initialize server configuration
        self._setup_server_pool()

    def _setup_server_pool(self):
        """Set up LDAP server pool for high availability."""
        servers = []

        # Parse server list (comma-separated for multiple servers)
        server_list = self.ldap_server.split(",")

        for server_addr in server_list:
            server_addr = server_addr.strip()

            # Setup TLS if required
            tls = None
            if self.use_ssl or self.use_tls:
                tls = Tls(
                    validate=ldap3.ssl.CERT_OPTIONAL,
                    version=ldap3.ssl.PROTOCOL_TLSv1_2,
                )

            # Create server object
            server = Server(
                server_addr,
                port=self.ldap_port,
                use_ssl=self.use_ssl,
                tls=tls,
                get_info=ALL,
                connect_timeout=DEFAULT_TIMEOUT,
            )
            servers.append(server)

        # Create server pool for failover
        if len(servers) > 1:
            self._server_pool = ServerPool(
                servers,
                ldap3.ROUND_ROBIN,
                active=True,
                exhaust=True,
            )
        else:
            self._server_pool = servers[0]

    async def initiate_flow(
        self,
        redirect_uri: str,
        state: str,
        nonce: str,
    ) -> str:
        """Initiate LDAP authentication flow.

        Note: LDAP doesn't use redirect flows. This returns a special URL
        that indicates LDAP authentication should be handled via direct login.

        Args:
            redirect_uri: Callback URI after authentication
            state: State parameter for CSRF protection
            nonce: Nonce for replay protection

        Returns:
            Special LDAP authentication URL
        """
        # LDAP uses direct authentication, not redirect flows
        # Return a special URL that the frontend can detect
        return f"ldap://authenticate?state={state}&nonce={nonce}&redirect_uri={redirect_uri}"

    async def handle_callback(
        self,
        authorization_code: str,  # This will be username:password for LDAP
        state: str,
        nonce: str,
    ) -> SSOAuthenticationResult:
        """Handle LDAP authentication with credentials.

        Args:
            authorization_code: Username and password in format "username:password"
            state: State parameter for validation
            nonce: Nonce for validation

        Returns:
            Authentication result with user claims
        """
        try:
            # Parse credentials
            if ":" not in authorization_code:
                return SSOAuthenticationResult(
                    success=False,
                    error_code="invalid_credentials",
                    error_message="Invalid credential format",
                    flow_state=SSOFlowState.FAILED,
                )

            username, password = authorization_code.split(":", 1)

            # Authenticate user
            result = await self.authenticate_user(username, password)

            if not result.success:
                return result

            logger.info(
                "LDAP authentication successful",
                extra={
                    "user": username,
                    "ldap_server": self.ldap_server,
                }
            )

            return result

        except Exception as e:
            logger.error(f"LDAP authentication failed: {e}")
            return SSOAuthenticationResult(
                success=False,
                error_code="authentication_error",
                error_message=str(e),
                flow_state=SSOFlowState.FAILED,
            )

    async def validate_token(
        self,
        token: str,
    ) -> SSOAuthenticationResult:
        """Validate LDAP token (not applicable for LDAP).

        LDAP doesn't use tokens. This method returns an error.

        Args:
            token: Token to validate

        Returns:
            Authentication result indicating tokens are not supported
        """
        return SSOAuthenticationResult(
            success=False,
            error_code="not_supported",
            error_message="LDAP does not support token validation",
            flow_state=SSOFlowState.FAILED,
        )

    async def authenticate_user(
        self,
        username: str,
        password: str,
    ) -> SSOAuthenticationResult:
        """Authenticate user against LDAP directory.

        Args:
            username: Username or email
            password: User password

        Returns:
            Authentication result with user claims
        """
        connection = None
        try:
            # First, find the user's DN
            user_dn, user_attributes = await self._search_user(username)

            if not user_dn:
                return SSOAuthenticationResult(
                    success=False,
                    error_code="user_not_found",
                    error_message=f"User {username} not found in directory",
                    flow_state=SSOFlowState.FAILED,
                )

            # Authenticate with user's credentials
            connection = await self._create_connection(user_dn, password)

            if not connection.bind():
                return SSOAuthenticationResult(
                    success=False,
                    error_code="invalid_credentials",
                    error_message="Authentication failed",
                    flow_state=SSOFlowState.FAILED,
                )

            # Get user groups
            groups = await self._get_user_groups(user_dn, connection)

            # Extract user claims
            user_claims = self._extract_user_claims(user_attributes, groups)

            return SSOAuthenticationResult(
                success=True,
                user_claims=user_claims,
                flow_state=SSOFlowState.COMPLETED,
                provider_response={
                    "dn": user_dn,
                    "attributes": user_attributes,
                    "groups": groups,
                },
            )

        except LDAPInvalidCredentialsResult:
            return SSOAuthenticationResult(
                success=False,
                error_code="invalid_credentials",
                error_message="Invalid username or password",
                flow_state=SSOFlowState.FAILED,
            )
        except LDAPException as e:
            logger.error(f"LDAP error during authentication: {e}")
            return SSOAuthenticationResult(
                success=False,
                error_code="ldap_error",
                error_message=str(e),
                flow_state=SSOFlowState.FAILED,
            )
        except Exception as e:
            logger.error(f"Unexpected error during LDAP authentication: {e}")
            return SSOAuthenticationResult(
                success=False,
                error_code="internal_error",
                error_message="An internal error occurred",
                flow_state=SSOFlowState.FAILED,
            )
        finally:
            if connection:
                connection.unbind()

    async def _search_user(self, username: str) -> tuple[str | None, dict[str, Any]]:
        """Search for user in LDAP directory.

        Args:
            username: Username or email to search

        Returns:
            Tuple of (user_dn, user_attributes)
        """
        connection = None
        try:
            # Create connection with bind credentials
            connection = await self._create_connection(self.bind_dn, self.bind_password)

            if not connection.bind():
                logger.error("Failed to bind with service account")
                return None, {}

            # Format search filter
            search_filter = self.user_search_filter.format(username=username)

            # Search for user
            connection.search(
                search_base=self.user_search_base,
                search_filter=search_filter,
                attributes=self.user_attributes,
            )

            if connection.entries:
                entry = connection.entries[0]
                user_dn = entry.entry_dn
                user_attributes = entry.entry_attributes_as_dict

                return user_dn, user_attributes

            return None, {}

        except Exception as e:
            logger.error(f"Error searching for user {username}: {e}")
            return None, {}
        finally:
            if connection:
                connection.unbind()

    async def _get_user_groups(
        self,
        user_dn: str,
        connection: Connection | None = None,
    ) -> list[str]:
        """Get user's group memberships.

        Args:
            user_dn: User's distinguished name
            connection: Optional existing connection

        Returns:
            List of group DNs
        """
        close_connection = False
        if not connection:
            connection = await self._create_connection(self.bind_dn, self.bind_password)
            close_connection = True

        try:
            if not connection.bind():
                logger.error("Failed to bind for group search")
                return []

            # Format search filter
            search_filter = self.group_search_filter.format(user_dn=user_dn)

            # Search for groups
            connection.search(
                search_base=self.group_search_base,
                search_filter=search_filter,
                attributes=["cn", "displayName", "description"],
            )

            groups = []
            for entry in connection.entries:
                group_cn = entry.entry_attributes_as_dict.get("cn", [None])[0]
                if group_cn:
                    groups.append(group_cn)

            return groups

        except Exception as e:
            logger.error(f"Error getting user groups: {e}")
            return []
        finally:
            if close_connection and connection:
                connection.unbind()

    async def _create_connection(
        self,
        user_dn: str | None,
        password: str | None,
    ) -> Connection:
        """Create LDAP connection.

        Args:
            user_dn: User DN for binding
            password: Password for binding

        Returns:
            LDAP connection object
        """
        # Determine authentication method
        if self.auth_method == "ANONYMOUS":
            auth = ANONYMOUS
            user_dn = None
            password = None
        elif self.auth_method == "NTLM":
            auth = NTLM
        elif self.auth_method == "SASL":
            auth = SASL
        else:
            auth = SIMPLE

        # Create connection
        connection = Connection(
            self._server_pool,
            user=user_dn,
            password=password,
            authentication=auth,
            auto_bind=False,
            raise_exceptions=True,
            pool_size=CONNECTION_POOL_SIZE,
            pool_lifetime=MAX_CONNECTION_LIFETIME,
        )

        # Start TLS if configured
        if self.use_tls and not self.use_ssl:
            connection.start_tls()

        return connection

    def _extract_user_claims(
        self,
        user_attributes: dict[str, Any],
        groups: list[str],
    ) -> SSOUserClaims:
        """Extract user claims from LDAP attributes.

        Args:
            user_attributes: LDAP user attributes
            groups: User's group memberships

        Returns:
            User claims object
        """
        # Common LDAP to claim mappings
        ldap_to_claim_map = {
            "uid": "sub",
            "sAMAccountName": "sub",
            "userPrincipalName": "sub",
            "mail": "email",
            "cn": "name",
            "displayName": "name",
            "givenName": "given_name",
            "sn": "family_name",
            "department": "department",
            "o": "organization",
            "organizationName": "organization",
        }

        claims = {}

        # Map LDAP attributes to claims
        for ldap_attr, claim_name in ldap_to_claim_map.items():
            if ldap_attr in user_attributes:
                value = user_attributes[ldap_attr]
                if isinstance(value, list) and value:
                    value = value[0]
                if value:
                    claims[claim_name] = value

        # Add groups
        claims["groups"] = groups

        # Extract roles from groups if they follow a pattern
        roles = []
        for group in groups:
            # Common patterns for role groups
            if group.startswith("role_") or group.startswith("Role-"):
                role_name = re.sub(r"^(role_|Role-)", "", group)
                roles.append(role_name)
            elif "_role_" in group.lower():
                roles.append(group)

        if roles:
            claims["roles"] = roles

        # Map to standard claims using provider's attribute mapping
        mapped_claims = self.map_attributes(claims)

        # Ensure required fields
        if not mapped_claims.sub and claims.get("email"):
            mapped_claims.sub = claims["email"]
        if not mapped_claims.email and claims.get("sub") and "@" in claims["sub"]:
            mapped_claims.email = claims["sub"]

        return mapped_claims

    async def test_connection(self) -> bool:
        """Test LDAP connection with bind credentials.

        Returns:
            True if connection successful
        """
        connection = None
        try:
            connection = await self._create_connection(self.bind_dn, self.bind_password)
            result = connection.bind()

            if result:
                logger.info(f"LDAP connection test successful to {self.ldap_server}")
            else:
                logger.error(f"LDAP connection test failed: {connection.result}")

            return result

        except Exception as e:
            logger.error(f"LDAP connection test error: {e}")
            return False
        finally:
            if connection:
                connection.unbind()

    async def get_all_users(self, page_size: int = 1000) -> list[dict[str, Any]]:
        """Get all users from LDAP directory (for sync operations).

        Args:
            page_size: Number of entries per page

        Returns:
            List of user entries
        """
        connection = None
        users = []

        try:
            connection = await self._create_connection(self.bind_dn, self.bind_password)

            if not connection.bind():
                logger.error("Failed to bind for user enumeration")
                return []

            # Search for all users
            connection.search(
                search_base=self.user_search_base,
                search_filter="(|(objectClass=user)(objectClass=person)(objectClass=inetOrgPerson))",
                attributes=self.user_attributes,
                paged_size=page_size,
            )

            for entry in connection.entries:
                user_data = {
                    "dn": entry.entry_dn,
                    "attributes": entry.entry_attributes_as_dict,
                }
                users.append(user_data)

            logger.info(f"Retrieved {len(users)} users from LDAP")
            return users

        except Exception as e:
            logger.error(f"Error getting all users: {e}")
            return []
        finally:
            if connection:
                connection.unbind()

    async def get_all_groups(self, page_size: int = 1000) -> list[dict[str, Any]]:
        """Get all groups from LDAP directory (for sync operations).

        Args:
            page_size: Number of entries per page

        Returns:
            List of group entries
        """
        connection = None
        groups = []

        try:
            connection = await self._create_connection(self.bind_dn, self.bind_password)

            if not connection.bind():
                logger.error("Failed to bind for group enumeration")
                return []

            # Search for all groups
            connection.search(
                search_base=self.group_search_base,
                search_filter="(|(objectClass=group)(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))",
                attributes=["cn", "member", "memberUid", "description", "displayName"],
                paged_size=page_size,
            )

            for entry in connection.entries:
                group_data = {
                    "dn": entry.entry_dn,
                    "attributes": entry.entry_attributes_as_dict,
                }
                groups.append(group_data)

            logger.info(f"Retrieved {len(groups)} groups from LDAP")
            return groups

        except Exception as e:
            logger.error(f"Error getting all groups: {e}")
            return []
        finally:
            if connection:
                connection.unbind()
