"""Tests for LDAP SSO provider implementation."""

from unittest.mock import MagicMock, patch

import pytest
from langflow.services.auth.ldap_provider import LDAPProvider
from langflow.services.auth.sso_service import SSOAuthenticationResult, SSOFlowState
from ldap3.core.exceptions import LDAPInvalidCredentialsResult


@pytest.fixture
def mock_ldap_config():
    """Mock LDAP configuration."""
    config = MagicMock()
    config.id = "test-ldap-provider"
    config.protocol = "ldap"
    config.provider_url = "ldap://ldap.example.com"
    config.ldap_server = "ldap.example.com"
    config.ldap_port = 389
    config.ldap_use_ssl = False
    config.ldap_use_tls = False
    config.ldap_bind_dn = "cn=admin,dc=example,dc=com"
    config.ldap_bind_password = "admin_password"
    config.ldap_base_dn = "dc=example,dc=com"
    config.ldap_user_search_base = "ou=users,dc=example,dc=com"
    config.ldap_group_search_base = "ou=groups,dc=example,dc=com"
    config.ldap_user_search_filter = "(|(uid={username})(mail={username}))"
    config.ldap_group_search_filter = "(&(objectClass=group)(member={user_dn}))"
    config.ldap_user_attributes = ["uid", "cn", "mail", "givenName", "sn", "memberOf"]
    config.ldap_auth_method = "SIMPLE"
    config.attribute_mapping = {
        "email": "mail",
        "name": "cn",
        "given_name": "givenName",
        "family_name": "sn"
    }
    return config


@pytest.fixture
def ldap_provider(mock_ldap_config):
    """Create LDAP provider instance."""
    return LDAPProvider(mock_ldap_config)


class TestLDAPProvider:
    """Test cases for LDAPProvider."""

    def test_initialization(self, ldap_provider, mock_ldap_config):
        """Test LDAP provider initialization."""
        assert ldap_provider.ldap_server == "ldap.example.com"
        assert ldap_provider.ldap_port == 389
        assert ldap_provider.use_ssl is False
        assert ldap_provider.use_tls is False
        assert ldap_provider.bind_dn == "cn=admin,dc=example,dc=com"
        assert ldap_provider.base_dn == "dc=example,dc=com"

    @pytest.mark.asyncio
    async def test_initiate_flow(self, ldap_provider):
        """Test LDAP authentication flow initiation."""
        redirect_uri = "https://app.example.com/auth/callback"
        state = "test-state"
        nonce = "test-nonce"

        authorization_url = await ldap_provider.initiate_flow(redirect_uri, state, nonce)

        assert authorization_url.startswith("ldap://authenticate")
        assert f"state={state}" in authorization_url
        assert f"nonce={nonce}" in authorization_url
        assert f"redirect_uri={redirect_uri}" in authorization_url

    @pytest.mark.asyncio
    async def test_handle_callback_success(self, ldap_provider):
        """Test successful LDAP callback handling."""
        credentials = "testuser:testpass"

        with patch.object(ldap_provider, "authenticate_user") as mock_auth:
            mock_auth.return_value = SSOAuthenticationResult(
                success=True,
                user_claims=MagicMock(email="test@example.com"),
                flow_state=SSOFlowState.COMPLETED
            )

            result = await ldap_provider.handle_callback(
                credentials,
                "test-state",
                "test-nonce"
            )

        assert result.success is True
        assert result.flow_state == SSOFlowState.COMPLETED
        mock_auth.assert_called_once_with("testuser", "testpass")

    @pytest.mark.asyncio
    async def test_handle_callback_invalid_format(self, ldap_provider):
        """Test callback handling with invalid credential format."""
        credentials = "invalid-format"

        result = await ldap_provider.handle_callback(
            credentials,
            "test-state",
            "test-nonce"
        )

        assert result.success is False
        assert result.error_code == "invalid_credentials"
        assert result.flow_state == SSOFlowState.FAILED

    @pytest.mark.asyncio
    async def test_validate_token_not_supported(self, ldap_provider):
        """Test token validation (not supported for LDAP)."""
        result = await ldap_provider.validate_token("some-token")

        assert result.success is False
        assert result.error_code == "not_supported"
        assert result.flow_state == SSOFlowState.FAILED

    @pytest.mark.asyncio
    async def test_authenticate_user_success(self, ldap_provider):
        """Test successful user authentication."""
        username = "testuser"
        password = "testpass"
        user_dn = "uid=testuser,ou=users,dc=example,dc=com"

        # Mock user search
        with patch.object(ldap_provider, "_search_user") as mock_search:
            mock_search.return_value = (user_dn, {
                "uid": ["testuser"],
                "mail": ["test@example.com"],
                "cn": ["Test User"],
                "givenName": ["Test"],
                "sn": ["User"]
            })

            # Mock connection creation and binding
            with patch.object(ldap_provider, "_create_connection") as mock_create_conn:
                mock_conn = MagicMock()
                mock_conn.bind.return_value = True
                mock_create_conn.return_value = mock_conn

                # Mock group search
                with patch.object(ldap_provider, "_get_user_groups") as mock_groups:
                    mock_groups.return_value = ["Administrators", "Users"]

                    result = await ldap_provider.authenticate_user(username, password)

        assert result.success is True
        assert result.flow_state == SSOFlowState.COMPLETED
        assert result.user_claims is not None
        assert result.user_claims.email == "test@example.com"
        assert "Administrators" in result.user_claims.groups

    @pytest.mark.asyncio
    async def test_authenticate_user_not_found(self, ldap_provider):
        """Test authentication with user not found."""
        username = "nonexistent"
        password = "testpass"

        with patch.object(ldap_provider, "_search_user") as mock_search:
            mock_search.return_value = (None, {})

            result = await ldap_provider.authenticate_user(username, password)

        assert result.success is False
        assert result.error_code == "user_not_found"
        assert result.flow_state == SSOFlowState.FAILED

    @pytest.mark.asyncio
    async def test_authenticate_user_invalid_credentials(self, ldap_provider):
        """Test authentication with invalid credentials."""
        username = "testuser"
        password = "wrongpass"
        user_dn = "uid=testuser,ou=users,dc=example,dc=com"

        with patch.object(ldap_provider, "_search_user") as mock_search:
            mock_search.return_value = (user_dn, {"uid": ["testuser"]})

            with patch.object(ldap_provider, "_create_connection") as mock_create_conn:
                mock_conn = MagicMock()
                mock_conn.bind.return_value = False
                mock_create_conn.return_value = mock_conn

                result = await ldap_provider.authenticate_user(username, password)

        assert result.success is False
        assert result.error_code == "invalid_credentials"
        assert result.flow_state == SSOFlowState.FAILED

    @pytest.mark.asyncio
    async def test_authenticate_user_ldap_exception(self, ldap_provider):
        """Test authentication with LDAP exception."""
        username = "testuser"
        password = "testpass"
        user_dn = "uid=testuser,ou=users,dc=example,dc=com"

        with patch.object(ldap_provider, "_search_user") as mock_search:
            mock_search.return_value = (user_dn, {"uid": ["testuser"]})

            with patch.object(ldap_provider, "_create_connection") as mock_create_conn:
                mock_create_conn.side_effect = LDAPInvalidCredentialsResult("Invalid credentials")

                result = await ldap_provider.authenticate_user(username, password)

        assert result.success is False
        assert result.error_code == "invalid_credentials"
        assert result.flow_state == SSOFlowState.FAILED

    @pytest.mark.asyncio
    async def test_search_user_success(self, ldap_provider):
        """Test successful user search."""
        username = "testuser"

        with patch.object(ldap_provider, "_create_connection") as mock_create_conn:
            mock_conn = MagicMock()
            mock_conn.bind.return_value = True

            # Mock search result
            mock_entry = MagicMock()
            mock_entry.entry_dn = "uid=testuser,ou=users,dc=example,dc=com"
            mock_entry.entry_attributes_as_dict = {
                "uid": ["testuser"],
                "mail": ["test@example.com"],
                "cn": ["Test User"]
            }
            mock_conn.entries = [mock_entry]

            mock_create_conn.return_value = mock_conn

            user_dn, user_attributes = await ldap_provider._search_user(username)

        assert user_dn == "uid=testuser,ou=users,dc=example,dc=com"
        assert user_attributes["uid"] == ["testuser"]
        assert user_attributes["mail"] == ["test@example.com"]

    @pytest.mark.asyncio
    async def test_search_user_not_found(self, ldap_provider):
        """Test user search with no results."""
        username = "nonexistent"

        with patch.object(ldap_provider, "_create_connection") as mock_create_conn:
            mock_conn = MagicMock()
            mock_conn.bind.return_value = True
            mock_conn.entries = []  # No results
            mock_create_conn.return_value = mock_conn

            user_dn, user_attributes = await ldap_provider._search_user(username)

        assert user_dn is None
        assert user_attributes == {}

    @pytest.mark.asyncio
    async def test_get_user_groups_success(self, ldap_provider):
        """Test successful user groups retrieval."""
        user_dn = "uid=testuser,ou=users,dc=example,dc=com"

        with patch.object(ldap_provider, "_create_connection") as mock_create_conn:
            mock_conn = MagicMock()
            mock_conn.bind.return_value = True

            # Mock group search results
            mock_group1 = MagicMock()
            mock_group1.entry_attributes_as_dict = {"cn": ["Administrators"]}
            mock_group2 = MagicMock()
            mock_group2.entry_attributes_as_dict = {"cn": ["Users"]}
            mock_conn.entries = [mock_group1, mock_group2]

            mock_create_conn.return_value = mock_conn

            groups = await ldap_provider._get_user_groups(user_dn)

        assert "Administrators" in groups
        assert "Users" in groups
        assert len(groups) == 2

    def test_extract_user_claims(self, ldap_provider):
        """Test user claims extraction from LDAP attributes."""
        user_attributes = {
            "uid": ["testuser"],
            "mail": ["test@example.com"],
            "cn": ["Test User"],
            "givenName": ["Test"],
            "sn": ["User"],
            "department": ["Engineering"]
        }
        groups = ["Administrators", "role_admin", "Role-Manager"]

        user_claims = ldap_provider._extract_user_claims(user_attributes, groups)

        assert user_claims.sub == "testuser"
        assert user_claims.email == "test@example.com"
        assert user_claims.name == "Test User"
        assert user_claims.given_name == "Test"
        assert user_claims.family_name == "User"
        assert user_claims.department == "Engineering"
        assert "Administrators" in user_claims.groups
        assert "admin" in user_claims.roles  # Extracted from role_admin
        assert "Role-Manager" in user_claims.roles

    @pytest.mark.asyncio
    async def test_test_connection_success(self, ldap_provider):
        """Test successful LDAP connection test."""
        with patch.object(ldap_provider, "_create_connection") as mock_create_conn:
            mock_conn = MagicMock()
            mock_conn.bind.return_value = True
            mock_create_conn.return_value = mock_conn

            result = await ldap_provider.test_connection()

        assert result is True

    @pytest.mark.asyncio
    async def test_test_connection_failure(self, ldap_provider):
        """Test failed LDAP connection test."""
        with patch.object(ldap_provider, "_create_connection") as mock_create_conn:
            mock_conn = MagicMock()
            mock_conn.bind.return_value = False
            mock_create_conn.return_value = mock_conn

            result = await ldap_provider.test_connection()

        assert result is False

    @pytest.mark.asyncio
    async def test_get_all_users(self, ldap_provider):
        """Test getting all users from LDAP."""
        with patch.object(ldap_provider, "_create_connection") as mock_create_conn:
            mock_conn = MagicMock()
            mock_conn.bind.return_value = True

            # Mock user entries
            mock_user1 = MagicMock()
            mock_user1.entry_dn = "uid=user1,ou=users,dc=example,dc=com"
            mock_user1.entry_attributes_as_dict = {"uid": ["user1"], "mail": ["user1@example.com"]}

            mock_user2 = MagicMock()
            mock_user2.entry_dn = "uid=user2,ou=users,dc=example,dc=com"
            mock_user2.entry_attributes_as_dict = {"uid": ["user2"], "mail": ["user2@example.com"]}

            mock_conn.entries = [mock_user1, mock_user2]
            mock_create_conn.return_value = mock_conn

            users = await ldap_provider.get_all_users()

        assert len(users) == 2
        assert users[0]["dn"] == "uid=user1,ou=users,dc=example,dc=com"
        assert users[1]["dn"] == "uid=user2,ou=users,dc=example,dc=com"

    @pytest.mark.asyncio
    async def test_get_all_groups(self, ldap_provider):
        """Test getting all groups from LDAP."""
        with patch.object(ldap_provider, "_create_connection") as mock_create_conn:
            mock_conn = MagicMock()
            mock_conn.bind.return_value = True

            # Mock group entries
            mock_group1 = MagicMock()
            mock_group1.entry_dn = "cn=Administrators,ou=groups,dc=example,dc=com"
            mock_group1.entry_attributes_as_dict = {"cn": ["Administrators"]}

            mock_group2 = MagicMock()
            mock_group2.entry_dn = "cn=Users,ou=groups,dc=example,dc=com"
            mock_group2.entry_attributes_as_dict = {"cn": ["Users"]}

            mock_conn.entries = [mock_group1, mock_group2]
            mock_create_conn.return_value = mock_conn

            groups = await ldap_provider.get_all_groups()

        assert len(groups) == 2
        assert groups[0]["dn"] == "cn=Administrators,ou=groups,dc=example,dc=com"
        assert groups[1]["dn"] == "cn=Users,ou=groups,dc=example,dc=com"

    def test_setup_server_pool_single_server(self, ldap_provider):
        """Test server pool setup with single server."""
        ldap_provider.ldap_server = "ldap1.example.com"
        ldap_provider._setup_server_pool()

        # Should have a single server, not a server pool
        assert hasattr(ldap_provider._server_pool, "host")

    def test_setup_server_pool_multiple_servers(self, ldap_provider):
        """Test server pool setup with multiple servers."""
        ldap_provider.ldap_server = "ldap1.example.com,ldap2.example.com,ldap3.example.com"
        ldap_provider._setup_server_pool()

        # Should have a server pool for failover
        assert hasattr(ldap_provider._server_pool, "servers")

    @pytest.mark.asyncio
    async def test_create_connection_simple_auth(self, ldap_provider):
        """Test connection creation with simple authentication."""
        user_dn = "uid=testuser,ou=users,dc=example,dc=com"
        password = "testpass"

        with patch("langflow.services.auth.ldap_provider.Connection") as mock_connection_class:
            mock_conn = MagicMock()
            mock_connection_class.return_value = mock_conn

            connection = await ldap_provider._create_connection(user_dn, password)

        assert connection == mock_conn
        mock_connection_class.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_connection_anonymous_auth(self, ldap_provider):
        """Test connection creation with anonymous authentication."""
        ldap_provider.auth_method = "ANONYMOUS"

        with patch("langflow.services.auth.ldap_provider.Connection") as mock_connection_class:
            mock_conn = MagicMock()
            mock_connection_class.return_value = mock_conn

            connection = await ldap_provider._create_connection("user", "pass")

        assert connection == mock_conn
        # Should call with None for user and password for anonymous auth
        call_args = mock_connection_class.call_args
        assert call_args[1]["user"] is None
        assert call_args[1]["password"] is None
