"""SSO Configuration model for enterprise identity provider integration."""


from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Union, List
from uuid import uuid4

from pydantic import field_validator
from sqlalchemy import CHAR, JSON, Column, Text, UniqueConstraint
from sqlmodel import Field, Relationship, SQLModel

from langflow.schema.serialize import UUIDstr, UUIDAsString

if TYPE_CHECKING:
    from langflow.services.database.models.rbac.workspace import Workspace
    from langflow.services.database.models.user.model import User


class SSOProviderType(str, Enum):
    """Supported SSO provider types."""

    OIDC = "oidc"           # OpenID Connect
    SAML2 = "saml2"         # SAML 2.0
    OAUTH2 = "oauth2"       # OAuth 2.0
    LDAP = "ldap"           # LDAP/Active Directory
    GOOGLE = "google"       # Google Workspace
    MICROSOFT = "microsoft" # Microsoft Azure AD
    OKTA = "okta"          # Okta
    AUTH0 = "auth0"        # Auth0
    CUSTOM = "custom"      # Custom provider


class SSOStatus(str, Enum):
    """SSO configuration status."""

    DRAFT = "draft"         # Configuration being set up
    TESTING = "testing"     # In testing phase
    ACTIVE = "active"       # Active and working
    INACTIVE = "inactive"   # Temporarily disabled
    ERROR = "error"         # Configuration error
    DEPRECATED = "deprecated" # No longer used


class SSOConfiguration(SQLModel, table=True):  # type: ignore[call-arg]
    """SSO provider configuration for workspace."""

    __tablename__ = "sso_configuration"

    id: UUIDstr = Field(default_factory=uuid4, primary_key=True, sa_type=UUIDAsString)

    # Basic configuration
    name: str = Field(index=True)  # Human-readable name
    provider_type: SSOProviderType = Field(index=True)
    status: SSOStatus = Field(default=SSOStatus.DRAFT, index=True)

    # Workspace association
    workspace_id: UUIDstr = Field(foreign_key="workspace.id", sa_type=UUIDAsString)
    workspace: "Workspace" = Relationship(back_populates="sso_configurations")

    # Provider configuration (encrypted in production)
    provider_config: dict = Field(sa_column=Column(JSON))

    # OIDC/OAuth2 Configuration
    client_id: Union[str, None] = Field(default=None)
    client_secret: Union[str, None] = Field(default=None)  # Should be encrypted
    discovery_url: Union[str, None] = Field(default=None)
    authorization_url: Union[str, None] = Field(default=None)
    token_url: Union[str, None] = Field(default=None)
    userinfo_url: Union[str, None] = Field(default=None)
    jwks_url: Union[str, None] = Field(default=None)

    # SAML2 Configuration
    saml_entity_id: Union[str, None] = Field(default=None)
    saml_sso_url: Union[str, None] = Field(default=None)
    saml_slo_url: Union[str, None] = Field(default=None)  # Single Logout URL
    saml_certificate: Union[str, None] = Field(default=None, sa_column=Column(Text))
    saml_private_key: Union[str, None] = Field(default=None, sa_column=Column(Text))

    # LDAP Configuration
    ldap_server: Union[str, None] = Field(default=None)
    ldap_port: Union[int, None] = Field(default=389)
    ldap_use_ssl: bool = Field(default=False)
    ldap_base_dn: Union[str, None] = Field(default=None)
    ldap_bind_dn: Union[str, None] = Field(default=None)
    ldap_bind_password_hash: Union[str, None] = Field(default=None)  # Encrypted/hashed password
    ldap_user_filter: Union[str, None] = Field(default=None)
    ldap_group_filter: Union[str, None] = Field(default=None)

    # User mapping configuration
    user_mapping: dict = Field(default={}, sa_column=Column(JSON))
    group_mapping: dict = Field(default={}, sa_column=Column(JSON))
    role_mapping: dict = Field(default={}, sa_column=Column(JSON))

    # Security and validation
    allowed_domains: Union[List[str], None] = Field(default=[], sa_column=Column(JSON))
    required_claims: Union[List[str], None] = Field(default=[], sa_column=Column(JSON))
    claim_mappings: dict = Field(default={}, sa_column=Column(JSON))

    # SCIM configuration
    scim_enabled: bool = Field(default=False)
    scim_endpoint: Union[str, None] = Field(default=None)
    scim_token: Union[str, None] = Field(default=None)  # Should be encrypted
    scim_sync_interval_hours: int = Field(default=24)
    last_scim_sync: Union[datetime, None] = Field(default=None)

    # Advanced settings
    auto_provision_users: bool = Field(default=True)
    auto_create_groups: bool = Field(default=True)
    default_role_id: Union[UUIDstr, None] = Field(default=None, sa_type=UUIDAsString)
    session_timeout_minutes: int = Field(default=1440)  # 24 hours
    force_reauth_hours: Union[int, None] = Field(default=None)
    is_active: bool = Field(default=True, index=True)

    # Metadata and tracking
    extra_metadata: dict = Field(default={}, sa_column=Column(JSON))
    tags: Union[List[str], None] = Field(default=[], sa_column=Column(JSON))

    # Connection testing
    last_test_at: Union[datetime, None] = Field(default=None)
    last_test_result: Union[str, None] = Field(default=None)
    test_user_email: Union[str, None] = Field(default=None)

    # Audit and lifecycle
    created_by_id: UUIDstr = Field(foreign_key="user.id", sa_type=UUIDAsString)
    created_by: "User" = Relationship(
        sa_relationship_kwargs={
            "foreign_keys": "[SSOConfiguration.created_by_id]",
            "primaryjoin": "SSOConfiguration.created_by_id == User.id"
        }
    )

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_used_at: Union[datetime, None] = Field(default=None)

    # Unique constraints
    __table_args__ = (
        UniqueConstraint("workspace_id", "name", name="unique_sso_config_name_per_workspace"),
        UniqueConstraint("workspace_id", "provider_type", name="unique_sso_provider_per_workspace"),
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("SSO configuration name cannot be empty")
        if len(v) > 255:
            raise ValueError("SSO configuration name cannot exceed 255 characters")
        return v.strip()

    @field_validator("provider_config")
    @classmethod
    def validate_provider_config(cls, v: dict) -> dict:
        if not isinstance(v, dict):
            raise ValueError("Provider config must be a dictionary")
        return v

    @field_validator("user_mapping", "group_mapping", "role_mapping", "claim_mappings")
    @classmethod
    def validate_mapping_configs(cls, v: dict) -> dict:
        if not isinstance(v, dict):
            raise ValueError("Mapping configuration must be a dictionary")
        return v


class SSOConfigurationCreate(SQLModel):
    """Schema for creating SSO configuration."""

    name: str
    provider_type: SSOProviderType
    workspace_id: UUIDstr
    provider_config: dict

    # Optional provider-specific fields
    client_id: Union[str, None] = None
    client_secret: Union[str, None] = None
    discovery_url: Union[str, None] = None
    authorization_url: Union[str, None] = None
    token_url: Union[str, None] = None
    userinfo_url: Union[str, None] = None

    # SAML fields
    saml_entity_id: Union[str, None] = None
    saml_sso_url: Union[str, None] = None
    saml_certificate: Union[str, None] = None

    # LDAP fields
    ldap_server: Union[str, None] = None
    ldap_port: Union[int, None] = None
    ldap_use_ssl: bool = False
    ldap_base_dn: Union[str, None] = None
    ldap_bind_dn: Union[str, None] = None
    ldap_bind_password_hash: Union[str, None] = None

    # Configuration
    user_mapping: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
    group_mapping: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
    role_mapping: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
    allowed_domains: Union[List[str], None] = None
    auto_provision_users: bool = True
    auto_create_groups: bool = True
    default_role_id: Union[UUIDstr, None] = None

    # SCIM
    scim_enabled: bool = False
    scim_endpoint: Union[str, None] = None
    scim_token: Union[str, None] = None
    scim_sync_interval_hours: int = 24


class SSOConfigurationRead(SQLModel):
    """Schema for reading SSO configuration (excludes secrets)."""

    id: UUIDstr
    name: str
    provider_type: SSOProviderType
    status: SSOStatus
    workspace_id: UUIDstr

    # Non-sensitive configuration
    client_id: Union[str, None]
    discovery_url: Union[str, None]
    authorization_url: Union[str, None]
    token_url: Union[str, None]
    userinfo_url: Union[str, None]

    # SAML (non-sensitive)
    saml_entity_id: Union[str, None]
    saml_sso_url: Union[str, None]

    # LDAP (non-sensitive)
    ldap_server: Union[str, None]
    ldap_port: Union[int, None]
    ldap_use_ssl: bool
    ldap_base_dn: Union[str, None]

    # Settings
    auto_provision_users: bool
    auto_create_groups: bool
    scim_enabled: bool
    session_timeout_minutes: int

    # Status
    last_test_at: Union[datetime, None]
    last_test_result: Union[str, None]
    last_scim_sync: Union[datetime, None]
    last_used_at: Union[datetime, None]

    # Audit
    created_by_id: UUIDstr
    created_at: datetime
    updated_at: datetime


class SSOConfigurationUpdate(SQLModel):
    """Schema for updating SSO configuration."""

    name: Union[str, None] = None
    status: SSOStatus | None = None
    provider_config: Union[dict, None] = Field(default=None, sa_column=Column(JSON))

    # Provider fields
    client_id: Union[str, None] = None
    client_secret: Union[str, None] = None
    discovery_url: Union[str, None] = None
    authorization_url: Union[str, None] = None
    token_url: Union[str, None] = None
    userinfo_url: Union[str, None] = None

    # SAML fields
    saml_entity_id: Union[str, None] = None
    saml_sso_url: Union[str, None] = None
    saml_certificate: Union[str, None] = None
    saml_private_key: Union[str, None] = None

    # LDAP fields
    ldap_server: Union[str, None] = None
    ldap_port: Union[int, None] = None
    ldap_use_ssl: Union[bool, None] = None
    ldap_base_dn: Union[str, None] = None
    ldap_bind_dn: Union[str, None] = None
    ldap_bind_password_hash: Union[str, None] = None

    # Mappings
    user_mapping: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
    group_mapping: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
    role_mapping: Union[dict, None] = Field(default=None, sa_column=Column(JSON))

    # Settings
    allowed_domains: Union[List[str], None] = None
    auto_provision_users: Union[bool, None] = None
    auto_create_groups: Union[bool, None] = None
    default_role_id: Union[UUIDstr, None] = None
    session_timeout_minutes: Union[int, None] = None

    # SCIM
    scim_enabled: Union[bool, None] = None
    scim_endpoint: Union[str, None] = None
    scim_token: Union[str, None] = None
    scim_sync_interval_hours: Union[int, None] = None


class SSOTestRequest(SQLModel):
    """Schema for testing SSO configuration."""

    test_user_email: Union[str, None] = None
    dry_run: bool = True


class SSOTestResult(SQLModel):
    """Result of SSO configuration test."""

    success: bool
    provider_type: SSOProviderType
    test_timestamp: datetime
    response_time_ms: float | None = None
    user_info: Union[dict, None] = Field(default=None, sa_column=Column(JSON))
    groups: Union[List[str], None] = None
    errors: Union[List[str], None] = None
    warnings: Union[List[str], None] = None
    recommendations: Union[List[str], None] = None


# Predefined SSO configuration templates
SSO_TEMPLATES = {
    SSOProviderType.GOOGLE: {
        "name": "Google Workspace",
        "discovery_url": "https://accounts.google.com/.well-known/openid_configuration",
        "user_mapping": {
            "email": "email",
            "first_name": "given_name",
            "last_name": "family_name",
            "display_name": "name"
        },
        "required_claims": ["email", "email_verified"],
        "claim_mappings": {
            "email": "email",
            "name": "name"
        }
    },
    SSOProviderType.MICROSOFT: {
        "name": "Microsoft Azure AD",
        "discovery_url": "https://login.microsoftonline.com/common/v2.0/.well-known/openid_configuration",
        "user_mapping": {
            "email": "preferred_username",
            "first_name": "given_name",
            "last_name": "family_name",
            "display_name": "name"
        },
        "required_claims": ["preferred_username", "email"],
        "claim_mappings": {
            "email": "preferred_username",
            "name": "name"
        }
    },
    SSOProviderType.OKTA: {
        "name": "Okta",
        "user_mapping": {
            "email": "email",
            "first_name": "given_name",
            "last_name": "family_name",
            "display_name": "name"
        },
        "required_claims": ["email", "email_verified"],
        "claim_mappings": {
            "email": "email",
            "name": "name",
            "groups": "groups"
        }
    }
}
