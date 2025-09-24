"""Security Configuration Module.

This module provides centralized security settings and validation
to ensure secure defaults and proper configuration for production environments.
"""

import os
from enum import Enum
from typing import List, Optional

from loguru import logger
from pydantic import BaseModel, Field, field_validator


class EnvironmentType(str, Enum):
    """Environment types for security configuration."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    TESTING = "testing"


class SecurityConfig(BaseModel):
    """Comprehensive security configuration with secure defaults."""

    # Environment Configuration
    environment: EnvironmentType = Field(
        default=EnvironmentType.PRODUCTION,
        description="Current environment type. Defaults to production for security.",
    )

    # Authentication Settings
    auto_login_enabled: bool = Field(
        default=False,
        description="Enable auto-login. ONLY for development. Automatically disabled in production.",
    )

    skip_authentication: bool = Field(
        default=False,
        description="Skip authentication checks. NEVER enable in production.",
    )

    enforce_strong_passwords: bool = Field(
        default=True,
        description="Enforce strong password requirements.",
    )

    password_min_length: int = Field(
        default=12,
        description="Minimum password length.",
        ge=8,
    )

    require_password_special_chars: bool = Field(
        default=True,
        description="Require special characters in passwords.",
    )

    # Session Security - DEVELOPMENT: Extended timeouts for dev
    session_timeout_minutes: int = Field(
        default=1440,  # 24 hours for development
        description="Session timeout in minutes.",
        ge=5,
        le=99999,  # Extended for development
    )

    max_concurrent_sessions: int = Field(
        default=999,  # Very large for development
        description="Maximum concurrent sessions per user.",
        ge=1,
        le=999999,  # Extended for development
    )

    # CORS Settings
    cors_allowed_origins: List[str] = Field(
        default_factory=lambda: ["http://localhost:3000", "http://127.0.0.1:3000"],
        description="Allowed CORS origins. Default localhost only for security.",
    )

    cors_allow_credentials: bool = Field(
        default=False,
        description="Allow credentials in CORS requests. Default False for security.",
    )

    cors_max_age: int = Field(
        default=3600,
        description="CORS preflight cache duration in seconds.",
    )

    # API Security - DEVELOPMENT: Enabled with very high limits for dev
    rate_limit_enabled: bool = Field(
        default=True,  # Enabled but with very high limits for development
        description="Enable rate limiting for API endpoints.",
    )

    rate_limit_requests_per_minute: int = Field(
        default=999999,  # Very high for development
        description="Maximum requests per minute per IP/user.",
        ge=10,
        le=999999,  # Extended for development
    )

    api_key_expiration_days: int = Field(
        default=90,
        description="API key expiration in days. 0 = no expiration.",
        ge=0,
        le=365,
    )

    # Security Headers
    enable_security_headers: bool = Field(
        default=True,
        description="Enable security headers (CSP, HSTS, etc.).",
    )

    content_security_policy: Optional[str] = Field(
        default="default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; media-src 'self'; object-src 'none'; child-src 'none'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; manifest-src 'self';",
        description="Content Security Policy header value. Enhanced for comprehensive protection.",
    )

    # Additional Security Headers
    x_permitted_cross_domain_policies: str = Field(
        default="none",
        description="X-Permitted-Cross-Domain-Policies header value.",
    )

    permissions_policy: Optional[str] = Field(
        default="geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), accelerometer=(), gyroscope=()",
        description="Permissions-Policy header value to restrict browser features.",
    )

    cross_origin_embedder_policy: str = Field(
        default="require-corp",
        description="Cross-Origin-Embedder-Policy header value.",
    )

    cross_origin_opener_policy: str = Field(
        default="same-origin",
        description="Cross-Origin-Opener-Policy header value.",
    )

    cross_origin_resource_policy: str = Field(
        default="same-origin",
        description="Cross-Origin-Resource-Policy header value.",
    )

    # Audit & Monitoring
    audit_logging_enabled: bool = Field(
        default=True,
        description="Enable security audit logging.",
    )

    failed_login_lockout_threshold: int = Field(
        default=5,
        description="Lock account after N failed login attempts.",
        ge=3,
        le=10,
    )

    lockout_duration_minutes: int = Field(
        default=30,
        description="Account lockout duration in minutes.",
        ge=5,
        le=1440,
    )

    @field_validator("auto_login_enabled", mode="after")
    @classmethod
    def validate_auto_login(cls, value: bool, info) -> bool:
        """Ensure auto-login is disabled in production and staging."""
        environment = info.data.get("environment", EnvironmentType.PRODUCTION)

        # SECURITY FIX: Block AUTO_LOGIN in production AND staging
        if environment in [EnvironmentType.PRODUCTION, EnvironmentType.STAGING] and value:
            logger.error(
                "🚨 CRITICAL SECURITY: AUTO_LOGIN is NEVER allowed in production/staging environments! "
                "This creates complete authentication bypass. Forcing to False."
            )
            return False

        # Additional warning for development
        if environment == EnvironmentType.DEVELOPMENT and value:
            logger.warning(
                "⚠️  SECURITY WARNING: AUTO_LOGIN enabled in development. "
                "Ensure this is NEVER deployed to production!"
            )

        return value

    @field_validator("skip_authentication", mode="after")
    @classmethod
    def validate_skip_auth(cls, value: bool, info) -> bool:
        """Ensure authentication is never skipped in production."""
        environment = info.data.get("environment", EnvironmentType.PRODUCTION)

        # SECURITY FIX: Absolute block on authentication bypass in production/staging
        if environment in [EnvironmentType.PRODUCTION, EnvironmentType.STAGING] and value:
            logger.error(
                "🚨 CRITICAL SECURITY: SKIP_AUTHENTICATION creates complete security bypass! "
                "This is NEVER allowed in production/staging. Forcing to False."
            )
            return False

        # Warning for development
        if environment == EnvironmentType.DEVELOPMENT and value:
            logger.warning(
                "⚠️  SECURITY WARNING: Authentication bypass enabled in development. "
                "This must NEVER be deployed to production!"
            )

        return value

    @field_validator("cors_allowed_origins", mode="after")
    @classmethod
    def validate_cors_origins(cls, value: List[str], info) -> List[str]:
        """Validate and set CORS origins based on environment."""
        environment = info.data.get("environment", EnvironmentType.PRODUCTION)

        # If no origins specified, use secure defaults
        if not value:
            if environment == EnvironmentType.DEVELOPMENT:
                # Development defaults
                return [
                    "http://localhost:3000",
                    "http://localhost:7860",
                    "http://127.0.0.1:3000",
                    "http://127.0.0.1:7860",
                ]
            elif environment == EnvironmentType.TESTING:
                # Testing defaults
                return ["http://localhost:3000", "http://testserver"]
            else:
                # Production/Staging - must be explicitly configured
                logger.warning(
                    f"No CORS origins configured for {environment.value} environment. "
                    "API will only be accessible from the same origin."
                )
                return []

        # Validate origins don't use wildcards in production
        if environment in [EnvironmentType.PRODUCTION, EnvironmentType.STAGING]:
            for origin in value:
                if "*" in origin:
                    logger.error(f"Wildcard origins not allowed in {environment.value}. Removing: {origin}")
                    value.remove(origin)

        return value

    @classmethod
    def from_env(cls) -> "SecurityConfig":
        """Create SecurityConfig from environment variables."""
        environment = os.getenv("LANGFLOW_ENVIRONMENT", "production").lower()

        # Map environment string to enum
        env_map = {
            "dev": EnvironmentType.DEVELOPMENT,
            "development": EnvironmentType.DEVELOPMENT,
            "staging": EnvironmentType.STAGING,
            "prod": EnvironmentType.PRODUCTION,
            "production": EnvironmentType.PRODUCTION,
            "test": EnvironmentType.TESTING,
            "testing": EnvironmentType.TESTING,
        }

        env_type = env_map.get(environment, EnvironmentType.PRODUCTION)

        # Parse CORS origins
        cors_origins_str = os.getenv("LANGFLOW_ALLOWED_ORIGINS", "")
        cors_origins = (
            [origin.strip() for origin in cors_origins_str.split(",") if origin.strip()] if cors_origins_str else []
        )

        config = cls(
            environment=env_type,
            auto_login_enabled=os.getenv("LANGFLOW_AUTO_LOGIN", "false").lower() == "true",
            skip_authentication=os.getenv("LANGFLOW_SKIP_AUTH", "false").lower() == "true",
            cors_allowed_origins=cors_origins,
            rate_limit_enabled=os.getenv("LANGFLOW_RATE_LIMIT_ENABLED", "true").lower() == "true",
            rate_limit_requests_per_minute=int(os.getenv("LANGFLOW_RATE_LIMIT_RPM", "60")),
            session_timeout_minutes=int(os.getenv("LANGFLOW_SESSION_TIMEOUT", "60")),
            audit_logging_enabled=os.getenv("LANGFLOW_AUDIT_LOG", "true").lower() == "true",
            enable_security_headers=os.getenv("LANGFLOW_SECURITY_HEADERS", "true").lower() == "true",
            content_security_policy=os.getenv(
                "LANGFLOW_CSP",
                "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; media-src 'self'; object-src 'none'; child-src 'none'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; manifest-src 'self';"
            ),
        )

        # Log security configuration summary
        logger.info(f"Security Configuration Loaded for {env_type.value} environment")
        logger.info(f"  - Auto-login: {config.auto_login_enabled}")
        logger.info(f"  - Skip Auth: {config.skip_authentication}")
        logger.info(f"  - Rate Limiting: {config.rate_limit_enabled}")
        logger.info(f"  - CORS Origins: {len(config.cors_allowed_origins)} configured")
        logger.info(f"  - Session Timeout: {config.session_timeout_minutes} minutes")

        # SECURITY FIX: Enhanced security warnings and runtime protection
        if config.auto_login_enabled or config.skip_authentication:
            if config.environment in [EnvironmentType.PRODUCTION, EnvironmentType.STAGING]:
                logger.error(
                    "🚨 CRITICAL SECURITY VIOLATION: Authentication bypass attempted in production/staging! "
                    "This should be impossible due to validation. Check configuration immediately!"
                )
                # Additional fail-safe: Force both to False in production
                config.auto_login_enabled = False
                config.skip_authentication = False
            else:
                logger.warning(
                    "⚠️  SECURITY WARNING: Authentication bypass is enabled in development. "
                    "Ensure this configuration is NEVER used in production!"
                )

        # SECURITY FIX: Final validation against environment variable manipulation
        cls._validate_production_security(config)

        return config

    @classmethod
    def _validate_production_security(cls, config: "SecurityConfig") -> None:
        """Final security validation to prevent production authentication bypass."""
        if config.environment in [EnvironmentType.PRODUCTION, EnvironmentType.STAGING]:
            # Check for any attempt to enable authentication bypass in production
            if config.auto_login_enabled:
                logger.error(
                    "🚨 CRITICAL SECURITY ALERT: AUTO_LOGIN detected in production! "
                    "Possible environment variable manipulation. Terminating for security."
                )
                raise RuntimeError(
                    "SECURITY VIOLATION: AUTO_LOGIN is not permitted in production environments. "
                    "Check LANGFLOW_AUTO_LOGIN environment variable."
                )

            if config.skip_authentication:
                logger.error(
                    "🚨 CRITICAL SECURITY ALERT: SKIP_AUTHENTICATION detected in production! "
                    "Possible environment variable manipulation. Terminating for security."
                )
                raise RuntimeError(
                    "SECURITY VIOLATION: SKIP_AUTHENTICATION is not permitted in production environments. "
                    "Check LANGFLOW_SKIP_AUTH environment variable."
                )

            logger.info("✅ Production security validation passed - authentication bypass properly disabled")

    def get_cors_config(self) -> dict:
        """Get CORS middleware configuration with secure defaults."""
        # SECURITY FIX: Never allow wildcard origins with credentials
        allowed_origins = self.cors_allowed_origins

        if self.environment == EnvironmentType.DEVELOPMENT:
            # Development: Allow localhost only if no origins specified
            if not allowed_origins:
                allowed_origins = ["http://localhost:3000", "http://127.0.0.1:3000"]
        else:
            # Production/Staging: Require explicit origins, no wildcard
            if not allowed_origins:
                logger.warning(
                    "🚨 SECURITY: No CORS origins configured for production environment. "
                    "CORS will be disabled for security."
                )
                allowed_origins = []

            # Security check: Never allow wildcard in production
            if "*" in allowed_origins:
                logger.error(
                    "🚨 CRITICAL SECURITY ISSUE: Wildcard CORS origin detected in production! "
                    "This creates CSRF vulnerability. Removing wildcard."
                )
                allowed_origins = [origin for origin in allowed_origins if origin != "*"]

        # SECURITY FIX: Disable credentials if using wildcard (should never happen now)
        allow_credentials = self.cors_allow_credentials
        if "*" in allowed_origins and allow_credentials:
            logger.error(
                "🚨 CRITICAL SECURITY ISSUE: Cannot allow credentials with wildcard CORS origins! "
                "Disabling credentials for security."
            )
            allow_credentials = False

        return {
            "allow_origins": allowed_origins,
            "allow_credentials": allow_credentials,
            "allow_methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
            "allow_headers": [
                "Accept",
                "Accept-Language",
                "Content-Language",
                "Content-Type",
                "Authorization",
                "X-Requested-With",
                "X-CSRFToken",
            ],  # SECURITY FIX: Restrict headers instead of wildcard
            "max_age": self.cors_max_age,
        }

    def get_security_headers(self) -> dict:
        """Get comprehensive security headers for responses."""
        if not self.enable_security_headers:
            return {}

        # SECURITY FIX: Comprehensive security headers implementation
        headers = {
            # Core security headers (REQUIRED)
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",

            # Additional security headers
            "X-Permitted-Cross-Domain-Policies": self.x_permitted_cross_domain_policies,
            "Cross-Origin-Embedder-Policy": self.cross_origin_embedder_policy,
            "Cross-Origin-Opener-Policy": self.cross_origin_opener_policy,
            "Cross-Origin-Resource-Policy": self.cross_origin_resource_policy,

            # Server information hiding
            "Server": "Langflow",  # Generic server name
            "X-Powered-By": "",    # Remove technology disclosure
        }

        # Content Security Policy
        if self.content_security_policy:
            headers["Content-Security-Policy"] = self.content_security_policy

        # Permissions Policy (Feature Policy successor)
        if self.permissions_policy:
            headers["Permissions-Policy"] = self.permissions_policy

        # Environment-specific headers
        if self.environment == EnvironmentType.PRODUCTION:
            # HSTS for production only (requires HTTPS)
            headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

            # Enhanced CSP for production
            if self.content_security_policy and "unsafe-eval" in self.content_security_policy:
                logger.warning(
                    "⚠️  SECURITY WARNING: 'unsafe-eval' detected in CSP for production. "
                    "Consider removing for enhanced security if possible."
                )
        else:
            # Development warning header
            headers["X-Development-Mode"] = "true"
            logger.info("🔧 Development mode: Some security headers may be relaxed")

        # Log security headers configuration
        if self.environment == EnvironmentType.PRODUCTION:
            logger.info(f"🛡️ {len(headers)} security headers configured for production")

        return headers


# Global instance for easy access
_security_config: Optional[SecurityConfig] = None


def get_security_config() -> SecurityConfig:
    """Get or create the global security configuration."""
    global _security_config
    if _security_config is None:
        _security_config = SecurityConfig.from_env()
    return _security_config


def reset_security_config() -> None:
    """Reset the global security configuration (mainly for testing)."""
    global _security_config
    _security_config = None
