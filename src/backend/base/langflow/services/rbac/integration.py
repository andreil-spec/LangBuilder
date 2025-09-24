"""RBAC integration with LangBuilder main application.

This module provides backward compatibility and integration functions for
seamlessly adding RBAC to the existing LangBuilder FastAPI application.

Implementation follows Phase 4 requirements:
- Backward compatibility with existing functionality
- Optional RBAC enforcement with graceful degradation
- Integration with existing middleware stack
- Minimal changes to existing codebase
"""

# NO future annotations per Phase 1 requirements
import os
from typing import TYPE_CHECKING, Optional

from fastapi import FastAPI
from loguru import logger

from langflow.services.base import Service

if TYPE_CHECKING:
    from langflow.services.rbac.flow_integration import RBACFlowIntegrationService
    from langflow.services.rbac.service import RBACService


class RBACIntegrationConfig:
    """Configuration for RBAC integration."""

    def __init__(
        self,
        enable_rbac: bool = True,
        enable_middleware: bool = True,
        enable_flow_integration: bool = True,
        enforce_permissions: bool = True,
        protected_patterns: list[str] | None = None,
        bypass_patterns: list[str] | None = None,
        cache_permissions: bool = True,
        log_access_events: bool = True
    ):
        self.enable_rbac = enable_rbac
        self.enable_middleware = enable_middleware
        self.enable_flow_integration = enable_flow_integration
        self.enforce_permissions = enforce_permissions
        self.protected_patterns = protected_patterns
        self.bypass_patterns = bypass_patterns
        self.cache_permissions = cache_permissions
        self.log_access_events = log_access_events

    @classmethod
    def from_environment(cls) -> "RBACIntegrationConfig":
        """Create configuration from environment variables.

        Returns:
            RBACIntegrationConfig: Configuration based on environment
        """
        return cls(
            enable_rbac=os.getenv("LANGFLOW_ENABLE_RBAC", "true").lower() == "true",
            enable_middleware=os.getenv("LANGFLOW_ENABLE_RBAC_MIDDLEWARE", "true").lower() == "true",
            enable_flow_integration=os.getenv("LANGFLOW_ENABLE_RBAC_FLOW_INTEGRATION", "true").lower() == "true",
            enforce_permissions=os.getenv("LANGFLOW_ENFORCE_RBAC_PERMISSIONS", "true").lower() == "true",
            cache_permissions=os.getenv("LANGFLOW_CACHE_RBAC_PERMISSIONS", "true").lower() == "true",
            log_access_events=os.getenv("LANGFLOW_LOG_RBAC_ACCESS_EVENTS", "true").lower() == "true"
        )


class RBACIntegrationService(Service):
    """Service for integrating RBAC with LangBuilder application.

    This service provides a centralized way to integrate RBAC features
    with the existing LangBuilder application while maintaining backward
    compatibility and allowing for graceful degradation.
    """

    name = "rbac_integration_service"

    def __init__(self, config: RBACIntegrationConfig | None = None):
        super().__init__()
        self.config = config or RBACIntegrationConfig.from_environment()
        self.rbac_service = None
        self.middleware_service = None
        self.flow_integration_service = None
        self._initialized = False

    async def initialize_service(self) -> None:
        """Initialize RBAC integration service."""
        if self._initialized:
            return

        logger.info("Initializing RBAC integration service", extra={
            "enable_rbac": self.config.enable_rbac,
            "enable_middleware": self.config.enable_middleware,
            "enable_flow_integration": self.config.enable_flow_integration
        })

        # Only initialize if RBAC is enabled
        if not self.config.enable_rbac:
            logger.info("RBAC disabled, skipping initialization")
            self._initialized = True
            return

        try:
            # Initialize core RBAC service
            from langflow.services.rbac.service import RBACService
            self.rbac_service = RBACService()
            await self.rbac_service.initialize_service()
            logger.info("RBAC core service initialized")

            # Initialize middleware service if enabled
            if self.config.enable_middleware:
                from langflow.services.rbac.middleware import RBACMiddlewareService
                self.middleware_service = RBACMiddlewareService(self.rbac_service)
                await self.middleware_service.initialize_service()
                logger.info("RBAC middleware service initialized")

            # Initialize Flow integration service if enabled
            if self.config.enable_flow_integration:
                from langflow.services.rbac.flow_integration import RBACFlowIntegrationService
                self.flow_integration_service = RBACFlowIntegrationService(self.rbac_service)
                await self.flow_integration_service.initialize_service()
                logger.info("RBAC Flow integration service initialized")

            self._initialized = True
            logger.info("RBAC integration service fully initialized")

        except Exception as exc:
            logger.error("Failed to initialize RBAC integration service", extra={
                "error": str(exc)
            }, exc_info=True)

            # Set to degraded mode but don't fail startup
            self.config.enable_rbac = False
            self._initialized = True
            logger.warning("RBAC integration running in degraded mode")

    def setup_middleware(self, app: FastAPI) -> None:
        """Setup RBAC middleware on FastAPI application.

        This method integrates RBAC middleware with the existing FastAPI
        application while maintaining backward compatibility.

        Args:
            app: FastAPI application instance
        """
        if not self.config.enable_rbac or not self.config.enable_middleware:
            logger.info("RBAC middleware disabled, skipping setup")
            return

        if not self.middleware_service:
            logger.warning("RBAC middleware service not initialized, skipping setup")
            return

        try:
            # Create RBAC middleware instance
            rbac_middleware = self.middleware_service.create_middleware(
                enforce_rbac=self.config.enforce_permissions,
                protected_patterns=self.config.protected_patterns,
                bypass_patterns=self.config.bypass_patterns
            )

            # Add RBAC middleware to the application
            # Position it after CORS but before other business logic middleware
            app.add_middleware(
                type(rbac_middleware),
                rbac_service=self.rbac_service,
                enforce_rbac=self.config.enforce_permissions,
                protected_patterns=self.config.protected_patterns,
                bypass_patterns=self.config.bypass_patterns
            )

            logger.info("RBAC middleware added to FastAPI application", extra={
                "enforce_rbac": self.config.enforce_permissions,
                "protected_patterns": len(self.config.protected_patterns or []),
                "bypass_patterns": len(self.config.bypass_patterns or [])
            })

        except Exception as exc:
            logger.error("Failed to setup RBAC middleware", extra={
                "error": str(exc)
            }, exc_info=True)

    def get_rbac_service(self) -> Optional["RBACService"]:
        """Get the RBAC service instance.

        Returns:
            RBACService or None: RBAC service if available
        """
        return self.rbac_service

    def get_flow_integration_service(self) -> Optional["RBACFlowIntegrationService"]:
        """Get the Flow integration service.

        Returns:
            RBACFlowIntegrationService or None: Flow integration service if available
        """
        return self.flow_integration_service

    def is_rbac_enabled(self) -> bool:
        """Check if RBAC is enabled.

        Returns:
            bool: True if RBAC is enabled and functional
        """
        return self.config.enable_rbac and self._initialized and self.rbac_service is not None

    def get_integration_status(self) -> dict:
        """Get RBAC integration status.

        Returns:
            dict: Status information about RBAC integration
        """
        return {
            "rbac_enabled": self.config.enable_rbac,
            "middleware_enabled": self.config.enable_middleware,
            "flow_integration_enabled": self.config.enable_flow_integration,
            "enforce_permissions": self.config.enforce_permissions,
            "initialized": self._initialized,
            "rbac_service_available": self.rbac_service is not None,
            "middleware_service_available": self.middleware_service is not None,
            "flow_integration_service_available": self.flow_integration_service is not None
        }


# Global RBAC integration service instance
_rbac_integration_service: RBACIntegrationService | None = None


def get_rbac_integration_service() -> RBACIntegrationService:
    """Get the global RBAC integration service instance.

    Returns:
        RBACIntegrationService: Global RBAC integration service
    """
    global _rbac_integration_service
    if _rbac_integration_service is None:
        _rbac_integration_service = RBACIntegrationService()
    return _rbac_integration_service


async def initialize_rbac_integration() -> None:
    """Initialize RBAC integration for LangBuilder.

    This function should be called during application startup to initialize
    RBAC services and integration components.
    """
    integration_service = get_rbac_integration_service()
    await integration_service.initialize_service()


def setup_rbac_middleware(app: FastAPI) -> None:
    """Setup RBAC middleware on FastAPI application.

    This function provides a simple way to add RBAC middleware to the
    existing LangBuilder FastAPI application.

    Args:
        app: FastAPI application instance
    """
    integration_service = get_rbac_integration_service()
    integration_service.setup_middleware(app)


def is_rbac_available() -> bool:
    """Check if RBAC is available and functional.

    Returns:
        bool: True if RBAC is available
    """
    integration_service = get_rbac_integration_service()
    return integration_service.is_rbac_enabled()


# Backward compatibility functions for existing code


async def check_user_access_to_flow(
    user,
    flow_id: str,
    action: str = "read",
    session = None
) -> bool:
    """Check if user has access to a Flow (backward compatibility).

    This function provides a simple interface for checking Flow access
    that can be used by existing code without major changes.

    Args:
        user: User object
        flow_id: Flow ID to check access for
        action: Action to check (read, write, execute, delete)
        session: Database session (optional)

    Returns:
        bool: True if access is granted
    """
    try:
        integration_service = get_rbac_integration_service()

        if not integration_service.is_rbac_enabled():
            # If RBAC is not enabled, allow access for active users
            return getattr(user, "is_active", True)

        flow_service = integration_service.get_flow_integration_service()
        if not flow_service:
            # Fallback to basic access check
            return getattr(user, "is_active", True)

        # Use session if provided, otherwise get one
        if session is None:
            from langflow.services.deps import get_session
            async with get_session() as session:
                return await flow_service.check_flow_access(
                    session=session,
                    user=user,
                    flow_id=flow_id,
                    action=action
                )
        else:
            return await flow_service.check_flow_access(
                session=session,
                user=user,
                flow_id=flow_id,
                action=action
            )

    except Exception as exc:
        logger.warning("Error checking user access to Flow", extra={
            "user_id": str(getattr(user, "id", "unknown")),
            "flow_id": flow_id,
            "action": action,
            "error": str(exc)
        })
        # On error, allow access for superusers, deny for others
        return getattr(user, "is_superuser", False)


async def get_user_accessible_flows(user, session = None) -> list[str]:
    """Get list of Flow IDs accessible to user (backward compatibility).

    This function provides a way to get accessible Flows for existing
    code that needs to filter Flow lists based on permissions.

    Args:
        user: User object
        session: Database session (optional)

    Returns:
        list[str]: List of accessible Flow IDs
    """
    try:
        integration_service = get_rbac_integration_service()

        if not integration_service.is_rbac_enabled():
            # If RBAC is not enabled, return all flows the user owns
            # This maintains existing behavior
            if session is None:
                from langflow.services.deps import get_session
                async with get_session() as session:
                    return await _get_user_flows(user, session)
            else:
                return await _get_user_flows(user, session)

        # If RBAC is enabled, use permission-based filtering
        rbac_service = integration_service.get_rbac_service()
        if not rbac_service:
            # Fallback to user-owned flows
            if session is None:
                from langflow.services.deps import get_session
                async with get_session() as session:
                    return await _get_user_flows(user, session)
            else:
                return await _get_user_flows(user, session)

        # Get flows with read permission
        if session is None:
            from langflow.services.deps import get_session
            async with get_session() as session:
                return await _get_rbac_accessible_flows(user, session, rbac_service)
        else:
            return await _get_rbac_accessible_flows(user, session, rbac_service)

    except Exception as exc:
        logger.warning("Error getting user accessible flows", extra={
            "user_id": str(getattr(user, "id", "unknown")),
            "error": str(exc)
        })
        # On error, return user-owned flows
        if session is None:
            from langflow.services.deps import get_session
            async with get_session() as session:
                return await _get_user_flows(user, session)
        else:
            return await _get_user_flows(user, session)


async def _get_user_flows(user, session) -> list[str]:
    """Get flows owned by user."""
    try:
        from sqlmodel import select

        from langflow.services.database.models.flow.model import Flow

        result = await session.exec(
            select(Flow.id).where(Flow.user_id == user.id)
        )
        return [str(flow_id) for flow_id in result.all()]
    except Exception:
        return []


async def _get_rbac_accessible_flows(user, session, rbac_service) -> list[str]:
    """Get flows accessible via RBAC permissions."""
    try:
        from sqlmodel import select

        from langflow.services.database.models.flow.model import Flow

        # Get all flows and check permissions
        result = await session.exec(select(Flow.id))
        all_flow_ids = [str(flow_id) for flow_id in result.all()]

        accessible_flows = []
        for flow_id in all_flow_ids:
            try:
                permission_result = await rbac_service.evaluate_permission(
                    session=session,
                    user=user,
                    resource_type="flow",
                    action="read",
                    resource_id=flow_id
                )
                if permission_result.granted:
                    accessible_flows.append(flow_id)
            except Exception:
                # If permission check fails, skip this flow
                continue

        return accessible_flows

    except Exception:
        return []
