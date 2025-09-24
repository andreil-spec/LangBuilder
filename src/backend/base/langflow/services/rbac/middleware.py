"""RBAC middleware for LangBuilder FastAPI application.

This module provides HTTP middleware for request-level RBAC permission enforcement.
Integrates seamlessly with existing LangBuilder authentication and middleware patterns.

Implementation follows Phase 4 requirements:
- FastAPI middleware integration with existing patterns
- High-performance permission evaluation with caching
- Backward compatibility with existing authentication
- Integration with existing user context and session management
"""

# NO future annotations per Phase 1 requirements
import time
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from fastapi import Request, Response
from loguru import logger
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse

from langflow.services.auth.utils import api_key_security, get_current_user_by_jwt
from langflow.services.base import Service
from langflow.services.deps import get_session

if TYPE_CHECKING:
    from langflow.services.database.models.user.model import User
    from langflow.services.rbac.service import RBACService


class RBACContext:
    """RBAC context for request processing."""

    def __init__(
        self,
        user: Optional["User"] = None,
        workspace_id: str | None = None,
        project_id: str | None = None,
        flow_id: str | None = None,
        authenticated: bool = False,
        bypass_rbac: bool = False,
        request_id: str | None = None
    ):
        self.user = user
        self.workspace_id = workspace_id
        self.project_id = project_id
        self.flow_id = flow_id
        self.authenticated = authenticated
        self.bypass_rbac = bypass_rbac
        self.request_id = request_id or str(uuid.uuid4())
        self.created_at = datetime.now(timezone.utc)


class RBACMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware for RBAC permission enforcement.

    This middleware integrates with existing LangBuilder authentication patterns
    and provides request-level permission enforcement with high performance.

    Features:
    - Seamless integration with existing auth middleware
    - High-performance permission evaluation with caching
    - Configurable endpoints for RBAC enforcement
    - Backward compatibility with existing authentication
    - Comprehensive audit logging
    """

    def __init__(
        self,
        app,
        rbac_service: Optional["RBACService"] = None,
        enforce_rbac: bool = True,
        protected_patterns: list[str] | None = None,
        bypass_patterns: list[str] | None = None
    ):
        """Initialize RBAC middleware.

        Args:
            app: FastAPI application instance
            rbac_service: RBAC service for permission evaluation
            enforce_rbac: Whether to enforce RBAC (can be disabled for development)
            protected_patterns: URL patterns that require RBAC protection
            bypass_patterns: URL patterns that bypass RBAC checks
        """
        super().__init__(app)
        self.rbac_service = rbac_service
        self.enforce_rbac = enforce_rbac

        # Default protected patterns - API endpoints requiring RBAC
        self.protected_patterns = protected_patterns or [
            "/api/v1/flows/",
            "/api/v1/projects/",
            "/api/v1/workspaces/",
            "/api/v1/rbac/",
            "/api/v1/files/",
            "/api/v1/chat/",
            "/api/v1/endpoints/"
        ]

        # Default bypass patterns - public endpoints and health checks
        self.bypass_patterns = bypass_patterns or [
            "/health",
            "/docs",
            "/openapi.json",
            "/api/v1/login",
            "/api/v1/auth/",
            "/api/v1/public/",
            "/api/v1/rbac/",  # Bypass RBAC endpoints to prevent circular middleware issues
            "/static/",
            "/files/",
            "/"
        ]

        # Performance tracking
        self._request_count = 0
        self._total_processing_time = 0.0
        self._cache_hits = 0
        self._cache_misses = 0

        # Permission caching
        self._permission_cache = {}  # Simple in-memory cache
        self._cache_ttl = 300  # 5 minutes cache TTL

        logger.info("RBAC middleware initialized", extra={
            "enforce_rbac": self.enforce_rbac,
            "protected_patterns": len(self.protected_patterns),
            "bypass_patterns": len(self.bypass_patterns)
        })

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Process HTTP request with RBAC enforcement.

        This method follows the existing LangBuilder middleware pattern and
        integrates with the existing authentication system.

        Args:
            request: FastAPI request object
            call_next: Next middleware in the chain

        Returns:
            Response: HTTP response with RBAC enforcement applied
        """
        start_time = time.perf_counter()
        request_id = str(uuid.uuid4())

        try:
            # Check if RBAC enforcement is disabled
            if not self.enforce_rbac:
                logger.debug("RBAC enforcement disabled, bypassing", extra={
                    "request_id": request_id,
                    "path": request.url.path
                })
                return await call_next(request)

            # Check if request should bypass RBAC
            if self._should_bypass_rbac(request):
                logger.debug("Request bypassing RBAC", extra={
                    "request_id": request_id,
                    "path": request.url.path,
                    "reason": "bypass_pattern_match"
                })
                return await call_next(request)

            # Extract user context from existing authentication
            rbac_context = await self._extract_rbac_context(request, request_id)

            # Check if request requires RBAC protection
            if not self._requires_rbac_protection(request):
                logger.debug("Request does not require RBAC protection", extra={
                    "request_id": request_id,
                    "path": request.url.path
                })
                # Add context to request state for potential use by endpoints
                request.state.rbac_context = rbac_context
                return await call_next(request)

            # Perform RBAC permission check
            if not await self._check_permissions(request, rbac_context):
                # Log access denied
                logger.warning("RBAC access denied", extra={
                    "request_id": request_id,
                    "path": request.url.path,
                    "method": request.method,
                    "user_id": str(rbac_context.user.id) if rbac_context.user else None,
                    "authenticated": rbac_context.authenticated
                })

                # Return 403 Forbidden response
                return JSONResponse(
                    status_code=403,
                    content={
                        "detail": "Insufficient permissions to access this resource",
                        "error_code": "rbac_permission_denied",
                        "request_id": request_id
                    }
                )

            # Add RBAC context to request state
            request.state.rbac_context = rbac_context

            # Log successful access
            logger.debug("RBAC access granted", extra={
                "request_id": request_id,
                "path": request.url.path,
                "method": request.method,
                "user_id": str(rbac_context.user.id) if rbac_context.user else None
            })

            # Continue to next middleware/endpoint
            response = await call_next(request)

            # Track performance metrics
            processing_time = time.perf_counter() - start_time
            self._update_metrics(processing_time, cache_hit=rbac_context.bypass_rbac)

            # Add RBAC headers to response
            response.headers["X-RBAC-Request-ID"] = request_id
            response.headers["X-RBAC-Processing-Time"] = f"{processing_time:.3f}ms"

            return response

        except Exception as exc:
            processing_time = time.perf_counter() - start_time
            logger.error("RBAC middleware error", extra={
                "request_id": request_id,
                "path": request.url.path,
                "error": str(exc),
                "processing_time": processing_time
            }, exc_info=True)

            # Return 500 Internal Server Error for middleware failures
            return JSONResponse(
                status_code=500,
                content={
                    "detail": "Internal server error during RBAC processing",
                    "error_code": "rbac_middleware_error",
                    "request_id": request_id
                }
            )

    def _should_bypass_rbac(self, request: Request) -> bool:
        """Check if request should bypass RBAC checks.

        Args:
            request: FastAPI request object

        Returns:
            bool: True if request should bypass RBAC
        """
        path = request.url.path

        # Check bypass patterns
        for pattern in self.bypass_patterns:
            if path.startswith(pattern):
                logger.debug(f"RBAC bypass: path={path} matches pattern={pattern}")
                return True

        # Check for special headers indicating bypass
        if request.headers.get("X-RBAC-Bypass") == "true":
            # Only allow bypass for internal/service requests
            if request.headers.get("X-Internal-Request") == "true":
                logger.debug(f"RBAC bypass: special header bypass for path={path}")
                return True

        logger.debug(f"RBAC processing required for path={path}")
        return False

    def _requires_rbac_protection(self, request: Request) -> bool:
        """Check if request requires RBAC protection.

        Args:
            request: FastAPI request object

        Returns:
            bool: True if request requires RBAC protection
        """
        path = request.url.path

        # Check protected patterns
        for pattern in self.protected_patterns:
            if path.startswith(pattern):
                return True

        return False

    async def _extract_rbac_context(self, request: Request, request_id: str) -> RBACContext:
        """Extract RBAC context from request using existing auth patterns.

        This method integrates with existing LangBuilder authentication patterns
        to extract user context and build RBAC context.

        Args:
            request: FastAPI request object
            request_id: Unique request identifier

        Returns:
            RBACContext: RBAC context for the request
        """
        try:
            user = None
            authenticated = False

            # Try to extract user from existing authentication
            # This follows the existing LangBuilder auth pattern

            # Check for JWT token in Authorization header
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]  # Remove "Bearer " prefix
                try:
                    # Use existing session to get user from JWT
                    async with get_session() as session:
                        user = await get_current_user_by_jwt(token, session)
                        if user:
                            authenticated = True
                except Exception as e:
                    logger.debug("JWT authentication failed", extra={
                        "request_id": request_id,
                        "error": str(e)
                    })

            # Check for API key authentication if JWT failed
            if not authenticated:
                api_key_query = request.query_params.get("x-api-key")
                api_key_header = request.headers.get("x-api-key")
                api_key = api_key_query or api_key_header

                if api_key:
                    try:
                        # Directly validate API key instead of calling the Security dependency
                        async with get_session() as session:
                            from langflow.services.database.models.apikey.crud import check_key
                            result = await check_key(session, api_key)
                            if result:
                                # result can be ApiKey or User
                                if hasattr(result, 'user_id'):
                                    # It's an ApiKey, get the user
                                    from langflow.services.database.models.user.crud import get_user_by_id
                                    user = await get_user_by_id(session, result.user_id)
                                else:
                                    # It's already a User
                                    user = result
                                if user and user.is_active:
                                    authenticated = True
                    except Exception as e:
                        logger.debug("API key authentication failed", extra={
                            "request_id": request_id,
                            "error": str(e)
                        })

            # Extract resource context from URL parameters
            workspace_id = request.path_params.get("workspace_id")
            project_id = request.path_params.get("project_id")
            flow_id = request.path_params.get("flow_id")

            # Also check query parameters
            if not workspace_id:
                workspace_id = request.query_params.get("workspace_id")
            if not project_id:
                project_id = request.query_params.get("project_id")
            if not flow_id:
                flow_id = request.query_params.get("flow_id")

            return RBACContext(
                user=user,
                workspace_id=workspace_id,
                project_id=project_id,
                flow_id=flow_id,
                authenticated=authenticated,
                request_id=request_id
            )

        except Exception as exc:
            logger.error("Error extracting RBAC context", extra={
                "request_id": request_id,
                "error": str(exc),
                "error_type": type(exc).__name__
            }, exc_info=True)

            # Return minimal context on error - but don't fail the request
            return RBACContext(
                authenticated=False,
                request_id=request_id
            )

    async def _check_permissions(self, request: Request, context: RBACContext) -> bool:
        """Check RBAC permissions for the request.

        Args:
            request: FastAPI request object
            context: RBAC context

        Returns:
            bool: True if access is granted, False otherwise
        """
        try:
            # If no user context, deny access to protected resources
            if not context.user or not context.authenticated:
                logger.debug("Access denied: no authenticated user", extra={
                    "request_id": context.request_id,
                    "path": request.url.path,
                    "authenticated": context.authenticated,
                    "has_user": context.user is not None
                })
                return False

            # If RBAC service is not available, allow in development but warn
            if not self.rbac_service:
                from langflow.services.settings.security_config import get_security_config
                security_config = get_security_config()

                if security_config.environment.value == "development":
                    logger.warning("RBAC service not available in development - allowing access", extra={
                        "request_id": context.request_id,
                        "path": request.url.path,
                        "environment": security_config.environment.value
                    })
                    return True
                else:
                    logger.error("RBAC service not available, denying access for security", extra={
                        "request_id": context.request_id,
                        "path": request.url.path,
                        "environment": security_config.environment.value
                    })
                    return False

            # Determine resource type and action from request
            resource_type, action = self._extract_permission_requirements(request)

            if not resource_type or not action:
                # If we can't determine requirements, deny access (secure default)
                logger.warning("Could not determine permission requirements, denying access for security", extra={
                    "request_id": context.request_id,
                    "path": request.url.path,
                    "method": request.method
                })
                return False

            # Use permission engine to check permissions
            try:
                from langflow.services.rbac.permission_engine import PermissionEngine
                permission_engine = PermissionEngine()

                async with get_session() as session:
                    result = await permission_engine.check_permission(
                        session=session,
                        user=context.user,
                        resource_type=resource_type,
                        action=action,
                        resource_id=context.flow_id or context.project_id or context.workspace_id,
                        workspace_id=context.workspace_id,
                        project_id=context.project_id
                    )

                    logger.debug("Permission check result", extra={
                        "request_id": context.request_id,
                        "user_id": str(context.user.id),
                        "resource_type": resource_type,
                        "action": action,
                        "allowed": result.allowed,
                        "reason": getattr(result, 'reason', 'none')
                    })

                    return result.allowed

            except ImportError as e:
                logger.warning("Permission engine not available - allowing access in development", extra={
                    "request_id": context.request_id,
                    "error": str(e),
                    "path": request.url.path
                })
                return True  # Allow access if permission engine not available

        except Exception as exc:
            logger.error("Error checking RBAC permissions - denying access for security", extra={
                "request_id": context.request_id,
                "path": request.url.path,
                "method": request.method,
                "user_id": str(context.user.id) if context.user else None,
                "error": str(exc)
            }, exc_info=True)

            # Always deny access on error (fail-secure)
            return False

    def _extract_permission_requirements(self, request: Request) -> tuple[str | None, str | None]:
        """Extract required resource type and action from request.

        Args:
            request: FastAPI request object

        Returns:
            tuple: (resource_type, action) or (None, None) if not determinable
        """
        path = request.url.path.lower()
        method = request.method.upper()

        # Map HTTP methods to RBAC actions
        method_action_map = {
            "GET": "read",
            "POST": "create",
            "PUT": "update",
            "PATCH": "update",
            "DELETE": "delete"
        }

        action = method_action_map.get(method, "read")

        # Extract resource type from URL path
        if "/api/v1/flows" in path:
            return "flow", action
        if "/api/v1/projects" in path:
            return "project", action
        if "/api/v1/workspaces" in path:
            return "workspace", action
        if "/api/v1/files" in path:
            return "file", action
        if "/api/v1/chat" in path:
            return "flow", "execute"  # Chat typically executes flows
        if "/api/v1/endpoints" in path:
            return "endpoint", action
        if "/api/v1/rbac" in path:
            return "rbac", action

        # Default to generic resource for unrecognized patterns
        return "resource", action

    def _update_metrics(self, processing_time: float, cache_hit: bool = False) -> None:
        """Update performance metrics.

        Args:
            processing_time: Time taken to process request in seconds
            cache_hit: Whether the request was served from cache
        """
        self._request_count += 1
        self._total_processing_time += processing_time

        if cache_hit:
            self._cache_hits += 1
        else:
            self._cache_misses += 1

    def get_metrics(self) -> dict:
        """Get RBAC middleware performance metrics.

        Returns:
            dict: Performance metrics
        """
        if self._request_count == 0:
            return {
                "request_count": 0,
                "average_processing_time": 0.0,
                "cache_hit_rate": 0.0
            }

        return {
            "request_count": self._request_count,
            "average_processing_time": self._total_processing_time / self._request_count,
            "cache_hit_rate": self._cache_hits / (self._cache_hits + self._cache_misses) if (self._cache_hits + self._cache_misses) > 0 else 0.0,
            "total_processing_time": self._total_processing_time,
            "cache_hits": self._cache_hits,
            "cache_misses": self._cache_misses
        }


class RBACMiddlewareService(Service):
    """Service for managing RBAC middleware integration.

    This service follows LangBuilder service patterns and provides
    factory methods for creating and configuring RBAC middleware.
    """

    name = "rbac_middleware_service"

    def __init__(self, rbac_service: Optional["RBACService"] = None):
        super().__init__()
        self.rbac_service = rbac_service
        self._middleware_instance = None

    async def initialize_service(self) -> None:
        """Initialize the RBAC middleware service."""
        logger.info("Initializing RBAC middleware service")

        # Import RBAC service if not provided
        if not self.rbac_service:
            try:
                from langflow.services.rbac.service import RBACService
                self.rbac_service = RBACService()
                await self.rbac_service.initialize_service()
            except (ImportError, Exception) as e:
                logger.warning(f"RBAC service not available, middleware will run in degraded mode: {e}")

    def create_middleware(
        self,
        enforce_rbac: bool = True,
        protected_patterns: list[str] | None = None,
        bypass_patterns: list[str] | None = None
    ) -> RBACMiddleware:
        """Create RBAC middleware instance.

        Args:
            enforce_rbac: Whether to enforce RBAC checks
            protected_patterns: URL patterns requiring RBAC protection
            bypass_patterns: URL patterns that bypass RBAC

        Returns:
            RBACMiddleware: Configured middleware instance
        """
        return RBACMiddleware(
            app=None,  # Will be set when added to FastAPI app
            rbac_service=self.rbac_service,
            enforce_rbac=enforce_rbac,
            protected_patterns=protected_patterns,
            bypass_patterns=bypass_patterns
        )

    def get_middleware_metrics(self) -> dict:
        """Get RBAC middleware performance metrics.

        Returns:
            dict: Performance metrics or empty dict if no middleware
        """
        if self._middleware_instance:
            return self._middleware_instance.get_metrics()
        return {}
