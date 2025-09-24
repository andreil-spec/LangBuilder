"""Flow execution integration with RBAC permission checking.

This module provides integration between LangBuilder's Flow execution system
and RBAC permission enforcement. Ensures that Flow execution is protected
by appropriate permission checks while maintaining backward compatibility.

Implementation follows Phase 4 requirements:
- Integration with existing Flow execution patterns
- Permission checks before Flow execution
- Backward compatibility with existing Flow APIs
- Performance optimization with permission caching
"""

# NO future annotations per Phase 1 requirements
import time
from typing import TYPE_CHECKING, Optional
from uuid import UUID

from loguru import logger

from langflow.services.base import Service

if TYPE_CHECKING:
    from sqlmodel.ext.asyncio.session import AsyncSession

    from langflow.graph.graph.base import Graph
    from langflow.services.database.models.user.model import User
    from langflow.services.rbac.service import RBACService


class FlowExecutionContext:
    """Context for Flow execution with RBAC integration."""

    def __init__(
        self,
        user: "User",
        flow_id: str,
        workspace_id: str | None = None,
        project_id: str | None = None,
        session_id: str | None = None,
        execution_type: str = "standard",
        permission_granted: bool = False,
        permission_check_time: float | None = None
    ):
        self.user = user
        self.flow_id = flow_id
        self.workspace_id = workspace_id
        self.project_id = project_id
        self.session_id = session_id
        self.execution_type = execution_type
        self.permission_granted = permission_granted
        self.permission_check_time = permission_check_time


class RBACFlowExecutionGuard:
    """Guard class for RBAC-protected Flow execution.

    This class wraps Flow execution with RBAC permission checks,
    providing a seamless integration that maintains backward compatibility
    while adding comprehensive security.
    """

    def __init__(self, rbac_service: Optional["RBACService"] = None):
        """Initialize Flow execution guard.

        Args:
            rbac_service: RBAC service for permission evaluation
        """
        self.rbac_service = rbac_service
        self._permission_cache = {}  # Simple in-memory cache
        self._cache_ttl = 300  # 5 minutes

    async def check_execution_permission(
        self,
        session: "AsyncSession",
        user: "User",
        flow_id: str,
        execution_type: str = "execute",
        workspace_id: str | None = None,
        project_id: str | None = None,
        use_cache: bool = True
    ) -> FlowExecutionContext:
        """Check permission for Flow execution.

        Args:
            session: Database session
            user: User requesting execution
            flow_id: ID of the Flow to execute
            execution_type: Type of execution (execute, debug, test)
            workspace_id: Workspace context
            project_id: Project context
            use_cache: Whether to use permission caching

        Returns:
            FlowExecutionContext: Execution context with permission status

        Raises:
            PermissionError: If execution is not permitted
        """
        start_time = time.perf_counter()

        try:
            # Create execution context
            context = FlowExecutionContext(
                user=user,
                flow_id=flow_id,
                workspace_id=workspace_id,
                project_id=project_id,
                execution_type=execution_type
            )

            # Superuser bypass
            if user.is_superuser:
                logger.debug("Superuser bypass for Flow execution", extra={
                    "user_id": str(user.id),
                    "flow_id": flow_id,
                    "execution_type": execution_type
                })
                context.permission_granted = True
                context.permission_check_time = time.perf_counter() - start_time
                return context

            # Check cache if enabled
            if use_cache:
                cached_result = self._get_cached_permission(user.id, flow_id, execution_type)
                if cached_result is not None:
                    context.permission_granted = cached_result
                    context.permission_check_time = time.perf_counter() - start_time

                    logger.debug("Using cached Flow execution permission", extra={
                        "user_id": str(user.id),
                        "flow_id": flow_id,
                        "permission_granted": cached_result,
                        "cache_hit": True
                    })

                    if not cached_result:
                        raise PermissionError(f"Insufficient permissions to {execution_type} Flow {flow_id}")

                    return context

            # If RBAC service is not available, allow for superusers only
            if not self.rbac_service:
                if user.is_superuser:
                    logger.warning("RBAC service unavailable, allowing superuser Flow execution", extra={
                        "user_id": str(user.id),
                        "flow_id": flow_id
                    })
                    context.permission_granted = True
                else:
                    logger.error("RBAC service unavailable, denying non-superuser Flow execution", extra={
                        "user_id": str(user.id),
                        "flow_id": flow_id
                    })
                    context.permission_granted = False
                    raise PermissionError("Permission service temporarily unavailable")

                context.permission_check_time = time.perf_counter() - start_time
                return context

            # Evaluate permission using RBAC service
            result = await self.rbac_service.evaluate_permission(
                session=session,
                user=user,
                resource_type="flow",
                action=execution_type,
                resource_id=flow_id,
                workspace_id=workspace_id,
                project_id=project_id
            )

            context.permission_granted = result.granted
            context.permission_check_time = time.perf_counter() - start_time

            # Cache the result
            if use_cache:
                self._cache_permission(user.id, flow_id, execution_type, result.granted)

            if not result.granted:
                logger.warning("Flow execution permission denied", extra={
                    "user_id": str(user.id),
                    "flow_id": flow_id,
                    "execution_type": execution_type,
                    "reason": result.reason,
                    "evaluation_time": result.evaluation_time
                })
                raise PermissionError(f"Insufficient permissions to {execution_type} Flow {flow_id}: {result.reason}")

            logger.debug("Flow execution permission granted", extra={
                "user_id": str(user.id),
                "flow_id": flow_id,
                "execution_type": execution_type,
                "evaluation_time": result.evaluation_time
            })

            return context

        except PermissionError:
            # Re-raise permission errors
            raise
        except Exception as exc:
            logger.error("Error checking Flow execution permission", extra={
                "user_id": str(user.id),
                "flow_id": flow_id,
                "execution_type": execution_type,
                "error": str(exc)
            }, exc_info=True)

            # For safety, deny access on unexpected errors
            raise PermissionError(f"Internal error during Flow execution permission check: {exc!s}")

    async def execute_flow_with_rbac(
        self,
        session: "AsyncSession",
        user: "User",
        flow_id: str,
        graph: "Graph",
        inputs: dict = None,
        workspace_id: str | None = None,
        project_id: str | None = None,
        session_id: str | None = None
    ) -> dict:
        """Execute Flow with RBAC permission checking.

        This method wraps Flow execution with comprehensive permission checks
        while maintaining compatibility with existing execution patterns.

        Args:
            session: Database session
            user: User requesting execution
            flow_id: ID of the Flow to execute
            graph: Graph object for execution
            inputs: Input data for Flow execution
            workspace_id: Workspace context
            project_id: Project context
            session_id: Session ID for execution tracking

        Returns:
            dict: Flow execution results

        Raises:
            PermissionError: If execution is not permitted
        """
        # Check execution permission
        context = await self.check_execution_permission(
            session=session,
            user=user,
            flow_id=flow_id,
            execution_type="execute",
            workspace_id=workspace_id,
            project_id=project_id
        )

        if not context.permission_granted:
            raise PermissionError(f"Flow execution not permitted for user {user.id}")

        try:
            # Set user context on graph if supported
            if hasattr(graph, "set_user_context"):
                graph.set_user_context(user)

            # Set session ID for tracking
            if session_id and hasattr(graph, "session_id"):
                graph.session_id = session_id

            # Execute the Flow using existing patterns
            # This integrates with the existing Flow execution system
            execution_start = time.perf_counter()

            # Build execution inputs
            execution_inputs = inputs or {}

            # Add RBAC context to execution environment
            execution_inputs["_rbac_context"] = {
                "user_id": str(user.id),
                "workspace_id": workspace_id,
                "project_id": project_id,
                "permission_check_time": context.permission_check_time
            }

            # Execute graph (this follows existing LangBuilder patterns)
            results = await graph.arun(inputs=execution_inputs)

            execution_time = time.perf_counter() - execution_start

            logger.info("Flow execution completed with RBAC", extra={
                "user_id": str(user.id),
                "flow_id": flow_id,
                "execution_time": execution_time,
                "permission_check_time": context.permission_check_time,
                "workspace_id": workspace_id,
                "project_id": project_id
            })

            # Log execution event if audit service is available
            await self._log_execution_event(
                session=session,
                user=user,
                flow_id=flow_id,
                execution_time=execution_time,
                success=True,
                workspace_id=workspace_id,
                project_id=project_id
            )

            return results

        except Exception as exc:
            logger.error("Error during RBAC-protected Flow execution", extra={
                "user_id": str(user.id),
                "flow_id": flow_id,
                "error": str(exc)
            }, exc_info=True)

            # Log execution failure
            await self._log_execution_event(
                session=session,
                user=user,
                flow_id=flow_id,
                execution_time=0,
                success=False,
                error=str(exc),
                workspace_id=workspace_id,
                project_id=project_id
            )

            raise

    def _get_cached_permission(self, user_id: UUID, flow_id: str, execution_type: str) -> bool | None:
        """Get cached permission result.

        Args:
            user_id: User ID
            flow_id: Flow ID
            execution_type: Type of execution

        Returns:
            bool or None: Cached permission result or None if not cached
        """
        cache_key = f"{user_id}:{flow_id}:{execution_type}"
        cached_entry = self._permission_cache.get(cache_key)

        if cached_entry:
            cached_time, cached_result = cached_entry
            # Check if cache entry is still valid
            if time.time() - cached_time < self._cache_ttl:
                return cached_result
            # Remove expired entry
            del self._permission_cache[cache_key]

        return None

    def _cache_permission(self, user_id: UUID, flow_id: str, execution_type: str, result: bool) -> None:
        """Cache permission result.

        Args:
            user_id: User ID
            flow_id: Flow ID
            execution_type: Type of execution
            result: Permission result to cache
        """
        cache_key = f"{user_id}:{flow_id}:{execution_type}"
        self._permission_cache[cache_key] = (time.time(), result)

        # Simple cache cleanup - remove oldest entries if cache gets too large
        if len(self._permission_cache) > 1000:
            # Remove 20% of oldest entries
            sorted_entries = sorted(self._permission_cache.items(), key=lambda x: x[1][0])
            entries_to_remove = sorted_entries[:200]
            for key, _ in entries_to_remove:
                del self._permission_cache[key]

    async def _log_execution_event(
        self,
        session: "AsyncSession",
        user: "User",
        flow_id: str,
        execution_time: float,
        success: bool,
        error: str | None = None,
        workspace_id: str | None = None,
        project_id: str | None = None
    ) -> None:
        """Log Flow execution event for audit purposes.

        Args:
            session: Database session
            user: User who executed the Flow
            flow_id: Flow ID
            execution_time: Time taken for execution
            success: Whether execution was successful
            error: Error message if execution failed
            workspace_id: Workspace context
            project_id: Project context
        """
        try:
            # Try to get audit service and log execution
            if self.rbac_service and hasattr(self.rbac_service, "audit_service"):
                audit_service = self.rbac_service.audit_service
                await audit_service.log_flow_execution(
                    session=session,
                    user_id=user.id,
                    flow_id=flow_id,
                    execution_time=execution_time,
                    success=success,
                    error_message=error,
                    workspace_id=workspace_id,
                    project_id=project_id
                )
        except Exception as exc:
            logger.warning("Failed to log Flow execution event", extra={
                "user_id": str(user.id),
                "flow_id": flow_id,
                "error": str(exc)
            })

    def clear_permission_cache(self) -> None:
        """Clear all cached permissions."""
        self._permission_cache.clear()
        logger.info("Flow execution permission cache cleared")

    def get_cache_stats(self) -> dict:
        """Get permission cache statistics.

        Returns:
            dict: Cache statistics
        """
        return {
            "cached_entries": len(self._permission_cache),
            "cache_ttl": self._cache_ttl
        }

    def get_metrics(self) -> dict:
        """Get performance metrics for Flow execution.

        Returns:
            dict: Performance metrics
        """
        return {
            "cache_stats": self.get_cache_stats(),
            "execution_count": getattr(self, "_execution_count", 0),
            "avg_execution_time": getattr(self, "_avg_execution_time", 0.0),
            "permission_check_avg_time": getattr(self, "_permission_check_avg_time", 0.0)
        }


class RBACFlowIntegrationService(Service):
    """Service for RBAC Flow integration.

    This service follows LangBuilder service patterns and provides
    factory methods for creating RBAC-protected Flow execution.
    """

    name = "rbac_flow_integration_service"

    def __init__(self, rbac_service: Optional["RBACService"] = None):
        super().__init__()
        self.rbac_service = rbac_service
        self._execution_guard = None

    async def initialize_service(self) -> None:
        """Initialize the RBAC Flow integration service."""
        logger.info("Initializing RBAC Flow integration service")

        # Import RBAC service if not provided
        if not self.rbac_service:
            try:
                from langflow.services.rbac.service import RBACService
                self.rbac_service = RBACService()
                await self.rbac_service.initialize_service()
            except ImportError:
                logger.warning("RBAC service not available, Flow integration will run in degraded mode")

        # Initialize execution guard
        self._execution_guard = RBACFlowExecutionGuard(self.rbac_service)

    def get_execution_guard(self) -> RBACFlowExecutionGuard:
        """Get the Flow execution guard.

        Returns:
            RBACFlowExecutionGuard: Guard for Flow execution permission checking
        """
        if not self._execution_guard:
            self._execution_guard = RBACFlowExecutionGuard(self.rbac_service)
        return self._execution_guard

    async def check_flow_access(
        self,
        session: "AsyncSession",
        user: "User",
        flow_id: str,
        action: str = "read",
        workspace_id: str | None = None,
        project_id: str | None = None
    ) -> bool:
        """Check if user has access to a Flow.

        Args:
            session: Database session
            user: User to check access for
            flow_id: Flow ID
            action: Action to check (read, write, execute, delete)
            workspace_id: Workspace context
            project_id: Project context

        Returns:
            bool: True if access is granted
        """
        try:
            guard = self.get_execution_guard()
            context = await guard.check_execution_permission(
                session=session,
                user=user,
                flow_id=flow_id,
                execution_type=action,
                workspace_id=workspace_id,
                project_id=project_id
            )
            return context.permission_granted
        except PermissionError:
            return False
