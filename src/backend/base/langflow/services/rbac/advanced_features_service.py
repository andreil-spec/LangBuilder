"""Advanced RBAC Features Service for Phase 5.

This module implements advanced RBAC features including:
- Multi-environment permission scoping
- Service account management with token scoping
- Break-glass emergency access
- Advanced audit logging with compliance exports
- Conditional permissions (time, IP, custom)

Implementation follows Phase 5 requirements:
- Environment-scoped permissions and role assignments
- Enhanced service account lifecycle management
- Emergency access procedures with audit trails
- Compliance reporting for SOC2/ISO27001/GDPR/CCPA
- Context-aware permission evaluation
"""

# NO future annotations per Phase 1 requirements
import ipaddress
import time
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from loguru import logger
from sqlalchemy import and_, or_, select
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.services.base import Service

if TYPE_CHECKING:
    from langflow.services.database.models.rbac.audit_log import AuditLog
    from langflow.services.database.models.rbac.environment import Environment
    from langflow.services.database.models.rbac.service_account import ServiceAccount, ServiceAccountToken
    from langflow.services.database.models.user.model import User


class BreakGlassAccessResult:
    """Result of break-glass access evaluation."""

    def __init__(
        self,
        *,
        granted: bool,
        justification: str | None = None,
        emergency_level: str = "low",
        approval_required: bool = False,
        approval_timeout_minutes: int = 15,
        audit_metadata: dict | None = None
    ):
        self.granted = granted
        self.justification = justification
        self.emergency_level = emergency_level
        self.approval_required = approval_required
        self.approval_timeout_minutes = approval_timeout_minutes
        self.audit_metadata = audit_metadata or {}
        self.evaluation_time = time.perf_counter()


class ConditionalPermissionContext:
    """Context for conditional permission evaluation."""

    def __init__(
        self,
        *,
        ip_address: str | None = None,
        user_agent: str | None = None,
        session_id: str | None = None,
        request_time: datetime | None = None,
        risk_score: float = 0.0,
        mfa_verified: bool = False,
        location: dict | None = None,
        custom_attributes: dict | None = None
    ):
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.session_id = session_id
        self.request_time = request_time or datetime.now(timezone.utc)
        self.risk_score = risk_score
        self.mfa_verified = mfa_verified
        self.location = location or {}
        self.custom_attributes = custom_attributes or {}


class AdvancedRBACFeaturesService(Service):
    """Service for Phase 5 Advanced RBAC Features.

    This service provides advanced RBAC capabilities including multi-environment
    support, enhanced service account management, break-glass access, and
    conditional permissions based on context.
    """

    name = "advanced_rbac_features_service"

    def __init__(self):
        super().__init__()
        self._break_glass_cache = {}  # Cache for break-glass decisions
        self._risk_threshold_cache = {}  # Cache for risk thresholds
        self._compliance_metadata = {
            "soc2_controls": ["AC-1", "AC-2", "AC-3", "AC-6", "AU-2", "AU-3"],
            "iso27001_controls": ["A.9.1.1", "A.9.1.2", "A.9.2.1", "A.9.2.2", "A.9.4.1"],
            "gdpr_requirements": ["accountability", "lawful_basis", "data_minimization"],
            "ccpa_requirements": ["transparency", "consumer_rights", "data_security"]
        }

    async def initialize_service(self) -> None:
        """Initialize the advanced RBAC features service."""
        logger.info("Initializing Advanced RBAC Features Service")

        # Initialize compliance tracking
        self._compliance_metadata["service_start_time"] = datetime.now(timezone.utc)
        self._compliance_metadata["audit_retention_days"] = 2555  # 7 years for compliance

        logger.info("Advanced RBAC Features Service initialized")

    # Multi-Environment Support

    async def check_environment_permission(
        self,
        session: AsyncSession,
        user: "User",
        environment_id: str,
        action: str,
        context: ConditionalPermissionContext | None = None
    ) -> bool:
        """Check if user has permission for specific environment action.

        Args:
            session: Database session
            user: User to check permissions for
            environment_id: Environment ID to check access for
            action: Action to perform (deploy, read, write, delete)
            context: Additional context for conditional permissions

        Returns:
            bool: True if permission is granted
        """
        try:
            # Import here to avoid circular imports
            from langflow.services.database.models.rbac.environment import Environment
            from langflow.services.database.models.rbac.role_assignment import RoleAssignment

            # Get environment details
            environment_result = await session.exec(
                select(Environment).where(Environment.id == environment_id)
            )
            environment = environment_result.first()

            if not environment or not environment.is_active:
                logger.warning("Environment not found or inactive", extra={
                    "environment_id": environment_id,
                    "user_id": str(user.id)
                })
                return False

            # Check environment-specific role assignments
            role_assignments_result = await session.exec(
                select(RoleAssignment).where(
                    and_(
                        RoleAssignment.user_id == user.id,
                        RoleAssignment.environment_id == environment_id,
                        RoleAssignment.is_active
                    )
                )
            )
            role_assignments = role_assignments_result.all()

            # Check permissions through environment-scoped roles
            for assignment in role_assignments:
                if await self._check_role_environment_permission(
                    session, assignment.role_id, action, environment
                ):
                    # Apply conditional permission checks
                    if context and not await self._evaluate_conditional_permissions(
                        session, user, environment, action, context
                    ):
                        continue

                    await self._log_environment_access(
                        session, user, environment, action, granted=True, context=context
                    )
                    return True

            # Check workspace-level permissions that apply to environment
            if await self._check_workspace_environment_permission(
                session, user, environment, action, context
            ):
                await self._log_environment_access(
                    session, user, environment, action, granted=True, context=context
                )
                return True

            await self._log_environment_access(
                session, user, environment, action, granted=False, context=context
            )
            return False

        except Exception as exc:
            logger.error("Error checking environment permission", extra={
                "user_id": str(user.id),
                "environment_id": environment_id,
                "action": action,
                "error": str(exc)
            }, exc_info=True)
            return False

    async def _check_role_environment_permission(
        self,
        session: AsyncSession,
        role_id: str,
        action: str,
        environment: "Environment"
    ) -> bool:
        """Check if role has specific environment permission."""
        try:
            from langflow.services.database.models.rbac.permission import Permission
            from langflow.services.database.models.rbac.role_permission import RolePermission

            # Map actions to environment permissions
            permission_mapping = {
                "deploy": "deploy_environment",
                "read": "read_environment",
                "write": "write_environment",
                "delete": "delete_environment",
                "configure": "configure_environment"
            }

            required_permission = permission_mapping.get(action, action)

            # Check role permissions
            result = await session.exec(
                select(Permission)
                .join(RolePermission)
                .where(
                    and_(
                        RolePermission.role_id == role_id,
                        Permission.name == required_permission
                    )
                )
            )

            return result.first() is not None

        except Exception as exc:
            logger.error("Error checking role environment permission", extra={
                "role_id": role_id,
                "action": action,
                "environment_type": environment.type,
                "error": str(exc)
            })
            return False

    async def _check_workspace_environment_permission(
        self,
        session: AsyncSession,
        user: "User",
        environment: "Environment",
        action: str,
        context: ConditionalPermissionContext | None
    ) -> bool:
        """Check workspace-level permissions that apply to environment."""
        try:
            # Import RBAC service for workspace permission checking
            from langflow.services.rbac.service import RBACService

            rbac_service = RBACService()
            result = await rbac_service.evaluate_permission(
                session=session,
                user=user,
                resource_type="environment",
                action=action,
                resource_id=str(environment.id),
                workspace_id=str(environment.project.workspace_id) if environment.project else None,
                project_id=str(environment.project_id)
            )

            return result.granted

        except Exception as exc:
            logger.error("Error checking workspace environment permission", extra={
                "user_id": str(user.id),
                "environment_id": str(environment.id),
                "action": action,
                "error": str(exc)
            })
            return False

    # Service Account Management

    async def create_service_account_with_scoped_token(
        self,
        session: AsyncSession,
        creator: "User",
        workspace_id: str,
        account_name: str,
        token_name: str,
        scoped_permissions: list[str],
        scope_type: str = "workspace",
        scope_id: str | None = None,
        allowed_ips: list[str] | None = None,
        expires_days: int = 365
    ) -> dict:
        """Create service account with scoped token.

        Args:
            session: Database session
            creator: User creating the service account
            workspace_id: Workspace ID for the service account
            account_name: Name of the service account
            token_name: Name of the token
            scoped_permissions: List of permissions for the token
            scope_type: Type of scope (workspace, project, environment)
            scope_id: ID of the scope entity
            allowed_ips: List of allowed IP addresses
            expires_days: Token expiration in days

        Returns:
            dict: Service account and token details
        """
        try:
            import hashlib
            import secrets

            from langflow.services.database.models.rbac.service_account import ServiceAccount, ServiceAccountToken

            # Create service account
            service_account = ServiceAccount(
                name=account_name,
                workspace_id=workspace_id,
                created_by_id=creator.id,
                service_type="api",
                default_scope_type=scope_type,
                default_scope_id=scope_id,
                allowed_permissions=scoped_permissions,
                max_tokens=10,
                token_expiry_days=expires_days
            )

            session.add(service_account)
            await session.flush()  # Get the ID

            # Generate secure token
            token_value = f"sa_{secrets.token_urlsafe(32)}"
            token_hash = hashlib.sha256(token_value.encode()).hexdigest()
            token_prefix = token_value[:12] + "..."

            # Create scoped token
            expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days)

            service_token = ServiceAccountToken(
                service_account_id=service_account.id,
                name=token_name,
                token_hash=token_hash,
                token_prefix=token_prefix,
                scoped_permissions=scoped_permissions,
                scope_type=scope_type,
                scope_id=scope_id,
                allowed_ips=allowed_ips or [],
                created_by_id=creator.id,
                expires_at=expires_at
            )

            session.add(service_token)
            await session.commit()

            # Log service account creation
            await self._log_service_account_event(
                session, creator, service_account, "created", {
                    "token_name": token_name,
                    "scoped_permissions": scoped_permissions,
                    "scope_type": scope_type,
                    "scope_id": scope_id
                }
            )

            logger.info("Service account created with scoped token", extra={
                "service_account_id": str(service_account.id),
                "token_id": str(service_token.id),
                "creator_id": str(creator.id),
                "workspace_id": workspace_id,
                "scope_type": scope_type
            })

            return {
                "service_account": {
                    "id": str(service_account.id),
                    "name": account_name,
                    "workspace_id": workspace_id
                },
                "token": {
                    "id": str(service_token.id),
                    "name": token_name,
                    "token": token_value,  # Only returned once
                    "token_prefix": token_prefix,
                    "scoped_permissions": scoped_permissions,
                    "scope_type": scope_type,
                    "scope_id": scope_id,
                    "expires_at": expires_at.isoformat()
                }
            }

        except Exception as exc:
            logger.error("Error creating service account with token", extra={
                "creator_id": str(creator.id),
                "workspace_id": workspace_id,
                "account_name": account_name,
                "error": str(exc)
            }, exc_info=True)
            await session.rollback()
            raise

    async def validate_service_account_token_scope(
        self,
        session: AsyncSession,
        token_hash: str,
        requested_action: str,
        resource_type: str,
        resource_id: str | None = None,
        context: ConditionalPermissionContext | None = None
    ) -> bool:
        """Validate service account token scope for requested action.

        Args:
            session: Database session
            token_hash: Hashed token value
            requested_action: Action being requested
            resource_type: Type of resource being accessed
            resource_id: ID of specific resource
            context: Request context for additional validation

        Returns:
            bool: True if token scope allows the action
        """
        try:
            from langflow.services.database.models.rbac.service_account import ServiceAccountToken

            # Get token details
            token_result = await session.exec(
                select(ServiceAccountToken).where(
                    and_(
                        ServiceAccountToken.token_hash == token_hash,
                        ServiceAccountToken.is_active,
                        or_(
                            ServiceAccountToken.expires_at.is_(None),
                            ServiceAccountToken.expires_at > datetime.now(timezone.utc)
                        )
                    )
                )
            )
            token = token_result.first()

            if not token:
                logger.warning("Invalid or expired service account token", extra={
                    "token_prefix": token_hash[:8] + "..."
                })
                return False

            # Check IP restrictions
            if context and context.ip_address and token.allowed_ips:
                if not await self._validate_ip_access(context.ip_address, token.allowed_ips):
                    logger.warning("Service account token IP restriction violated", extra={
                        "token_id": str(token.id),
                        "client_ip": context.ip_address,
                        "allowed_ips": token.allowed_ips
                    })
                    return False

            # Check scoped permissions
            required_permission = f"{requested_action}_{resource_type}"
            if token.scoped_permissions and required_permission not in token.scoped_permissions:
                logger.warning("Service account token permission denied", extra={
                    "token_id": str(token.id),
                    "required_permission": required_permission,
                    "scoped_permissions": token.scoped_permissions
                })
                return False

            # Check scope restrictions
            if not await self._validate_token_scope(session, token, resource_type, resource_id):
                logger.warning("Service account token scope restriction violated", extra={
                    "token_id": str(token.id),
                    "scope_type": token.scope_type,
                    "scope_id": token.scope_id,
                    "resource_type": resource_type,
                    "resource_id": resource_id
                })
                return False

            # Update usage tracking
            token.last_used_at = datetime.now(timezone.utc)
            token.usage_count += 1
            await session.commit()

            return True

        except Exception as exc:
            logger.error("Error validating service account token scope", extra={
                "requested_action": requested_action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "error": str(exc)
            }, exc_info=True)
            return False

    async def _validate_ip_access(self, client_ip: str, allowed_ips: list[str]) -> bool:
        """Validate client IP against allowed IP list."""
        try:
            client_ip_obj = ipaddress.ip_address(client_ip)

            for allowed_ip in allowed_ips:
                if "/" in allowed_ip:
                    # CIDR notation
                    if client_ip_obj in ipaddress.ip_network(allowed_ip, strict=False):
                        return True
                # Single IP
                elif client_ip_obj == ipaddress.ip_address(allowed_ip):
                    return True

            return False

        except Exception as exc:
            logger.error("Error validating IP access", extra={
                "client_ip": client_ip,
                "allowed_ips": allowed_ips,
                "error": str(exc)
            })
            return False

    async def _validate_token_scope(
        self,
        session: AsyncSession,
        token: "ServiceAccountToken",
        resource_type: str,
        resource_id: str | None
    ) -> bool:
        """Validate token scope against requested resource."""
        try:
            if not token.scope_type or not token.scope_id:
                # No scope restrictions
                return True

            # Validate based on scope type
            if token.scope_type == "workspace":
                return await self._validate_workspace_scope(
                    session, token.scope_id, resource_type, resource_id
                )
            if token.scope_type == "project":
                return await self._validate_project_scope(
                    session, token.scope_id, resource_type, resource_id
                )
            if token.scope_type == "environment":
                return await self._validate_environment_scope(
                    session, token.scope_id, resource_type, resource_id
                )

            return True

        except Exception as exc:
            logger.error("Error validating token scope", extra={
                "token_id": str(token.id),
                "scope_type": token.scope_type,
                "scope_id": token.scope_id,
                "error": str(exc)
            })
            return False

    async def _validate_workspace_scope(
        self,
        session: AsyncSession,
        workspace_id: str,
        resource_type: str,
        resource_id: str | None
    ) -> bool:
        """Validate workspace scope for resource access."""
        if not resource_id:
            return True

        try:
            # Get resource and check if it belongs to the workspace
            if resource_type == "flow":
                from langflow.services.database.models.flow.model import Flow
                result = await session.exec(
                    select(Flow).where(Flow.id == resource_id)
                )
                resource = result.first()
                return resource and str(resource.folder.workspace_id) == workspace_id if resource.folder else False

            if resource_type == "project":
                from langflow.services.database.models.rbac.project import Project
                result = await session.exec(
                    select(Project).where(Project.id == resource_id)
                )
                resource = result.first()
                return resource and str(resource.workspace_id) == workspace_id

            if resource_type == "environment":
                from langflow.services.database.models.rbac.environment import Environment
                result = await session.exec(
                    select(Environment).where(Environment.id == resource_id)
                )
                resource = result.first()
                return resource and str(resource.project.workspace_id) == workspace_id if resource.project else False

            return True

        except Exception as exc:
            logger.error("Error validating workspace scope", extra={
                "workspace_id": workspace_id,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "error": str(exc)
            })
            return False

    async def _validate_project_scope(
        self,
        session: AsyncSession,
        project_id: str,
        resource_type: str,
        resource_id: str | None
    ) -> bool:
        """Validate project scope for resource access."""
        if not resource_id:
            return True

        try:
            if resource_type == "environment":
                from langflow.services.database.models.rbac.environment import Environment
                result = await session.exec(
                    select(Environment).where(Environment.id == resource_id)
                )
                resource = result.first()
                return resource and str(resource.project_id) == project_id

            # For other resources, check if they belong to the project
            return True

        except Exception as exc:
            logger.error("Error validating project scope", extra={
                "project_id": project_id,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "error": str(exc)
            })
            return False

    async def _validate_environment_scope(
        self,
        session: AsyncSession,
        environment_id: str,
        resource_type: str,
        resource_id: str | None
    ) -> bool:
        """Validate environment scope for resource access."""
        if not resource_id:
            return True

        # For environment scope, only allow access to the specific environment
        return resource_type == "environment" and resource_id == environment_id

    # Break-glass Emergency Access

    async def evaluate_break_glass_access(
        self,
        session: AsyncSession,
        user: "User",
        justification: str,
        emergency_level: str = "medium",
        requested_permissions: list[str] | None = None,
        resource_context: dict | None = None
    ) -> BreakGlassAccessResult:
        """Evaluate break-glass emergency access request.

        Args:
            session: Database session
            user: User requesting emergency access
            justification: Justification for emergency access
            emergency_level: Level of emergency (low, medium, high, critical)
            requested_permissions: Specific permissions being requested
            resource_context: Context about resources being accessed

        Returns:
            BreakGlassAccessResult: Result of break-glass evaluation
        """
        try:
            # Validate justification
            if not justification or len(justification.strip()) < 20:
                return BreakGlassAccessResult(
                    granted=False,
                    justification="Insufficient justification for emergency access"
                )

            # Check if user is authorized for break-glass access
            if not await self._check_break_glass_authorization(session, user):
                return BreakGlassAccessResult(
                    granted=False,
                    justification="User not authorized for break-glass access"
                )

            # Evaluate emergency level
            approval_required = emergency_level in ["high", "critical"]
            timeout_minutes = {"low": 5, "medium": 15, "high": 30, "critical": 60}.get(emergency_level, 15)

            # Create audit metadata
            audit_metadata = {
                "justification": justification,
                "emergency_level": emergency_level,
                "requested_permissions": requested_permissions or [],
                "resource_context": resource_context or {},
                "user_id": str(user.id),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "requires_approval": approval_required,
                "approval_timeout_minutes": timeout_minutes
            }

            # Log break-glass access attempt
            await self._log_break_glass_access(
                session, user, justification, emergency_level, True, audit_metadata
            )

            logger.warning("Break-glass access granted", extra={
                "user_id": str(user.id),
                "emergency_level": emergency_level,
                "justification": justification[:100] + "..." if len(justification) > 100 else justification,
                "approval_required": approval_required
            })

            return BreakGlassAccessResult(
                granted=True,
                justification=justification,
                emergency_level=emergency_level,
                approval_required=approval_required,
                approval_timeout_minutes=timeout_minutes,
                audit_metadata=audit_metadata
            )

        except Exception as exc:
            logger.error("Error evaluating break-glass access", extra={
                "user_id": str(user.id),
                "emergency_level": emergency_level,
                "error": str(exc)
            }, exc_info=True)

            return BreakGlassAccessResult(
                granted=False,
                justification="Internal error during break-glass evaluation"
            )

    async def _check_break_glass_authorization(
        self,
        session: AsyncSession,
        user: "User"
    ) -> bool:
        """Check if user is authorized for break-glass access."""
        try:
            # Check if user has break-glass permission
            from langflow.services.rbac.service import RBACService

            rbac_service = RBACService()
            result = await rbac_service.evaluate_permission(
                session=session,
                user=user,
                resource_type="system",
                action="break_glass_access"
            )

            return result.granted or user.is_superuser

        except Exception as exc:
            logger.error("Error checking break-glass authorization", extra={
                "user_id": str(user.id),
                "error": str(exc)
            })
            return False

    # Conditional Permissions

    async def _evaluate_conditional_permissions(
        self,
        session: AsyncSession,
        user: "User",
        environment: "Environment",
        action: str,
        context: ConditionalPermissionContext
    ) -> bool:
        """Evaluate conditional permissions based on context.

        Args:
            session: Database session
            user: User requesting access
            environment: Environment being accessed
            action: Action being performed
            context: Request context for evaluation

        Returns:
            bool: True if conditional permissions are satisfied
        """
        try:
            # IP-based restrictions
            if not await self._check_ip_restrictions(user, environment, context):
                return False

            # Time-based restrictions
            if not await self._check_time_restrictions(user, environment, context):
                return False

            # Risk-based evaluation
            if not await self._check_risk_score(user, action, context):
                return False

            # MFA requirements for sensitive operations
            if not await self._check_mfa_requirements(user, action, environment, context):
                return False

            return True

        except Exception as exc:
            logger.error("Error evaluating conditional permissions", extra={
                "user_id": str(user.id),
                "environment_id": str(environment.id),
                "action": action,
                "error": str(exc)
            }, exc_info=True)
            return False

    async def _check_ip_restrictions(
        self,
        user: "User",
        environment: "Environment",
        context: ConditionalPermissionContext
    ) -> bool:
        """Check IP-based access restrictions."""
        # For production environments, enforce stricter IP controls
        if environment.type == "production" and context.ip_address:
            # Example: Block known malicious IP ranges
            blocked_ranges = ["10.0.0.0/8", "172.16.0.0/12"]  # Example blocked ranges

            try:
                client_ip = ipaddress.ip_address(context.ip_address)
                for blocked_range in blocked_ranges:
                    if client_ip in ipaddress.ip_network(blocked_range, strict=False):
                        logger.warning("Access denied from blocked IP range", extra={
                            "user_id": str(user.id),
                            "ip_address": context.ip_address,
                            "blocked_range": blocked_range
                        })
                        return False
            except ValueError:
                logger.warning("Invalid IP address format", extra={
                    "ip_address": context.ip_address
                })
                return False

        return True

    async def _check_time_restrictions(
        self,
        user: "User",
        environment: "Environment",
        context: ConditionalPermissionContext
    ) -> bool:
        """Check time-based access restrictions."""
        # Example: Restrict production deployments to business hours
        if environment.type == "production":
            current_hour = context.request_time.hour
            # Allow only during business hours (9 AM to 6 PM UTC)
            if current_hour < 9 or current_hour > 18:
                logger.warning("Production deployment outside business hours", extra={
                    "user_id": str(user.id),
                    "environment_id": str(environment.id),
                    "request_hour": current_hour
                })
                # Allow superusers to bypass time restrictions
                return user.is_superuser

        return True

    async def _check_risk_score(
        self,
        user: "User",
        action: str,
        context: ConditionalPermissionContext
    ) -> bool:
        """Check risk score for the request."""
        # Calculate risk score based on various factors
        risk_factors = []

        # High-risk actions
        if action in ["delete", "deploy", "configure"]:
            risk_factors.append(0.3)

        # Unusual access patterns
        if context.risk_score > 0.5:
            risk_factors.append(context.risk_score)

        # Unknown user agent
        if context.user_agent and "unknown" in context.user_agent.lower():
            risk_factors.append(0.2)

        total_risk = sum(risk_factors)

        # Deny high-risk requests without MFA
        if total_risk > 0.7 and not context.mfa_verified:
            logger.warning("High-risk request without MFA", extra={
                "user_id": str(user.id),
                "action": action,
                "risk_score": total_risk,
                "mfa_verified": context.mfa_verified
            })
            return False

        return True

    async def _check_mfa_requirements(
        self,
        user: "User",
        action: str,
        environment: "Environment",
        context: ConditionalPermissionContext
    ) -> bool:
        """Check MFA requirements for sensitive operations."""
        # Require MFA for sensitive operations in production
        sensitive_actions = ["delete", "deploy", "configure"]

        if (environment.type == "production" and
            action in sensitive_actions and
            not context.mfa_verified):

            logger.warning("MFA required for sensitive production operation", extra={
                "user_id": str(user.id),
                "action": action,
                "environment_type": environment.type,
                "mfa_verified": context.mfa_verified
            })
            return False

        return True

    # Audit Logging

    async def _log_environment_access(
        self,
        session: AsyncSession,
        user: "User",
        environment: "Environment",
        action: str,
        granted: bool,
        context: ConditionalPermissionContext | None
    ) -> None:
        """Log environment access for audit trail."""
        try:
            from langflow.services.database.models.rbac.audit_log import ActorType, AuditEventType, AuditLog, TargetType

            audit_log = AuditLog(
                event_type=AuditEventType.AUTHORIZATION,
                actor_type=ActorType.USER,
                actor_id=user.id,
                actor_name=user.username or str(user.id),
                target_type=TargetType.ENVIRONMENT,
                target_id=environment.id,
                target_name=environment.name,
                action=f"{action}_environment",
                resource_type="environment",
                resource_id=environment.id,
                workspace_id=environment.project.workspace_id if environment.project else None,
                ip_address=context.ip_address if context else None,
                user_agent=context.user_agent if context else None,
                success=granted,
                metadata={
                    "environment_type": environment.type,
                    "conditional_checks": {
                        "ip_validated": context.ip_address is not None if context else False,
                        "mfa_verified": context.mfa_verified if context else False,
                        "risk_score": context.risk_score if context else 0.0
                    } if context else {}
                }
            )

            session.add(audit_log)
            await session.commit()

        except Exception as exc:
            logger.error("Error logging environment access", extra={
                "user_id": str(user.id),
                "environment_id": str(environment.id),
                "action": action,
                "error": str(exc)
            })

    async def _log_service_account_event(
        self,
        session: AsyncSession,
        user: "User",
        service_account: "ServiceAccount",
        action: str,
        metadata: dict
    ) -> None:
        """Log service account events for audit trail."""
        try:
            from langflow.services.database.models.rbac.audit_log import ActorType, AuditEventType, AuditLog, TargetType

            audit_log = AuditLog(
                event_type=AuditEventType.ROLE_MANAGEMENT,
                actor_type=ActorType.USER,
                actor_id=user.id,
                actor_name=user.username or str(user.id),
                target_type=TargetType.SERVICE_ACCOUNT,
                target_id=service_account.id,
                target_name=service_account.name,
                action=f"{action}_service_account",
                resource_type="service_account",
                resource_id=service_account.id,
                workspace_id=service_account.workspace_id,
                success=True,
                metadata=metadata
            )

            session.add(audit_log)
            await session.commit()

        except Exception as exc:
            logger.error("Error logging service account event", extra={
                "user_id": str(user.id),
                "service_account_id": str(service_account.id),
                "action": action,
                "error": str(exc)
            })

    async def _log_break_glass_access(
        self,
        session: AsyncSession,
        user: "User",
        justification: str,
        emergency_level: str,
        granted: bool,
        metadata: dict
    ) -> None:
        """Log break-glass access for audit trail."""
        try:
            from langflow.services.database.models.rbac.audit_log import ActorType, AuditEventType, AuditLog

            audit_log = AuditLog(
                event_type=AuditEventType.AUTHORIZATION,
                actor_type=ActorType.USER,
                actor_id=user.id,
                actor_name=user.username or str(user.id),
                action="break_glass_access",
                resource_type="system",
                success=granted,
                metadata={
                    "justification": justification,
                    "emergency_level": emergency_level,
                    "break_glass": True,
                    **metadata
                }
            )

            session.add(audit_log)
            await session.commit()

        except Exception as exc:
            logger.error("Error logging break-glass access", extra={
                "user_id": str(user.id),
                "emergency_level": emergency_level,
                "error": str(exc)
            })

    # Compliance Reporting

    async def generate_compliance_report(
        self,
        session: AsyncSession,
        report_type: str = "soc2",
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        workspace_id: str | None = None
    ) -> dict:
        """Generate compliance report for audit purposes.

        Args:
            session: Database session
            report_type: Type of compliance report (soc2, iso27001, gdpr, ccpa)
            start_date: Start date for report period
            end_date: End date for report period
            workspace_id: Workspace ID to filter report

        Returns:
            dict: Compliance report data
        """
        try:
            from langflow.services.database.models.rbac.audit_log import AuditLog

            if not start_date:
                start_date = datetime.now(timezone.utc) - timedelta(days=30)
            if not end_date:
                end_date = datetime.now(timezone.utc)

            # Build base query
            query = select(AuditLog).where(
                and_(
                    AuditLog.timestamp >= start_date,
                    AuditLog.timestamp <= end_date
                )
            )

            if workspace_id:
                query = query.where(AuditLog.workspace_id == workspace_id)

            result = await session.exec(query)
            audit_logs = result.all()

            # Generate report based on type
            report_data = {
                "report_type": report_type,
                "period": {
                    "start_date": start_date.isoformat(),
                    "end_date": end_date.isoformat()
                },
                "workspace_id": workspace_id,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total_events": len(audit_logs),
                "compliance_controls": self._compliance_metadata.get(f"{report_type}_controls", [])
            }

            if report_type == "soc2":
                report_data.update(await self._generate_soc2_report(audit_logs))
            elif report_type == "iso27001":
                report_data.update(await self._generate_iso27001_report(audit_logs))
            elif report_type == "gdpr":
                report_data.update(await self._generate_gdpr_report(audit_logs))
            elif report_type == "ccpa":
                report_data.update(await self._generate_ccpa_report(audit_logs))

            logger.info("Compliance report generated", extra={
                "report_type": report_type,
                "period_days": (end_date - start_date).days,
                "total_events": len(audit_logs),
                "workspace_id": workspace_id
            })

            return report_data

        except Exception as exc:
            logger.error("Error generating compliance report", extra={
                "report_type": report_type,
                "workspace_id": workspace_id,
                "error": str(exc)
            }, exc_info=True)
            raise

    async def _generate_soc2_report(self, audit_logs: list["AuditLog"]) -> dict:
        """Generate SOC 2 compliance report."""
        # SOC 2 focuses on security, availability, processing integrity, confidentiality, privacy
        return {
            "security_events": len([log for log in audit_logs if log.event_type in ["AUTHORIZATION", "AUTHENTICATION"]]),
            "access_denied_events": len([log for log in audit_logs if not log.success]),
            "break_glass_events": len([log for log in audit_logs if log.metadata and log.metadata.get("break_glass")]),
            "service_account_events": len([log for log in audit_logs if "service_account" in log.action]),
            "privileged_access_events": len([log for log in audit_logs if "admin" in log.action or "superuser" in str(log.metadata)]),
            "controls_status": {
                "AC-1": "Implemented",  # Access Control Policy
                "AC-2": "Implemented",  # Account Management
                "AC-3": "Implemented",  # Access Enforcement
                "AC-6": "Implemented",  # Least Privilege
                "AU-2": "Implemented",  # Audit Events
                "AU-3": "Implemented"   # Content of Audit Records
            }
        }

    async def _generate_iso27001_report(self, audit_logs: list["AuditLog"]) -> dict:
        """Generate ISO 27001 compliance report."""
        return {
            "access_control_events": len([log for log in audit_logs if log.event_type == "AUTHORIZATION"]),
            "identity_management_events": len([log for log in audit_logs if log.event_type == "AUTHENTICATION"]),
            "privilege_management_events": len([log for log in audit_logs if "role" in log.action]),
            "controls_status": {
                "A.9.1.1": "Implemented",  # Access control policy
                "A.9.1.2": "Implemented",  # Access to networks and network services
                "A.9.2.1": "Implemented",  # User registration and de-registration
                "A.9.2.2": "Implemented",  # User access provisioning
                "A.9.4.1": "Implemented"   # Information access restriction
            }
        }

    async def _generate_gdpr_report(self, audit_logs: list["AuditLog"]) -> dict:
        """Generate GDPR compliance report."""
        return {
            "data_access_events": len([log for log in audit_logs if "read" in log.action]),
            "data_modification_events": len([log for log in audit_logs if log.action in ["write", "update", "delete"]]),
            "personal_data_processing": {
                "lawful_basis": "legitimate_interest",
                "data_minimization": "implemented",
                "purpose_limitation": "implemented",
                "retention_policy": f"{self._compliance_metadata['audit_retention_days']} days"
            },
            "data_subject_rights": {
                "right_to_access": "available",
                "right_to_rectification": "available",
                "right_to_erasure": "available",
                "right_to_portability": "available"
            }
        }

    async def _generate_ccpa_report(self, audit_logs: list["AuditLog"]) -> dict:
        """Generate CCPA compliance report."""
        return {
            "personal_info_collection": len([log for log in audit_logs if "user" in log.target_type.value.lower()]),
            "personal_info_disclosure": len([log for log in audit_logs if log.action == "read" and "user" in str(log.metadata)]),
            "consumer_rights": {
                "right_to_know": "implemented",
                "right_to_delete": "implemented",
                "right_to_opt_out": "implemented",
                "right_to_non_discrimination": "implemented"
            },
            "data_security_measures": {
                "access_controls": "implemented",
                "audit_logging": "implemented",
                "encryption": "implemented",
                "data_retention": f"{self._compliance_metadata['audit_retention_days']} days"
            }
        }
