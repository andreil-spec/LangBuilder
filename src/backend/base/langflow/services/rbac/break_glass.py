"""Break-glass access implementation for emergency situations.

This module provides emergency access controls that bypass normal authorization
in critical situations while maintaining full audit trails and approval workflows.
"""

from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from loguru import logger
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.schema.serialize import UUIDstr
from langflow.services.base import Service


class BreakGlassReason(str, Enum):
    """Predefined reasons for break-glass access."""

    PRODUCTION_OUTAGE = "production_outage"
    SECURITY_INCIDENT = "security_incident"
    DATA_RECOVERY = "data_recovery"
    SYSTEM_MAINTENANCE = "system_maintenance"
    COMPLIANCE_AUDIT = "compliance_audit"
    CUSTOMER_ESCALATION = "customer_escalation"
    LEGAL_REQUEST = "legal_request"
    OTHER = "other"


class BreakGlassUrgency(str, Enum):
    """Urgency levels for break-glass requests."""

    LOW = "low"           # 24 hour response time
    MEDIUM = "medium"     # 8 hour response time
    HIGH = "high"         # 2 hour response time
    CRITICAL = "critical" # Immediate response required


class BreakGlassStatus(str, Enum):
    """Status of break-glass access requests."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    REVOKED = "revoked"
    USED = "used"


class BreakGlassAccessRequest:
    """Break-glass access request model."""

    def __init__(
        self,
        id_: UUIDstr,
        user_id: UUIDstr,
        workspace_id: UUIDstr | None = None,
        environment_id: UUIDstr | None = None,
        resource_type: str | None = None,
        resource_id: UUIDstr | None = None,
        reason: BreakGlassReason = BreakGlassReason.OTHER,
        urgency: BreakGlassUrgency = BreakGlassUrgency.MEDIUM,
        justification: str = "",
        requested_permissions: list[str] | None = None,
        duration_hours: int = 4,
        *,
        auto_approve: bool = False,
        requested_at: datetime | None = None,
        expires_at: datetime | None = None,
        status: BreakGlassStatus = BreakGlassStatus.PENDING,
        approved_by_id: UUIDstr | None = None,
        approved_at: datetime | None = None,
        approval_comments: str | None = None,
        used_at: datetime | None = None,
        revoked_at: datetime | None = None,
        revoked_by_id: UUIDstr | None = None,
        revoke_reason: str | None = None,
        audit_trail: list[dict[str, Any]] | None = None
    ):
        self.id = id_
        self.user_id = user_id
        self.workspace_id = workspace_id
        self.environment_id = environment_id
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.reason = reason
        self.urgency = urgency
        self.justification = justification
        self.requested_permissions = requested_permissions or []
        self.duration_hours = duration_hours
        self.auto_approve = auto_approve
        self.requested_at = requested_at or datetime.now(timezone.utc)
        self.expires_at = expires_at
        self.status = status
        self.approved_by_id = approved_by_id
        self.approved_at = approved_at
        self.approval_comments = approval_comments
        self.used_at = used_at
        self.revoked_at = revoked_at
        self.revoked_by_id = revoked_by_id
        self.revoke_reason = revoke_reason
        self.audit_trail = audit_trail or []


class BreakGlassService(Service):
    """Service for managing break-glass emergency access."""

    name = "break_glass_service"

    def __init__(self):
        super().__init__()
        self._active_requests = {}  # In-memory cache for active requests
        self._approval_matrix = self._initialize_approval_matrix()

    def _initialize_approval_matrix(self) -> dict[str, dict[str, Any]]:
        """Initialize approval requirements matrix."""
        return {
            BreakGlassReason.PRODUCTION_OUTAGE: {
                "auto_approve_roles": ["site_admin", "incident_commander"],
                "required_approvers": 1,
                "max_duration_hours": 8,
                "notification_channels": ["slack", "email", "sms"]
            },
            BreakGlassReason.SECURITY_INCIDENT: {
                "auto_approve_roles": ["security_admin", "ciso"],
                "required_approvers": 2,
                "max_duration_hours": 12,
                "notification_channels": ["slack", "email", "sms", "security_team"]
            },
            BreakGlassReason.DATA_RECOVERY: {
                "auto_approve_roles": ["data_admin", "backup_admin"],
                "required_approvers": 2,
                "max_duration_hours": 6,
                "notification_channels": ["email", "slack"]
            },
            BreakGlassReason.SYSTEM_MAINTENANCE: {
                "auto_approve_roles": ["site_admin", "ops_admin"],
                "required_approvers": 1,
                "max_duration_hours": 4,
                "notification_channels": ["email"]
            },
            BreakGlassReason.COMPLIANCE_AUDIT: {
                "auto_approve_roles": ["compliance_officer", "audit_admin"],
                "required_approvers": 2,
                "max_duration_hours": 24,
                "notification_channels": ["email", "compliance_team"]
            },
            BreakGlassReason.CUSTOMER_ESCALATION: {
                "auto_approve_roles": ["customer_success_manager", "site_admin"],
                "required_approvers": 1,
                "max_duration_hours": 2,
                "notification_channels": ["slack", "email"]
            },
            BreakGlassReason.LEGAL_REQUEST: {
                "auto_approve_roles": ["legal_admin", "general_counsel"],
                "required_approvers": 2,
                "max_duration_hours": 48,
                "notification_channels": ["email", "legal_team"]
            },
            BreakGlassReason.OTHER: {
                "auto_approve_roles": [],
                "required_approvers": 2,
                "max_duration_hours": 2,
                "notification_channels": ["email", "slack"]
            }
        }

    async def request_break_glass_access(
        self,
        session: AsyncSession,
        user_id: UUIDstr,
        reason: BreakGlassReason,
        justification: str,
        *,
        workspace_id: UUIDstr | None = None,
        environment_id: UUIDstr | None = None,
        resource_type: str | None = None,
        resource_id: UUIDstr | None = None,
        requested_permissions: list[str] | None = None,
        urgency: BreakGlassUrgency = BreakGlassUrgency.MEDIUM,
        duration_hours: int = 4,
        emergency_contact: str | None = None
    ) -> dict[str, Any]:
        """Request break-glass emergency access.

        Args:
            session: Database session
            user_id: User requesting access
            reason: Reason for break-glass access
            justification: Detailed justification
            workspace_id: Workspace ID if applicable
            environment_id: Environment ID if applicable
            resource_type: Type of resource needing access
            resource_id: Specific resource ID
            requested_permissions: Specific permissions needed
            urgency: Urgency level
            duration_hours: Requested duration in hours
            emergency_contact: Emergency contact information

        Returns:
            Break-glass request result
        """
        try:
            # Validate request parameters
            validation_result = await self._validate_break_glass_request(
                session, user_id, reason, duration_hours, workspace_id, environment_id
            )
            if not validation_result["valid"]:
                return {"success": False, "error": validation_result["error"]}

            # Get approval requirements for this reason
            approval_config = self._approval_matrix.get(reason, self._approval_matrix[BreakGlassReason.OTHER])

            # Check if user has auto-approve role
            auto_approve = await self._check_auto_approve_eligibility(
                session, user_id, approval_config["auto_approve_roles"]
            )

            # Limit duration based on reason
            max_duration = approval_config["max_duration_hours"]
            duration_hours = min(duration_hours, max_duration)

            # Generate request ID
            import uuid
            request_id = str(uuid.uuid4())

            # Calculate expiry
            expires_at = datetime.now(timezone.utc) + timedelta(hours=duration_hours)

            # Create request
            request = BreakGlassAccessRequest(
                id=request_id,
                user_id=user_id,
                workspace_id=workspace_id,
                environment_id=environment_id,
                resource_type=resource_type,
                resource_id=resource_id,
                reason=reason,
                urgency=urgency,
                justification=justification,
                requested_permissions=requested_permissions or [],
                duration_hours=duration_hours,
                auto_approve=auto_approve,
                expires_at=expires_at,
                status=BreakGlassStatus.APPROVED if auto_approve else BreakGlassStatus.PENDING
            )

            # Store request
            self._active_requests[request_id] = request

            # Log the request
            await self._log_break_glass_event(
                session, "break_glass_requested", request, user_id, {
                    "reason": reason.value,
                    "urgency": urgency.value,
                    "duration_hours": duration_hours,
                    "auto_approved": auto_approve,
                    "emergency_contact": emergency_contact
                }
            )

            # Send notifications
            await self._send_break_glass_notifications(
                session, request, approval_config["notification_channels"]
            )

            # If auto-approved, activate immediately
            if auto_approve:
                request.approved_at = datetime.now(timezone.utc)
                request.approved_by_id = user_id  # Self-approved
                request.approval_comments = "Auto-approved based on user role"

            return {
                "success": True,
                "request_id": request_id,
                "status": request.status.value,
                "auto_approved": auto_approve,
                "expires_at": expires_at,
                "approval_required": not auto_approve,
                "estimated_approval_time": self._get_estimated_approval_time(urgency)
            }

        except Exception as e:
            logger.error(f"Break-glass request failed: {e}")
            return {"success": False, "error": str(e)}

    async def approve_break_glass_request(
        self,
        session: AsyncSession,
        request_id: UUIDstr,
        approver_id: UUIDstr,
        *,
        approved: bool = True,
        comments: str | None = None,
        modified_duration_hours: int | None = None,
        modified_permissions: list[str] | None = None
    ) -> dict[str, Any]:
        """Approve or deny a break-glass access request.

        Args:
            session: Database session
            request_id: Request ID to approve/deny
            approver_id: User approving the request
            approved: Whether to approve or deny
            comments: Approval/denial comments
            modified_duration_hours: Modified duration if different from request
            modified_permissions: Modified permissions if different from request

        Returns:
            Approval result
        """
        try:
            # Get request
            request = self._active_requests.get(request_id)
            if not request:
                return {"success": False, "error": "Break-glass request not found"}

            if request.status != BreakGlassStatus.PENDING:
                return {"success": False, "error": f"Request is not pending (status: {request.status})"}

            # Check if approver has approval authority
            can_approve = await self._check_approval_authority(
                session, approver_id, request.workspace_id, request.reason
            )
            if not can_approve:
                return {"success": False, "error": "Insufficient authority to approve break-glass requests"}

            # Update request
            if approved:
                request.status = BreakGlassStatus.APPROVED
                request.approved_by_id = approver_id
                request.approved_at = datetime.now(timezone.utc)
                request.approval_comments = comments

                # Apply modifications if provided
                if modified_duration_hours:
                    request.duration_hours = modified_duration_hours
                    request.expires_at = datetime.now(timezone.utc) + timedelta(hours=modified_duration_hours)

                if modified_permissions:
                    request.requested_permissions = modified_permissions

                # Log approval
                await self._log_break_glass_event(
                    session, "break_glass_approved", request, approver_id, {
                        "original_duration": request.duration_hours,
                        "modified_duration": modified_duration_hours,
                        "modified_permissions": modified_permissions,
                        "approval_comments": comments
                    }
                )

                # Notify user of approval
                await self._notify_user_approval(session, request, approved=True)

            else:
                request.status = BreakGlassStatus.DENIED
                request.approval_comments = comments

                # Log denial
                await self._log_break_glass_event(
                    session, "break_glass_denied", request, approver_id, {
                        "denial_reason": comments
                    }
                )

                # Notify user of denial
                await self._notify_user_approval(session, request, approved=False)

            return {
                "success": True,
                "request_id": request_id,
                "status": request.status.value,
                "approved": approved,
                "expires_at": request.expires_at if approved else None
            }

        except Exception as e:
            logger.error(f"Break-glass approval failed: {e}")
            return {"success": False, "error": str(e)}

    async def activate_break_glass_access(
        self,
        session: AsyncSession,
        request_id: UUIDstr,
        user_id: UUIDstr
    ) -> dict[str, Any]:
        """Activate approved break-glass access.

        Args:
            session: Database session
            request_id: Request ID to activate
            user_id: User activating the access

        Returns:
            Activation result
        """
        try:
            # Get request
            request = self._active_requests.get(request_id)
            if not request:
                return {"success": False, "error": "Break-glass request not found"}

            if request.user_id != user_id:
                return {"success": False, "error": "Can only activate your own break-glass access"}

            if request.status != BreakGlassStatus.APPROVED:
                return {"success": False, "error": f"Request is not approved (status: {request.status})"}

            # Check if expired
            if request.expires_at and datetime.now(timezone.utc) > request.expires_at:
                request.status = BreakGlassStatus.EXPIRED
                return {"success": False, "error": "Break-glass access has expired"}

            # Activate access
            request.status = BreakGlassStatus.USED
            request.used_at = datetime.now(timezone.utc)

            # Create temporary elevated permissions
            elevated_permissions = await self._create_temporary_permissions(
                session, request
            )

            # Log activation
            await self._log_break_glass_event(
                session, "break_glass_activated", request, user_id, {
                    "activated_permissions": request.requested_permissions,
                    "temporary_role_id": elevated_permissions.get("role_id")
                }
            )

            return {
                "success": True,
                "request_id": request_id,
                "activated_at": request.used_at,
                "expires_at": request.expires_at,
                "granted_permissions": request.requested_permissions,
                "temporary_role_id": elevated_permissions.get("role_id"),
                "warning": "This access is being monitored and audited. Use only for the stated emergency purpose."
            }

        except Exception as e:
            logger.error(f"Break-glass activation failed: {e}")
            return {"success": False, "error": str(e)}

    async def check_break_glass_access(
        self,
        session: AsyncSession,
        user_id: UUIDstr,
        resource_type: str,
        resource_id: UUIDstr,
        permission: str
    ) -> dict[str, Any]:
        """Check if user has active break-glass access for resource.

        Args:
            session: Database session
            user_id: User ID to check
            resource_type: Type of resource
            resource_id: Resource ID
            permission: Required permission

        Returns:
            Access check result
        """
        try:
            # Find active break-glass requests for user
            active_requests = [
                req for req in self._active_requests.values()
                if (req.user_id == user_id and
                    req.status == BreakGlassStatus.USED and
                    req.expires_at and
                    datetime.now(timezone.utc) <= req.expires_at)
            ]

            for request in active_requests:
                # Check if request covers this resource and permission
                if (self._request_covers_resource(request, resource_type, resource_id) and
                    self._request_has_permission(request, permission)):

                    # Log access
                    await self._log_break_glass_event(
                        session, "break_glass_access_used", request, user_id, {
                            "resource_type": resource_type,
                            "resource_id": resource_id,
                            "permission": permission
                        }
                    )

                    return {
                        "access_granted": True,
                        "request_id": request.id,
                        "reason": request.reason.value,
                        "expires_at": request.expires_at,
                        "remaining_minutes": int((request.expires_at - datetime.now(timezone.utc)).total_seconds() / 60)
                    }

            return {"access_granted": False}

        except Exception as e:
            logger.error(f"Break-glass access check failed: {e}")
            return {"access_granted": False, "error": str(e)}

    async def revoke_break_glass_access(
        self,
        session: AsyncSession,
        request_id: UUIDstr,
        revoked_by: UUIDstr,
        *,
        reason: str | None = None
    ) -> dict[str, Any]:
        """Revoke active break-glass access.

        Args:
            session: Database session
            request_id: Request ID to revoke
            revoked_by: User revoking the access
            reason: Reason for revocation

        Returns:
            Revocation result
        """
        try:
            # Get request
            request = self._active_requests.get(request_id)
            if not request:
                return {"success": False, "error": "Break-glass request not found"}

            if request.status not in [BreakGlassStatus.APPROVED, BreakGlassStatus.USED]:
                return {"success": False, "error": "Cannot revoke inactive break-glass access"}

            # Check revocation authority
            can_revoke = await self._check_revocation_authority(
                session, revoked_by, request.workspace_id
            )
            if not can_revoke and revoked_by != request.user_id:
                return {"success": False, "error": "Insufficient authority to revoke break-glass access"}

            # Revoke access
            request.status = BreakGlassStatus.REVOKED
            request.revoked_at = datetime.now(timezone.utc)
            request.revoked_by_id = revoked_by
            request.revoke_reason = reason

            # Remove temporary permissions
            await self._remove_temporary_permissions(session, request)

            # Log revocation
            await self._log_break_glass_event(
                session, "break_glass_revoked", request, revoked_by, {
                    "revoke_reason": reason,
                    "was_active": request.status == BreakGlassStatus.USED
                }
            )

            return {
                "success": True,
                "request_id": request_id,
                "revoked_at": request.revoked_at,
                "revoked_by": revoked_by
            }

        except Exception as e:
            logger.error(f"Break-glass revocation failed: {e}")
            return {"success": False, "error": str(e)}

    async def list_break_glass_requests(
        self,
        session: AsyncSession,
        *,
        user_id: UUIDstr | None = None,
        workspace_id: UUIDstr | None = None,
        status: BreakGlassStatus | None = None,
        reason: BreakGlassReason | None = None,
        include_expired: bool = False
    ) -> list[dict[str, Any]]:
        """List break-glass requests with optional filtering.

        Args:
            session: Database session
            user_id: Filter by user ID
            workspace_id: Filter by workspace ID
            status: Filter by status
            reason: Filter by reason
            include_expired: Include expired requests

        Returns:
            List of break-glass requests
        """
        try:
            requests = []

            for request in self._active_requests.values():
                # Apply filters
                if user_id and request.user_id != user_id:
                    continue
                if workspace_id and request.workspace_id != workspace_id:
                    continue
                if status and request.status != status:
                    continue
                if reason and request.reason != reason:
                    continue

                # Check expiry
                if not include_expired and request.expires_at:
                    if datetime.now(timezone.utc) > request.expires_at:
                        continue

                requests.append({
                    "id": request.id,
                    "user_id": request.user_id,
                    "workspace_id": request.workspace_id,
                    "environment_id": request.environment_id,
                    "resource_type": request.resource_type,
                    "resource_id": request.resource_id,
                    "reason": request.reason.value,
                    "urgency": request.urgency.value,
                    "justification": request.justification,
                    "requested_permissions": request.requested_permissions,
                    "duration_hours": request.duration_hours,
                    "status": request.status.value,
                    "requested_at": request.requested_at,
                    "expires_at": request.expires_at,
                    "approved_by_id": request.approved_by_id,
                    "approved_at": request.approved_at,
                    "used_at": request.used_at,
                    "revoked_at": request.revoked_at
                })

            return requests

        except Exception as e:
            logger.error(f"Failed to list break-glass requests: {e}")
            return []

    async def _validate_break_glass_request(
        self,
        session: AsyncSession,
        user_id: UUIDstr,
        reason: BreakGlassReason,
        duration_hours: int,
        workspace_id: UUIDstr | None,
        environment_id: UUIDstr | None
    ) -> dict[str, Any]:
        """Validate break-glass request parameters."""
        # Check if user exists and is active
        from langflow.services.database.models.user.model import User

        user = await session.get(User, user_id)
        if not user or not user.is_active:
            return {"valid": False, "error": "User not found or inactive"}

        # Check workspace access if specified
        if workspace_id:
            from langflow.services.database.models.rbac.workspace import Workspace

            workspace = await session.get(Workspace, workspace_id)
            if not workspace or not workspace.is_active:
                return {"valid": False, "error": "Workspace not found or inactive"}

        # Check environment access if specified
        if environment_id:
            from langflow.services.database.models.rbac.environment import Environment

            environment = await session.get(Environment, environment_id)
            if not environment or not environment.is_active:
                return {"valid": False, "error": "Environment not found or inactive"}

        # Validate duration
        max_duration = self._approval_matrix.get(reason, {}).get("max_duration_hours", 24)
        if duration_hours > max_duration:
            return {
                "valid": False,
                "error": f"Duration exceeds maximum allowed for {reason.value} ({max_duration} hours)"
            }

        # Check for active requests (prevent abuse)
        active_count = len([
            req for req in self._active_requests.values()
            if (req.user_id == user_id and
                req.status in [BreakGlassStatus.PENDING, BreakGlassStatus.APPROVED, BreakGlassStatus.USED])
        ])

        if active_count >= 3:  # Maximum 3 concurrent requests
            return {"valid": False, "error": "Too many active break-glass requests"}

        return {"valid": True}

    async def _check_auto_approve_eligibility(
        self,
        session: AsyncSession,
        user_id: UUIDstr,
        auto_approve_roles: list[str]
    ) -> bool:
        """Check if user has roles that allow auto-approval."""
        if not auto_approve_roles:
            return False

        # Check user's roles
        from langflow.services.database.models.rbac.role import Role
        from langflow.services.database.models.rbac.role_assignment import RoleAssignment

        query = select(Role).join(RoleAssignment).where(
            RoleAssignment.user_id == user_id,
            RoleAssignment.is_active.is_(True),
            Role.is_active.is_(True)
        )

        result = await session.exec(query)
        user_roles = result.all()

        user_role_names = [role.name for role in user_roles]
        return any(role in auto_approve_roles for role in user_role_names)

    async def _check_approval_authority(
        self,
        session: AsyncSession,
        approver_id: UUIDstr,
        workspace_id: UUIDstr | None,
        reason: BreakGlassReason
    ) -> bool:
        """Check if user has authority to approve break-glass requests."""
        from langflow.services.database.models.user.model import User

        user = await session.get(User, approver_id)

        # Superusers can always approve
        if user and user.is_superuser:
            return True

        # Check specific roles for this reason type
        auto_approve_roles = self._approval_matrix.get(reason, {}).get("auto_approve_roles", [])
        return await self._check_auto_approve_eligibility(session, approver_id, auto_approve_roles)

    async def _check_revocation_authority(
        self,
        session: AsyncSession,
        revoker_id: UUIDstr,
        workspace_id: UUIDstr | None
    ) -> bool:
        """Check if user has authority to revoke break-glass access."""
        from langflow.services.database.models.user.model import User

        user = await session.get(User, revoker_id)
        return user and user.is_superuser  # Only superusers can revoke others' access

    def _request_covers_resource(
        self,
        request: BreakGlassAccessRequest,
        resource_type: str,
        resource_id: UUIDstr
    ) -> bool:
        """Check if break-glass request covers the specified resource."""
        # If no specific resource in request, it covers everything in scope
        if not request.resource_type or not request.resource_id:
            return True

        return (request.resource_type == resource_type and
                request.resource_id == resource_id)

    def _request_has_permission(
        self,
        request: BreakGlassAccessRequest,
        permission: str
    ) -> bool:
        """Check if break-glass request includes the specified permission."""
        # If no specific permissions requested, assume all permissions
        if not request.requested_permissions:
            return True

        return permission in request.requested_permissions

    def _get_estimated_approval_time(self, urgency: BreakGlassUrgency) -> str:
        """Get estimated approval time based on urgency."""
        return {
            BreakGlassUrgency.CRITICAL: "Immediate",
            BreakGlassUrgency.HIGH: "Within 2 hours",
            BreakGlassUrgency.MEDIUM: "Within 8 hours",
            BreakGlassUrgency.LOW: "Within 24 hours"
        }.get(urgency, "Unknown")

    async def _create_temporary_permissions(
        self,
        session: AsyncSession,
        request: BreakGlassAccessRequest
    ) -> dict[str, Any]:
        """Create temporary elevated permissions for break-glass access."""
        # This would create temporary role assignments
        # For now, return a placeholder
        return {"role_id": "temp_break_glass_role", "created": True}

    async def _remove_temporary_permissions(
        self,
        session: AsyncSession,
        request: BreakGlassAccessRequest
    ) -> None:
        """Remove temporary permissions when break-glass access is revoked."""
        # This would remove temporary role assignments

    async def _log_break_glass_event(
        self,
        session: AsyncSession,
        event_type: str,
        request: BreakGlassAccessRequest,
        actor_id: UUIDstr,
        metadata: dict[str, Any]
    ) -> None:
        """Log break-glass events for audit trail."""
        from langflow.services.database.models.rbac.audit_log import ActorType, AuditEventType, AuditLog, AuditOutcome

        audit_log = AuditLog(
            event_type=AuditEventType.BREAK_GLASS_ACCESS,
            action=event_type,
            outcome=AuditOutcome.SUCCESS,
            actor_type=ActorType.USER,
            actor_id=actor_id,
            resource_type="break_glass_request",
            resource_id=request.id,
            workspace_id=request.workspace_id,
            environment_id=request.environment_id,
            event_metadata={
                **metadata,
                "request_id": request.id,
                "reason": request.reason.value,
                "urgency": request.urgency.value
            }
        )

        session.add(audit_log)
        await session.commit()

    async def _send_break_glass_notifications(
        self,
        session: AsyncSession,
        request: BreakGlassAccessRequest,
        channels: list[str]
    ) -> None:
        """Send notifications for break-glass request."""
        # This would integrate with notification systems
        logger.info(f"Break-glass notification sent via {channels} for request {request.id}")

    async def _notify_user_approval(
        self,
        session: AsyncSession,
        request: BreakGlassAccessRequest,
        approved: bool
    ) -> None:
        """Notify user of approval/denial decision."""
        # This would send notification to the requesting user
        status = "approved" if approved else "denied"
        logger.info(f"Break-glass request {request.id} {status} - user {request.user_id} notified")
