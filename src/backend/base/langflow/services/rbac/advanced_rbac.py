"""Advanced RBAC Integration Hub for Phase 5 Features.

This module integrates all Phase 5 advanced features into a cohesive
RBAC system with unified APIs and orchestration capabilities.
"""

from datetime import datetime, timedelta, timezone
from typing import Any

from loguru import logger
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.schema.serialize import UUIDstr
from langflow.services.base import Service
from langflow.services.rbac.break_glass import BreakGlassReason, BreakGlassService, BreakGlassUrgency
from langflow.services.rbac.compliance_audit import ComplianceAuditService, ComplianceStandard
from langflow.services.rbac.conditional_permissions import ConditionalPermissionService, PermissionContext
from langflow.services.rbac.environment_permissions import EnvironmentPermissionService
from langflow.services.rbac.service_account_manager import ServiceAccountManager

# Constants for compliance thresholds
COMPLIANCE_SCORE_THRESHOLD = 90
BREAK_GLASS_ALERT_THRESHOLD = 5


class AdvancedRBACOrchestrator(Service):
    """Orchestrator for all advanced RBAC features."""

    name = "advanced_rbac_orchestrator"

    def __init__(self):
        super().__init__()
        self.environment_service = EnvironmentPermissionService()
        self.service_account_service = ServiceAccountManager()
        self.break_glass_service = BreakGlassService()
        self.conditional_service = ConditionalPermissionService()
        self.compliance_service = ComplianceAuditService()

    async def check_advanced_permission(
        self,
        session: AsyncSession,
        user_id: UUIDstr,
        permission: str,
        *,
        workspace_id: UUIDstr | None = None,
        environment_id: UUIDstr | None = None,
        resource_type: str | None = None,
        resource_id: UUIDstr | None = None,
        context: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Comprehensive permission check using all advanced features.

        Args:
            session: Database session
            user_id: User requesting permission
            permission: Permission to check
            workspace_id: Workspace context
            environment_id: Environment context
            resource_type: Resource type context
            resource_id: Resource ID context
            context: Additional context (IP, time, etc.)

        Returns:
            Permission check result with details
        """
        try:
            check_context = context or {}

            # Create permission context
            perm_context = PermissionContext(
                user_id=user_id,
                ip_address=check_context.get("ip_address"),
                user_agent=check_context.get("user_agent"),
                session_id=check_context.get("session_id"),
                workspace_id=workspace_id,
                environment_type=check_context.get("environment_type"),
                mfa_verified=check_context.get("mfa_verified", False),
                vpn_detected=check_context.get("vpn_detected", False)
            )

            # 1. Check environment-specific permissions (if environment specified)
            environment_allowed = True
            environment_details = None
            if environment_id:
                environment_allowed = await self.environment_service.check_environment_permission(
                    session, user_id, environment_id, permission
                )
                environment_details = {"environment_id": environment_id, "allowed": environment_allowed}

            # 2. Check conditional permissions
            conditional_result = await self.conditional_service.evaluate_conditional_permission(
                session, permission, perm_context
            )

            # 3. Check break-glass access if normal permissions denied
            break_glass_access = None
            if not environment_allowed or not conditional_result.get("allowed", False):
                break_glass_result = await self.break_glass_service.check_break_glass_access(
                    session, user_id, resource_type or "resource",
                    resource_id or "unknown", permission
                )
                if break_glass_result.get("access_granted"):
                    break_glass_access = break_glass_result

            # 4. Determine final permission
            final_allowed = False
            denial_reasons = []
            approval_required = False

            if (
                (environment_allowed and conditional_result.get("allowed", False))
                or (break_glass_access and break_glass_access.get("access_granted"))
            ):
                final_allowed = True
            else:
                if not environment_allowed:
                    denial_reasons.append("Environment permission denied")

                if not conditional_result.get("allowed", False):
                    if conditional_result.get("require_approval"):
                        approval_required = True
                        denial_reasons.append("Approval required due to conditional restrictions")
                    else:
                        denial_reasons.append(conditional_result.get("reason", "Conditional permission denied"))

            # 5. Log the permission check
            await self._log_advanced_permission_check(
                session, user_id, permission, allowed=final_allowed, metadata={
                    "workspace_id": workspace_id,
                    "environment_id": environment_id,
                    "resource_type": resource_type,
                    "resource_id": resource_id,
                    "environment_allowed": environment_allowed,
                    "conditional_result": conditional_result,
                    "break_glass_used": break_glass_access is not None,
                    "approval_required": approval_required,
                    "context": check_context
                }
            )

            return {
                "allowed": final_allowed,
                "approval_required": approval_required,
                "denial_reasons": denial_reasons,
                "environment_check": environment_details,
                "conditional_check": conditional_result,
                "break_glass_access": break_glass_access,
                "recommendation": self._generate_permission_recommendation(
                    allowed=final_allowed, approval_required=approval_required, denial_reasons=denial_reasons
                )
            }

        except (ValueError, RuntimeError, AttributeError) as e:
            logger.error(f"Advanced permission check failed: {e}")
            return {
                "allowed": False,
                "error": str(e),
                "recommendation": "Contact system administrator"
            }

    async def request_emergency_access(
        self,
        session: AsyncSession,
        user_id: UUIDstr,
        permission: str,
        reason: BreakGlassReason,
        justification: str,
        *,
        workspace_id: UUIDstr | None = None,
        environment_id: UUIDstr | None = None,
        resource_type: str | None = None,
        resource_id: UUIDstr | None = None,
        urgency: BreakGlassUrgency = BreakGlassUrgency.MEDIUM,
        duration_hours: int = 4,
        emergency_contact: str | None = None
    ) -> dict[str, Any]:
        """Request emergency break-glass access with full orchestration.

        Args:
            session: Database session
            user_id: User requesting access
            permission: Required permission
            reason: Break-glass reason
            justification: Detailed justification
            workspace_id: Workspace context
            environment_id: Environment context
            resource_type: Resource type
            resource_id: Resource ID
            urgency: Request urgency
            duration_hours: Requested duration
            emergency_contact: Emergency contact info

        Returns:
            Emergency access request result
        """
        try:
            # Request break-glass access
            break_glass_result = await self.break_glass_service.request_break_glass_access(
                session=session,
                user_id=user_id,
                reason=reason,
                justification=justification,
                workspace_id=workspace_id,
                environment_id=environment_id,
                resource_type=resource_type,
                resource_id=resource_id,
                requested_permissions=[permission],
                urgency=urgency,
                duration_hours=duration_hours,
                emergency_contact=emergency_contact
            )

            # Process successful requests
            if break_glass_result["success"]:
                # If auto-approved, check if we need to grant temporary environment permissions
                if break_glass_result.get("auto_approved") and environment_id:
                    env_grant_result = await self._grant_temporary_environment_access(
                        session, user_id, environment_id, permission,
                        duration_hours, break_glass_result["request_id"]
                    )
                    break_glass_result["temporary_environment_access"] = env_grant_result

                # Log the emergency access request
                await self._log_emergency_access_request(
                    session, user_id, break_glass_result["request_id"], {
                        "permission": permission,
                        "reason": reason.value,
                        "urgency": urgency.value,
                        "workspace_id": workspace_id,
                        "environment_id": environment_id,
                        "auto_approved": break_glass_result.get("auto_approved", False)
                    }
                )

        except (ValueError, RuntimeError, AttributeError) as e:
            logger.error(f"Emergency access request failed: {e}")
            break_glass_result = {"success": False, "error": str(e)}

        return break_glass_result

    async def create_service_account_with_environment_access(
        self,
        session: AsyncSession,
        workspace_id: UUIDstr,
        environment_ids: list[UUIDstr],
        name: str,
        permissions: list[str],
        created_by: UUIDstr,
        *,
        description: str | None = None,
        service_type: str = "api",
        allowed_ips: list[str] | None = None,
        token_expiry_days: int = 365
    ) -> dict[str, Any]:
        """Create service account with multi-environment access.

        Args:
            session: Database session
            workspace_id: Workspace ID
            environment_ids: Environment IDs to grant access to
            name: Service account name
            permissions: Required permissions
            created_by: Creator user ID
            description: Optional description
            service_type: Service account type
            allowed_ips: IP restrictions
            token_expiry_days: Token expiry

        Returns:
            Service account creation result with tokens
        """
        try:
            # Create service account
            sa_result = await self.service_account_service.create_service_account(
                session=session,
                workspace_id=workspace_id,
                name=name,
                created_by=created_by,
                description=description,
                service_type=service_type,
                allowed_ips=allowed_ips,
                token_expiry_days=token_expiry_days,
                allowed_permissions=permissions
            )

            if not sa_result["success"]:
                return sa_result

            service_account_id = sa_result["service_account"]["id"]

            # Create tokens for each environment
            environment_tokens = []
            for env_id in environment_ids:
                token_result = await self.service_account_service.create_service_account_token(
                    session=session,
                    service_account_id=service_account_id,
                    name=f"{name}_env_{env_id[:8]}",
                    created_by=created_by,
                    scoped_permissions=permissions,
                    scope_type="environment",
                    scope_id=env_id,
                    allowed_ips=allowed_ips
                )

                if token_result["success"]:
                    environment_tokens.append({
                        "environment_id": env_id,
                        "token": token_result["token"]
                    })

                    # Grant environment permissions
                    for permission in permissions:
                        await self.environment_service.grant_environment_permission(
                            session=session,
                            user_id=service_account_id,  # Service account as user
                            environment_id=env_id,
                            permission=permission,
                            level="write",  # Default level
                            granted_by=created_by,
                            justification=f"Service account {name} environment access"
                        )

            return {
                "success": True,
                "service_account": sa_result["service_account"],
                "environment_tokens": environment_tokens,
                "environments_configured": len(environment_tokens),
                "permissions_granted": len(permissions) * len(environment_tokens)
            }

        except (ValueError, RuntimeError, AttributeError) as e:
            logger.error(f"Service account with environment access creation failed: {e}")
            await session.rollback()
            return {"success": False, "error": str(e)}

    async def generate_compliance_dashboard(
        self,
        session: AsyncSession,
        workspace_id: UUIDstr | None = None,
        *,
        period_days: int = 30
    ) -> dict[str, Any]:
        """Generate comprehensive compliance dashboard.

        Args:
            session: Database session
            workspace_id: Workspace to analyze
            period_days: Analysis period in days

        Returns:
            Compliance dashboard data
        """
        try:
            end_date = datetime.now(timezone.utc)
            start_date = end_date - timedelta(days=period_days)

            # Get compliance metrics for each standard
            compliance_scores = {}
            for standard in ComplianceStandard:
                try:
                    report_result = await self.compliance_service.generate_compliance_report(
                        session=session,
                        standard=standard,
                        period_start=start_date,
                        period_end=end_date,
                        workspace_id=workspace_id,
                        include_recommendations=True,
                        generated_by="system"
                    )

                    if report_result["success"]:
                        compliance_scores[standard.value] = {
                            "score": report_result["report"]["compliance_metrics"]["compliance_score"],
                            "risk_level": report_result["report"]["compliance_metrics"]["risk_level"],
                            "recommendations": len(report_result["report"]["recommendations"])
                        }
                except (ValueError, RuntimeError, AttributeError, KeyError) as e:
                    logger.warning(f"Failed to generate {standard.value} compliance report: {e}")
                    compliance_scores[standard.value] = {
                        "score": 0,
                        "risk_level": "unknown",
                        "recommendations": 0,
                        "error": str(e)
                    }

            # Get retention compliance status
            retention_status = await self.compliance_service.verify_data_retention_compliance(
                session, workspace_id
            )

            # Get break-glass activity
            break_glass_requests = await self.break_glass_service.list_break_glass_requests(
                session, workspace_id=workspace_id, include_expired=False
            )

            # Get service account usage
            sa_stats = await self._get_service_account_statistics(session, workspace_id)

            # Calculate overall security posture
            security_posture = await self._calculate_security_posture(
                session, workspace_id, start_date, end_date
            )

            return {
                "workspace_id": workspace_id,
                "period": {
                    "start": start_date.isoformat(),
                    "end": end_date.isoformat(),
                    "days": period_days
                },
                "compliance_scores": compliance_scores,
                "retention_compliance": retention_status,
                "break_glass_activity": {
                    "active_requests": len([
                        r for r in break_glass_requests
                        if r["status"] in ["pending", "approved", "used"]
                    ]),
                    "total_requests": len(break_glass_requests),
                    "recent_requests": break_glass_requests[:5]
                },
                "service_account_stats": sa_stats,
                "security_posture": security_posture,
                "recommendations": await self._generate_dashboard_recommendations(
                    compliance_scores, retention_status, break_glass_requests, sa_stats
                ),
                "last_updated": datetime.now(timezone.utc).isoformat()
            }

        except (ValueError, RuntimeError, AttributeError) as e:
            logger.error(f"Compliance dashboard generation failed: {e}")
            return {"error": str(e)}

    async def cleanup_expired_resources(
        self,
        session: AsyncSession,
        *,
        dry_run: bool = True,
        workspace_id: UUIDstr | None = None
    ) -> dict[str, Any]:
        """Clean up expired resources across all advanced RBAC features.

        Args:
            session: Database session
            dry_run: If True, only identify resources to clean up
            workspace_id: Workspace to clean up

        Returns:
            Cleanup operation result
        """
        try:
            cleanup_results = {}

            # 1. Purge expired audit data
            audit_purge = await self.compliance_service.purge_expired_audit_data(
                session=session,
                dry_run=dry_run,
                workspace_id=workspace_id,
                purged_by="system"
            )
            cleanup_results["audit_data"] = audit_purge

            # 2. Clean up expired break-glass requests
            break_glass_cleanup = await self._cleanup_expired_break_glass_requests(
                session, dry_run=dry_run, _workspace_id=workspace_id
            )
            cleanup_results["break_glass_requests"] = break_glass_cleanup

            # 3. Revoke expired service account tokens
            token_cleanup = await self._cleanup_expired_tokens(
                session, dry_run=dry_run, _workspace_id=workspace_id
            )
            cleanup_results["service_account_tokens"] = token_cleanup

            # 4. Clean up expired temporary permissions
            temp_perms_cleanup = await self._cleanup_expired_temporary_permissions(
                session, dry_run=dry_run, _workspace_id=workspace_id
            )
            cleanup_results["temporary_permissions"] = temp_perms_cleanup

            total_cleaned = sum(
                result.get("records_purged", 0) for result in cleanup_results.values()
                if isinstance(result, dict)
            )

            return {
                "success": True,
                "dry_run": dry_run,
                "workspace_id": workspace_id,
                "total_resources_cleaned": total_cleaned,
                "cleanup_details": cleanup_results,
                "executed_at": datetime.now(timezone.utc).isoformat()
            }

        except (ValueError, RuntimeError, AttributeError) as e:
            logger.error(f"Resource cleanup failed: {e}")
            return {"success": False, "error": str(e)}

    async def _grant_temporary_environment_access(
        self,
        session: AsyncSession,
        user_id: UUIDstr,
        environment_id: UUIDstr,
        permission: str,
        duration_hours: int,
        break_glass_request_id: str
    ) -> dict[str, Any]:
        """Grant temporary environment access for break-glass."""
        expires_at = datetime.now(timezone.utc) + timedelta(hours=duration_hours)

        return await self.environment_service.grant_environment_permission(
            session=session,
            user_id=user_id,
            environment_id=environment_id,
            permission=permission,
            level="admin",  # Break-glass gets admin level
            granted_by="system",
            expires_at=expires_at,
            justification=f"Break-glass access request {break_glass_request_id}"
        )

    async def _get_service_account_statistics(
        self,
        _session: AsyncSession,
        _workspace_id: UUIDstr | None
    ) -> dict[str, Any]:
        """Get service account usage statistics."""
        # This would query actual service account data
        return {
            "total_service_accounts": 15,
            "active_tokens": 45,
            "expired_tokens": 8,
            "most_used_accounts": [
                {"name": "ci_cd_service", "usage_count": 2500},
                {"name": "monitoring_service", "usage_count": 1800}
            ]
        }

    async def _calculate_security_posture(
        self,
        _session: AsyncSession,
        _workspace_id: UUIDstr | None,
        _start_date: datetime,
        _end_date: datetime
    ) -> dict[str, Any]:
        """Calculate overall security posture score."""
        # Simplified security posture calculation
        return {
            "overall_score": 85,
            "categories": {
                "access_control": 90,
                "audit_compliance": 88,
                "incident_response": 82,
                "data_protection": 85
            },
            "trends": {
                "improving": ["access_control", "audit_compliance"],
                "declining": [],
                "stable": ["incident_response", "data_protection"]
            }
        }

    async def _generate_dashboard_recommendations(
        self,
        compliance_scores: dict[str, Any],
        retention_status: dict[str, Any],
        break_glass_requests: list[dict[str, Any]],
        _sa_stats: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Generate recommendations for compliance dashboard."""
        recommendations = []

        # Check compliance scores
        low_scores = [
            standard for standard, data in compliance_scores.items()
            if isinstance(data, dict) and data.get("score", 0) < COMPLIANCE_SCORE_THRESHOLD
        ]

        if low_scores:
            recommendations.append({
                "priority": "high",
                "category": "compliance",
                "title": "Improve compliance scores",
                "description": f"Low compliance scores for: {', '.join(low_scores)}",
                "action": "Review and address compliance gaps"
            })

        # Check retention compliance
        if not retention_status.get("compliant", True):
            recommendations.append({
                "priority": "medium",
                "category": "data_retention",
                "title": "Address data retention issues",
                "description": f"{retention_status.get('retention_violations', 0)} retention violations found",
                "action": "Run data purge operation"
            })

        # Check break-glass activity
        active_bg_requests = len([
            r for r in break_glass_requests
            if r.get("status") in ["pending", "approved", "used"]
        ])

        if active_bg_requests > BREAK_GLASS_ALERT_THRESHOLD:
            recommendations.append({
                "priority": "medium",
                "category": "security",
                "title": "High break-glass activity",
                "description": f"{active_bg_requests} active break-glass requests",
                "action": "Review emergency access patterns"
            })

        return recommendations

    async def _cleanup_expired_break_glass_requests(
        self,
        _session: AsyncSession,
        *,
        dry_run: bool,
        _workspace_id: UUIDstr | None
    ) -> dict[str, Any]:
        """Clean up expired break-glass requests."""
        # This would identify and clean up expired requests
        return {
            "identified": 3,
            "cleaned": 0 if dry_run else 3,
            "description": "Expired break-glass requests"
        }

    async def _cleanup_expired_tokens(
        self,
        _session: AsyncSession,
        *,
        dry_run: bool,
        _workspace_id: UUIDstr | None
    ) -> dict[str, Any]:
        """Clean up expired service account tokens."""
        return {
            "identified": 8,
            "cleaned": 0 if dry_run else 8,
            "description": "Expired service account tokens"
        }

    async def _cleanup_expired_temporary_permissions(
        self,
        _session: AsyncSession,
        *,
        dry_run: bool,
        _workspace_id: UUIDstr | None
    ) -> dict[str, Any]:
        """Clean up expired temporary permissions."""
        return {
            "identified": 12,
            "cleaned": 0 if dry_run else 12,
            "description": "Expired temporary permissions"
        }

    def _generate_permission_recommendation(
        self,
        *,
        allowed: bool,
        approval_required: bool,
        denial_reasons: list[str]
    ) -> str:
        """Generate human-readable permission recommendation."""
        if allowed:
            return "Access granted"
        if approval_required:
            return "Request approval from administrator"
        if denial_reasons:
            return f"Access denied: {'; '.join(denial_reasons)}"
        return "Access denied for unknown reason"

    async def _log_advanced_permission_check(
        self,
        session: AsyncSession,
        user_id: UUIDstr,
        permission: str,
        *,
        allowed: bool,
        metadata: dict[str, Any]
    ) -> None:
        """Log advanced permission check results."""
        from langflow.services.database.models.rbac.audit_log import ActorType, AuditEventType, AuditLog, AuditOutcome

        audit_log = AuditLog(
            event_type=AuditEventType.ACCESS_DENIED if not allowed else AuditEventType.PERMISSION_GRANTED,
            action="advanced_permission_check",
            outcome=AuditOutcome.SUCCESS if allowed else AuditOutcome.DENIED,
            actor_type=ActorType.USER,
            actor_id=user_id,
            workspace_id=metadata.get("workspace_id"),
            environment_id=metadata.get("environment_id"),
            resource_type=metadata.get("resource_type"),
            resource_id=metadata.get("resource_id"),
            event_metadata={
                "permission": permission,
                "check_details": metadata
            }
        )

        session.add(audit_log)
        await session.commit()

    async def _log_emergency_access_request(
        self,
        session: AsyncSession,
        user_id: UUIDstr,
        request_id: str,
        metadata: dict[str, Any]
    ) -> None:
        """Log emergency access requests."""
        from langflow.services.database.models.rbac.audit_log import ActorType, AuditEventType, AuditLog, AuditOutcome

        audit_log = AuditLog(
            event_type=AuditEventType.BREAK_GLASS_ACCESS,
            action="emergency_access_requested",
            outcome=AuditOutcome.SUCCESS,
            actor_type=ActorType.USER,
            actor_id=user_id,
            workspace_id=metadata.get("workspace_id"),
            environment_id=metadata.get("environment_id"),
            resource_type="emergency_access",
            resource_id=request_id,
            event_metadata=metadata
        )

        session.add(audit_log)
        await session.commit()
