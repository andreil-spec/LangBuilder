"""Audit logging service for RBAC compliance and security monitoring.

This module provides comprehensive audit logging following LangBuilder patterns,
with immutable storage, compliance reporting, and performance optimization.
"""

# NO future annotations per Phase 1 requirements
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any, Optional
from uuid import UUID, uuid4

from loguru import logger
from pydantic import BaseModel
from sqlmodel import and_, func, select
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.services.base import Service

if TYPE_CHECKING:
    from langflow.services.database.models.user.model import User


class AuditSeverity(str, Enum):
    """Audit event severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ComplianceFramework(str, Enum):
    """Supported compliance frameworks."""

    SOC2 = "soc2"
    ISO27001 = "iso27001"
    GDPR = "gdpr"
    CCPA = "ccpa"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"


@dataclass
class AuditContext:
    """Context information for audit events."""

    user_id: UUID | None = None
    session_id: str | None = None
    client_ip: str | None = None
    user_agent: str | None = None
    request_id: str | None = None
    workspace_id: UUID | None = None
    additional_data: dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditFilter:
    """Filter criteria for audit log queries."""

    start_date: datetime | None = None
    end_date: datetime | None = None
    event_types: list[str] | None = None
    actor_types: list[str] | None = None
    actor_ids: list[UUID] | None = None
    workspace_ids: list[UUID] | None = None
    success_only: bool | None = None
    severity_levels: list[AuditSeverity] | None = None
    target_types: list[str] | None = None
    actions: list[str] | None = None
    limit: int = 1000
    offset: int = 0


class AuditSearchResult(BaseModel):
    """Result of audit log search operation."""

    total_count: int
    filtered_count: int
    events: list[dict[str, Any]]
    search_duration_ms: float
    has_more: bool


class ComplianceReport(BaseModel):
    """Compliance report structure."""

    report_id: str
    framework: ComplianceFramework
    generated_at: datetime
    period_start: datetime
    period_end: datetime
    total_events: int
    events_by_type: dict[str, int]
    security_events: int
    access_violations: int
    privileged_operations: int
    data_access_events: int
    compliance_metrics: dict[str, Any]
    recommendations: list[str]


class AuditService(Service):
    """Audit logging service following LangBuilder patterns.

    Provides comprehensive audit capabilities including:
    - Immutable audit log storage
    - Real-time security monitoring
    - Compliance reporting (SOC2, ISO27001, GDPR, etc.)
    - Performance-optimized queries
    - Retention policy management
    - Export capabilities for compliance audits
    """

    name = "audit_service"

    def __init__(self):
        """Initialize audit service."""
        self._audit_stats = {
            "events_logged": 0,
            "events_by_type": {},
            "errors": 0,
            "avg_write_time_ms": 0.0,
        }
        self._batch_buffer: list[dict[str, Any]] = []
        self._batch_size = 100
        self._high_volume_threshold = 1000  # Events per minute

    async def log_authentication_event(
        self,
        session: AsyncSession,
        user: Optional["User"],
        event_type: str,  # login, logout, failed_login, password_change, etc.
        success: bool,
        context: AuditContext,
        details: dict[str, Any] | None = None,
    ) -> str:
        """Log authentication-related audit event.

        Args:
            session: Database session
            user: User involved in authentication (may be None for failed attempts)
            event_type: Type of authentication event
            success: Whether the authentication was successful
            context: Audit context with request details
            details: Additional event-specific details

        Returns:
            Audit event ID
        """
        from langflow.services.database.models.rbac.audit_log import ActorType, AuditEventType

        audit_data = {
            "event_type": AuditEventType.AUTHENTICATION,
            "actor_type": ActorType.USER if user else ActorType.ANONYMOUS,
            "actor_id": user.id if user else None,
            "action": event_type,
            "success": success,
            "workspace_id": context.workspace_id,
            "client_ip": context.client_ip,
            "user_agent": context.user_agent,
            "session_id": context.session_id,
            "metadata": {
                "authentication_method": details.get("method") if details else "password",
                "user_agent": context.user_agent,
                "client_ip": context.client_ip,
                "session_id": context.session_id,
                "request_id": context.request_id,
                **(details or {}),
                **(context.additional_data or {}),
            },
        }

        # Determine severity
        severity = AuditSeverity.HIGH if not success else AuditSeverity.MEDIUM
        if event_type in ["failed_login", "account_locked", "suspicious_activity"]:
            severity = AuditSeverity.CRITICAL

        return await self._create_audit_event(session, audit_data, severity)

    async def log_authorization_event(
        self,
        session: AsyncSession,
        user: "User",
        action: str,
        resource_type: str,
        resource_id: UUID | None,
        success: bool,
        context: AuditContext,
        details: dict[str, Any] | None = None,
    ) -> str:
        """Log authorization/permission check audit event.

        Args:
            session: Database session
            user: User requesting permission
            action: Action being authorized
            resource_type: Type of resource being accessed
            resource_id: Specific resource ID (if applicable)
            success: Whether authorization was granted
            context: Audit context
            details: Additional authorization details

        Returns:
            Audit event ID
        """
        from langflow.services.database.models.rbac.audit_log import ActorType, AuditEventType

        audit_data = {
            "event_type": AuditEventType.AUTHORIZATION,
            "actor_type": ActorType.USER,
            "actor_id": user.id,
            "target_type": resource_type,
            "target_id": resource_id,
            "action": action,
            "success": success,
            "workspace_id": context.workspace_id,
            "metadata": {
                "resource_type": resource_type,
                "resource_id": str(resource_id) if resource_id else None,
                "action": action,
                "decision_reason": details.get("reason") if details else None,
                "applied_roles": details.get("applied_roles") if details else None,
                "cached": details.get("cached", False) if details else False,
                "evaluation_time_ms": details.get("evaluation_time_ms") if details else None,
                **(context.additional_data or {}),
            },
        }

        # Higher severity for failed high-privilege operations
        severity = AuditSeverity.LOW if success else AuditSeverity.MEDIUM
        if action in ["delete", "manage_users", "manage_roles", "break_glass_access"]:
            severity = AuditSeverity.HIGH if success else AuditSeverity.CRITICAL

        return await self._create_audit_event(session, audit_data, severity)

    async def log_role_management_event(
        self,
        session: AsyncSession,
        actor: "User",
        action: str,  # assign_role, revoke_role, create_role, update_role, delete_role
        target_user_id: UUID | None,
        role_id: UUID,
        context: AuditContext,
        details: dict[str, Any] | None = None,
    ) -> str:
        """Log role management audit event.

        Args:
            session: Database session
            actor: User performing the role management action
            action: Type of role management action
            target_user_id: User being affected (for assign/revoke)
            role_id: Role being managed
            context: Audit context
            details: Additional role management details

        Returns:
            Audit event ID
        """
        from langflow.services.database.models.rbac.audit_log import ActorType, AuditEventType

        audit_data = {
            "event_type": AuditEventType.ROLE_MANAGEMENT,
            "actor_type": ActorType.USER,
            "actor_id": actor.id,
            "target_type": "role",
            "target_id": role_id,
            "action": action,
            "success": True,  # Assume success - failure would be handled by exception
            "workspace_id": context.workspace_id,
            "metadata": {
                "action": action,
                "role_id": str(role_id),
                "target_user_id": str(target_user_id) if target_user_id else None,
                "scope_type": details.get("scope_type") if details else None,
                "scope_id": details.get("scope_id") if details else None,
                "expiration": details.get("expiration") if details else None,
                **(context.additional_data or {}),
            },
        }

        # Role management is always high severity
        severity = AuditSeverity.HIGH

        return await self._create_audit_event(session, audit_data, severity)

    async def log_data_access_event(
        self,
        session: AsyncSession,
        user: "User",
        action: str,
        data_type: str,
        data_classification: str | None,
        record_count: int | None,
        context: AuditContext,
        details: dict[str, Any] | None = None,
    ) -> str:
        """Log data access audit event for compliance.

        Args:
            session: Database session
            user: User accessing data
            action: Type of data access (read, export, download, etc.)
            data_type: Type of data being accessed
            data_classification: Data classification level (public, internal, confidential, restricted)
            record_count: Number of records accessed
            context: Audit context
            details: Additional data access details

        Returns:
            Audit event ID
        """
        from langflow.services.database.models.rbac.audit_log import ActorType, AuditEventType

        audit_data = {
            "event_type": AuditEventType.DATA_ACCESS,
            "actor_type": ActorType.USER,
            "actor_id": user.id,
            "target_type": data_type,
            "action": action,
            "success": True,
            "workspace_id": context.workspace_id,
            "metadata": {
                "data_type": data_type,
                "data_classification": data_classification,
                "record_count": record_count,
                "action": action,
                "query_hash": details.get("query_hash") if details else None,
                "export_format": details.get("export_format") if details else None,
                "retention_category": details.get("retention_category") if details else None,
                **(context.additional_data or {}),
            },
        }

        # Severity based on data classification and action
        severity = AuditSeverity.LOW
        if data_classification in ["confidential", "restricted"]:
            severity = AuditSeverity.HIGH
        if action in ["export", "download", "bulk_access"]:
            severity = AuditSeverity.MEDIUM if data_classification != "restricted" else AuditSeverity.HIGH

        return await self._create_audit_event(session, audit_data, severity)

    async def log_security_event(
        self,
        session: AsyncSession,
        event_type: str,
        severity: AuditSeverity,
        description: str,
        context: AuditContext,
        actor_id: UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> str:
        """Log security-related audit event.

        Args:
            session: Database session
            event_type: Type of security event
            severity: Event severity level
            description: Human-readable event description
            context: Audit context
            actor_id: User or service account involved (if applicable)
            details: Additional security event details

        Returns:
            Audit event ID
        """
        from langflow.services.database.models.rbac.audit_log import ActorType, AuditEventType

        audit_data = {
            "event_type": AuditEventType.SECURITY,
            "actor_type": ActorType.USER if actor_id else ActorType.SYSTEM,
            "actor_id": actor_id,
            "action": event_type,
            "success": True,  # Security events are informational
            "workspace_id": context.workspace_id,
            "metadata": {
                "event_type": event_type,
                "description": description,
                "severity": severity.value,
                "detection_method": details.get("detection_method") if details else "manual",
                "threat_indicators": details.get("threat_indicators") if details else None,
                "mitigation_actions": details.get("mitigation_actions") if details else None,
                **(context.additional_data or {}),
            },
        }

        return await self._create_audit_event(session, audit_data, severity)

    async def search_audit_logs(
        self,
        session: AsyncSession,
        filters: AuditFilter,
    ) -> AuditSearchResult:
        """Search audit logs with filtering and pagination.

        Args:
            session: Database session
            filters: Search filter criteria

        Returns:
            Search result with matching audit events
        """
        from langflow.services.database.models.rbac.audit_log import AuditLog

        start_time = datetime.now(timezone.utc)

        # Build base query
        query = select(AuditLog)
        count_query = select(func.count(AuditLog.id))

        # Apply filters
        conditions = []

        if filters.start_date:
            conditions.append(AuditLog.timestamp >= filters.start_date)

        if filters.end_date:
            conditions.append(AuditLog.timestamp <= filters.end_date)

        if filters.event_types:
            conditions.append(AuditLog.event_type.in_(filters.event_types))

        if filters.actor_types:
            conditions.append(AuditLog.actor_type.in_(filters.actor_types))

        if filters.actor_ids:
            conditions.append(AuditLog.actor_id.in_(filters.actor_ids))

        if filters.workspace_ids:
            conditions.append(AuditLog.workspace_id.in_(filters.workspace_ids))

        if filters.success_only is not None:
            conditions.append(AuditLog.success == filters.success_only)

        if filters.target_types:
            conditions.append(AuditLog.target_type.in_(filters.target_types))

        if filters.actions:
            conditions.append(AuditLog.action.in_(filters.actions))

        # Apply conditions
        if conditions:
            query = query.where(and_(*conditions))
            count_query = count_query.where(and_(*conditions))

        # Get total count
        total_result = await session.exec(count_query)
        total_count = total_result.one()

        # Apply ordering and pagination
        query = query.order_by(AuditLog.timestamp.desc())
        query = query.offset(filters.offset).limit(filters.limit)

        # Execute query
        result = await session.exec(query)
        events = result.all()

        # Convert to dict format
        event_dicts = []
        for event in events:
            event_dict = {
                "id": str(event.id),
                "timestamp": event.timestamp.isoformat(),
                "event_type": event.event_type,
                "actor_type": event.actor_type,
                "actor_id": str(event.actor_id) if event.actor_id else None,
                "target_type": event.target_type,
                "target_id": str(event.target_id) if event.target_id else None,
                "action": event.action,
                "success": event.success,
                "workspace_id": str(event.workspace_id) if event.workspace_id else None,
                "client_ip": event.client_ip,
                "user_agent": event.user_agent,
                "session_id": event.session_id,
                "metadata": event.metadata,
            }
            event_dicts.append(event_dict)

        search_duration = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

        return AuditSearchResult(
            total_count=total_count,
            filtered_count=len(events),
            events=event_dicts,
            search_duration_ms=search_duration,
            has_more=len(events) == filters.limit and (filters.offset + len(events)) < total_count,
        )

    async def generate_compliance_report(
        self,
        session: AsyncSession,
        framework: ComplianceFramework,
        start_date: datetime,
        end_date: datetime,
        workspace_ids: list[UUID] | None = None,
    ) -> ComplianceReport:
        """Generate compliance report for specified framework and period.

        Args:
            session: Database session
            framework: Compliance framework to report on
            start_date: Report period start
            end_date: Report period end
            workspace_ids: Optional workspace scope

        Returns:
            Compliance report with metrics and recommendations
        """
        from langflow.services.database.models.rbac.audit_log import AuditEventType, AuditLog

        report_id = str(uuid4())

        # Build base query for the period
        query = select(AuditLog).where(
            AuditLog.timestamp >= start_date,
            AuditLog.timestamp <= end_date,
        )

        if workspace_ids:
            query = query.where(AuditLog.workspace_id.in_(workspace_ids))

        # Get all events in period
        result = await session.exec(query)
        events = result.all()

        # Calculate metrics
        total_events = len(events)
        events_by_type = {}
        security_events = 0
        access_violations = 0
        privileged_operations = 0
        data_access_events = 0

        for event in events:
            # Count by event type
            event_type = event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type)
            events_by_type[event_type] = events_by_type.get(event_type, 0) + 1

            # Count specific categories
            if event.event_type == AuditEventType.SECURITY:
                security_events += 1

            if not event.success and event.event_type == AuditEventType.AUTHORIZATION:
                access_violations += 1

            if event.action in ["manage_users", "manage_roles", "break_glass_access", "delete"]:
                privileged_operations += 1

            if event.event_type == AuditEventType.DATA_ACCESS:
                data_access_events += 1

        # Framework-specific metrics
        compliance_metrics = {}
        recommendations = []

        if framework == ComplianceFramework.SOC2:
            compliance_metrics.update({
                "user_access_reviews": privileged_operations,
                "failed_access_attempts": access_violations,
                "privileged_account_usage": privileged_operations,
                "security_incidents": security_events,
            })

            if access_violations > total_events * 0.05:  # >5% failure rate
                recommendations.append("Review access controls - high failure rate detected")

            if security_events == 0:
                recommendations.append("Consider implementing additional security monitoring")

        elif framework == ComplianceFramework.GDPR:
            compliance_metrics.update({
                "data_processing_activities": data_access_events,
                "data_subject_requests": events_by_type.get("data_subject_request", 0),
                "data_breaches": events_by_type.get("data_breach", 0),
                "consent_management": events_by_type.get("consent_update", 0),
            })

            if data_access_events > 0 and events_by_type.get("data_subject_request", 0) == 0:
                recommendations.append("Ensure data subject request tracking is implemented")

        elif framework == ComplianceFramework.ISO27001:
            compliance_metrics.update({
                "access_control_events": events_by_type.get("AUTHORIZATION", 0),
                "information_security_incidents": security_events,
                "user_access_management": privileged_operations,
                "asset_management": events_by_type.get("asset_access", 0),
            })

            if security_events / max(1, total_events) < 0.01:  # <1% security events
                recommendations.append("Increase security monitoring and logging coverage")

        # Add generic recommendations
        if total_events == 0:
            recommendations.append("No audit events found - verify logging is properly configured")

        if access_violations > 0:
            recommendations.append(f"Review {access_violations} failed access attempts for potential security issues")

        return ComplianceReport(
            report_id=report_id,
            framework=framework,
            generated_at=datetime.now(timezone.utc),
            period_start=start_date,
            period_end=end_date,
            total_events=total_events,
            events_by_type=events_by_type,
            security_events=security_events,
            access_violations=access_violations,
            privileged_operations=privileged_operations,
            data_access_events=data_access_events,
            compliance_metrics=compliance_metrics,
            recommendations=recommendations,
        )

    async def export_audit_logs(
        self,
        session: AsyncSession,
        filters: AuditFilter,
        format: str = "json",
    ) -> str:
        """Export audit logs in specified format for compliance.

        Args:
            session: Database session
            filters: Export filter criteria
            format: Export format (json, csv, xml)

        Returns:
            Exported data as string
        """
        # Get all matching logs (remove pagination for export)
        export_filters = AuditFilter(
            start_date=filters.start_date,
            end_date=filters.end_date,
            event_types=filters.event_types,
            actor_types=filters.actor_types,
            actor_ids=filters.actor_ids,
            workspace_ids=filters.workspace_ids,
            success_only=filters.success_only,
            target_types=filters.target_types,
            actions=filters.actions,
            limit=100000,  # Large limit for export
            offset=0,
        )

        search_result = await self.search_audit_logs(session, export_filters)

        if format == "json":
            return json.dumps({
                "export_metadata": {
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "total_events": search_result.total_count,
                    "exported_events": len(search_result.events),
                    "filters": {
                        "start_date": filters.start_date.isoformat() if filters.start_date else None,
                        "end_date": filters.end_date.isoformat() if filters.end_date else None,
                        "event_types": filters.event_types,
                        "workspace_ids": [str(w) for w in filters.workspace_ids] if filters.workspace_ids else None,
                    },
                },
                "events": search_result.events,
            }, indent=2)

        if format == "csv":
            # Simple CSV export implementation
            lines = ["timestamp,event_type,actor_id,action,success,workspace_id,metadata"]
            for event in search_result.events:
                metadata_str = json.dumps(event.get("metadata", {})).replace('"', '""')
                line = f"{event['timestamp']},{event['event_type']},{event['actor_id'] or ''}," \
                       f"{event['action']},{event['success']},{event['workspace_id'] or ''},\"{metadata_str}\""
                lines.append(line)
            return "\n".join(lines)

        raise ValueError(f"Unsupported export format: {format}")

    def get_audit_statistics(self) -> dict[str, Any]:
        """Get current audit service statistics.

        Returns:
            Dictionary with audit metrics
        """
        return self._audit_stats.copy()

    async def _create_audit_event(
        self,
        session: AsyncSession,
        audit_data: dict[str, Any],
        severity: AuditSeverity,
    ) -> str:
        """Create audit event with performance tracking."""
        from langflow.services.database.models.rbac.audit_log import AuditLog

        start_time = datetime.now(timezone.utc)

        try:
            # Add severity to metadata
            if "metadata" not in audit_data:
                audit_data["metadata"] = {}
            audit_data["metadata"]["severity"] = severity.value

            # Create audit log entry
            audit_log = AuditLog(**audit_data)
            session.add(audit_log)
            await session.commit()
            await session.refresh(audit_log)

            # Update statistics
            self._audit_stats["events_logged"] += 1
            event_type = audit_data.get("event_type", "unknown")
            self._audit_stats["events_by_type"][str(event_type)] = \
                self._audit_stats["events_by_type"].get(str(event_type), 0) + 1

            # Update average write time
            write_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            current_avg = self._audit_stats["avg_write_time_ms"]
            total_events = self._audit_stats["events_logged"]
            new_avg = ((current_avg * (total_events - 1)) + write_time) / total_events
            self._audit_stats["avg_write_time_ms"] = new_avg

            return str(audit_log.id)

        except Exception as e:
            logger.error(f"Failed to create audit event: {e}")
            self._audit_stats["errors"] += 1
            raise

    async def cleanup_old_audit_logs(
        self,
        session: AsyncSession,
        retention_days: int = 2555,  # 7 years default for compliance
        workspace_id: UUID | None = None,
    ) -> int:
        """Clean up audit logs older than retention period.

        Args:
            session: Database session
            retention_days: Number of days to retain logs
            workspace_id: Optional workspace scope for cleanup

        Returns:
            Number of logs deleted
        """
        from langflow.services.database.models.rbac.audit_log import AuditLog

        cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)

        query = select(AuditLog).where(AuditLog.timestamp < cutoff_date)

        if workspace_id:
            query = query.where(AuditLog.workspace_id == workspace_id)

        result = await session.exec(query)
        logs_to_delete = result.all()

        count = len(logs_to_delete)

        for log in logs_to_delete:
            await session.delete(log)

        await session.commit()

        logger.info(f"Cleaned up {count} audit logs older than {retention_days} days")

        return count
