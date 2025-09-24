"""Conditional permissions system with time and IP-based restrictions.

This module implements dynamic permission evaluation based on contextual
factors like time of day, IP address, location, device, and other conditions.
"""

import ipaddress
from datetime import datetime, time, timezone
from enum import Enum
from typing import Any

from loguru import logger
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.schema.serialize import UUIDstr
from langflow.services.base import Service


class ConditionType(str, Enum):
    """Types of conditional restrictions."""

    TIME_WINDOW = "time_window"  # Time-based restrictions
    IP_ADDRESS = "ip_address"  # IP address restrictions
    GEOLOCATION = "geolocation"  # Geographic restrictions
    DEVICE_TYPE = "device_type"  # Device type restrictions
    USER_AGENT = "user_agent"  # Browser/client restrictions
    MFA_REQUIRED = "mfa_required"  # Multi-factor auth required
    VPN_REQUIRED = "vpn_required"  # VPN connection required
    CONCURRENT_SESSIONS = "concurrent_sessions"  # Session limit
    REQUEST_RATE = "request_rate"  # Rate limiting
    ENVIRONMENT_TYPE = "environment_type"  # Environment restrictions


class ConditionOperator(str, Enum):
    """Operators for condition evaluation."""

    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    IN = "in"
    NOT_IN = "not_in"
    GREATER_THAN = "gt"
    LESS_THAN = "lt"
    GREATER_EQUAL = "gte"
    LESS_EQUAL = "lte"
    BETWEEN = "between"
    MATCHES = "matches"  # Regex match
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"


class ConditionalPermission:
    """Represents a permission with conditional restrictions."""

    def __init__(
        self,
        permission: str,
        conditions: list[dict[str, Any]],
        *,
        enabled: bool = True,
        priority: int = 0,
        description: str | None = None,
        failure_action: str = "deny",  # deny, require_approval, log_only
        bypass_roles: list[str] | None = None,
    ):
        self.permission = permission
        self.conditions = conditions
        self.enabled = enabled
        self.priority = priority
        self.description = description
        self.failure_action = failure_action
        self.bypass_roles = bypass_roles or []


class PermissionContext:
    """Context information for permission evaluation."""

    def __init__(
        self,
        user_id: UUIDstr,
        ip_address: str | None = None,
        user_agent: str | None = None,
        session_id: str | None = None,
        device_fingerprint: str | None = None,
        geolocation: dict[str, Any] | None = None,
        timestamp: datetime | None = None,
        environment_type: str | None = None,
        workspace_id: UUIDstr | None = None,
        mfa_verified: bool = False,
        vpn_detected: bool = False,
        request_metadata: dict[str, Any] | None = None,
    ):
        self.user_id = user_id
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.session_id = session_id
        self.device_fingerprint = device_fingerprint
        self.geolocation = geolocation or {}
        self.timestamp = timestamp or datetime.now(timezone.utc)
        self.environment_type = environment_type
        self.workspace_id = workspace_id
        self.mfa_verified = mfa_verified
        self.vpn_detected = vpn_detected
        self.request_metadata = request_metadata or {}


class ConditionalPermissionService(Service):
    """Service for evaluating conditional permissions."""

    name = "conditional_permission_service"

    def __init__(self):
        super().__init__()
        self._permission_cache = {}
        self._cache_ttl = 300  # 5 minutes
        # Import policy manager for configurable policies
        from langflow.services.rbac.conditional_policy_manager import ConditionalPolicyManager

        self._policy_manager = ConditionalPolicyManager()

    async def _initialize_default_policies(self, session: AsyncSession) -> None:
        """Initialize default conditional permission policies in database if they don't exist."""
        try:
            # Check if default policies already exist
            existing_policies = await self._policy_manager.get_all_policies(session=session)
            if existing_policies:
                return  # Default policies already exist

            logger.info("Initializing default conditional permission policies")

            # Create default policies in database
            default_policies = [
                {
                    "name": "Production Deployment Time Restriction",
                    "permission": "flows.deploy",
                    "description": "Production deployments only during business hours",
                    "conditions": [
                        {
                            "type": ConditionType.TIME_WINDOW,
                            "operator": ConditionOperator.BETWEEN,
                            "value": {"start": "09:00", "end": "17:00"},
                            "timezone": "UTC",
                        },
                        {
                            "type": ConditionType.ENVIRONMENT_TYPE,
                            "operator": ConditionOperator.EQUALS,
                            "value": "production",
                        },
                    ],
                    "priority": 100,
                    "failure_action": "require_approval",
                    "enabled": True,
                },
                {
                    "name": "Admin Access Security Requirements",
                    "permission": "workspace.admin",
                    "description": "Admin access requires internal network and MFA",
                    "conditions": [
                        {
                            "type": ConditionType.IP_ADDRESS,
                            "operator": ConditionOperator.IN,
                            "value": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
                        },
                        {"type": ConditionType.MFA_REQUIRED, "operator": ConditionOperator.EQUALS, "value": True},
                    ],
                    "priority": 200,
                    "failure_action": "deny",
                    "enabled": True,
                },
                {
                    "name": "Data Export Compliance Policy",
                    "permission": "data.export",
                    "description": "Data export restrictions for compliance",
                    "conditions": [
                        {
                            "type": ConditionType.TIME_WINDOW,
                            "operator": ConditionOperator.BETWEEN,
                            "value": {"start": "08:00", "end": "18:00"},
                            "timezone": "UTC",
                        },
                        {
                            "type": ConditionType.GEOLOCATION,
                            "operator": ConditionOperator.IN,
                            "value": ["US", "CA", "EU"],
                        },
                        {
                            "type": ConditionType.REQUEST_RATE,
                            "operator": ConditionOperator.LESS_EQUAL,
                            "value": 5,
                            "window": 3600,
                        },
                    ],
                    "priority": 150,
                    "failure_action": "require_approval",
                    "bypass_roles": ["compliance_officer", "data_steward"],
                    "enabled": True,
                },
            ]

            # Create each default policy
            for policy_data in default_policies:
                await self._policy_manager.create_policy(session=session, **policy_data)

            logger.info(f"Created {len(default_policies)} default conditional permission policies")

        except Exception as e:
            logger.error(f"Failed to initialize default policies: {e}")
            # Don't raise - service should still work without default policies

    async def evaluate_conditional_permission(
        self, session: AsyncSession, permission: str, context: PermissionContext
    ) -> dict[str, Any]:
        """Evaluate conditional permission with given context.

        Args:
            session: Database session
            permission: Permission to evaluate
            context: Context information for evaluation

        Returns:
            Evaluation result with decision and details
        """
        try:
            # Check cache first
            cache_key = f"{context.user_id}:{permission}:{hash(str(context.__dict__))}"
            if cache_key in self._permission_cache:
                cached_result, timestamp = self._permission_cache[cache_key]
                if (datetime.now(timezone.utc) - timestamp).seconds < self._cache_ttl:
                    return cached_result

            # Initialize default policies if needed (only on first use)
            await self._initialize_default_policies(session)

            # Get conditional permissions for this permission
            conditional_perms = await self._get_conditional_permissions(session, permission, context.workspace_id)

            # If no conditional permissions defined, allow
            if not conditional_perms:
                result = {"allowed": True, "reason": "No conditional restrictions"}
                self._cache_result(cache_key, result)
                return result

            # Check if user has bypass roles
            if await self._has_bypass_role(session, context.user_id, conditional_perms):
                result = {"allowed": True, "reason": "User has bypass role"}
                self._cache_result(cache_key, result)
                return result

            # Evaluate conditions
            evaluation_results: list[dict[str, Any]] = []
            for cond_perm in conditional_perms:
                if not cond_perm.enabled:
                    continue

                result = await self._evaluate_conditions(session, cond_perm, context)
                evaluation_results.append({"permission": cond_perm, "result": result, "priority": cond_perm.priority})

            # Process results based on priority
            evaluation_results.sort(key=lambda x: int(x["priority"]), reverse=True)

            for eval_result in evaluation_results:
                perm: ConditionalPermission = eval_result["permission"]  # type: ignore
                result_data: dict[str, Any] = eval_result["result"]  # type: ignore
                conditions_met = result_data["all_conditions_met"]

                if not conditions_met:
                    # Handle failure action
                    if perm.failure_action == "deny":
                        result = {
                            "allowed": False,
                            "reason": f"Conditional restriction failed: {perm.description}",
                            "failed_conditions": result_data["failed_conditions"],
                            "failure_action": perm.failure_action,
                        }
                        await self._log_conditional_denial(session, context, permission, result)
                        self._cache_result(cache_key, result)
                        return result

                    if perm.failure_action == "require_approval":
                        result = {
                            "allowed": False,
                            "require_approval": True,
                            "reason": f"Approval required: {perm.description}",
                            "failed_conditions": result_data["failed_conditions"],
                            "failure_action": perm.failure_action,
                        }
                        await self._log_conditional_approval_required(session, context, permission, result)
                        self._cache_result(cache_key, result)
                        return result

                    if perm.failure_action == "log_only":
                        # Log but continue evaluation
                        await self._log_conditional_violation(session, context, permission, result_data)

            # All conditions passed or log-only failures
            result = {"allowed": True, "reason": "All conditional restrictions satisfied"}
            self._cache_result(cache_key, result)
            return result

        except Exception as e:
            logger.error(f"Conditional permission evaluation failed: {e}")
            return {"allowed": False, "reason": f"Evaluation error: {e}"}

    async def add_conditional_permission(
        self,
        session: AsyncSession,
        workspace_id: UUIDstr,
        permission: str,
        conditions: list[dict[str, Any]],
        *,
        priority: int = 0,
        description: str | None = None,
        failure_action: str = "deny",
        bypass_roles: list[str] | None = None,
        created_by: UUIDstr,
    ) -> dict[str, Any]:
        """Add a new conditional permission rule.

        Args:
            session: Database session
            workspace_id: Workspace ID
            permission: Permission name
            conditions: List of conditions
            priority: Rule priority (higher = evaluated first)
            description: Human-readable description
            failure_action: Action when conditions fail
            bypass_roles: Roles that can bypass this rule
            created_by: User creating the rule

        Returns:
            Creation result
        """
        try:
            # Use policy manager to create the policy
            policy = await self._policy_manager.create_policy(
                session=session,
                name=description or f"Policy for {permission}",
                permission=permission,
                conditions=conditions,
                workspace_id=workspace_id,
                priority=priority,
                failure_action=failure_action,
                bypass_roles=bypass_roles or [],
                created_by_id=created_by,
            )

            # Log creation
            await self._log_conditional_permission_change(
                session,
                "conditional_permission_created",
                workspace_id,
                created_by,
                {
                    "policy_id": policy.id,
                    "permission": permission,
                    "conditions_count": len(conditions),
                    "priority": priority,
                    "failure_action": failure_action,
                },
            )

            return {"success": True, "policy_id": policy.id, "message": "Conditional permission policy created"}

        except Exception as e:
            logger.error(f"Failed to add conditional permission: {e}")
            return {"success": False, "error": str(e)}

    async def evaluate_time_condition(self, condition: dict[str, Any], context: PermissionContext) -> dict[str, Any]:
        """Evaluate time-based conditions."""
        try:
            operator = ConditionOperator(condition["operator"])
            value = condition["value"]
            tz_name = condition.get("timezone", "UTC")

            # Convert context timestamp to specified timezone
            if tz_name != "UTC":
                import zoneinfo

                tz = zoneinfo.ZoneInfo(tz_name)
                local_time = context.timestamp.astimezone(tz)
            else:
                local_time = context.timestamp

            current_time = local_time.time()

            if operator == ConditionOperator.BETWEEN:
                start_time = time.fromisoformat(value["start"])
                end_time = time.fromisoformat(value["end"])

                if start_time <= end_time:
                    # Same day range
                    met = start_time <= current_time <= end_time
                else:
                    # Overnight range
                    met = current_time >= start_time or current_time <= end_time

                window_status = "within" if met else "outside"
                return {
                    "met": met,
                    "details": f"Current time {current_time} {window_status} allowed window {start_time}-{end_time}",
                }

            if operator == ConditionOperator.GREATER_THAN:
                threshold_time = time.fromisoformat(value)
                met = current_time > threshold_time
                return {
                    "met": met,
                    "details": f"Current time {current_time} {'after' if met else 'before'} threshold {threshold_time}",
                }

            if operator == ConditionOperator.LESS_THAN:
                threshold_time = time.fromisoformat(value)
                met = current_time < threshold_time
                return {
                    "met": met,
                    "details": f"Current time {current_time} {'before' if met else 'after'} threshold {threshold_time}",
                }

            return {"met": False, "details": f"Unsupported time operator: {operator}"}

        except Exception as e:
            return {"met": False, "details": f"Time condition evaluation error: {e}"}

    async def evaluate_ip_condition(self, condition: dict[str, Any], context: PermissionContext) -> dict[str, Any]:
        """Evaluate IP address-based conditions."""
        try:
            if not context.ip_address:
                return {"met": False, "details": "No IP address provided"}

            operator = ConditionOperator(condition["operator"])
            allowed_ranges = condition["value"]

            if not isinstance(allowed_ranges, list):
                allowed_ranges = [allowed_ranges]

            client_ip = ipaddress.ip_address(context.ip_address)
            ip_allowed = False

            for ip_range in allowed_ranges:
                try:
                    if "/" in str(ip_range):
                        # CIDR notation
                        network = ipaddress.ip_network(ip_range, strict=False)
                        if client_ip in network:
                            ip_allowed = True
                            break
                    # Single IP
                    elif client_ip == ipaddress.ip_address(ip_range):
                        ip_allowed = True
                        break
                except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
                    continue

            if operator == ConditionOperator.IN:
                met = ip_allowed
            elif operator == ConditionOperator.NOT_IN:
                met = not ip_allowed
            else:
                return {"met": False, "details": f"Unsupported IP operator: {operator}"}

            return {"met": met, "details": f"IP {context.ip_address} {'allowed' if met else 'denied'} by rule"}

        except Exception as e:
            return {"met": False, "details": f"IP condition evaluation error: {e}"}

    async def evaluate_geolocation_condition(
        self, condition: dict[str, Any], context: PermissionContext
    ) -> dict[str, Any]:
        """Evaluate geolocation-based conditions."""
        try:
            if not context.geolocation:
                return {"met": False, "details": "No geolocation data provided"}

            operator = ConditionOperator(condition["operator"])
            allowed_locations = condition["value"]

            if not isinstance(allowed_locations, list):
                allowed_locations = [allowed_locations]

            user_country = context.geolocation.get("country")
            user_region = context.geolocation.get("region")

            location_allowed = False

            for location in allowed_locations:
                if user_country and user_country.upper() == location.upper():
                    location_allowed = True
                    break
                if user_region and user_region.upper() == location.upper():
                    location_allowed = True
                    break

            if operator == ConditionOperator.IN:
                met = location_allowed
            elif operator == ConditionOperator.NOT_IN:
                met = not location_allowed
            else:
                return {"met": False, "details": f"Unsupported geolocation operator: {operator}"}

            return {
                "met": met,
                "details": f"Location {user_country}/{user_region} {'allowed' if met else 'denied'} by rule",
            }

        except Exception as e:
            return {"met": False, "details": f"Geolocation condition evaluation error: {e}"}

    async def evaluate_mfa_condition(self, condition: dict[str, Any], context: PermissionContext) -> dict[str, Any]:
        """Evaluate MFA requirement conditions."""
        try:
            operator = ConditionOperator(condition["operator"])
            required = condition["value"]

            if operator == ConditionOperator.EQUALS:
                met = context.mfa_verified if required else not context.mfa_verified
            else:
                return {"met": False, "details": f"Unsupported MFA operator: {operator}"}

            mfa_status = "verified" if context.mfa_verified else "not verified"
            req_status = "required" if required else "not required"
            return {"met": met, "details": f"MFA {mfa_status}, {req_status}"}

        except Exception as e:
            return {"met": False, "details": f"MFA condition evaluation error: {e}"}

    async def evaluate_rate_limit_condition(
        self, session: AsyncSession, condition: dict[str, Any], context: PermissionContext
    ) -> dict[str, Any]:
        """Evaluate request rate limiting conditions."""
        try:
            operator = ConditionOperator(condition["operator"])
            limit = condition["value"]
            window_seconds = condition.get("window", 3600)  # Default 1 hour

            # Get recent requests count for this user
            recent_count = await self._get_recent_request_count(session, context.user_id, window_seconds)

            if operator == ConditionOperator.LESS_EQUAL:
                met = recent_count <= limit
            elif operator == ConditionOperator.LESS_THAN:
                met = recent_count < limit
            else:
                return {"met": False, "details": f"Unsupported rate limit operator: {operator}"}

            return {"met": met, "details": f"Recent requests: {recent_count}/{limit} in {window_seconds}s window"}

        except Exception as e:
            return {"met": False, "details": f"Rate limit condition evaluation error: {e}"}

    async def _get_conditional_permissions(
        self, session: AsyncSession, permission: str, workspace_id: UUIDstr | None
    ) -> list[ConditionalPermission]:
        """Get conditional permissions for a specific permission."""
        # Get policies from database using policy manager
        policies = await self._policy_manager.get_policies_for_permission(
            session=session, permission=permission, workspace_id=workspace_id, enabled_only=True
        )

        # Convert database policies to ConditionalPermission objects
        conditional_perms = []
        for policy in policies:
            conditions = policy.conditions.get("conditions", [])
            conditional_perm = ConditionalPermission(
                permission=policy.permission,
                conditions=conditions,
                enabled=policy.enabled,
                priority=policy.priority,
                description=policy.description,
                failure_action=policy.failure_action,
                bypass_roles=policy.bypass_roles,
            )
            conditional_perms.append(conditional_perm)

        return conditional_perms

    async def _has_bypass_role(
        self, session: AsyncSession, user_id: UUIDstr, conditional_perms: list[ConditionalPermission]
    ) -> bool:
        """Check if user has any bypass roles."""
        all_bypass_roles = set()
        for perm in conditional_perms:
            all_bypass_roles.update(perm.bypass_roles)

        if not all_bypass_roles:
            return False

        # Check user's roles
        from langflow.services.database.models.rbac.role import Role
        from langflow.services.database.models.rbac.role_assignment import RoleAssignment

        query = (
            select(Role)
            .join(RoleAssignment)
            .where(RoleAssignment.user_id == user_id, RoleAssignment.is_active.is_(True), Role.is_active.is_(True))
        )

        result = await session.exec(query)
        user_roles = result.all()
        user_role_names = {role.name for role in user_roles}

        return bool(all_bypass_roles.intersection(user_role_names))

    async def _evaluate_conditions(
        self, session: AsyncSession, conditional_perm: ConditionalPermission, context: PermissionContext
    ) -> dict[str, Any]:
        """Evaluate all conditions for a conditional permission."""
        failed_conditions = []
        passed_conditions = []

        for condition in conditional_perm.conditions:
            condition_type = ConditionType(condition["type"])

            if condition_type == ConditionType.TIME_WINDOW:
                result = await self.evaluate_time_condition(condition, context)
            elif condition_type == ConditionType.IP_ADDRESS:
                result = await self.evaluate_ip_condition(condition, context)
            elif condition_type == ConditionType.GEOLOCATION:
                result = await self.evaluate_geolocation_condition(condition, context)
            elif condition_type == ConditionType.MFA_REQUIRED:
                result = await self.evaluate_mfa_condition(condition, context)
            elif condition_type == ConditionType.REQUEST_RATE:
                result = await self.evaluate_rate_limit_condition(session, condition, context)
            else:
                result = {"met": False, "details": f"Unsupported condition type: {condition_type}"}

            if result["met"]:
                passed_conditions.append({"type": condition_type.value, "details": result["details"]})
            else:
                failed_conditions.append({"type": condition_type.value, "details": result["details"]})

        return {
            "all_conditions_met": len(failed_conditions) == 0,
            "passed_conditions": passed_conditions,
            "failed_conditions": failed_conditions,
            "total_conditions": len(conditional_perm.conditions),
        }

    def _validate_conditions(self, conditions: list[dict[str, Any]]) -> dict[str, Any]:
        """Validate conditional permission conditions."""
        try:
            for condition in conditions:
                if "type" not in condition:
                    return {"valid": False, "error": "Condition missing 'type' field"}

                if "operator" not in condition:
                    return {"valid": False, "error": "Condition missing 'operator' field"}

                if "value" not in condition:
                    return {"valid": False, "error": "Condition missing 'value' field"}

                # Validate condition type
                try:
                    ConditionType(condition["type"])
                except ValueError:
                    return {"valid": False, "error": f"Invalid condition type: {condition['type']}"}

                # Validate operator
                try:
                    ConditionOperator(condition["operator"])
                except ValueError:
                    return {"valid": False, "error": f"Invalid operator: {condition['operator']}"}

            return {"valid": True}

        except Exception as e:
            return {"valid": False, "error": f"Validation error: {e}"}

    async def _get_recent_request_count(self, session: AsyncSession, user_id: UUIDstr, window_seconds: int) -> int:
        """Get count of recent requests for rate limiting."""
        # This would query audit logs for recent requests
        # For now, return a mock value
        return 3

    def _cache_result(self, cache_key: str, result: dict[str, Any]) -> None:
        """Cache evaluation result."""
        self._permission_cache[cache_key] = (result, datetime.now(timezone.utc))

    async def _log_conditional_denial(
        self, session: AsyncSession, context: PermissionContext, permission: str, result: dict[str, Any]
    ) -> None:
        """Log conditional permission denial."""
        from langflow.services.database.models.rbac.audit_log import ActorType, AuditEventType, AuditLog, AuditOutcome

        audit_log = AuditLog(
            event_type=AuditEventType.ACCESS_DENIED,
            action="conditional_permission_denied",
            outcome=AuditOutcome.DENIED,
            actor_type=ActorType.USER,
            actor_id=context.user_id,
            workspace_id=context.workspace_id,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            session_id=context.session_id,
            event_metadata={
                "permission": permission,
                "failed_conditions": result["failed_conditions"],
                "reason": result["reason"],
            },
        )

        session.add(audit_log)
        await session.commit()

    async def _log_conditional_approval_required(
        self, session: AsyncSession, context: PermissionContext, permission: str, result: dict[str, Any]
    ) -> None:
        """Log when conditional permission requires approval."""
        from langflow.services.database.models.rbac.audit_log import ActorType, AuditEventType, AuditLog, AuditOutcome

        audit_log = AuditLog(
            event_type=AuditEventType.ACCESS_DENIED,
            action="conditional_permission_approval_required",
            outcome=AuditOutcome.PARTIAL,
            actor_type=ActorType.USER,
            actor_id=context.user_id,
            workspace_id=context.workspace_id,
            ip_address=context.ip_address,
            event_metadata={
                "permission": permission,
                "failed_conditions": result["failed_conditions"],
                "approval_required": True,
            },
        )

        session.add(audit_log)
        await session.commit()

    async def _log_conditional_violation(
        self, session: AsyncSession, context: PermissionContext, permission: str, evaluation_result: dict[str, Any]
    ) -> None:
        """Log conditional permission violations for monitoring."""
        from langflow.services.database.models.rbac.audit_log import ActorType, AuditEventType, AuditLog, AuditOutcome

        audit_log = AuditLog(
            event_type=AuditEventType.SECURITY_ALERT,
            action="conditional_permission_violation",
            outcome=AuditOutcome.SUCCESS,  # Allowed but logged
            actor_type=ActorType.USER,
            actor_id=context.user_id,
            workspace_id=context.workspace_id,
            ip_address=context.ip_address,
            event_metadata={
                "permission": permission,
                "failed_conditions": evaluation_result["failed_conditions"],
                "action": "log_only",
            },
        )

        session.add(audit_log)
        await session.commit()

    async def _log_conditional_permission_change(
        self, session: AsyncSession, event_type: str, workspace_id: UUIDstr, actor_id: UUIDstr, metadata: dict[str, Any]
    ) -> None:
        """Log changes to conditional permission rules."""
        from langflow.services.database.models.rbac.audit_log import ActorType, AuditEventType, AuditLog, AuditOutcome

        audit_log = AuditLog(
            event_type=AuditEventType.SYSTEM_CONFIG_CHANGE,
            action=event_type,
            outcome=AuditOutcome.SUCCESS,
            actor_type=ActorType.USER,
            actor_id=actor_id,
            workspace_id=workspace_id,
            resource_type="conditional_permission",
            event_metadata=metadata,
        )

        session.add(audit_log)
        await session.commit()
