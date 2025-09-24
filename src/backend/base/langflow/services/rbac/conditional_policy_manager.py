"""Conditional policy management service for configurable policies.

This service manages the creation, storage, and retrieval of conditional
permission policies from the database, replacing hardcoded configurations.
"""

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from loguru import logger
from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import desc
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.schema.serialize import UUIDstr
from langflow.services.base import Service
from langflow.services.database.models.rbac.conditional_policy import (
    ConditionalPolicy,
    ConditionalPolicyAudit,
    ConditionalPolicyEvaluation,
    ConditionalPolicyTemplate,
)


class ConditionalPolicyManager(Service):
    """Service for managing conditional permission policies."""

    name = "conditional_policy_manager"

    def __init__(self):
        super().__init__()
        self._cache = {}
        self._cache_ttl = 300  # 5 minutes

    async def create_policy(
        self,
        session: AsyncSession,
        *,
        name: str,
        permission: str,
        conditions: list[dict[str, Any]],
        description: str | None = None,
        workspace_id: UUIDstr | None = None,
        environment_type: str | None = None,
        enabled: bool = True,
        priority: int = 0,
        failure_action: str = "deny",
        bypass_roles: list[str] | None = None,
        effective_from: datetime | None = None,
        effective_until: datetime | None = None,
        created_by_id: UUIDstr | None = None,
    ) -> ConditionalPolicy:
        """Create a new conditional policy.

        Args:
            session: Database session
            name: Policy name
            permission: Permission string
            conditions: List of condition definitions
            description: Policy description
            workspace_id: Workspace scope
            environment_type: Environment type restriction
            enabled: Whether policy is enabled
            priority: Policy priority
            failure_action: Action when conditions fail
            bypass_roles: Roles that bypass this policy
            effective_from: Policy effective start time
            effective_until: Policy effective end time
            created_by_id: User who created the policy

        Returns:
            Created conditional policy
        """
        try:
            # Validate conditions format
            validated_conditions = await self._validate_conditions(conditions)

            # Create policy
            policy = ConditionalPolicy(
                name=name,
                description=description,
                permission=permission,
                workspace_id=workspace_id,
                environment_type=environment_type,
                conditions={"conditions": validated_conditions},
                enabled=enabled,
                priority=priority,
                failure_action=failure_action,
                bypass_roles=bypass_roles or [],
                effective_from=effective_from,
                effective_until=effective_until,
                created_by_id=created_by_id,
                updated_by_id=created_by_id,
            )

            session.add(policy)
            await session.commit()
            await session.refresh(policy)

            # Audit log
            await self._log_policy_change(
                session,
                policy_id=policy.id,
                action="created",
                new_values={
                    "name": name,
                    "permission": permission,
                    "enabled": enabled,
                    "priority": priority,
                },
                changed_by_id=created_by_id,
            )

            # Clear cache
            self._clear_cache()

            logger.info(f"Created conditional policy: {name} for permission: {permission}")
            return policy

        except Exception as e:
            logger.error(f"Failed to create conditional policy: {e}")
            await session.rollback()
            raise

    async def update_policy(
        self,
        session: AsyncSession,
        policy_id: str | UUID,
        updated_by_id: UUIDstr | None = None,
        **updates: Any,
    ) -> ConditionalPolicy | None:
        """Update an existing conditional policy.

        Args:
            session: Database session
            policy_id: Policy ID
            updated_by_id: User who updated the policy
            **updates: Fields to update

        Returns:
            Updated policy or None if not found
        """
        try:
            # Convert to UUIDstr if needed
            policy_id_str = policy_id if isinstance(policy_id, str) else str(policy_id)

            # Get existing policy
            result = await session.get(ConditionalPolicy, policy_id_str)
            if not result:
                return None

            policy = result
            old_values = {
                "name": policy.name,
                "enabled": policy.enabled,
                "priority": policy.priority,
                "conditions": policy.conditions,
            }

            # Validate conditions if provided
            if "conditions" in updates:
                updates["conditions"] = {"conditions": await self._validate_conditions(updates["conditions"])}

            # Update fields
            for field, value in updates.items():
                if hasattr(policy, field):
                    setattr(policy, field, value)

            policy.updated_at = datetime.now(timezone.utc)
            policy.updated_by_id = updated_by_id
            policy.version += 1

            await session.commit()
            await session.refresh(policy)

            # Audit log
            await self._log_policy_change(
                session=session,
                policy_id=UUIDstr(policy_id_str),
                action="updated",
                old_values=old_values,
                new_values=updates,
                changed_by_id=updated_by_id,
            )

            # Clear cache
            self._clear_cache()

            logger.info(f"Updated conditional policy: {policy.name}")
            return policy

        except Exception as e:
            logger.error(f"Failed to update conditional policy: {e}")
            await session.rollback()
            raise

    async def delete_policy(
        self,
        session: AsyncSession,
        policy_id: str | UUID,
        deleted_by_id: UUIDstr | None = None,
    ) -> bool:
        """Delete a conditional policy.

        Args:
            session: Database session
            policy_id: Policy ID
            deleted_by_id: User who deleted the policy

        Returns:
            True if deleted successfully
        """
        try:
            # Convert to UUIDstr if needed
            policy_id_str = policy_id if isinstance(policy_id, str) else str(policy_id)

            # Get policy
            result = await session.get(ConditionalPolicy, policy_id_str)
            if not result:
                return False

            policy = result

            # Audit log before deletion
            await self._log_policy_change(
                session=session,
                policy_id=UUIDstr(policy_id_str),
                action="deleted",
                old_values={
                    "name": policy.name,
                    "permission": policy.permission,
                    "enabled": policy.enabled,
                },
                changed_by_id=deleted_by_id,
            )

            # Delete policy
            await session.delete(policy)
            await session.commit()

            # Clear cache
            self._clear_cache()

            logger.info(f"Deleted conditional policy: {policy.name}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete conditional policy: {e}")
            await session.rollback()
            raise

    async def get_policy(
        self,
        session: AsyncSession,
        policy_id: UUIDstr,
    ) -> ConditionalPolicy | None:
        """Get a conditional policy by ID.

        Args:
            session: Database session
            policy_id: Policy ID

        Returns:
            Conditional policy or None if not found
        """
        return await session.get(ConditionalPolicy, policy_id)

    async def list_policies(
        self,
        session: AsyncSession,
        *,
        permission: str | None = None,
        workspace_id: UUIDstr | None = None,
        environment_type: str | None = None,
        enabled_only: bool = True,
        include_expired: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ConditionalPolicy]:
        """List conditional policies with optional filtering.

        Args:
            session: Database session
            permission: Filter by permission
            workspace_id: Filter by workspace
            environment_type: Filter by environment type
            enabled_only: Only return enabled policies
            include_expired: Include expired policies
            limit: Maximum number of results
            offset: Result offset

        Returns:
            List of conditional policies
        """
        try:
            query = select(ConditionalPolicy)

            # Apply filters
            if permission:
                query = query.where(ConditionalPolicy.permission == permission)

            if workspace_id:
                query = query.where(
                    (ConditionalPolicy.workspace_id == workspace_id) | (ConditionalPolicy.workspace_id is None)
                )

            if environment_type:
                query = query.where(
                    (ConditionalPolicy.environment_type == environment_type)
                    | (ConditionalPolicy.environment_type is None)
                )

            if enabled_only:
                query = query.where(ConditionalPolicy.enabled)

            if not include_expired:
                now = datetime.now(timezone.utc)
                query = query.where(
                    (ConditionalPolicy.effective_until is None) | (ConditionalPolicy.effective_until > now)
                )

            # Apply ordering and pagination
            query = query.order_by(desc(ConditionalPolicy.priority), ConditionalPolicy.created_at)
            query = query.offset(offset).limit(limit)

            result = await session.exec(query)
            return list(result.all())

        except (SQLAlchemyError, ValidationError) as e:
            logger.error(f"Failed to list conditional policies: {e}")
            return []

    async def get_policies_for_permission(
        self,
        session: AsyncSession,
        permission: str,
        workspace_id: UUIDstr | None = None,
        environment_type: str | None = None,
        *,
        enabled_only: bool = True,
    ) -> list[ConditionalPolicy]:
        """Get all applicable policies for a specific permission.

        Args:
            session: Database session
            permission: Permission string
            workspace_id: Workspace context
            environment_type: Environment context
            enabled_only: Only return enabled policies

        Returns:
            List of applicable policies ordered by priority
        """
        # Check cache first
        cache_key = f"policies:{permission}:{workspace_id}:{environment_type}:{enabled_only}"
        if cache_key in self._cache:
            cache_entry = self._cache[cache_key]
            if (datetime.now(timezone.utc) - cache_entry["timestamp"]).seconds < self._cache_ttl:
                return cache_entry["policies"]

        try:
            policies = await self.list_policies(
                session,
                permission=permission,
                workspace_id=workspace_id,
                environment_type=environment_type,
                enabled_only=enabled_only,
                include_expired=False,
            )

            # Filter by effective dates
            now = datetime.now(timezone.utc)
            effective_policies = []

            for policy in policies:
                # Check effective from
                if policy.effective_from and now < policy.effective_from:
                    continue

                # Check effective until
                if policy.effective_until and now >= policy.effective_until:
                    continue

                effective_policies.append(policy)

            # Sort by priority (higher priority first)
            effective_policies.sort(key=lambda p: p.priority, reverse=True)

            # Cache result
            self._cache[cache_key] = {
                "policies": effective_policies,
                "timestamp": datetime.now(timezone.utc),
            }

            return effective_policies

        except Exception as e:
            logger.error(f"Failed to get policies for permission {permission}: {e}")
            return []

    async def create_template(
        self,
        session: AsyncSession,
        *,
        name: str,
        category: str,
        conditions_template: list[dict[str, Any]],
        description: str | None = None,
        default_priority: int = 0,
        default_failure_action: str = "deny",
        suggested_bypass_roles: list[str] | None = None,
        created_by_id: UUIDstr | None = None,
    ) -> ConditionalPolicyTemplate:
        """Create a policy template.

        Args:
            session: Database session
            name: Template name
            category: Template category
            conditions_template: Template conditions
            description: Template description
            default_priority: Default priority
            default_failure_action: Default failure action
            suggested_bypass_roles: Suggested bypass roles
            created_by_id: User who created the template

        Returns:
            Created template
        """
        try:
            # Validate conditions template
            validated_conditions = await self._validate_conditions(conditions_template)

            template = ConditionalPolicyTemplate(
                name=name,
                description=description,
                category=category,
                conditions_template={"conditions": validated_conditions},
                default_priority=default_priority,
                default_failure_action=default_failure_action,
                suggested_bypass_roles=suggested_bypass_roles or [],
                created_by_id=created_by_id,
            )

            session.add(template)
            await session.commit()
            await session.refresh(template)

            logger.info(f"Created policy template: {name}")
            return template

        except Exception as e:
            logger.error(f"Failed to create policy template: {e}")
            await session.rollback()
            raise

    async def list_templates(
        self,
        session: AsyncSession,
        *,
        category: str | None = None,
        active_only: bool = True,
    ) -> list[ConditionalPolicyTemplate]:
        """List policy templates.

        Args:
            session: Database session
            category: Filter by category
            active_only: Only return active templates

        Returns:
            List of templates
        """
        try:
            query = select(ConditionalPolicyTemplate)

            if category:
                query = query.where(ConditionalPolicyTemplate.category == category)

            if active_only:
                query = query.where(ConditionalPolicyTemplate.is_active)

            query = query.order_by(ConditionalPolicyTemplate.name)

            result = await session.exec(query)
            return list(result.all())

        except Exception as e:
            logger.error(f"Failed to list policy templates: {e}")
            return []

    async def create_policy_from_template(
        self,
        session: AsyncSession,
        template_id: UUIDstr,
        *,
        name: str,
        permission: str,
        workspace_id: UUIDstr | None = None,
        environment_type: str | None = None,
        created_by_id: UUIDstr | None = None,
        condition_overrides: dict[str, Any] | None = None,
    ) -> ConditionalPolicy:
        """Create a policy from a template.

        Args:
            session: Database session
            template_id: Template ID
            name: Policy name
            permission: Permission string
            workspace_id: Workspace scope
            environment_type: Environment type
            created_by_id: User creating the policy
            condition_overrides: Condition value overrides

        Returns:
            Created policy

        Raises:
            ValueError: If template not found
        """
        try:
            # Get template
            template = await session.get(ConditionalPolicyTemplate, template_id)
            if not template:
                msg = f"Template {template_id} not found"
                raise ValueError(msg)

            # Apply condition overrides
            conditions = template.conditions_template.get("conditions", []).copy()
            if condition_overrides:
                for condition in conditions:
                    condition_type = condition.get("type")
                    if condition_type in condition_overrides:
                        condition["value"] = condition_overrides[condition_type]

            # Create policy
            policy = await self.create_policy(
                session,
                name=name,
                permission=permission,
                conditions=conditions,
                description=f"Created from template: {template.name}",
                workspace_id=workspace_id,
                environment_type=environment_type,
                priority=template.default_priority,
                failure_action=template.default_failure_action,
                bypass_roles=template.suggested_bypass_roles.copy(),
                created_by_id=created_by_id,
            )

            # Update template usage count
            template.usage_count += 1
            await session.commit()

            return policy

        except Exception as e:
            logger.error(f"Failed to create policy from template: {e}")
            raise

    async def log_evaluation(
        self,
        session: AsyncSession,
        *,
        policy_id: UUIDstr,
        user_id: UUIDstr,
        permission: str,
        result: str,
        execution_time_ms: float,
        evaluation_context: dict[str, Any] | None = None,
        decision_reason: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        session_id: str | None = None,
        environment_type: str | None = None,
        workspace_id: UUIDstr | None = None,
    ) -> None:
        """Log a policy evaluation for analytics.

        Args:
            session: Database session
            policy_id: Policy ID
            user_id: User ID
            permission: Permission evaluated
            result: Evaluation result
            execution_time_ms: Execution time
            evaluation_context: Context used for evaluation
            decision_reason: Reason for the decision
            ip_address: Client IP address
            user_agent: User agent
            session_id: Session ID
            environment_type: Environment type
            workspace_id: Workspace ID
        """
        try:
            evaluation = ConditionalPolicyEvaluation(
                policy_id=policy_id,
                user_id=user_id,
                permission=permission,
                evaluation_context=evaluation_context or {},
                result=result,
                decision_reason=decision_reason,
                execution_time_ms=execution_time_ms,
                ip_address=ip_address,
                user_agent=user_agent,
                session_id=session_id,
                environment_type=environment_type,
                workspace_id=workspace_id,
            )

            session.add(evaluation)

            # Update policy evaluation count and timestamp
            policy = await session.get(ConditionalPolicy, policy_id)
            if policy:
                policy.evaluation_count += 1
                policy.last_evaluated_at = datetime.now(timezone.utc)

            await session.commit()

        except Exception as e:
            logger.error(f"Failed to log policy evaluation: {e}")

    async def _validate_conditions(self, conditions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Validate condition definitions.

        Args:
            conditions: List of condition definitions

        Returns:
            Validated conditions

        Raises:
            ValueError: If conditions are invalid
        """
        if not conditions:
            msg = "At least one condition is required"
            raise ValueError(msg)

        valid_types = {
            "time_window",
            "ip_address",
            "geolocation",
            "device_type",
            "user_agent",
            "mfa_required",
            "vpn_required",
            "concurrent_sessions",
            "request_rate",
            "environment_type",
        }

        valid_operators = {
            "equals",
            "not_equals",
            "in",
            "not_in",
            "gt",
            "lt",
            "gte",
            "lte",
            "between",
            "matches",
            "contains",
            "not_contains",
        }

        validated = []
        for condition in conditions:
            # Validate required fields
            if "type" not in condition or "operator" not in condition or "value" not in condition:
                msg = "Condition must have type, operator, and value"
                raise ValueError(msg)

            # Validate type
            if condition["type"] not in valid_types:
                msg = f"Invalid condition type: {condition['type']}"
                raise ValueError(msg)

            # Validate operator
            if condition["operator"] not in valid_operators:
                msg = f"Invalid operator: {condition['operator']}"
                raise ValueError(msg)

            # Type-specific validation
            await self._validate_condition_value(condition)

            validated.append(condition)

        return validated

    async def _validate_condition_value(self, condition: dict[str, Any]) -> None:
        """Validate condition value based on type.

        Args:
            condition: Condition definition

        Raises:
            ValueError: If condition value is invalid
        """
        condition_type = condition["type"]
        operator = condition["operator"]
        value = condition["value"]

        if condition_type == "time_window":
            if operator == "between" and isinstance(value, dict):
                if "start" not in value or "end" not in value:
                    msg = "Time window between requires start and end"
                    raise ValueError(msg)
            elif not isinstance(value, str | int):
                msg = "Time window value must be string or number"
                raise ValueError(msg)

        elif condition_type == "ip_address":
            if operator in ["in", "not_in"] and not isinstance(value, list):
                msg = "IP address in/not_in requires list of IPs/CIDRs"
                raise ValueError(msg)

        elif condition_type == "request_rate":
            if not isinstance(value, int) or value <= 0:
                msg = "Request rate value must be positive integer"
                raise ValueError(msg)
            if "window" not in condition:
                msg = "Request rate condition requires window parameter"
                raise ValueError(msg)

    async def _log_policy_change(
        self,
        session: AsyncSession,
        *,
        policy_id: UUIDstr,
        action: str,
        old_values: dict[str, Any] | None = None,
        new_values: dict[str, Any] | None = None,
        changed_by_id: UUIDstr | None = None,
        change_reason: str | None = None,
    ) -> None:
        """Log policy changes for auditing.

        Args:
            session: Database session
            policy_id: Policy ID
            action: Action performed
            old_values: Previous values
            new_values: New values
            changed_by_id: User who made the change
            change_reason: Reason for the change
        """
        try:
            audit_entry = ConditionalPolicyAudit(
                policy_id=policy_id,
                action=action,
                old_values=old_values,
                new_values=new_values,
                changed_by_id=changed_by_id,
                change_reason=change_reason,
            )

            session.add(audit_entry)
            # Note: Commit is handled by the calling method

        except Exception as e:
            logger.error(f"Failed to log policy change: {e}")

    def _clear_cache(self) -> None:
        """Clear the policy cache."""
        self._cache.clear()
        logger.debug("Cleared conditional policy cache")

    async def get_policy_by_id(self, session: AsyncSession, policy_id: str | UUID) -> ConditionalPolicy | None:
        """Get a policy by its ID (alias for get_policy)."""
        return await self.get_policy(session, policy_id=UUIDstr(str(policy_id)))

    async def get_all_policies(
        self,
        session: AsyncSession,
        workspace_id: UUIDstr | None = None,
        *,
        enabled_only: bool = False,
    ) -> list[ConditionalPolicy]:
        """Get all policies (alias for list_policies)."""
        return await self.list_policies(session=session, workspace_id=workspace_id, enabled_only=enabled_only)

    async def toggle_policy_status(
        self,
        session: AsyncSession,
        policy_id: str | UUID,
        updated_by_id: UUIDstr | None = None,
    ) -> ConditionalPolicy | None:
        """Toggle a policy's enabled status."""
        try:
            # Convert to UUIDstr if needed
            policy_id_str = policy_id if isinstance(policy_id, str) else str(policy_id)

            # Get current policy
            policy = await self.get_policy(session, policy_id=UUIDstr(policy_id_str))
            if not policy:
                return None

            # Toggle enabled status
            old_enabled = policy.enabled
            policy.enabled = not policy.enabled
            policy.updated_at = datetime.now(timezone.utc)
            policy.updated_by_id = updated_by_id

            await session.commit()
            await session.refresh(policy)

            # Log the change
            await self._log_policy_change(
                session=session,
                policy_id=policy.id,
                action="toggled",
                old_values={"enabled": old_enabled},
                new_values={"enabled": policy.enabled},
                changed_by_id=updated_by_id,
            )

            self._clear_cache()
            return policy

        except Exception as e:
            logger.error(f"Failed to toggle policy status: {e}")
            await session.rollback()
            return None

    async def enable_policy(
        self,
        session: AsyncSession,
        policy_id: str | UUID,
        updated_by_id: UUIDstr | None = None,
    ) -> bool:
        """Enable a policy."""
        try:
            policy = await self.update_policy(
                session=session,
                policy_id=policy_id,
                enabled=True,
                updated_by_id=updated_by_id,
            )
            return policy is not None
        except Exception as e:
            logger.error(f"Failed to enable policy: {e}")
            return False

    async def disable_policy(
        self,
        session: AsyncSession,
        policy_id: str | UUID,
        updated_by_id: UUIDstr | None = None,
    ) -> bool:
        """Disable a policy."""
        try:
            policy = await self.update_policy(
                session=session,
                policy_id=policy_id,
                enabled=False,
                updated_by_id=updated_by_id,
            )
            return policy is not None
        except Exception as e:
            logger.error(f"Failed to disable policy: {e}")
            return False

    async def get_policy_analytics(
        self,
        session: AsyncSession,
        policy_id: str | UUID,
    ) -> Any | None:
        """Get analytics data for a policy."""
        try:
            # Import here to avoid circular imports
            from langflow.api.v1.schemas.conditional_policy_schemas import PolicyAnalytics

            # Convert to UUIDstr if needed
            policy_id_str = policy_id if isinstance(policy_id, str) else str(policy_id)

            # Get policy
            policy = await self.get_policy(session, policy_id=UUIDstr(policy_id_str))
            if not policy:
                return None

            # Get evaluation data
            evaluations_query = select(ConditionalPolicyEvaluation).where(
                ConditionalPolicyEvaluation.policy_id == policy_id_str
            )
            evaluations_result = await session.exec(evaluations_query)
            evaluations = evaluations_result.all()

            if not evaluations:
                # Return analytics with zero values
                return PolicyAnalytics(
                    policy_id=policy_id_str,
                    policy_name=policy.name,
                    evaluation_count=0,
                    allow_rate=0.0,
                    deny_rate=0.0,
                    approval_rate=0.0,
                    avg_execution_time_ms=0.0,
                    last_evaluation=None,
                    top_failing_conditions=[],
                )

            # Calculate metrics
            total_evaluations = len(evaluations)
            allowed_count = len([e for e in evaluations if e.result == "allowed"])
            denied_count = len([e for e in evaluations if e.result == "denied"])
            approval_count = len([e for e in evaluations if e.result == "require_approval"])

            allow_rate = allowed_count / total_evaluations if total_evaluations > 0 else 0.0
            deny_rate = denied_count / total_evaluations if total_evaluations > 0 else 0.0
            approval_rate = approval_count / total_evaluations if total_evaluations > 0 else 0.0

            avg_execution_time = (
                sum(e.execution_time_ms for e in evaluations) / total_evaluations if total_evaluations > 0 else 0.0
            )

            last_evaluation = max((e.evaluated_at for e in evaluations), default=None)

            # Get top failing conditions (simplified - would need more complex analysis)
            top_failing_conditions = ["condition_analysis_placeholder"]

            return PolicyAnalytics(
                policy_id=policy_id_str,
                policy_name=policy.name,
                evaluation_count=total_evaluations,
                allow_rate=allow_rate,
                deny_rate=deny_rate,
                approval_rate=approval_rate,
                avg_execution_time_ms=avg_execution_time,
                last_evaluation=last_evaluation,
                top_failing_conditions=top_failing_conditions,
            )

        except Exception as e:
            logger.error(f"Failed to get policy analytics: {e}")
            return None

    async def log_policy_evaluation(
        self,
        session: AsyncSession,
        policy_id: str | UUID,
        user_id: UUIDstr,
        permission: str,
        evaluation_context: dict[str, Any],
        conditions_evaluated: dict[str, Any],
        result: str,
        decision_reason: str | None = None,
        execution_time_ms: float = 0.0,
        ip_address: str | None = None,
        user_agent: str | None = None,
        session_id: str | None = None,
        environment_type: str | None = None,
        workspace_id: UUIDstr | None = None,
    ) -> None:
        """Log a policy evaluation for analytics and auditing."""
        try:
            # Convert to UUIDstr if needed
            policy_id_str = policy_id if isinstance(policy_id, str) else str(policy_id)

            evaluation = ConditionalPolicyEvaluation(
                policy_id=policy_id_str,
                user_id=user_id,
                permission=permission,
                evaluation_context=evaluation_context,
                conditions_evaluated=conditions_evaluated,
                result=result,
                decision_reason=decision_reason,
                execution_time_ms=execution_time_ms,
                ip_address=ip_address,
                user_agent=user_agent,
                session_id=session_id,
                environment_type=environment_type,
                workspace_id=workspace_id,
            )

            session.add(evaluation)
            # Note: Commit is handled by calling method

        except Exception as e:
            logger.error(f"Failed to log policy evaluation: {e}")

    async def get_policy_evaluation_logs(
        self,
        session: AsyncSession,
        policy_id: str | UUID,
        limit: int = 100,
    ) -> list[ConditionalPolicyEvaluation]:
        """Get evaluation logs for a policy."""
        try:
            # Convert to UUIDstr if needed
            policy_id_str = policy_id if isinstance(policy_id, str) else str(policy_id)

            query = (
                select(ConditionalPolicyEvaluation)
                .where(ConditionalPolicyEvaluation.policy_id == policy_id_str)
                .order_by(desc(ConditionalPolicyEvaluation.evaluated_at))
                .limit(limit)
            )

            result = await session.exec(query)
            return result.all()

        except Exception as e:
            logger.error(f"Failed to get policy evaluation logs: {e}")
            return []

    async def get_policy_audit_log(
        self,
        session: AsyncSession,
        policy_id: str | UUID,
        limit: int = 100,
    ) -> list[ConditionalPolicyAudit]:
        """Get audit log for a policy."""
        try:
            # Convert to UUIDstr if needed
            policy_id_str = policy_id if isinstance(policy_id, str) else str(policy_id)

            query = (
                select(ConditionalPolicyAudit)
                .where(ConditionalPolicyAudit.policy_id == policy_id_str)
                .order_by(desc(ConditionalPolicyAudit.changed_at))
                .limit(limit)
            )

            result = await session.exec(query)
            return result.all()

        except Exception as e:
            logger.error(f"Failed to get policy audit log: {e}")
            return []
