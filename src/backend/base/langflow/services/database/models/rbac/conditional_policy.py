"""Database models for conditional permission policies.

This module defines the database models for storing and managing
conditional permission policies that can be configured dynamically.
"""

from datetime import datetime, timezone
from typing import Any, Union, List
from uuid import uuid4

from sqlmodel import JSON, Column, Field, Relationship, SQLModel

from langflow.schema.serialize import UUIDstr


class ConditionalPolicy(SQLModel, table=True):
    """Model for storing conditional permission policies.

    This replaces hardcoded policies with configurable database entries
    that can be managed through APIs and UI interfaces.
    """

    __tablename__ = "conditional_policy"

    id: UUIDstr = Field(default_factory=uuid4, primary_key=True)

    # Policy identification
    name: str = Field(max_length=255, index=True)
    description: Union[str, None] = Field(max_length=1000, default=None)

    # Permission and scope
    permission: str = Field(max_length=255, index=True)
    workspace_id: Union[UUIDstr, None] = Field(default=None, foreign_key="workspace.id", index=True)
    environment_type: Union[str, None] = Field(max_length=50, default=None, index=True)

    # Policy configuration
    conditions: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))

    # Policy behavior
    enabled: bool = Field(default=True, index=True)
    priority: int = Field(default=0, index=True)
    failure_action: str = Field(max_length=50, default="deny")  # deny, require_approval, log_only
    bypass_roles: List[str] = Field(default_factory=list, sa_column=Column(JSON))

    # Metadata
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_by_id: Union[UUIDstr, None] = Field(default=None, foreign_key="user.id")
    updated_by_id: Union[UUIDstr, None] = Field(default=None, foreign_key="user.id")

    # Policy scheduling
    effective_from: Union[datetime, None] = Field(default=None)
    effective_until: Union[datetime, None] = Field(default=None)

    # Usage tracking
    last_evaluated_at: Union[datetime, None] = Field(default=None)
    evaluation_count: int = Field(default=0)

    # Version control
    version: int = Field(default=1)
    parent_policy_id: Union[UUIDstr, None] = Field(default=None, foreign_key="conditional_policy.id")


class ConditionalPolicyTemplate(SQLModel, table=True):
    """Model for storing reusable conditional policy templates.

    Templates provide pre-configured policy patterns that can be
    instantiated for different permissions or environments.
    """

    __tablename__ = "conditional_policy_template"

    id: UUIDstr = Field(default_factory=uuid4, primary_key=True)

    # Template identification
    name: str = Field(max_length=255, index=True)
    description: Union[str, None] = Field(max_length=1000, default=None)
    category: str = Field(max_length=100, index=True)  # security, compliance, business_hours, etc.

    # Template configuration
    conditions_template: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    default_priority: int = Field(default=0)
    default_failure_action: str = Field(max_length=50, default="deny")
    suggested_bypass_roles: List[str] = Field(default_factory=list, sa_column=Column(JSON))

    # Template metadata
    is_builtin: bool = Field(default=False)  # System-provided templates
    is_active: bool = Field(default=True)
    usage_count: int = Field(default=0)

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_by_id: Union[UUIDstr, None] = Field(default=None, foreign_key="user.id")


class ConditionalPolicyEvaluation(SQLModel, table=True):
    """Model for tracking conditional policy evaluations.

    Stores evaluation results for auditing, analytics, and optimization.
    """

    __tablename__ = "conditional_policy_evaluation"

    id: UUIDstr = Field(default_factory=uuid4, primary_key=True)

    # Evaluation context
    policy_id: UUIDstr = Field(foreign_key="conditional_policy.id", index=True)
    user_id: UUIDstr = Field(foreign_key="user.id", index=True)
    permission: str = Field(max_length=255, index=True)

    # Evaluation details
    evaluation_context: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    conditions_evaluated: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))

    # Results
    result: str = Field(max_length=50, index=True)  # allowed, denied, require_approval
    decision_reason: Union[str, None] = Field(max_length=500, default=None)
    execution_time_ms: float = Field(default=0.0)

    # Context information
    ip_address: Union[str, None] = Field(max_length=45, default=None, index=True)
    user_agent: Union[str, None] = Field(max_length=500, default=None)
    session_id: Union[str, None] = Field(max_length=255, default=None, index=True)
    environment_type: Union[str, None] = Field(max_length=50, default=None, index=True)
    workspace_id: Union[UUIDstr, None] = Field(default=None, foreign_key="workspace.id", index=True)

    # Timestamps
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)


class ConditionalPolicyAudit(SQLModel, table=True):
    """Model for auditing conditional policy changes.

    Tracks all modifications to policies for compliance and security.
    """

    __tablename__ = "conditional_policy_audit"

    id: UUIDstr = Field(default_factory=uuid4, primary_key=True)

    # Audit context
    policy_id: UUIDstr = Field(foreign_key="conditional_policy.id", index=True)
    action: str = Field(max_length=50, index=True)  # created, updated, deleted, enabled, disabled

    # Change details
    old_values: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    new_values: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    change_summary: Union[str, None] = Field(max_length=1000, default=None)

    # Actor information
    changed_by_id: UUIDstr = Field(foreign_key="user.id", index=True)
    change_reason: Union[str, None] = Field(max_length=500, default=None)

    # Context
    ip_address: Union[str, None] = Field(max_length=45, default=None)
    user_agent: Union[str, None] = Field(max_length=500, default=None)

    # Timestamps
    changed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)
