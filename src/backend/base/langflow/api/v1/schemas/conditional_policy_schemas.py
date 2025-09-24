"""Pydantic schemas for conditional policy API endpoints."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from langflow.schema.serialize import UUIDstr


class ConditionDefinition(BaseModel):
    """Schema for individual condition definition."""

    type: str = Field(..., description="Type of condition (time_window, ip_address, etc.)")
    operator: str = Field(..., description="Comparison operator (equals, in, between, etc.)")
    value: Any = Field(..., description="Value to compare against")
    timezone: str | None = Field(None, description="Timezone for time-based conditions")
    window: int | None = Field(None, description="Time window in seconds for rate limiting")

    @field_validator("type")
    @classmethod
    def validate_condition_type(cls, v: str) -> str:
        """Validate condition type."""
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
        if v not in valid_types:
            msg = f"Invalid condition type. Must be one of: {valid_types}"
            raise ValueError(msg)
        return v

    @field_validator("operator")
    @classmethod
    def validate_operator(cls, v: str) -> str:
        """Validate operator."""
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
        if v not in valid_operators:
            msg = f"Invalid operator. Must be one of: {valid_operators}"
            raise ValueError(msg)
        return v


class ConditionalPolicyCreate(BaseModel):
    """Schema for creating conditional policies."""

    name: str = Field(..., min_length=1, max_length=255, description="Policy name")
    description: str | None = Field(None, max_length=1000, description="Policy description")
    permission: str = Field(..., min_length=1, max_length=255, description="Permission string")
    workspace_id: UUIDstr | None = Field(None, description="Workspace scope (optional)")
    environment_type: str | None = Field(None, max_length=50, description="Environment type")
    conditions: list[ConditionDefinition] = Field(..., min_length=1, description="Policy conditions")
    enabled: bool = Field(True, description="Whether policy is enabled")
    priority: int = Field(0, ge=0, le=1000, description="Policy priority (0-1000)")
    failure_action: str = Field("deny", description="Action when conditions fail")
    bypass_roles: list[str] = Field(default_factory=list, description="Roles that bypass this policy")
    effective_from: datetime | None = Field(None, description="Policy effective start time")
    effective_until: datetime | None = Field(None, description="Policy effective end time")

    @field_validator("failure_action")
    @classmethod
    def validate_failure_action(cls, v: str) -> str:
        """Validate failure action."""
        valid_actions = {"deny", "require_approval", "log_only"}
        if v not in valid_actions:
            msg = f"Invalid failure action. Must be one of: {valid_actions}"
            raise ValueError(msg)
        return v

    @field_validator("environment_type")
    @classmethod
    def validate_environment_type(cls, v: str | None) -> str | None:
        """Validate environment type."""
        if v is None:
            return v
        valid_types = {"development", "staging", "production", "testing", "preview"}
        if v not in valid_types:
            msg = f"Invalid environment type. Must be one of: {valid_types}"
            raise ValueError(msg)
        return v


class ConditionalPolicyUpdate(BaseModel):
    """Schema for updating conditional policies."""

    name: str | None = Field(None, min_length=1, max_length=255, description="Policy name")
    description: str | None = Field(None, max_length=1000, description="Policy description")
    conditions: list[ConditionDefinition] | None = Field(None, description="Policy conditions")
    enabled: bool | None = Field(None, description="Whether policy is enabled")
    priority: int | None = Field(None, ge=0, le=1000, description="Policy priority")
    failure_action: str | None = Field(None, description="Action when conditions fail")
    bypass_roles: list[str] | None = Field(None, description="Roles that bypass this policy")
    effective_from: datetime | None = Field(None, description="Policy effective start time")
    effective_until: datetime | None = Field(None, description="Policy effective end time")

    @field_validator("failure_action")
    @classmethod
    def validate_failure_action(cls, v: str | None) -> str | None:
        """Validate failure action."""
        if v is None:
            return v
        valid_actions = {"deny", "require_approval", "log_only"}
        if v not in valid_actions:
            msg = f"Invalid failure action. Must be one of: {valid_actions}"
            raise ValueError(msg)
        return v


class ConditionalPolicyRead(BaseModel):
    """Schema for reading conditional policies."""

    id: UUIDstr
    name: str
    description: str | None
    permission: str
    workspace_id: UUIDstr | None
    environment_type: str | None
    conditions: list[ConditionDefinition]
    enabled: bool
    priority: int
    failure_action: str
    bypass_roles: list[str]
    created_at: datetime
    updated_at: datetime
    created_by_id: UUIDstr | None
    updated_by_id: UUIDstr | None
    effective_from: datetime | None
    effective_until: datetime | None
    last_evaluated_at: datetime | None
    evaluation_count: int
    version: int


class ConditionalPolicyTemplateCreate(BaseModel):
    """Schema for creating policy templates."""

    name: str = Field(..., min_length=1, max_length=255, description="Template name")
    description: str | None = Field(None, max_length=1000, description="Template description")
    category: str = Field(..., max_length=100, description="Template category")
    conditions_template: list[ConditionDefinition] = Field(..., description="Template conditions")
    default_priority: int = Field(0, ge=0, le=1000, description="Default priority")
    default_failure_action: str = Field("deny", description="Default failure action")
    suggested_bypass_roles: list[str] = Field(default_factory=list, description="Suggested bypass roles")

    @field_validator("category")
    @classmethod
    def validate_category(cls, v: str) -> str:
        """Validate template category."""
        valid_categories = {
            "security",
            "compliance",
            "business_hours",
            "geographic",
            "device_restriction",
            "network_security",
            "rate_limiting",
            "custom",
        }
        if v not in valid_categories:
            msg = f"Invalid category. Must be one of: {valid_categories}"
            raise ValueError(msg)
        return v


class ConditionalPolicyTemplateRead(BaseModel):
    """Schema for reading policy templates."""

    id: UUIDstr
    name: str
    description: str | None
    category: str
    conditions_template: list[ConditionDefinition]
    default_priority: int
    default_failure_action: str
    suggested_bypass_roles: list[str]
    is_builtin: bool
    is_active: bool
    usage_count: int
    created_at: datetime
    updated_at: datetime


class PolicyEvaluationRequest(BaseModel):
    """Schema for policy evaluation requests."""

    permission: str = Field(..., description="Permission to evaluate")
    user_id: UUIDstr = Field(..., description="User ID")
    ip_address: str | None = Field(None, description="Client IP address")
    user_agent: str | None = Field(None, description="User agent string")
    session_id: str | None = Field(None, description="Session ID")
    environment_type: str | None = Field(None, description="Environment type")
    workspace_id: UUIDstr | None = Field(None, description="Workspace ID")
    mfa_verified: bool = Field(False, description="Whether MFA is verified")
    vpn_detected: bool = Field(False, description="Whether VPN is detected")
    additional_context: dict[str, Any] = Field(default_factory=dict, description="Additional context")


class PolicyEvaluationResult(BaseModel):
    """Schema for policy evaluation results."""

    allowed: bool = Field(..., description="Whether permission is allowed")
    policies_evaluated: int = Field(..., description="Number of policies evaluated")
    failing_policies: list[str] = Field(..., description="Names of failing policies")
    require_approval: bool = Field(False, description="Whether approval is required")
    approval_reason: str | None = Field(None, description="Reason approval is required")
    log_entry_id: UUIDstr | None = Field(None, description="Evaluation log entry ID")
    execution_time_ms: float = Field(..., description="Execution time in milliseconds")


class PolicyAnalytics(BaseModel):
    """Schema for policy analytics data."""

    policy_id: UUIDstr
    policy_name: str
    evaluation_count: int
    allow_rate: float = Field(..., ge=0.0, le=1.0, description="Percentage of allows")
    deny_rate: float = Field(..., ge=0.0, le=1.0, description="Percentage of denies")
    approval_rate: float = Field(..., ge=0.0, le=1.0, description="Percentage requiring approval")
    avg_execution_time_ms: float = Field(..., description="Average execution time")
    last_evaluation: datetime | None
    top_failing_conditions: list[str] = Field(..., description="Most common failing conditions")


class BulkPolicyOperation(BaseModel):
    """Schema for bulk policy operations."""

    operation: str = Field(..., description="Operation type")
    policy_ids: list[UUIDstr] = Field(..., min_length=1, description="Policy IDs to operate on")
    parameters: dict[str, Any] = Field(default_factory=dict, description="Operation parameters")

    @field_validator("operation")
    @classmethod
    def validate_operation(cls, v: str) -> str:
        """Validate operation type."""
        valid_operations = {"enable", "disable", "delete", "update_priority", "export"}
        if v not in valid_operations:
            msg = f"Invalid operation. Must be one of: {valid_operations}"
            raise ValueError(msg)
        return v


class PolicyImportExport(BaseModel):
    """Schema for policy import/export operations."""

    policies: list[ConditionalPolicyCreate] = Field(..., description="Policies to import/export")
    templates: list[ConditionalPolicyTemplateCreate] = Field(default_factory=list, description="Templates")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Export metadata")


class PolicyValidationResult(BaseModel):
    """Schema for policy validation results."""

    is_valid: bool = Field(..., description="Whether policy is valid")
    errors: list[str] = Field(default_factory=list, description="Validation errors")
    warnings: list[str] = Field(default_factory=list, description="Validation warnings")
    suggestions: list[str] = Field(default_factory=list, description="Optimization suggestions")
