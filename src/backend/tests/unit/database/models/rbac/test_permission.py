"""Tests for Permission model."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from langflow.services.database.models.rbac.permission import (
    Permission,
    PermissionAction,
    PermissionCreate,
    PermissionRead,
    PermissionUpdate,
    ResourceType,
    RolePermission,
    RolePermissionCreate,
)
from pydantic import ValidationError


class TestPermissionAction:
    """Test PermissionAction enum."""

    def test_permission_action_values(self):
        """Test PermissionAction enum values."""
        assert PermissionAction.CREATE == "create"
        assert PermissionAction.READ == "read"
        assert PermissionAction.UPDATE == "update"
        assert PermissionAction.DELETE == "delete"
        assert PermissionAction.EXECUTE == "execute"
        assert PermissionAction.MANAGE == "manage"
        assert PermissionAction.ALL == "*"

    def test_permission_action_enumeration(self):
        """Test PermissionAction enumeration."""
        actions = list(PermissionAction)
        assert len(actions) == 7
        assert PermissionAction.CREATE in actions
        assert PermissionAction.READ in actions
        assert PermissionAction.UPDATE in actions
        assert PermissionAction.DELETE in actions
        assert PermissionAction.EXECUTE in actions
        assert PermissionAction.MANAGE in actions
        assert PermissionAction.ALL in actions


class TestResourceType:
    """Test ResourceType enum."""

    def test_resource_type_values(self):
        """Test ResourceType enum values."""
        assert ResourceType.WORKSPACE == "workspace"
        assert ResourceType.PROJECT == "project"
        assert ResourceType.ENVIRONMENT == "environment"
        assert ResourceType.FLOW == "flow"
        assert ResourceType.COMPONENT == "component"
        assert ResourceType.USER == "user"
        assert ResourceType.ROLE == "role"
        assert ResourceType.API_KEY == "api_key"
        assert ResourceType.VARIABLE == "variable"
        assert ResourceType.AUDIT_LOG == "audit_log"

    def test_resource_type_enumeration(self):
        """Test ResourceType enumeration."""
        resources = list(ResourceType)
        assert len(resources) == 10
        assert ResourceType.WORKSPACE in resources
        assert ResourceType.PROJECT in resources
        assert ResourceType.ENVIRONMENT in resources
        assert ResourceType.FLOW in resources
        assert ResourceType.COMPONENT in resources
        assert ResourceType.USER in resources
        assert ResourceType.ROLE in resources
        assert ResourceType.API_KEY in resources
        assert ResourceType.VARIABLE in resources
        assert ResourceType.AUDIT_LOG in resources


class TestPermission:
    """Test Permission model."""

    def test_permission_creation_minimal(self):
        """Test permission creation with minimal required fields."""
        created_by_id = uuid4()

        permission = Permission(
            code="workspace:read",
            name="Read Workspace",
            resource_type=ResourceType.WORKSPACE,
            action=PermissionAction.READ,
            created_by_id=created_by_id
        )

        assert permission.code == "workspace:read"
        assert permission.name == "Read Workspace"
        assert permission.resource_type == ResourceType.WORKSPACE
        assert permission.action == PermissionAction.READ
        assert permission.created_by_id == created_by_id
        assert permission.description is None
        assert permission.is_system is False  # Default value
        assert permission.is_active is True  # Default value
        assert permission.metadata == {}  # Default value
        assert permission.tags == []  # Default value
        assert permission.created_at is not None
        assert permission.updated_at is not None

    def test_permission_creation_full(self):
        """Test permission creation with all fields."""
        created_by_id = uuid4()

        permission = Permission(
            code="project:manage",
            name="Manage Project",
            resource_type=ResourceType.PROJECT,
            action=PermissionAction.MANAGE,
            created_by_id=created_by_id,
            description="Full management access to projects",
            is_system=True,
            is_active=True,
            metadata={"scope": "full", "level": "admin"},
            tags=["management", "project", "admin"]
        )

        assert permission.code == "project:manage"
        assert permission.name == "Manage Project"
        assert permission.resource_type == ResourceType.PROJECT
        assert permission.action == PermissionAction.MANAGE
        assert permission.created_by_id == created_by_id
        assert permission.description == "Full management access to projects"
        assert permission.is_system is True
        assert permission.is_active is True
        assert permission.metadata == {"scope": "full", "level": "admin"}
        assert permission.tags == ["management", "project", "admin"]

    def test_permission_code_validation_empty(self):
        """Test permission code validation with empty string."""
        with pytest.raises(ValidationError) as exc_info:
            Permission(
                code="",
                name="Test Permission",
                resource_type=ResourceType.WORKSPACE,
                action=PermissionAction.READ,
                created_by_id=uuid4()
            )

        assert "Permission code cannot be empty" in str(exc_info.value)

    def test_permission_code_validation_invalid_format(self):
        """Test permission code validation with invalid format."""
        with pytest.raises(ValidationError) as exc_info:
            Permission(
                code="invalid_format",  # Should be resource:action
                name="Test Permission",
                resource_type=ResourceType.WORKSPACE,
                action=PermissionAction.READ,
                created_by_id=uuid4()
            )

        assert "Permission code must be in format 'resource:action'" in str(exc_info.value)

    def test_permission_code_validation_valid_formats(self):
        """Test permission code validation with valid formats."""
        created_by_id = uuid4()

        # Standard format
        permission1 = Permission(
            code="workspace:read",
            name="Read Workspace",
            resource_type=ResourceType.WORKSPACE,
            action=PermissionAction.READ,
            created_by_id=created_by_id
        )
        assert permission1.code == "workspace:read"

        # Wildcard action
        permission2 = Permission(
            code="flow:*",
            name="All Flow Actions",
            resource_type=ResourceType.FLOW,
            action=PermissionAction.ALL,
            created_by_id=created_by_id
        )
        assert permission2.code == "flow:*"

        # Complex resource names
        permission3 = Permission(
            code="api_key:create",
            name="Create API Key",
            resource_type=ResourceType.API_KEY,
            action=PermissionAction.CREATE,
            created_by_id=created_by_id
        )
        assert permission3.code == "api_key:create"

    def test_permission_name_validation(self):
        """Test permission name validation."""
        created_by_id = uuid4()

        # Valid name
        permission = Permission(
            code="workspace:read",
            name="  Read Workspace Permission  ",
            resource_type=ResourceType.WORKSPACE,
            action=PermissionAction.READ,
            created_by_id=created_by_id
        )
        # Name should be stripped
        assert permission.name == "Read Workspace Permission"

        # Empty name should fail
        with pytest.raises(ValidationError) as exc_info:
            Permission(
                code="workspace:read",
                name="",
                resource_type=ResourceType.WORKSPACE,
                action=PermissionAction.READ,
                created_by_id=created_by_id
            )
        assert "Permission name cannot be empty" in str(exc_info.value)


class TestPermissionCreate:
    """Test PermissionCreate schema."""

    def test_permission_create_minimal(self):
        """Test permission creation schema with minimal data."""
        permission_data = PermissionCreate(
            code="environment:read",
            name="Read Environment",
            resource_type=ResourceType.ENVIRONMENT,
            action=PermissionAction.READ
        )

        assert permission_data.code == "environment:read"
        assert permission_data.name == "Read Environment"
        assert permission_data.resource_type == ResourceType.ENVIRONMENT
        assert permission_data.action == PermissionAction.READ
        assert permission_data.description is None
        assert permission_data.is_system is False  # Default
        assert permission_data.metadata is None
        assert permission_data.tags is None

    def test_permission_create_full(self):
        """Test permission creation schema with full data."""
        permission_data = PermissionCreate(
            code="component:execute",
            name="Execute Component",
            resource_type=ResourceType.COMPONENT,
            action=PermissionAction.EXECUTE,
            description="Execute component in flows",
            is_system=True,
            metadata={"category": "execution"},
            tags=["execution", "component"]
        )

        assert permission_data.code == "component:execute"
        assert permission_data.name == "Execute Component"
        assert permission_data.resource_type == ResourceType.COMPONENT
        assert permission_data.action == PermissionAction.EXECUTE
        assert permission_data.description == "Execute component in flows"
        assert permission_data.is_system is True
        assert permission_data.metadata == {"category": "execution"}
        assert permission_data.tags == ["execution", "component"]


class TestPermissionRead:
    """Test PermissionRead schema."""

    def test_permission_read_structure(self):
        """Test permission read schema structure."""
        permission_data = PermissionRead(
            id=uuid4(),
            code="variable:update",
            name="Update Variable",
            resource_type=ResourceType.VARIABLE,
            action=PermissionAction.UPDATE,
            created_by_id=uuid4(),
            description="Update environment variables",
            is_system=False,
            is_active=True,
            metadata={"scope": "environment"},
            tags=["variables"],
            created_at="2024-01-01T00:00:00Z",
            updated_at="2024-01-01T00:00:00Z",
            usage_count=25
        )

        assert permission_data.id is not None
        assert permission_data.code == "variable:update"
        assert permission_data.name == "Update Variable"
        assert permission_data.resource_type == ResourceType.VARIABLE
        assert permission_data.action == PermissionAction.UPDATE
        assert permission_data.usage_count == 25


class TestPermissionUpdate:
    """Test PermissionUpdate schema."""

    def test_permission_update_partial(self):
        """Test permission update schema with partial data."""
        update_data = PermissionUpdate(
            name="Updated Permission Name",
            description="Updated description"
        )

        assert update_data.name == "Updated Permission Name"
        assert update_data.description == "Updated description"
        assert update_data.is_active is None
        assert update_data.metadata is None
        assert update_data.tags is None

    def test_permission_update_full(self):
        """Test permission update schema with all fields."""
        update_data = PermissionUpdate(
            name="Fully Updated Permission",
            description="Fully updated description",
            is_active=False,
            metadata={"updated": True},
            tags=["updated", "v2"]
        )

        assert update_data.name == "Fully Updated Permission"
        assert update_data.description == "Fully updated description"
        assert update_data.is_active is False
        assert update_data.metadata == {"updated": True}
        assert update_data.tags == ["updated", "v2"]


class TestRolePermission:
    """Test RolePermission model."""

    def test_role_permission_creation_minimal(self):
        """Test role permission creation with minimal required fields."""
        role_id = uuid4()
        permission_id = uuid4()
        granted_by_id = uuid4()

        role_permission = RolePermission(
            role_id=role_id,
            permission_id=permission_id,
            is_granted=True,
            granted_by_id=granted_by_id
        )

        assert role_permission.role_id == role_id
        assert role_permission.permission_id == permission_id
        assert role_permission.is_granted is True
        assert role_permission.granted_by_id == granted_by_id
        assert role_permission.granted_at is not None
        assert role_permission.expires_at is None
        assert role_permission.conditions == {}  # Default value
        assert role_permission.metadata == {}  # Default value

    def test_role_permission_creation_full(self):
        """Test role permission creation with all fields."""
        role_id = uuid4()
        permission_id = uuid4()
        granted_by_id = uuid4()
        expires_at = datetime(2024, 12, 31, 23, 59, 59, tzinfo=timezone.utc)

        role_permission = RolePermission(
            role_id=role_id,
            permission_id=permission_id,
            is_granted=True,
            granted_by_id=granted_by_id,
            expires_at=expires_at,
            conditions={"time_based": True, "ip_restricted": False},
            metadata={"reason": "temporary_access", "ticket": "TICK-123"}
        )

        assert role_permission.role_id == role_id
        assert role_permission.permission_id == permission_id
        assert role_permission.is_granted is True
        assert role_permission.granted_by_id == granted_by_id
        assert role_permission.expires_at == expires_at
        assert role_permission.conditions == {"time_based": True, "ip_restricted": False}
        assert role_permission.metadata == {"reason": "temporary_access", "ticket": "TICK-123"}

    def test_role_permission_denied(self):
        """Test role permission with denied access."""
        role_id = uuid4()
        permission_id = uuid4()
        granted_by_id = uuid4()

        role_permission = RolePermission(
            role_id=role_id,
            permission_id=permission_id,
            is_granted=False,  # Explicitly denied
            granted_by_id=granted_by_id,
            metadata={"reason": "security_policy", "denied_reason": "insufficient_privileges"}
        )

        assert role_permission.is_granted is False
        assert role_permission.metadata["reason"] == "security_policy"
        assert role_permission.metadata["denied_reason"] == "insufficient_privileges"


class TestRolePermissionCreate:
    """Test RolePermissionCreate schema."""

    def test_role_permission_create_minimal(self):
        """Test role permission creation schema with minimal data."""
        role_permission_data = RolePermissionCreate(
            permission_id=uuid4(),
            is_granted=True
        )

        assert role_permission_data.permission_id is not None
        assert role_permission_data.is_granted is True
        assert role_permission_data.expires_at is None
        assert role_permission_data.conditions is None
        assert role_permission_data.metadata is None

    def test_role_permission_create_full(self):
        """Test role permission creation schema with full data."""
        permission_id = uuid4()
        expires_at = datetime(2024, 12, 31, 23, 59, 59, tzinfo=timezone.utc)

        role_permission_data = RolePermissionCreate(
            permission_id=permission_id,
            is_granted=True,
            expires_at=expires_at,
            conditions={"requires_mfa": True},
            metadata={"approval_id": "APP-456"}
        )

        assert role_permission_data.permission_id == permission_id
        assert role_permission_data.is_granted is True
        assert role_permission_data.expires_at == expires_at
        assert role_permission_data.conditions == {"requires_mfa": True}
        assert role_permission_data.metadata == {"approval_id": "APP-456"}


class TestPermissionValidationEdgeCases:
    """Test edge cases for permission validation."""

    def test_permission_code_case_sensitivity(self):
        """Test permission code case sensitivity."""
        created_by_id = uuid4()

        permission = Permission(
            code="WORKSPACE:READ",  # Uppercase
            name="Read Workspace",
            resource_type=ResourceType.WORKSPACE,
            action=PermissionAction.READ,
            created_by_id=created_by_id
        )
        assert permission.code == "WORKSPACE:READ"

    def test_permission_wildcard_combinations(self):
        """Test various wildcard combinations in permission codes."""
        created_by_id = uuid4()

        # Resource wildcard with specific action
        permission1 = Permission(
            code="*:read",
            name="Read Any Resource",
            resource_type=ResourceType.WORKSPACE,  # Base resource type
            action=PermissionAction.READ,
            created_by_id=created_by_id
        )
        assert permission1.code == "*:read"

        # Specific resource with action wildcard
        permission2 = Permission(
            code="flow:*",
            name="All Flow Actions",
            resource_type=ResourceType.FLOW,
            action=PermissionAction.ALL,
            created_by_id=created_by_id
        )
        assert permission2.code == "flow:*"

        # Full wildcard
        permission3 = Permission(
            code="*:*",
            name="Super Admin",
            resource_type=ResourceType.WORKSPACE,  # Base resource type
            action=PermissionAction.ALL,
            created_by_id=created_by_id
        )
        assert permission3.code == "*:*"

    def test_permission_metadata_complex_conditions(self):
        """Test permission with complex conditional metadata."""
        created_by_id = uuid4()

        complex_metadata = {
            "conditions": {
                "time_restrictions": {
                    "business_hours_only": True,
                    "timezone": "America/New_York",
                    "excluded_days": ["saturday", "sunday"]
                },
                "location_restrictions": {
                    "allowed_countries": ["US", "CA", "UK"],
                    "blocked_ips": ["192.168.1.100"],
                    "vpn_required": True
                },
                "user_restrictions": {
                    "min_account_age_days": 30,
                    "requires_2fa": True,
                    "max_concurrent_sessions": 3
                }
            },
            "audit": {
                "log_access": True,
                "alert_on_usage": False,
                "retention_period": "1_year"
            }
        }

        permission = Permission(
            code="audit_log:read",
            name="Read Audit Logs",
            resource_type=ResourceType.AUDIT_LOG,
            action=PermissionAction.READ,
            created_by_id=created_by_id,
            metadata=complex_metadata
        )

        assert permission.metadata == complex_metadata
        assert permission.metadata["conditions"]["time_restrictions"]["business_hours_only"] is True
        assert permission.metadata["conditions"]["user_restrictions"]["requires_2fa"] is True
        assert permission.metadata["audit"]["retention_period"] == "1_year"

    def test_role_permission_expiration_scenarios(self):
        """Test role permission with various expiration scenarios."""
        role_id = uuid4()
        permission_id = uuid4()
        granted_by_id = uuid4()

        # Past expiration (expired)
        past_expiration = datetime(2020, 1, 1, tzinfo=timezone.utc)
        expired_permission = RolePermission(
            role_id=role_id,
            permission_id=permission_id,
            is_granted=True,
            granted_by_id=granted_by_id,
            expires_at=past_expiration
        )
        assert expired_permission.expires_at == past_expiration

        # Future expiration (valid)
        future_expiration = datetime(2030, 12, 31, tzinfo=timezone.utc)
        valid_permission = RolePermission(
            role_id=role_id,
            permission_id=permission_id,
            is_granted=True,
            granted_by_id=granted_by_id,
            expires_at=future_expiration
        )
        assert valid_permission.expires_at == future_expiration

        # No expiration (permanent)
        permanent_permission = RolePermission(
            role_id=role_id,
            permission_id=permission_id,
            is_granted=True,
            granted_by_id=granted_by_id,
            expires_at=None
        )
        assert permanent_permission.expires_at is None

    def test_permission_tags_categorization(self):
        """Test permission categorization through tags."""
        created_by_id = uuid4()

        # Administrative permissions
        admin_permission = Permission(
            code="user:manage",
            name="Manage Users",
            resource_type=ResourceType.USER,
            action=PermissionAction.MANAGE,
            created_by_id=created_by_id,
            tags=["admin", "user-management", "sensitive", "audit-required"]
        )
        assert "admin" in admin_permission.tags
        assert "sensitive" in admin_permission.tags

        # Developer permissions
        dev_permission = Permission(
            code="flow:execute",
            name="Execute Flows",
            resource_type=ResourceType.FLOW,
            action=PermissionAction.EXECUTE,
            created_by_id=created_by_id,
            tags=["developer", "execution", "runtime", "standard"]
        )
        assert "developer" in dev_permission.tags
        assert "runtime" in dev_permission.tags

        # Viewer permissions
        viewer_permission = Permission(
            code="project:read",
            name="View Projects",
            resource_type=ResourceType.PROJECT,
            action=PermissionAction.READ,
            created_by_id=created_by_id,
            tags=["viewer", "read-only", "safe", "basic"]
        )
        assert "viewer" in viewer_permission.tags
        assert "read-only" in viewer_permission.tags
