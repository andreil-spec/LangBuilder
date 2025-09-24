"""Tests for RoleAssignment model."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from langflow.services.database.models.rbac.role_assignment import (
    AssignmentScope,
    RoleAssignment,
    RoleAssignmentCreate,
    RoleAssignmentRead,
    RoleAssignmentUpdate,
)
from pydantic import ValidationError


class TestAssignmentScope:
    """Test AssignmentScope enum."""

    def test_assignment_scope_values(self):
        """Test AssignmentScope enum values."""
        assert AssignmentScope.WORKSPACE == "workspace"
        assert AssignmentScope.PROJECT == "project"
        assert AssignmentScope.ENVIRONMENT == "environment"
        assert AssignmentScope.FLOW == "flow"
        assert AssignmentScope.COMPONENT == "component"

    def test_assignment_scope_enumeration(self):
        """Test AssignmentScope enumeration."""
        scopes = list(AssignmentScope)
        assert len(scopes) == 5
        assert AssignmentScope.WORKSPACE in scopes
        assert AssignmentScope.PROJECT in scopes
        assert AssignmentScope.ENVIRONMENT in scopes
        assert AssignmentScope.FLOW in scopes
        assert AssignmentScope.COMPONENT in scopes


class TestRoleAssignment:
    """Test RoleAssignment model."""

    def test_role_assignment_creation_workspace_scope(self):
        """Test role assignment creation at workspace scope."""
        user_id = uuid4()
        role_id = uuid4()
        workspace_id = uuid4()
        assigned_by_id = uuid4()

        assignment = RoleAssignment(
            user_id=user_id,
            role_id=role_id,
            scope_type=AssignmentScope.WORKSPACE,
            workspace_id=workspace_id,
            assigned_by_id=assigned_by_id
        )

        assert assignment.user_id == user_id
        assert assignment.role_id == role_id
        assert assignment.scope_type == AssignmentScope.WORKSPACE
        assert assignment.workspace_id == workspace_id
        assert assignment.assigned_by_id == assigned_by_id
        assert assignment.project_id is None
        assert assignment.environment_id is None
        assert assignment.flow_id is None
        assert assignment.component_id is None
        assert assignment.is_active is True  # Default value
        assert assignment.conditions == {}  # Default value
        assert assignment.metadata == {}  # Default value
        assert assignment.assigned_at is not None
        assert assignment.expires_at is None

    def test_role_assignment_creation_project_scope(self):
        """Test role assignment creation at project scope."""
        user_id = uuid4()
        role_id = uuid4()
        workspace_id = uuid4()
        project_id = uuid4()
        assigned_by_id = uuid4()

        assignment = RoleAssignment(
            user_id=user_id,
            role_id=role_id,
            scope_type=AssignmentScope.PROJECT,
            workspace_id=workspace_id,
            project_id=project_id,
            assigned_by_id=assigned_by_id
        )

        assert assignment.user_id == user_id
        assert assignment.role_id == role_id
        assert assignment.scope_type == AssignmentScope.PROJECT
        assert assignment.workspace_id == workspace_id
        assert assignment.project_id == project_id
        assert assignment.environment_id is None
        assert assignment.flow_id is None
        assert assignment.component_id is None

    def test_role_assignment_creation_environment_scope(self):
        """Test role assignment creation at environment scope."""
        user_id = uuid4()
        role_id = uuid4()
        workspace_id = uuid4()
        project_id = uuid4()
        environment_id = uuid4()
        assigned_by_id = uuid4()

        assignment = RoleAssignment(
            user_id=user_id,
            role_id=role_id,
            scope_type=AssignmentScope.ENVIRONMENT,
            workspace_id=workspace_id,
            project_id=project_id,
            environment_id=environment_id,
            assigned_by_id=assigned_by_id
        )

        assert assignment.scope_type == AssignmentScope.ENVIRONMENT
        assert assignment.workspace_id == workspace_id
        assert assignment.project_id == project_id
        assert assignment.environment_id == environment_id
        assert assignment.flow_id is None
        assert assignment.component_id is None

    def test_role_assignment_creation_flow_scope(self):
        """Test role assignment creation at flow scope."""
        user_id = uuid4()
        role_id = uuid4()
        workspace_id = uuid4()
        project_id = uuid4()
        environment_id = uuid4()
        flow_id = uuid4()
        assigned_by_id = uuid4()

        assignment = RoleAssignment(
            user_id=user_id,
            role_id=role_id,
            scope_type=AssignmentScope.FLOW,
            workspace_id=workspace_id,
            project_id=project_id,
            environment_id=environment_id,
            flow_id=flow_id,
            assigned_by_id=assigned_by_id
        )

        assert assignment.scope_type == AssignmentScope.FLOW
        assert assignment.workspace_id == workspace_id
        assert assignment.project_id == project_id
        assert assignment.environment_id == environment_id
        assert assignment.flow_id == flow_id
        assert assignment.component_id is None

    def test_role_assignment_creation_component_scope(self):
        """Test role assignment creation at component scope."""
        user_id = uuid4()
        role_id = uuid4()
        workspace_id = uuid4()
        project_id = uuid4()
        environment_id = uuid4()
        flow_id = uuid4()
        component_id = uuid4()
        assigned_by_id = uuid4()

        assignment = RoleAssignment(
            user_id=user_id,
            role_id=role_id,
            scope_type=AssignmentScope.COMPONENT,
            workspace_id=workspace_id,
            project_id=project_id,
            environment_id=environment_id,
            flow_id=flow_id,
            component_id=component_id,
            assigned_by_id=assigned_by_id
        )

        assert assignment.scope_type == AssignmentScope.COMPONENT
        assert assignment.workspace_id == workspace_id
        assert assignment.project_id == project_id
        assert assignment.environment_id == environment_id
        assert assignment.flow_id == flow_id
        assert assignment.component_id == component_id

    def test_role_assignment_with_expiration(self):
        """Test role assignment with expiration date."""
        user_id = uuid4()
        role_id = uuid4()
        workspace_id = uuid4()
        assigned_by_id = uuid4()
        expires_at = datetime(2024, 12, 31, 23, 59, 59, tzinfo=timezone.utc)

        assignment = RoleAssignment(
            user_id=user_id,
            role_id=role_id,
            scope_type=AssignmentScope.WORKSPACE,
            workspace_id=workspace_id,
            assigned_by_id=assigned_by_id,
            expires_at=expires_at
        )

        assert assignment.expires_at == expires_at

    def test_role_assignment_with_conditions(self):
        """Test role assignment with conditional access."""
        user_id = uuid4()
        role_id = uuid4()
        workspace_id = uuid4()
        assigned_by_id = uuid4()

        conditions = {
            "time_based": {
                "business_hours_only": True,
                "timezone": "America/New_York"
            },
            "ip_restrictions": {
                "allowed_ips": ["192.168.1.0/24"],
                "blocked_ips": []
            },
            "device_restrictions": {
                "trusted_devices_only": True,
                "max_concurrent_sessions": 3
            }
        }

        assignment = RoleAssignment(
            user_id=user_id,
            role_id=role_id,
            scope_type=AssignmentScope.WORKSPACE,
            workspace_id=workspace_id,
            assigned_by_id=assigned_by_id,
            conditions=conditions
        )

        assert assignment.conditions == conditions
        assert assignment.conditions["time_based"]["business_hours_only"] is True
        assert assignment.conditions["ip_restrictions"]["allowed_ips"] == ["192.168.1.0/24"]
        assert assignment.conditions["device_restrictions"]["max_concurrent_sessions"] == 3

    def test_role_assignment_with_metadata(self):
        """Test role assignment with metadata."""
        user_id = uuid4()
        role_id = uuid4()
        workspace_id = uuid4()
        assigned_by_id = uuid4()

        metadata = {
            "reason": "Project collaboration",
            "approval_ticket": "TICKET-12345",
            "requested_by": "manager@company.com",
            "business_justification": "Needs access for Q4 project delivery",
            "review_date": "2024-06-01",
            "auto_renewal": False
        }

        assignment = RoleAssignment(
            user_id=user_id,
            role_id=role_id,
            scope_type=AssignmentScope.PROJECT,
            workspace_id=workspace_id,
            project_id=uuid4(),
            assigned_by_id=assigned_by_id,
            metadata=metadata
        )

        assert assignment.metadata == metadata
        assert assignment.metadata["reason"] == "Project collaboration"
        assert assignment.metadata["approval_ticket"] == "TICKET-12345"
        assert assignment.metadata["auto_renewal"] is False

    def test_role_assignment_conditions_validation_dict(self):
        """Test role assignment conditions validation with dict input."""
        conditions_dict = {
            "requires_mfa": True,
            "audit_level": "high"
        }

        assignment = RoleAssignment(
            user_id=uuid4(),
            role_id=uuid4(),
            scope_type=AssignmentScope.WORKSPACE,
            workspace_id=uuid4(),
            assigned_by_id=uuid4(),
            conditions=conditions_dict
        )

        assert assignment.conditions == conditions_dict

    def test_role_assignment_conditions_validation_invalid_type(self):
        """Test role assignment conditions validation with invalid type."""
        with pytest.raises(ValidationError) as exc_info:
            RoleAssignment(
                user_id=uuid4(),
                role_id=uuid4(),
                scope_type=AssignmentScope.WORKSPACE,
                workspace_id=uuid4(),
                assigned_by_id=uuid4(),
                conditions="invalid_conditions"  # Should be dict
            )

        assert "Conditions must be a dictionary" in str(exc_info.value)

    def test_role_assignment_metadata_validation_dict(self):
        """Test role assignment metadata validation with dict input."""
        metadata_dict = {
            "created_by_system": True,
            "import_source": "ldap_sync"
        }

        assignment = RoleAssignment(
            user_id=uuid4(),
            role_id=uuid4(),
            scope_type=AssignmentScope.WORKSPACE,
            workspace_id=uuid4(),
            assigned_by_id=uuid4(),
            metadata=metadata_dict
        )

        assert assignment.metadata == metadata_dict

    def test_role_assignment_metadata_validation_invalid_type(self):
        """Test role assignment metadata validation with invalid type."""
        with pytest.raises(ValidationError) as exc_info:
            RoleAssignment(
                user_id=uuid4(),
                role_id=uuid4(),
                scope_type=AssignmentScope.WORKSPACE,
                workspace_id=uuid4(),
                assigned_by_id=uuid4(),
                metadata="invalid_metadata"  # Should be dict
            )

        assert "Metadata must be a dictionary" in str(exc_info.value)


class TestRoleAssignmentCreate:
    """Test RoleAssignmentCreate schema."""

    def test_role_assignment_create_workspace_scope(self):
        """Test role assignment creation schema for workspace scope."""
        assignment_data = RoleAssignmentCreate(
            user_id=uuid4(),
            role_id=uuid4(),
            scope_type=AssignmentScope.WORKSPACE,
            workspace_id=uuid4()
        )

        assert assignment_data.scope_type == AssignmentScope.WORKSPACE
        assert assignment_data.workspace_id is not None
        assert assignment_data.project_id is None
        assert assignment_data.environment_id is None
        assert assignment_data.flow_id is None
        assert assignment_data.component_id is None
        assert assignment_data.expires_at is None
        assert assignment_data.conditions is None
        assert assignment_data.metadata is None

    def test_role_assignment_create_project_scope(self):
        """Test role assignment creation schema for project scope."""
        workspace_id = uuid4()
        project_id = uuid4()

        assignment_data = RoleAssignmentCreate(
            user_id=uuid4(),
            role_id=uuid4(),
            scope_type=AssignmentScope.PROJECT,
            workspace_id=workspace_id,
            project_id=project_id
        )

        assert assignment_data.scope_type == AssignmentScope.PROJECT
        assert assignment_data.workspace_id == workspace_id
        assert assignment_data.project_id == project_id
        assert assignment_data.environment_id is None
        assert assignment_data.flow_id is None
        assert assignment_data.component_id is None

    def test_role_assignment_create_with_expiration(self):
        """Test role assignment creation schema with expiration."""
        expires_at = datetime(2024, 12, 31, 23, 59, 59, tzinfo=timezone.utc)

        assignment_data = RoleAssignmentCreate(
            user_id=uuid4(),
            role_id=uuid4(),
            scope_type=AssignmentScope.WORKSPACE,
            workspace_id=uuid4(),
            expires_at=expires_at,
            conditions={"requires_mfa": True},
            metadata={"temporary_access": True}
        )

        assert assignment_data.expires_at == expires_at
        assert assignment_data.conditions == {"requires_mfa": True}
        assert assignment_data.metadata == {"temporary_access": True}


class TestRoleAssignmentRead:
    """Test RoleAssignmentRead schema."""

    def test_role_assignment_read_structure(self):
        """Test role assignment read schema structure."""
        assignment_data = RoleAssignmentRead(
            id=uuid4(),
            user_id=uuid4(),
            role_id=uuid4(),
            scope_type=AssignmentScope.PROJECT,
            workspace_id=uuid4(),
            project_id=uuid4(),
            environment_id=None,
            flow_id=None,
            component_id=None,
            assigned_by_id=uuid4(),
            is_active=True,
            assigned_at="2024-01-01T00:00:00Z",
            expires_at=None,
            conditions={},
            metadata={"source": "manual"},
            user_username="testuser",
            role_name="Project Manager",
            assigned_by_username="admin"
        )

        assert assignment_data.id is not None
        assert assignment_data.scope_type == AssignmentScope.PROJECT
        assert assignment_data.workspace_id is not None
        assert assignment_data.project_id is not None
        assert assignment_data.environment_id is None
        assert assignment_data.user_username == "testuser"
        assert assignment_data.role_name == "Project Manager"
        assert assignment_data.assigned_by_username == "admin"


class TestRoleAssignmentUpdate:
    """Test RoleAssignmentUpdate schema."""

    def test_role_assignment_update_partial(self):
        """Test role assignment update schema with partial data."""
        update_data = RoleAssignmentUpdate(
            is_active=False,
            expires_at=datetime(2024, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        )

        assert update_data.is_active is False
        assert update_data.expires_at is not None
        assert update_data.conditions is None
        assert update_data.metadata is None

    def test_role_assignment_update_full(self):
        """Test role assignment update schema with all fields."""
        expires_at = datetime(2024, 12, 31, 23, 59, 59, tzinfo=timezone.utc)

        update_data = RoleAssignmentUpdate(
            is_active=True,
            expires_at=expires_at,
            conditions={"updated_mfa_required": True},
            metadata={"last_updated_by": "admin", "update_reason": "policy_change"}
        )

        assert update_data.is_active is True
        assert update_data.expires_at == expires_at
        assert update_data.conditions == {"updated_mfa_required": True}
        assert update_data.metadata["last_updated_by"] == "admin"
        assert update_data.metadata["update_reason"] == "policy_change"


class TestRoleAssignmentValidationEdgeCases:
    """Test edge cases for role assignment validation."""

    def test_role_assignment_scope_hierarchy_consistency(self):
        """Test role assignment scope hierarchy consistency."""
        user_id = uuid4()
        role_id = uuid4()
        assigned_by_id = uuid4()
        workspace_id = uuid4()
        project_id = uuid4()
        environment_id = uuid4()
        flow_id = uuid4()
        component_id = uuid4()

        # Component scope should have all parent IDs
        component_assignment = RoleAssignment(
            user_id=user_id,
            role_id=role_id,
            scope_type=AssignmentScope.COMPONENT,
            workspace_id=workspace_id,
            project_id=project_id,
            environment_id=environment_id,
            flow_id=flow_id,
            component_id=component_id,
            assigned_by_id=assigned_by_id
        )

        assert component_assignment.workspace_id == workspace_id
        assert component_assignment.project_id == project_id
        assert component_assignment.environment_id == environment_id
        assert component_assignment.flow_id == flow_id
        assert component_assignment.component_id == component_id

        # Workspace scope should only have workspace ID
        workspace_assignment = RoleAssignment(
            user_id=user_id,
            role_id=role_id,
            scope_type=AssignmentScope.WORKSPACE,
            workspace_id=workspace_id,
            assigned_by_id=assigned_by_id
        )

        assert workspace_assignment.workspace_id == workspace_id
        assert workspace_assignment.project_id is None
        assert workspace_assignment.environment_id is None
        assert workspace_assignment.flow_id is None
        assert workspace_assignment.component_id is None

    def test_role_assignment_complex_conditions(self):
        """Test role assignment with complex conditional logic."""
        complex_conditions = {
            "temporal": {
                "business_hours": {
                    "enabled": True,
                    "start_time": "09:00",
                    "end_time": "17:00",
                    "timezone": "America/New_York",
                    "days": ["monday", "tuesday", "wednesday", "thursday", "friday"]
                },
                "date_range": {
                    "start_date": "2024-01-01",
                    "end_date": "2024-12-31"
                }
            },
            "location": {
                "ip_whitelist": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
                "ip_blacklist": ["192.168.1.100"],
                "country_restrictions": {
                    "allowed": ["US", "CA", "UK"],
                    "blocked": ["CN", "RU"]
                },
                "vpn_required": True
            },
            "device": {
                "trusted_devices_only": True,
                "device_registration_required": True,
                "max_concurrent_sessions": 2,
                "session_timeout_minutes": 480
            },
            "authentication": {
                "mfa_required": True,
                "mfa_methods": ["totp", "sms", "hardware_key"],
                "password_policy": {
                    "min_age_days": 1,
                    "max_age_days": 90,
                    "complexity_required": True
                }
            },
            "audit": {
                "log_all_actions": True,
                "real_time_monitoring": True,
                "alert_on_suspicious_activity": True
            }
        }

        assignment = RoleAssignment(
            user_id=uuid4(),
            role_id=uuid4(),
            scope_type=AssignmentScope.WORKSPACE,
            workspace_id=uuid4(),
            assigned_by_id=uuid4(),
            conditions=complex_conditions
        )

        assert assignment.conditions == complex_conditions
        assert assignment.conditions["temporal"]["business_hours"]["enabled"] is True
        assert assignment.conditions["location"]["vpn_required"] is True
        assert assignment.conditions["device"]["max_concurrent_sessions"] == 2
        assert assignment.conditions["authentication"]["mfa_required"] is True
        assert assignment.conditions["audit"]["log_all_actions"] is True

    def test_role_assignment_metadata_audit_trail(self):
        """Test role assignment with comprehensive audit metadata."""
        audit_metadata = {
            "creation": {
                "timestamp": "2024-01-01T00:00:00Z",
                "created_by": "admin@company.com",
                "creation_method": "manual",
                "approval_required": True,
                "approval_ticket": "APPROVAL-12345"
            },
            "approval": {
                "approved_by": "manager@company.com",
                "approved_at": "2024-01-01T12:00:00Z",
                "approval_reason": "Temporary project access",
                "approval_duration_days": 90
            },
            "business": {
                "justification": "Q1 project delivery requirements",
                "project_code": "PROJ-2024-001",
                "cost_center": "engineering",
                "budget_approved": True
            },
            "compliance": {
                "data_classification": "confidential",
                "background_check_required": True,
                "background_check_completed": True,
                "training_required": ["security", "data_privacy"],
                "training_completed": ["security"]
            },
            "monitoring": {
                "usage_tracking": True,
                "access_review_date": "2024-04-01",
                "last_access": None,
                "access_frequency": "daily"
            }
        }

        assignment = RoleAssignment(
            user_id=uuid4(),
            role_id=uuid4(),
            scope_type=AssignmentScope.PROJECT,
            workspace_id=uuid4(),
            project_id=uuid4(),
            assigned_by_id=uuid4(),
            metadata=audit_metadata
        )

        assert assignment.metadata == audit_metadata
        assert assignment.metadata["creation"]["approval_required"] is True
        assert assignment.metadata["business"]["budget_approved"] is True
        assert assignment.metadata["compliance"]["background_check_completed"] is True
        assert assignment.metadata["monitoring"]["usage_tracking"] is True

    def test_role_assignment_temporary_access_patterns(self):
        """Test role assignment patterns for temporary access."""
        user_id = uuid4()
        role_id = uuid4()
        workspace_id = uuid4()
        assigned_by_id = uuid4()

        # Short-term emergency access
        emergency_assignment = RoleAssignment(
            user_id=user_id,
            role_id=role_id,
            scope_type=AssignmentScope.WORKSPACE,
            workspace_id=workspace_id,
            assigned_by_id=assigned_by_id,
            expires_at=datetime(2024, 1, 2, 0, 0, 0, tzinfo=timezone.utc),  # 24 hours
            conditions={"emergency_access": True, "requires_manager_approval": True},
            metadata={
                "access_type": "emergency",
                "incident_ticket": "INC-001",
                "escalation_level": "high",
                "auto_revoke": True
            }
        )

        # Project-based temporary access
        project_assignment = RoleAssignment(
            user_id=user_id,
            role_id=role_id,
            scope_type=AssignmentScope.PROJECT,
            workspace_id=workspace_id,
            project_id=uuid4(),
            assigned_by_id=assigned_by_id,
            expires_at=datetime(2024, 6, 30, 23, 59, 59, tzinfo=timezone.utc),  # 6 months
            conditions={"project_based": True, "requires_weekly_review": True},
            metadata={
                "access_type": "project_temporary",
                "project_end_date": "2024-06-30",
                "renewal_required": True,
                "max_renewals": 2
            }
        )

        # Contractor access with strict conditions
        contractor_assignment = RoleAssignment(
            user_id=user_id,
            role_id=role_id,
            scope_type=AssignmentScope.ENVIRONMENT,
            workspace_id=workspace_id,
            project_id=uuid4(),
            environment_id=uuid4(),
            assigned_by_id=assigned_by_id,
            expires_at=datetime(2024, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
            conditions={
                "contractor_access": True,
                "ip_restrictions": True,
                "business_hours_only": True,
                "vpn_required": True,
                "session_recording": True
            },
            metadata={
                "access_type": "contractor",
                "contract_number": "CONTRACT-2024-001",
                "security_clearance": "standard",
                "background_check_date": "2023-12-01"
            }
        )

        assert emergency_assignment.metadata["access_type"] == "emergency"
        assert project_assignment.metadata["access_type"] == "project_temporary"
        assert contractor_assignment.metadata["access_type"] == "contractor"
