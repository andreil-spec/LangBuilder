"""Tests for Workspace model."""

from __future__ import annotations

from uuid import uuid4

import pytest
from langflow.services.database.models.rbac.workspace import (
    Workspace,
    WorkspaceCreate,
    WorkspaceInvitation,
    WorkspaceRead,
    WorkspaceSettings,
    WorkspaceUpdate,
)
from pydantic import ValidationError


class TestWorkspaceSettings:
    """Test WorkspaceSettings model."""

    def test_workspace_settings_defaults(self):
        """Test default values for workspace settings."""
        settings = WorkspaceSettings()

        assert settings.sso_enabled is False
        assert settings.sso_provider is None
        assert settings.scim_enabled is False
        assert settings.max_projects is None
        assert settings.max_users is None
        assert settings.allowed_domains == []
        assert settings.default_role_id is None
        assert settings.session_timeout_minutes == 1440  # 24 hours
        assert settings.ip_allowlist == []
        assert settings.features_enabled == {}
        assert settings.compliance_settings == {}

    def test_workspace_settings_custom_values(self):
        """Test custom values for workspace settings."""
        settings = WorkspaceSettings(
            sso_enabled=True,
            sso_provider="okta",
            scim_enabled=True,
            max_projects=100,
            max_users=500,
            allowed_domains=["company.com", "contractor.com"],
            session_timeout_minutes=480,  # 8 hours
            ip_allowlist=["192.168.1.0/24"],
            features_enabled={"advanced_analytics": True, "api_access": True},
            compliance_settings={"audit_retention_days": 365}
        )

        assert settings.sso_enabled is True
        assert settings.sso_provider == "okta"
        assert settings.scim_enabled is True
        assert settings.max_projects == 100
        assert settings.max_users == 500
        assert settings.allowed_domains == ["company.com", "contractor.com"]
        assert settings.session_timeout_minutes == 480
        assert settings.ip_allowlist == ["192.168.1.0/24"]
        assert settings.features_enabled == {"advanced_analytics": True, "api_access": True}
        assert settings.compliance_settings == {"audit_retention_days": 365}


class TestWorkspaceBase:
    """Test WorkspaceBase model validation."""

    def test_workspace_name_validation_empty(self):
        """Test workspace name validation with empty string."""
        with pytest.raises(ValidationError) as exc_info:
            Workspace(name="", owner_id=uuid4())

        assert "Workspace name cannot be empty" in str(exc_info.value)

    def test_workspace_name_validation_whitespace(self):
        """Test workspace name validation with whitespace only."""
        with pytest.raises(ValidationError) as exc_info:
            Workspace(name="   ", owner_id=uuid4())

        assert "Workspace name cannot be empty" in str(exc_info.value)

    def test_workspace_name_validation_too_long(self):
        """Test workspace name validation with too long string."""
        long_name = "a" * 256  # Exceeds 255 character limit

        with pytest.raises(ValidationError) as exc_info:
            Workspace(name=long_name, owner_id=uuid4())

        assert "Workspace name cannot exceed 255 characters" in str(exc_info.value)

    def test_workspace_name_validation_valid(self):
        """Test workspace name validation with valid input."""
        workspace = Workspace(name="  Valid Workspace Name  ", owner_id=uuid4())

        # Name should be stripped
        assert workspace.name == "Valid Workspace Name"

    def test_workspace_settings_validation_dict(self):
        """Test workspace settings validation with dict input."""
        settings_dict = {
            "sso_enabled": True,
            "max_projects": 50
        }

        workspace = Workspace(
            name="Test Workspace",
            owner_id=uuid4(),
            settings=settings_dict
        )

        assert workspace.settings == settings_dict

    def test_workspace_settings_validation_none(self):
        """Test workspace settings validation with None input."""
        workspace = Workspace(name="Test Workspace", owner_id=uuid4(), settings=None)

        # Should use default WorkspaceSettings
        assert isinstance(workspace.settings, dict)
        assert workspace.settings["sso_enabled"] is False

    def test_workspace_settings_validation_invalid_type(self):
        """Test workspace settings validation with invalid type."""
        with pytest.raises(ValidationError) as exc_info:
            Workspace(
                name="Test Workspace",
                owner_id=uuid4(),
                settings="invalid_settings"  # Should be dict
            )

        assert "Settings must be a dictionary" in str(exc_info.value)


class TestWorkspace:
    """Test Workspace model."""

    def test_workspace_creation_minimal(self):
        """Test workspace creation with minimal required fields."""
        owner_id = uuid4()
        workspace = Workspace(name="Test Workspace", owner_id=owner_id)

        assert workspace.name == "Test Workspace"
        assert workspace.owner_id == owner_id
        assert workspace.description is None
        assert workspace.organization is None
        assert workspace.is_active is True
        assert workspace.is_deleted is False
        assert workspace.deletion_requested_at is None
        assert workspace.created_at is not None
        assert workspace.updated_at is not None
        assert isinstance(workspace.settings, dict)
        assert workspace.metadata == {}
        assert workspace.tags == []

    def test_workspace_creation_full(self):
        """Test workspace creation with all fields."""
        owner_id = uuid4()
        settings = WorkspaceSettings(sso_enabled=True, max_projects=100)

        workspace = Workspace(
            name="Full Test Workspace",
            owner_id=owner_id,
            description="A comprehensive test workspace",
            organization="Test Organization",
            settings=settings.model_dump(),
            metadata={"department": "engineering", "cost_center": "tech"},
            tags=["test", "development", "staging"],
            is_active=True
        )

        assert workspace.name == "Full Test Workspace"
        assert workspace.owner_id == owner_id
        assert workspace.description == "A comprehensive test workspace"
        assert workspace.organization == "Test Organization"
        assert workspace.settings["sso_enabled"] is True
        assert workspace.settings["max_projects"] == 100
        assert workspace.metadata == {"department": "engineering", "cost_center": "tech"}
        assert workspace.tags == ["test", "development", "staging"]
        assert workspace.is_active is True
        assert workspace.is_deleted is False


class TestWorkspaceCreate:
    """Test WorkspaceCreate schema."""

    def test_workspace_create_minimal(self):
        """Test workspace creation schema with minimal data."""
        workspace_data = WorkspaceCreate(name="New Workspace")

        assert workspace_data.name == "New Workspace"
        assert workspace_data.description is None
        assert workspace_data.organization is None
        assert workspace_data.settings is None
        assert workspace_data.metadata is None
        assert workspace_data.tags is None

    def test_workspace_create_full(self):
        """Test workspace creation schema with full data."""
        workspace_data = WorkspaceCreate(
            name="New Full Workspace",
            description="A new workspace with all fields",
            organization="New Organization",
            settings={"sso_enabled": True},
            metadata={"type": "production"},
            tags=["production", "live"]
        )

        assert workspace_data.name == "New Full Workspace"
        assert workspace_data.description == "A new workspace with all fields"
        assert workspace_data.organization == "New Organization"
        assert workspace_data.settings == {"sso_enabled": True}
        assert workspace_data.metadata == {"type": "production"}
        assert workspace_data.tags == ["production", "live"]


class TestWorkspaceRead:
    """Test WorkspaceRead schema."""

    def test_workspace_read_structure(self):
        """Test workspace read schema structure."""
        workspace_data = WorkspaceRead(
            id=uuid4(),
            name="Read Workspace",
            owner_id=uuid4(),
            description="Test description",
            organization="Test Org",
            settings={"sso_enabled": False},
            metadata={"env": "test"},
            tags=["test"],
            is_active=True,
            is_deleted=False,
            deletion_requested_at=None,
            created_at="2024-01-01T00:00:00Z",
            updated_at="2024-01-01T00:00:00Z",
            project_count=5,
            user_count=10,
            role_count=3
        )

        assert workspace_data.id is not None
        assert workspace_data.name == "Read Workspace"
        assert workspace_data.owner_id is not None
        assert workspace_data.project_count == 5
        assert workspace_data.user_count == 10
        assert workspace_data.role_count == 3


class TestWorkspaceUpdate:
    """Test WorkspaceUpdate schema."""

    def test_workspace_update_partial(self):
        """Test workspace update schema with partial data."""
        update_data = WorkspaceUpdate(
            name="Updated Workspace Name",
            description="Updated description"
        )

        assert update_data.name == "Updated Workspace Name"
        assert update_data.description == "Updated description"
        assert update_data.organization is None
        assert update_data.settings is None
        assert update_data.metadata is None
        assert update_data.tags is None
        assert update_data.is_active is None

    def test_workspace_update_full(self):
        """Test workspace update schema with all fields."""
        update_data = WorkspaceUpdate(
            name="Fully Updated Workspace",
            description="Fully updated description",
            organization="Updated Organization",
            settings={"sso_enabled": True, "max_users": 1000},
            metadata={"updated": True},
            tags=["updated", "v2"],
            is_active=False
        )

        assert update_data.name == "Fully Updated Workspace"
        assert update_data.description == "Fully updated description"
        assert update_data.organization == "Updated Organization"
        assert update_data.settings["sso_enabled"] is True
        assert update_data.settings["max_users"] == 1000
        assert update_data.metadata == {"updated": True}
        assert update_data.tags == ["updated", "v2"]
        assert update_data.is_active is False


class TestWorkspaceInvitation:
    """Test WorkspaceInvitation model."""

    def test_workspace_invitation_creation(self):
        """Test workspace invitation creation."""
        workspace_id = uuid4()
        role_id = uuid4()
        invited_by_id = uuid4()

        invitation = WorkspaceInvitation(
            workspace_id=workspace_id,
            email="user@example.com",
            role_id=role_id,
            invited_by_id=invited_by_id,
            invitation_code="secure_token_123",
            expires_at="2024-12-31T23:59:59Z"
        )

        assert invitation.workspace_id == workspace_id
        assert invitation.email == "user@example.com"
        assert invitation.role_id == role_id
        assert invitation.invited_by_id == invited_by_id
        assert invitation.invitation_code == "secure_token_123"
        assert invitation.is_accepted is False
        assert invitation.accepted_at is None
        assert invitation.accepted_by_id is None
        assert invitation.created_at is not None

    def test_workspace_invitation_accepted(self):
        """Test accepted workspace invitation."""
        workspace_id = uuid4()
        invited_by_id = uuid4()
        accepted_by_id = uuid4()

        invitation = WorkspaceInvitation(
            workspace_id=workspace_id,
            email="user@example.com",
            invited_by_id=invited_by_id,
            invitation_code="secure_token_456",
            expires_at="2024-12-31T23:59:59Z",
            is_accepted=True,
            accepted_at="2024-06-01T12:00:00Z",
            accepted_by_id=accepted_by_id
        )

        assert invitation.is_accepted is True
        assert invitation.accepted_at is not None
        assert invitation.accepted_by_id == accepted_by_id


class TestWorkspaceValidationEdgeCases:
    """Test edge cases for workspace validation."""

    def test_workspace_name_unicode(self):
        """Test workspace name with unicode characters."""
        workspace = Workspace(name="测试工作区 🚀", owner_id=uuid4())
        assert workspace.name == "测试工作区 🚀"

    def test_workspace_settings_empty_dict(self):
        """Test workspace with empty settings dict."""
        workspace = Workspace(
            name="Test Workspace",
            owner_id=uuid4(),
            settings={}
        )
        assert workspace.settings == {}

    def test_workspace_metadata_complex_structure(self):
        """Test workspace with complex metadata structure."""
        complex_metadata = {
            "permissions": {
                "admin": ["read", "write", "delete"],
                "editor": ["read", "write"],
                "viewer": ["read"]
            },
            "features": {
                "analytics": True,
                "reporting": False,
                "integrations": ["slack", "teams"]
            },
            "billing": {
                "plan": "enterprise",
                "seats": 100,
                "expires": "2024-12-31"
            }
        }

        workspace = Workspace(
            name="Complex Workspace",
            owner_id=uuid4(),
            metadata=complex_metadata
        )

        assert workspace.metadata == complex_metadata
        assert workspace.metadata["permissions"]["admin"] == ["read", "write", "delete"]
        assert workspace.metadata["features"]["integrations"] == ["slack", "teams"]
        assert workspace.metadata["billing"]["seats"] == 100

    def test_workspace_tags_empty_list(self):
        """Test workspace with empty tags list."""
        workspace = Workspace(name="Test Workspace", owner_id=uuid4(), tags=[])
        assert workspace.tags == []

    def test_workspace_tags_duplicate_removal(self):
        """Test that workspace handles duplicate tags gracefully."""
        # Note: The model doesn't automatically remove duplicates,
        # but we should test the expected behavior
        workspace = Workspace(
            name="Test Workspace",
            owner_id=uuid4(),
            tags=["test", "production", "test", "staging", "production"]
        )

        # The model stores exactly what's provided
        assert workspace.tags == ["test", "production", "test", "staging", "production"]

    def test_workspace_creation_with_all_none_optionals(self):
        """Test workspace creation with all optional fields as None."""
        workspace = Workspace(
            name="Minimal Workspace",
            owner_id=uuid4(),
            description=None,
            organization=None,
            settings=None,
            metadata=None,
            tags=None
        )

        assert workspace.name == "Minimal Workspace"
        assert workspace.description is None
        assert workspace.organization is None
        # settings should get default values
        assert isinstance(workspace.settings, dict)
        assert workspace.metadata == {}
        assert workspace.tags == []
