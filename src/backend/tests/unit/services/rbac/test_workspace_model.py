"""Unit tests for Workspace model."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from langflow.services.database.models.rbac.workspace import (
    Workspace,
    WorkspaceCreate,
    WorkspaceRead,
    WorkspaceSettings,
    WorkspaceUpdate,
)
from langflow.services.database.models.user.model import User


class TestWorkspaceModel:
    """Test cases for Workspace model."""

    def test_workspace_creation(self):
        """Test basic workspace creation."""
        workspace_data = WorkspaceCreate(
            name="Test Workspace",
            description="A test workspace",
            organization="Test Org"
        )

        user_id = uuid4()
        workspace = Workspace(
            **workspace_data.model_dump(),
            owner_id=user_id
        )

        assert workspace.name == "Test Workspace"
        assert workspace.description == "A test workspace"
        assert workspace.organization == "Test Org"
        assert workspace.owner_id == user_id
        assert workspace.is_active is True
        assert workspace.is_deleted is False
        assert isinstance(workspace.created_at, datetime)
        assert isinstance(workspace.updated_at, datetime)

    def test_workspace_settings_default(self):
        """Test default workspace settings."""
        settings = WorkspaceSettings()

        assert settings.sso_enabled is False
        assert settings.sso_provider is None
        assert settings.scim_enabled is False
        assert settings.max_projects is None
        assert settings.max_users is None
        assert settings.allowed_domains == []
        assert settings.default_role_id is None
        assert settings.session_timeout_minutes == 1440
        assert settings.ip_allowlist == []
        assert settings.features_enabled == {}
        assert settings.compliance_settings == {}

    def test_workspace_name_validation(self):
        """Test workspace name validation."""
        # Test empty name
        with pytest.raises(ValueError, match="Workspace name cannot be empty"):
            workspace = Workspace(
                name="",
                owner_id=uuid4()
            )
            workspace.validate_name("")

        # Test name too long
        long_name = "x" * 256
        with pytest.raises(ValueError, match="Workspace name cannot exceed 255 characters"):
            workspace = Workspace(
                name=long_name,
                owner_id=uuid4()
            )
            workspace.validate_name(long_name)

        # Test whitespace trimming
        workspace = Workspace(
            name="  Test Workspace  ",
            owner_id=uuid4()
        )
        assert workspace.name == "Test Workspace"

    def test_workspace_settings_validation(self):
        """Test workspace settings validation."""
        # Test invalid settings type
        with pytest.raises(ValueError, match="Settings must be a dictionary"):
            workspace = Workspace(
                name="Test",
                owner_id=uuid4(),
                settings="invalid"
            )
            workspace.validate_settings("invalid")

        # Test None settings get default
        workspace = Workspace(
            name="Test",
            owner_id=uuid4(),
            settings=None
        )
        validated_settings = workspace.validate_settings(None)
        assert isinstance(validated_settings, dict)

    def test_workspace_read_model(self):
        """Test WorkspaceRead model."""
        workspace_id = uuid4()
        owner_id = uuid4()

        workspace_read = WorkspaceRead(
            id=workspace_id,
            name="Test Workspace",
            description="Test description",
            organization="Test Org",
            owner_id=owner_id,
            is_active=True,
            is_deleted=False,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            project_count=5,
            user_count=10,
            role_count=3
        )

        assert workspace_read.id == workspace_id
        assert workspace_read.owner_id == owner_id
        assert workspace_read.project_count == 5
        assert workspace_read.user_count == 10
        assert workspace_read.role_count == 3

    def test_workspace_update_model(self):
        """Test WorkspaceUpdate model."""
        workspace_update = WorkspaceUpdate(
            name="Updated Name",
            description="Updated description",
            is_active=False
        )

        assert workspace_update.name == "Updated Name"
        assert workspace_update.description == "Updated description"
        assert workspace_update.is_active is False
        assert workspace_update.organization is None  # Not provided

    def test_workspace_model_dump(self):
        """Test model serialization."""
        workspace = Workspace(
            name="Test Workspace",
            description="Test description",
            owner_id=uuid4(),
            organization="Test Org"
        )

        data = workspace.model_dump()

        assert data["name"] == "Test Workspace"
        assert data["description"] == "Test description"
        assert data["organization"] == "Test Org"
        assert data["is_active"] is True
        assert data["is_deleted"] is False
        assert "created_at" in data
        assert "updated_at" in data


class TestWorkspaceInvitation:
    """Test cases for WorkspaceInvitation model."""

    def test_invitation_creation(self):
        """Test workspace invitation creation."""
        from datetime import timedelta

        from langflow.services.database.models.rbac.workspace import WorkspaceInvitation

        workspace_id = uuid4()
        invited_by_id = uuid4()

        invitation = WorkspaceInvitation(
            workspace_id=workspace_id,
            email="test@example.com",
            invited_by_id=invited_by_id,
            invitation_code="test_code_123",
            expires_at=datetime.now(timezone.utc) + timedelta(days=7)
        )

        assert invitation.workspace_id == workspace_id
        assert invitation.email == "test@example.com"
        assert invitation.invited_by_id == invited_by_id
        assert invitation.invitation_code == "test_code_123"
        assert invitation.is_accepted is False
        assert invitation.accepted_at is None
        assert invitation.accepted_by_id is None
        assert isinstance(invitation.created_at, datetime)


class TestWorkspaceIntegration:
    """Integration tests for Workspace with related models."""

    @pytest.fixture
    def sample_user(self):
        """Create a sample user for testing."""
        return User(
            id=uuid4(),
            username="testuser",
            password="hashed_password",
            is_active=True,
            is_superuser=False
        )

    def test_workspace_owner_relationship(self, sample_user):
        """Test workspace-owner relationship."""
        workspace = Workspace(
            name="Test Workspace",
            owner_id=sample_user.id,
            description="Test workspace for owner relationship"
        )

        # In a real test with database, we would verify the relationship
        assert workspace.owner_id == sample_user.id

    def test_workspace_projects_relationship(self):
        """Test workspace-projects relationship."""
        from langflow.services.database.models.rbac.project import Project

        workspace_id = uuid4()
        owner_id = uuid4()

        workspace = Workspace(
            name="Test Workspace",
            owner_id=owner_id
        )
        workspace.id = workspace_id

        project = Project(
            name="Test Project",
            workspace_id=workspace_id,
            owner_id=owner_id
        )

        # In a real test with database, we would verify the relationship
        assert project.workspace_id == workspace_id
