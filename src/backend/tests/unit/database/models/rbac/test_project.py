"""Tests for Project model."""

from __future__ import annotations

from uuid import uuid4

import pytest
from langflow.services.database.models.rbac.project import (
    Project,
    ProjectCreate,
    ProjectRead,
    ProjectStatus,
    ProjectUpdate,
)
from pydantic import ValidationError


class TestProjectStatus:
    """Test ProjectStatus enum."""

    def test_project_status_values(self):
        """Test ProjectStatus enum values."""
        assert ProjectStatus.ACTIVE == "active"
        assert ProjectStatus.INACTIVE == "inactive"
        assert ProjectStatus.ARCHIVED == "archived"
        assert ProjectStatus.DRAFT == "draft"

    def test_project_status_enumeration(self):
        """Test ProjectStatus enumeration."""
        statuses = list(ProjectStatus)
        assert len(statuses) == 4
        assert ProjectStatus.ACTIVE in statuses
        assert ProjectStatus.INACTIVE in statuses
        assert ProjectStatus.ARCHIVED in statuses
        assert ProjectStatus.DRAFT in statuses


class TestProject:
    """Test Project model."""

    def test_project_creation_minimal(self):
        """Test project creation with minimal required fields."""
        workspace_id = uuid4()
        created_by_id = uuid4()

        project = Project(
            name="Test Project",
            workspace_id=workspace_id,
            created_by_id=created_by_id
        )

        assert project.name == "Test Project"
        assert project.workspace_id == workspace_id
        assert project.created_by_id == created_by_id
        assert project.description is None
        assert project.status == ProjectStatus.ACTIVE  # Default value
        assert project.is_active is True  # Default value
        assert project.is_archived is False  # Default value
        assert project.settings == {}  # Default value
        assert project.metadata == {}  # Default value
        assert project.tags == []  # Default value
        assert project.created_at is not None
        assert project.updated_at is not None

    def test_project_creation_full(self):
        """Test project creation with all fields."""
        workspace_id = uuid4()
        created_by_id = uuid4()

        project = Project(
            name="Full Test Project",
            workspace_id=workspace_id,
            created_by_id=created_by_id,
            description="A comprehensive test project",
            status=ProjectStatus.DRAFT,
            is_active=True,
            is_archived=False,
            settings={
                "auto_save": True,
                "version_control": True,
                "collaboration": {"real_time": True}
            },
            metadata={
                "department": "engineering",
                "priority": "high",
                "estimated_completion": "2024-12-31"
            },
            tags=["ml", "production", "critical"]
        )

        assert project.name == "Full Test Project"
        assert project.workspace_id == workspace_id
        assert project.created_by_id == created_by_id
        assert project.description == "A comprehensive test project"
        assert project.status == ProjectStatus.DRAFT
        assert project.is_active is True
        assert project.is_archived is False
        assert project.settings["auto_save"] is True
        assert project.settings["collaboration"]["real_time"] is True
        assert project.metadata["department"] == "engineering"
        assert project.metadata["priority"] == "high"
        assert project.tags == ["ml", "production", "critical"]

    def test_project_name_validation_empty(self):
        """Test project name validation with empty string."""
        with pytest.raises(ValidationError) as exc_info:
            Project(
                name="",
                workspace_id=uuid4(),
                created_by_id=uuid4()
            )

        assert "Project name cannot be empty" in str(exc_info.value)

    def test_project_name_validation_whitespace(self):
        """Test project name validation with whitespace only."""
        with pytest.raises(ValidationError) as exc_info:
            Project(
                name="   ",
                workspace_id=uuid4(),
                created_by_id=uuid4()
            )

        assert "Project name cannot be empty" in str(exc_info.value)

    def test_project_name_validation_too_long(self):
        """Test project name validation with too long string."""
        long_name = "a" * 256  # Exceeds 255 character limit

        with pytest.raises(ValidationError) as exc_info:
            Project(
                name=long_name,
                workspace_id=uuid4(),
                created_by_id=uuid4()
            )

        assert "Project name cannot exceed 255 characters" in str(exc_info.value)

    def test_project_name_validation_valid(self):
        """Test project name validation with valid input."""
        project = Project(
            name="  Valid Project Name  ",
            workspace_id=uuid4(),
            created_by_id=uuid4()
        )

        # Name should be stripped
        assert project.name == "Valid Project Name"

    def test_project_settings_validation_dict(self):
        """Test project settings validation with dict input."""
        settings_dict = {
            "auto_backup": True,
            "backup_interval_hours": 24,
            "max_flows": 100
        }

        project = Project(
            name="Test Project",
            workspace_id=uuid4(),
            created_by_id=uuid4(),
            settings=settings_dict
        )

        assert project.settings == settings_dict

    def test_project_settings_validation_invalid_type(self):
        """Test project settings validation with invalid type."""
        with pytest.raises(ValidationError) as exc_info:
            Project(
                name="Test Project",
                workspace_id=uuid4(),
                created_by_id=uuid4(),
                settings="invalid_settings"  # Should be dict
            )

        assert "Settings must be a dictionary" in str(exc_info.value)

    def test_project_metadata_validation_dict(self):
        """Test project metadata validation with dict input."""
        metadata_dict = {
            "team": "data-science",
            "budget": 50000,
            "deadline": "2024-12-31"
        }

        project = Project(
            name="Test Project",
            workspace_id=uuid4(),
            created_by_id=uuid4(),
            metadata=metadata_dict
        )

        assert project.metadata == metadata_dict

    def test_project_metadata_validation_invalid_type(self):
        """Test project metadata validation with invalid type."""
        with pytest.raises(ValidationError) as exc_info:
            Project(
                name="Test Project",
                workspace_id=uuid4(),
                created_by_id=uuid4(),
                metadata="invalid_metadata"  # Should be dict
            )

        assert "Metadata must be a dictionary" in str(exc_info.value)


class TestProjectCreate:
    """Test ProjectCreate schema."""

    def test_project_create_minimal(self):
        """Test project creation schema with minimal data."""
        project_data = ProjectCreate(name="New Project")

        assert project_data.name == "New Project"
        assert project_data.description is None
        assert project_data.status == ProjectStatus.ACTIVE  # Default
        assert project_data.settings is None
        assert project_data.metadata is None
        assert project_data.tags is None

    def test_project_create_full(self):
        """Test project creation schema with full data."""
        project_data = ProjectCreate(
            name="New Full Project",
            description="A new project with all fields",
            status=ProjectStatus.DRAFT,
            settings={"version_control": True},
            metadata={"priority": "medium"},
            tags=["new", "draft"]
        )

        assert project_data.name == "New Full Project"
        assert project_data.description == "A new project with all fields"
        assert project_data.status == ProjectStatus.DRAFT
        assert project_data.settings == {"version_control": True}
        assert project_data.metadata == {"priority": "medium"}
        assert project_data.tags == ["new", "draft"]


class TestProjectRead:
    """Test ProjectRead schema."""

    def test_project_read_structure(self):
        """Test project read schema structure."""
        project_data = ProjectRead(
            id=uuid4(),
            name="Read Project",
            workspace_id=uuid4(),
            created_by_id=uuid4(),
            description="Test description",
            status=ProjectStatus.ACTIVE,
            is_active=True,
            is_archived=False,
            settings={"auto_save": True},
            metadata={"env": "test"},
            tags=["test"],
            created_at="2024-01-01T00:00:00Z",
            updated_at="2024-01-01T00:00:00Z",
            flow_count=10,
            environment_count=3,
            collaborator_count=5
        )

        assert project_data.id is not None
        assert project_data.name == "Read Project"
        assert project_data.workspace_id is not None
        assert project_data.created_by_id is not None
        assert project_data.status == ProjectStatus.ACTIVE
        assert project_data.flow_count == 10
        assert project_data.environment_count == 3
        assert project_data.collaborator_count == 5


class TestProjectUpdate:
    """Test ProjectUpdate schema."""

    def test_project_update_partial(self):
        """Test project update schema with partial data."""
        update_data = ProjectUpdate(
            name="Updated Project Name",
            description="Updated description"
        )

        assert update_data.name == "Updated Project Name"
        assert update_data.description == "Updated description"
        assert update_data.status is None
        assert update_data.is_active is None
        assert update_data.is_archived is None
        assert update_data.settings is None
        assert update_data.metadata is None
        assert update_data.tags is None

    def test_project_update_full(self):
        """Test project update schema with all fields."""
        update_data = ProjectUpdate(
            name="Fully Updated Project",
            description="Fully updated description",
            status=ProjectStatus.ARCHIVED,
            is_active=False,
            is_archived=True,
            settings={"archived": True},
            metadata={"archived_reason": "completed"},
            tags=["archived", "completed"]
        )

        assert update_data.name == "Fully Updated Project"
        assert update_data.description == "Fully updated description"
        assert update_data.status == ProjectStatus.ARCHIVED
        assert update_data.is_active is False
        assert update_data.is_archived is True
        assert update_data.settings == {"archived": True}
        assert update_data.metadata == {"archived_reason": "completed"}
        assert update_data.tags == ["archived", "completed"]


class TestProjectValidationEdgeCases:
    """Test edge cases for project validation."""

    def test_project_name_unicode(self):
        """Test project name with unicode characters."""
        project = Project(
            name="项目测试 🚀",
            workspace_id=uuid4(),
            created_by_id=uuid4()
        )
        assert project.name == "项目测试 🚀"

    def test_project_settings_empty_dict(self):
        """Test project with empty settings dict."""
        project = Project(
            name="Test Project",
            workspace_id=uuid4(),
            created_by_id=uuid4(),
            settings={}
        )
        assert project.settings == {}

    def test_project_settings_complex_structure(self):
        """Test project with complex settings structure."""
        complex_settings = {
            "collaboration": {
                "real_time_editing": True,
                "commenting": True,
                "version_history": {
                    "enabled": True,
                    "max_versions": 50,
                    "auto_cleanup_days": 90
                }
            },
            "execution": {
                "default_environment": "production",
                "timeout_minutes": 30,
                "retry_attempts": 3,
                "resource_limits": {
                    "cpu_cores": 4,
                    "memory_gb": 8,
                    "storage_gb": 100
                }
            },
            "security": {
                "encryption_at_rest": True,
                "access_logging": True,
                "data_retention_days": 365
            }
        }

        project = Project(
            name="Complex Project",
            workspace_id=uuid4(),
            created_by_id=uuid4(),
            settings=complex_settings
        )

        assert project.settings == complex_settings
        assert project.settings["collaboration"]["real_time_editing"] is True
        assert project.settings["execution"]["resource_limits"]["cpu_cores"] == 4
        assert project.settings["security"]["data_retention_days"] == 365

    def test_project_metadata_complex_structure(self):
        """Test project with complex metadata structure."""
        complex_metadata = {
            "business": {
                "owner": "john.doe@company.com",
                "stakeholders": ["jane.smith@company.com", "bob.johnson@company.com"],
                "budget": {
                    "allocated": 100000,
                    "spent": 25000,
                    "currency": "USD"
                },
                "timeline": {
                    "start_date": "2024-01-01",
                    "end_date": "2024-12-31",
                    "milestones": [
                        {"name": "MVP", "date": "2024-06-01"},
                        {"name": "Beta", "date": "2024-09-01"},
                        {"name": "GA", "date": "2024-12-01"}
                    ]
                }
            },
            "technical": {
                "architecture": "microservices",
                "technologies": ["python", "fastapi", "postgresql", "redis"],
                "dependencies": {
                    "internal": ["user-service", "auth-service"],
                    "external": ["openai-api", "stripe-api"]
                }
            },
            "compliance": {
                "data_classification": "confidential",
                "regulations": ["gdpr", "ccpa"],
                "audit_requirements": True
            }
        }

        project = Project(
            name="Enterprise Project",
            workspace_id=uuid4(),
            created_by_id=uuid4(),
            metadata=complex_metadata
        )

        assert project.metadata == complex_metadata
        assert project.metadata["business"]["budget"]["allocated"] == 100000
        assert "python" in project.metadata["technical"]["technologies"]
        assert project.metadata["compliance"]["audit_requirements"] is True

    def test_project_status_transitions(self):
        """Test project status transitions and implications."""
        workspace_id = uuid4()
        created_by_id = uuid4()

        # Draft project
        draft_project = Project(
            name="Draft Project",
            workspace_id=workspace_id,
            created_by_id=created_by_id,
            status=ProjectStatus.DRAFT,
            is_active=True,
            is_archived=False
        )
        assert draft_project.status == ProjectStatus.DRAFT
        assert draft_project.is_active is True
        assert draft_project.is_archived is False

        # Active project
        active_project = Project(
            name="Active Project",
            workspace_id=workspace_id,
            created_by_id=created_by_id,
            status=ProjectStatus.ACTIVE,
            is_active=True,
            is_archived=False
        )
        assert active_project.status == ProjectStatus.ACTIVE
        assert active_project.is_active is True
        assert active_project.is_archived is False

        # Inactive project
        inactive_project = Project(
            name="Inactive Project",
            workspace_id=workspace_id,
            created_by_id=created_by_id,
            status=ProjectStatus.INACTIVE,
            is_active=False,
            is_archived=False
        )
        assert inactive_project.status == ProjectStatus.INACTIVE
        assert inactive_project.is_active is False
        assert inactive_project.is_archived is False

        # Archived project
        archived_project = Project(
            name="Archived Project",
            workspace_id=workspace_id,
            created_by_id=created_by_id,
            status=ProjectStatus.ARCHIVED,
            is_active=False,
            is_archived=True
        )
        assert archived_project.status == ProjectStatus.ARCHIVED
        assert archived_project.is_active is False
        assert archived_project.is_archived is True

    def test_project_tags_categorization(self):
        """Test project categorization through tags."""
        workspace_id = uuid4()
        created_by_id = uuid4()

        # ML/AI project
        ml_project = Project(
            name="ML Project",
            workspace_id=workspace_id,
            created_by_id=created_by_id,
            tags=["machine-learning", "ai", "data-science", "tensorflow", "production"]
        )
        assert "machine-learning" in ml_project.tags
        assert "ai" in ml_project.tags
        assert "data-science" in ml_project.tags

        # Web development project
        web_project = Project(
            name="Web Project",
            workspace_id=workspace_id,
            created_by_id=created_by_id,
            tags=["web", "frontend", "react", "api", "javascript"]
        )
        assert "web" in web_project.tags
        assert "frontend" in web_project.tags
        assert "react" in web_project.tags

        # Infrastructure project
        infra_project = Project(
            name="Infrastructure Project",
            workspace_id=workspace_id,
            created_by_id=created_by_id,
            tags=["infrastructure", "devops", "kubernetes", "monitoring", "security"]
        )
        assert "infrastructure" in infra_project.tags
        assert "devops" in infra_project.tags
        assert "kubernetes" in infra_project.tags

    def test_project_creation_with_all_none_optionals(self):
        """Test project creation with all optional fields as None."""
        project = Project(
            name="Minimal Project",
            workspace_id=uuid4(),
            created_by_id=uuid4(),
            description=None,
            settings=None,
            metadata=None,
            tags=None
        )

        assert project.name == "Minimal Project"
        assert project.description is None
        # settings, metadata, and tags should get default values
        assert project.settings == {}
        assert project.metadata == {}
        assert project.tags == []


class TestProjectBusinessLogic:
    """Test business logic related to projects."""

    def test_project_lifecycle_states(self):
        """Test project lifecycle state management."""
        workspace_id = uuid4()
        created_by_id = uuid4()

        # New project starts as draft
        new_project = Project(
            name="New Project",
            workspace_id=workspace_id,
            created_by_id=created_by_id,
            status=ProjectStatus.DRAFT
        )
        assert new_project.status == ProjectStatus.DRAFT
        assert new_project.is_active is True  # Can still be edited
        assert new_project.is_archived is False

        # Active project in production
        prod_project = Project(
            name="Production Project",
            workspace_id=workspace_id,
            created_by_id=created_by_id,
            status=ProjectStatus.ACTIVE,
            metadata={"environment": "production", "criticality": "high"}
        )
        assert prod_project.status == ProjectStatus.ACTIVE
        assert prod_project.metadata["environment"] == "production"
        assert prod_project.metadata["criticality"] == "high"

    def test_project_collaboration_settings(self):
        """Test project collaboration and sharing settings."""
        workspace_id = uuid4()
        created_by_id = uuid4()

        # Public project with open collaboration
        public_project = Project(
            name="Public Project",
            workspace_id=workspace_id,
            created_by_id=created_by_id,
            settings={
                "visibility": "public",
                "collaboration": {
                    "allow_comments": True,
                    "allow_forks": True,
                    "allow_contributions": True
                },
                "permissions": {
                    "default_access": "read",
                    "require_approval": False
                }
            }
        )
        assert public_project.settings["visibility"] == "public"
        assert public_project.settings["collaboration"]["allow_comments"] is True

        # Private project with restricted access
        private_project = Project(
            name="Private Project",
            workspace_id=workspace_id,
            created_by_id=created_by_id,
            settings={
                "visibility": "private",
                "collaboration": {
                    "allow_comments": False,
                    "allow_forks": False,
                    "allow_contributions": False
                },
                "permissions": {
                    "default_access": "none",
                    "require_approval": True
                }
            }
        )
        assert private_project.settings["visibility"] == "private"
        assert private_project.settings["collaboration"]["allow_comments"] is False

    def test_project_resource_management(self):
        """Test project resource limits and quotas."""
        workspace_id = uuid4()
        created_by_id = uuid4()

        project = Project(
            name="Resource Limited Project",
            workspace_id=workspace_id,
            created_by_id=created_by_id,
            settings={
                "limits": {
                    "max_flows": 100,
                    "max_environments": 10,
                    "max_storage_gb": 50,
                    "max_execution_time_minutes": 60
                },
                "quotas": {
                    "api_calls_per_day": 10000,
                    "compute_hours_per_month": 100,
                    "bandwidth_gb_per_month": 500
                }
            },
            metadata={
                "resource_usage": {
                    "current_flows": 25,
                    "current_environments": 3,
                    "storage_used_gb": 12.5
                }
            }
        )

        assert project.settings["limits"]["max_flows"] == 100
        assert project.settings["quotas"]["api_calls_per_day"] == 10000
        assert project.metadata["resource_usage"]["current_flows"] == 25
