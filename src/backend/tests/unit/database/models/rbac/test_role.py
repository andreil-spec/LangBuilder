"""Tests for Role model."""

from __future__ import annotations

from uuid import uuid4

import pytest
from langflow.services.database.models.rbac.role import Role, RoleCreate, RoleRead, RoleType, RoleUpdate
from pydantic import ValidationError


class TestRoleType:
    """Test RoleType enum."""

    def test_role_type_values(self):
        """Test RoleType enum values."""
        assert RoleType.SYSTEM == "system"
        assert RoleType.WORKSPACE == "workspace"
        assert RoleType.PROJECT == "project"
        assert RoleType.CUSTOM == "custom"

    def test_role_type_enumeration(self):
        """Test RoleType enumeration."""
        role_types = list(RoleType)
        assert len(role_types) == 4
        assert RoleType.SYSTEM in role_types
        assert RoleType.WORKSPACE in role_types
        assert RoleType.PROJECT in role_types
        assert RoleType.CUSTOM in role_types


class TestRole:
    """Test Role model."""

    def test_role_creation_minimal(self):
        """Test role creation with minimal required fields."""
        workspace_id = uuid4()
        created_by_id = uuid4()

        role = Role(
            name="Test Role",
            workspace_id=workspace_id,
            created_by_id=created_by_id
        )

        assert role.name == "Test Role"
        assert role.workspace_id == workspace_id
        assert role.created_by_id == created_by_id
        assert role.description is None
        assert role.role_type == RoleType.CUSTOM  # Default value
        assert role.is_system is False  # Default value
        assert role.is_active is True  # Default value
        assert role.is_immutable is False  # Default value
        assert role.metadata == {}  # Default value
        assert role.tags == []  # Default value
        assert role.created_at is not None
        assert role.updated_at is not None

    def test_role_creation_full(self):
        """Test role creation with all fields."""
        workspace_id = uuid4()
        created_by_id = uuid4()

        role = Role(
            name="Full Test Role",
            workspace_id=workspace_id,
            created_by_id=created_by_id,
            description="A comprehensive test role",
            role_type=RoleType.WORKSPACE,
            is_system=True,
            is_active=True,
            is_immutable=True,
            metadata={"department": "security", "level": "advanced"},
            tags=["security", "admin", "workspace"]
        )

        assert role.name == "Full Test Role"
        assert role.workspace_id == workspace_id
        assert role.created_by_id == created_by_id
        assert role.description == "A comprehensive test role"
        assert role.role_type == RoleType.WORKSPACE
        assert role.is_system is True
        assert role.is_active is True
        assert role.is_immutable is True
        assert role.metadata == {"department": "security", "level": "advanced"}
        assert role.tags == ["security", "admin", "workspace"]

    def test_role_name_validation_empty(self):
        """Test role name validation with empty string."""
        with pytest.raises(ValidationError) as exc_info:
            Role(name="", workspace_id=uuid4(), created_by_id=uuid4())

        assert "Role name cannot be empty" in str(exc_info.value)

    def test_role_name_validation_whitespace(self):
        """Test role name validation with whitespace only."""
        with pytest.raises(ValidationError) as exc_info:
            Role(name="   ", workspace_id=uuid4(), created_by_id=uuid4())

        assert "Role name cannot be empty" in str(exc_info.value)

    def test_role_name_validation_too_long(self):
        """Test role name validation with too long string."""
        long_name = "a" * 256  # Exceeds 255 character limit

        with pytest.raises(ValidationError) as exc_info:
            Role(name=long_name, workspace_id=uuid4(), created_by_id=uuid4())

        assert "Role name cannot exceed 255 characters" in str(exc_info.value)

    def test_role_name_validation_valid(self):
        """Test role name validation with valid input."""
        role = Role(
            name="  Valid Role Name  ",
            workspace_id=uuid4(),
            created_by_id=uuid4()
        )

        # Name should be stripped
        assert role.name == "Valid Role Name"

    def test_role_metadata_validation_dict(self):
        """Test role metadata validation with dict input."""
        metadata_dict = {
            "permissions_count": 10,
            "created_by_system": True
        }

        role = Role(
            name="Test Role",
            workspace_id=uuid4(),
            created_by_id=uuid4(),
            metadata=metadata_dict
        )

        assert role.metadata == metadata_dict

    def test_role_metadata_validation_invalid_type(self):
        """Test role metadata validation with invalid type."""
        with pytest.raises(ValidationError) as exc_info:
            Role(
                name="Test Role",
                workspace_id=uuid4(),
                created_by_id=uuid4(),
                metadata="invalid_metadata"  # Should be dict
            )

        assert "Metadata must be a dictionary" in str(exc_info.value)


class TestRoleCreate:
    """Test RoleCreate schema."""

    def test_role_create_minimal(self):
        """Test role creation schema with minimal data."""
        role_data = RoleCreate(name="New Role")

        assert role_data.name == "New Role"
        assert role_data.description is None
        assert role_data.role_type == RoleType.CUSTOM  # Default
        assert role_data.is_system is False  # Default
        assert role_data.is_immutable is False  # Default
        assert role_data.metadata is None
        assert role_data.tags is None

    def test_role_create_full(self):
        """Test role creation schema with full data."""
        role_data = RoleCreate(
            name="New Full Role",
            description="A new role with all fields",
            role_type=RoleType.PROJECT,
            is_system=True,
            is_immutable=True,
            metadata={"priority": "high"},
            tags=["important", "project-level"]
        )

        assert role_data.name == "New Full Role"
        assert role_data.description == "A new role with all fields"
        assert role_data.role_type == RoleType.PROJECT
        assert role_data.is_system is True
        assert role_data.is_immutable is True
        assert role_data.metadata == {"priority": "high"}
        assert role_data.tags == ["important", "project-level"]


class TestRoleRead:
    """Test RoleRead schema."""

    def test_role_read_structure(self):
        """Test role read schema structure."""
        role_data = RoleRead(
            id=uuid4(),
            name="Read Role",
            workspace_id=uuid4(),
            created_by_id=uuid4(),
            description="Test description",
            role_type=RoleType.WORKSPACE,
            is_system=False,
            is_active=True,
            is_immutable=False,
            metadata={"env": "test"},
            tags=["test"],
            created_at="2024-01-01T00:00:00Z",
            updated_at="2024-01-01T00:00:00Z",
            permission_count=5,
            assignment_count=3
        )

        assert role_data.id is not None
        assert role_data.name == "Read Role"
        assert role_data.workspace_id is not None
        assert role_data.created_by_id is not None
        assert role_data.role_type == RoleType.WORKSPACE
        assert role_data.permission_count == 5
        assert role_data.assignment_count == 3


class TestRoleUpdate:
    """Test RoleUpdate schema."""

    def test_role_update_partial(self):
        """Test role update schema with partial data."""
        update_data = RoleUpdate(
            name="Updated Role Name",
            description="Updated description"
        )

        assert update_data.name == "Updated Role Name"
        assert update_data.description == "Updated description"
        assert update_data.role_type is None
        assert update_data.is_active is None
        assert update_data.metadata is None
        assert update_data.tags is None

    def test_role_update_full(self):
        """Test role update schema with all fields."""
        update_data = RoleUpdate(
            name="Fully Updated Role",
            description="Fully updated description",
            role_type=RoleType.SYSTEM,
            is_active=False,
            metadata={"updated": True},
            tags=["updated", "v2"]
        )

        assert update_data.name == "Fully Updated Role"
        assert update_data.description == "Fully updated description"
        assert update_data.role_type == RoleType.SYSTEM
        assert update_data.is_active is False
        assert update_data.metadata == {"updated": True}
        assert update_data.tags == ["updated", "v2"]


class TestRoleValidationEdgeCases:
    """Test edge cases for role validation."""

    def test_role_name_unicode(self):
        """Test role name with unicode characters."""
        role = Role(
            name="管理员角色 👑",
            workspace_id=uuid4(),
            created_by_id=uuid4()
        )
        assert role.name == "管理员角色 👑"

    def test_role_metadata_empty_dict(self):
        """Test role with empty metadata dict."""
        role = Role(
            name="Test Role",
            workspace_id=uuid4(),
            created_by_id=uuid4(),
            metadata={}
        )
        assert role.metadata == {}

    def test_role_metadata_complex_structure(self):
        """Test role with complex metadata structure."""
        complex_metadata = {
            "permissions": {
                "resources": ["workspace", "project", "flow"],
                "actions": ["read", "write", "delete", "execute"]
            },
            "constraints": {
                "time_based": {
                    "start_time": "09:00",
                    "end_time": "17:00",
                    "timezone": "UTC"
                },
                "ip_based": {
                    "allowed_ips": ["192.168.1.0/24"],
                    "blocked_ips": []
                }
            },
            "audit": {
                "track_usage": True,
                "retention_days": 90
            }
        }

        role = Role(
            name="Complex Role",
            workspace_id=uuid4(),
            created_by_id=uuid4(),
            metadata=complex_metadata
        )

        assert role.metadata == complex_metadata
        assert role.metadata["permissions"]["resources"] == ["workspace", "project", "flow"]
        assert role.metadata["constraints"]["time_based"]["timezone"] == "UTC"
        assert role.metadata["audit"]["retention_days"] == 90

    def test_role_tags_empty_list(self):
        """Test role with empty tags list."""
        role = Role(
            name="Test Role",
            workspace_id=uuid4(),
            created_by_id=uuid4(),
            tags=[]
        )
        assert role.tags == []

    def test_role_system_vs_immutable_combinations(self):
        """Test different combinations of is_system and is_immutable."""
        workspace_id = uuid4()
        created_by_id = uuid4()

        # System role that is immutable
        system_immutable = Role(
            name="System Immutable",
            workspace_id=workspace_id,
            created_by_id=created_by_id,
            is_system=True,
            is_immutable=True
        )
        assert system_immutable.is_system is True
        assert system_immutable.is_immutable is True

        # System role that is not immutable
        system_mutable = Role(
            name="System Mutable",
            workspace_id=workspace_id,
            created_by_id=created_by_id,
            is_system=True,
            is_immutable=False
        )
        assert system_mutable.is_system is True
        assert system_mutable.is_immutable is False

        # Non-system role that is immutable
        custom_immutable = Role(
            name="Custom Immutable",
            workspace_id=workspace_id,
            created_by_id=created_by_id,
            is_system=False,
            is_immutable=True
        )
        assert custom_immutable.is_system is False
        assert custom_immutable.is_immutable is True

        # Non-system role that is mutable (most common)
        custom_mutable = Role(
            name="Custom Mutable",
            workspace_id=workspace_id,
            created_by_id=created_by_id,
            is_system=False,
            is_immutable=False
        )
        assert custom_mutable.is_system is False
        assert custom_mutable.is_immutable is False

    def test_role_type_defaults_and_overrides(self):
        """Test role type defaults and explicit overrides."""
        workspace_id = uuid4()
        created_by_id = uuid4()

        # Default role type
        default_role = Role(
            name="Default Role",
            workspace_id=workspace_id,
            created_by_id=created_by_id
        )
        assert default_role.role_type == RoleType.CUSTOM

        # Explicit role types
        for role_type in RoleType:
            explicit_role = Role(
                name=f"{role_type.value.title()} Role",
                workspace_id=workspace_id,
                created_by_id=created_by_id,
                role_type=role_type
            )
            assert explicit_role.role_type == role_type

    def test_role_creation_with_all_none_optionals(self):
        """Test role creation with all optional fields as None."""
        role = Role(
            name="Minimal Role",
            workspace_id=uuid4(),
            created_by_id=uuid4(),
            description=None,
            metadata=None,
            tags=None
        )

        assert role.name == "Minimal Role"
        assert role.description is None
        # metadata and tags should get default values
        assert role.metadata == {}
        assert role.tags == []


class TestRoleBusinessLogic:
    """Test business logic related to roles."""

    def test_system_role_implications(self):
        """Test implications of system roles."""
        system_role = Role(
            name="System Admin",
            workspace_id=uuid4(),
            created_by_id=uuid4(),
            role_type=RoleType.SYSTEM,
            is_system=True,
            is_immutable=True
        )

        # System roles are typically immutable and active
        assert system_role.is_system is True
        assert system_role.is_immutable is True
        assert system_role.is_active is True  # Default
        assert system_role.role_type == RoleType.SYSTEM

    def test_workspace_role_implications(self):
        """Test implications of workspace-level roles."""
        workspace_role = Role(
            name="Workspace Manager",
            workspace_id=uuid4(),
            created_by_id=uuid4(),
            role_type=RoleType.WORKSPACE,
            is_system=False
        )

        # Workspace roles are typically custom and mutable
        assert workspace_role.role_type == RoleType.WORKSPACE
        assert workspace_role.is_system is False
        assert workspace_role.is_immutable is False  # Default

    def test_project_role_implications(self):
        """Test implications of project-level roles."""
        project_role = Role(
            name="Project Lead",
            workspace_id=uuid4(),
            created_by_id=uuid4(),
            role_type=RoleType.PROJECT,
            metadata={"scope": "project-specific"}
        )

        # Project roles are scoped to specific projects
        assert project_role.role_type == RoleType.PROJECT
        assert project_role.metadata["scope"] == "project-specific"

    def test_custom_role_flexibility(self):
        """Test flexibility of custom roles."""
        custom_role = Role(
            name="Data Scientist",
            workspace_id=uuid4(),
            created_by_id=uuid4(),
            role_type=RoleType.CUSTOM,
            metadata={
                "permissions": ["read_data", "execute_flows", "create_experiments"],
                "restrictions": ["no_delete", "time_limited"]
            },
            tags=["data-science", "ml", "analytics"]
        )

        # Custom roles can have flexible metadata and tags
        assert custom_role.role_type == RoleType.CUSTOM
        assert "execute_flows" in custom_role.metadata["permissions"]
        assert "no_delete" in custom_role.metadata["restrictions"]
        assert "ml" in custom_role.tags
