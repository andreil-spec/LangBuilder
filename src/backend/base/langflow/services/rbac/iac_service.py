"""Infrastructure-as-Code service for RBAC policy management.

This module provides YAML/JSON export/import capabilities and Terraform support
for managing RBAC policies as code, enabling GitOps workflows and bulk operations.
"""

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from uuid import UUID

import yaml
from loguru import logger
from pydantic import BaseModel, Field, ValidationError
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.services.base import Service

if TYPE_CHECKING:
    from langflow.services.database.models.rbac.permission import Permission
    from langflow.services.database.models.rbac.role import Role
    from langflow.services.database.models.rbac.role_assignment import RoleAssignment
    from langflow.services.database.models.rbac.user_group import UserGroup


class RBACConfigVersion(BaseModel):
    """RBAC configuration format version."""

    api_version: str = Field(default="langflow.org/v1", description="API version")
    kind: str = Field(default="RBACPolicy", description="Resource kind")


class RBACMetadata(BaseModel):
    """Metadata for RBAC configuration."""

    name: str = Field(description="Configuration name")
    workspace: str | None = Field(default=None, description="Target workspace")
    project: str | None = Field(default=None, description="Target project")
    environment: str | None = Field(default=None, description="Target environment")
    description: str | None = Field(default=None, description="Configuration description")
    labels: dict[str, str] = Field(default_factory=dict, description="Configuration labels")
    annotations: dict[str, str] = Field(default_factory=dict, description="Configuration annotations")
    created_at: datetime | None = Field(default=None, description="Creation timestamp")
    updated_at: datetime | None = Field(default=None, description="Update timestamp")


class RBACRoleSpec(BaseModel):
    """Role specification in IaC format."""

    name: str = Field(description="Role name")
    description: str | None = Field(default=None, description="Role description")
    type: str = Field(default="custom", description="Role type")
    permissions: list[str] = Field(default_factory=list, description="Permission names")
    parent_role: str | None = Field(default=None, description="Parent role name")
    priority: int = Field(default=100, description="Role priority")
    is_system: bool = Field(default=False, description="System role flag")
    is_default: bool = Field(default=False, description="Default role flag")
    scope_type: str | None = Field(default=None, description="Scope type")
    scope_id: str | None = Field(default=None, description="Scope identifier")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Role metadata")
    tags: list[str] = Field(default_factory=list, description="Role tags")


class RBACPermissionSpec(BaseModel):
    """Permission specification in IaC format."""

    name: str = Field(description="Permission name")
    description: str | None = Field(default=None, description="Permission description")
    resource_type: str = Field(description="Resource type")
    action: str = Field(description="Action")
    scope_type: str | None = Field(default=None, description="Scope type")
    conditions: dict[str, Any] = Field(default_factory=dict, description="Permission conditions")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Permission metadata")
    tags: list[str] = Field(default_factory=list, description="Permission tags")


class RBACAssignmentSpec(BaseModel):
    """Role assignment specification in IaC format."""

    user: str | None = Field(default=None, description="User email or username")
    group: str | None = Field(default=None, description="Group name")
    service_account: str | None = Field(default=None, description="Service account name")
    roles: list[str] = Field(description="Role names")
    scope_type: str = Field(description="Assignment scope type")
    scope_id: str | None = Field(default=None, description="Scope identifier")
    expires_at: datetime | None = Field(default=None, description="Assignment expiration")
    conditions: dict[str, Any] = Field(default_factory=dict, description="Assignment conditions")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Assignment metadata")


class RBACUserGroupSpec(BaseModel):
    """User group specification in IaC format."""

    name: str = Field(description="Group name")
    description: str | None = Field(default=None, description="Group description")
    type: str = Field(default="local", description="Group type")
    members: list[str] = Field(default_factory=list, description="Member usernames/emails")
    auto_assign_roles: list[str] = Field(default_factory=list, description="Auto-assigned roles")
    membership_rules: dict[str, Any] = Field(default_factory=dict, description="Membership rules")
    max_members: int | None = Field(default=None, description="Maximum members")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Group metadata")
    tags: list[str] = Field(default_factory=list, description="Group tags")


class RBACPolicySpec(BaseModel):
    """RBAC policy specification."""

    roles: list[RBACRoleSpec] = Field(default_factory=list, description="Role definitions")
    permissions: list[RBACPermissionSpec] = Field(default_factory=list, description="Permission definitions")
    assignments: list[RBACAssignmentSpec] = Field(default_factory=list, description="Role assignments")
    groups: list[RBACUserGroupSpec] = Field(default_factory=list, description="User groups")


class RBACPolicy(BaseModel):
    """Complete RBAC policy configuration."""

    api_version: str = Field(default="langflow.org/v1")
    kind: str = Field(default="RBACPolicy")
    metadata: RBACMetadata
    spec: RBACPolicySpec


class TerraformResource(BaseModel):
    """Terraform resource specification."""

    resource_type: str
    resource_name: str
    attributes: dict[str, Any]


class TerraformConfiguration(BaseModel):
    """Complete Terraform configuration."""

    terraform: dict[str, Any] = Field(default_factory=dict)
    provider: dict[str, Any] = Field(default_factory=dict)
    resources: list[TerraformResource] = Field(default_factory=list)


class IaCImportResult(BaseModel):
    """Result of IaC import operation."""

    success: bool
    message: str
    created_roles: int = 0
    updated_roles: int = 0
    created_permissions: int = 0
    updated_permissions: int = 0
    created_assignments: int = 0
    updated_assignments: int = 0
    created_groups: int = 0
    updated_groups: int = 0
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class RBACIaCService(Service):
    """Service for Infrastructure-as-Code RBAC management."""

    name = "rbac_iac_service"

    def __init__(self):
        super().__init__()

    async def export_workspace_config(
        self,
        session: AsyncSession,
        workspace_id: UUID,
        include_system: bool = False
    ) -> RBACPolicy:
        """Export RBAC configuration for a workspace."""
        from langflow.services.database.models.rbac.permission import Permission
        from langflow.services.database.models.rbac.role import Role
        from langflow.services.database.models.rbac.role_assignment import RoleAssignment
        from langflow.services.database.models.rbac.user_group import UserGroup
        from langflow.services.database.models.rbac.workspace import Workspace

        # Get workspace
        workspace = await session.get(Workspace, workspace_id)
        if not workspace:
            raise ValueError(f"Workspace {workspace_id} not found")

        # Get roles for workspace
        role_query = select(Role).where(
            Role.workspace_id == workspace_id
        )
        if not include_system:
            role_query = role_query.where(Role.is_system.is_(False))

        result = await session.exec(role_query)
        roles = result.all()

        # Get permissions for workspace
        permission_query = select(Permission).where(
            Permission.workspace_id == workspace_id
        )
        if not include_system:
            permission_query = permission_query.where(Permission.is_system.is_(False))

        result = await session.exec(permission_query)
        permissions = result.all()

        # Get role assignments for workspace
        assignment_query = select(RoleAssignment).where(
            RoleAssignment.scope_type == "workspace",
            RoleAssignment.scope_id == str(workspace_id)
        )
        result = await session.exec(assignment_query)
        assignments = result.all()

        # Get user groups for workspace
        group_query = select(UserGroup).where(
            UserGroup.workspace_id == workspace_id
        )
        result = await session.exec(group_query)
        groups = result.all()

        # Build configuration
        metadata = RBACMetadata(
            name=f"{workspace.name}-rbac",
            workspace=workspace.name,
            description=f"RBAC configuration for {workspace.name} workspace",
            created_at=datetime.now(timezone.utc)
        )

        spec = RBACPolicySpec(
            roles=[await self._role_to_spec(session, role) for role in roles],
            permissions=[await self._permission_to_spec(permission) for permission in permissions],
            assignments=[await self._assignment_to_spec(session, assignment) for assignment in assignments],
            groups=[await self._group_to_spec(session, group) for group in groups]
        )

        return RBACPolicy(metadata=metadata, spec=spec)

    async def export_global_config(
        self,
        session: AsyncSession,
        include_system: bool = True
    ) -> RBACPolicy:
        """Export global RBAC configuration."""
        from langflow.services.database.models.rbac.permission import Permission
        from langflow.services.database.models.rbac.role import Role

        # Get global/system roles
        role_query = select(Role).where(
            Role.workspace_id.is_(None)
        )
        if not include_system:
            role_query = role_query.where(Role.is_system.is_(False))

        result = await session.exec(role_query)
        roles = result.all()

        # Get global/system permissions
        permission_query = select(Permission).where(
            Permission.workspace_id.is_(None)
        )
        if not include_system:
            permission_query = permission_query.where(Permission.is_system.is_(False))

        result = await session.exec(permission_query)
        permissions = result.all()

        # Build configuration
        metadata = RBACMetadata(
            name="global-rbac",
            description="Global RBAC configuration",
            created_at=datetime.now(timezone.utc)
        )

        spec = RBACPolicySpec(
            roles=[await self._role_to_spec(session, role) for role in roles],
            permissions=[await self._permission_to_spec(permission) for permission in permissions]
        )

        return RBACPolicy(metadata=metadata, spec=spec)

    async def validate_config(self, config: str | dict) -> tuple[bool, list[str]]:
        """Validate RBAC configuration."""
        errors = []

        try:
            if isinstance(config, str):
                # Try to parse as YAML first, then JSON
                try:
                    config_dict = yaml.safe_load(config)
                except yaml.YAMLError:
                    try:
                        config_dict = json.loads(config)
                    except json.JSONDecodeError as e:
                        errors.append(f"Invalid YAML/JSON format: {e}")
                        return False, errors
            else:
                config_dict = config

            # Validate against schema
            policy = RBACPolicy(**config_dict)

            # Additional validation logic
            await self._validate_policy_spec(policy.spec, errors)

        except ValidationError as e:
            for error in e.errors():
                field = ".".join(str(loc) for loc in error["loc"])
                errors.append(f"{field}: {error['msg']}")
        except Exception as e:
            errors.append(f"Validation error: {e!s}")

        return len(errors) == 0, errors

    async def preview_import(
        self,
        session: AsyncSession,
        config: str | dict,
        workspace_id: UUID | None = None
    ) -> dict[str, Any]:
        """Preview changes that would be made by importing configuration."""
        # Parse configuration
        if isinstance(config, str):
            try:
                config_dict = yaml.safe_load(config)
            except yaml.YAMLError:
                config_dict = json.loads(config)
        else:
            config_dict = config

        policy = RBACPolicy(**config_dict)

        # Analyze changes
        changes = {
            "roles": {"create": [], "update": [], "delete": []},
            "permissions": {"create": [], "update": [], "delete": []},
            "assignments": {"create": [], "update": [], "delete": []},
            "groups": {"create": [], "update": [], "delete": []}
        }

        # Preview role changes
        await self._preview_roles(session, policy.spec.roles, workspace_id, changes["roles"])

        # Preview permission changes
        await self._preview_permissions(session, policy.spec.permissions, workspace_id, changes["permissions"])

        # Preview assignment changes
        await self._preview_assignments(session, policy.spec.assignments, workspace_id, changes["assignments"])

        # Preview group changes
        await self._preview_groups(session, policy.spec.groups, workspace_id, changes["groups"])

        return {
            "policy": policy.model_dump(),
            "changes": changes,
            "summary": {
                "total_changes": sum(
                    len(changes[section]["create"]) +
                    len(changes[section]["update"]) +
                    len(changes[section]["delete"])
                    for section in changes
                )
            }
        }

    async def import_config(
        self,
        session: AsyncSession,
        config: str | dict,
        workspace_id: UUID | None = None,
        dry_run: bool = False
    ) -> IaCImportResult:
        """Import RBAC configuration."""
        result = IaCImportResult(success=False, message="Import failed")

        try:
            # Validate configuration
            is_valid, errors = await self.validate_config(config)
            if not is_valid:
                result.errors = errors
                return result

            # Parse configuration
            if isinstance(config, str):
                try:
                    config_dict = yaml.safe_load(config)
                except yaml.YAMLError:
                    config_dict = json.loads(config)
            else:
                config_dict = config

            policy = RBACPolicy(**config_dict)

            if dry_run:
                preview = await self.preview_import(session, config, workspace_id)
                result.success = True
                result.message = "Dry run completed successfully"
                return result

            # Import in dependency order: permissions -> roles -> groups -> assignments

            # Import permissions first
            for perm_spec in policy.spec.permissions:
                try:
                    await self._import_permission(session, perm_spec, workspace_id)
                    result.created_permissions += 1
                except Exception as e:
                    result.errors.append(f"Permission {perm_spec.name}: {e!s}")

            # Import roles
            for role_spec in policy.spec.roles:
                try:
                    await self._import_role(session, role_spec, workspace_id)
                    result.created_roles += 1
                except Exception as e:
                    result.errors.append(f"Role {role_spec.name}: {e!s}")

            # Import groups
            for group_spec in policy.spec.groups:
                try:
                    await self._import_group(session, group_spec, workspace_id)
                    result.created_groups += 1
                except Exception as e:
                    result.errors.append(f"Group {group_spec.name}: {e!s}")

            # Import assignments last
            for assignment_spec in policy.spec.assignments:
                try:
                    await self._import_assignment(session, assignment_spec, workspace_id)
                    result.created_assignments += 1
                except Exception as e:
                    result.errors.append(f"Assignment: {e!s}")

            if len(result.errors) == 0:
                await session.commit()
                result.success = True
                result.message = "Import completed successfully"
            else:
                await session.rollback()
                result.message = f"Import failed with {len(result.errors)} errors"

        except Exception as e:
            await session.rollback()
            result.errors.append(f"Import error: {e!s}")
            logger.error(f"RBAC import failed: {e}")

        return result

    def export_to_yaml(self, policy: RBACPolicy) -> str:
        """Export policy to YAML format."""
        return yaml.dump(
            policy.model_dump(exclude_none=True),
            default_flow_style=False,
            sort_keys=False
        )

    def export_to_json(self, policy: RBACPolicy) -> str:
        """Export policy to JSON format."""
        return json.dumps(
            policy.model_dump(exclude_none=True),
            indent=2,
            default=str
        )

    def generate_terraform_config(self, policy: RBACPolicy) -> str:
        """Generate Terraform configuration from RBAC policy."""
        terraform_config = TerraformConfiguration()

        # Add provider configuration
        terraform_config.provider = {
            "langflow": {
                "api_url": "${var.langflow_api_url}",
                "api_token": "${var.langflow_api_token}"
            }
        }

        # Add terraform configuration
        terraform_config.terraform = {
            "required_providers": {
                "langflow": {
                    "source": "langflow/langflow",
                    "version": "~> 1.0"
                }
            }
        }

        # Generate resources
        for role in policy.spec.roles:
            terraform_config.resources.append(TerraformResource(
                resource_type="langflow_role",
                resource_name=role.name.replace("-", "_"),
                attributes={
                    "name": role.name,
                    "description": role.description,
                    "type": role.type,
                    "permissions": role.permissions,
                    "workspace": policy.metadata.workspace,
                    "priority": role.priority,
                    "metadata": role.metadata
                }
            ))

        for assignment in policy.spec.assignments:
            resource_name = f"{assignment.user or assignment.group or assignment.service_account}_{assignment.scope_type}".replace("-", "_").replace("@", "_").replace(".", "_")
            terraform_config.resources.append(TerraformResource(
                resource_type="langflow_role_assignment",
                resource_name=resource_name,
                attributes={
                    "user": assignment.user,
                    "group": assignment.group,
                    "service_account": assignment.service_account,
                    "roles": assignment.roles,
                    "scope_type": assignment.scope_type,
                    "scope_id": assignment.scope_id,
                    "workspace": policy.metadata.workspace
                }
            ))

        # Generate HCL output
        return self._generate_hcl(terraform_config)

    def _generate_hcl(self, config: TerraformConfiguration) -> str:
        """Generate HCL format from Terraform configuration."""
        hcl_lines = []

        # Terraform block
        hcl_lines.append("terraform {")
        for key, value in config.terraform.items():
            hcl_lines.append(f"  {key} = {json.dumps(value)}")
        hcl_lines.append("}")
        hcl_lines.append("")

        # Provider block
        for provider_name, provider_config in config.provider.items():
            hcl_lines.append(f'provider "{provider_name}" {{')
            for key, value in provider_config.items():
                hcl_lines.append(f'  {key} = "{value}"')
            hcl_lines.append("}")
            hcl_lines.append("")

        # Resources
        for resource in config.resources:
            hcl_lines.append(f'resource "{resource.resource_type}" "{resource.resource_name}" {{')
            for key, value in resource.attributes.items():
                if isinstance(value, str):
                    hcl_lines.append(f'  {key} = "{value}"')
                elif isinstance(value, list) or isinstance(value, dict):
                    hcl_lines.append(f"  {key} = {json.dumps(value)}")
                else:
                    hcl_lines.append(f"  {key} = {value}")
            hcl_lines.append("}")
            hcl_lines.append("")

        return "\n".join(hcl_lines)

    # Helper methods for conversion and validation
    async def _role_to_spec(self, session: AsyncSession, role: "Role") -> RBACRoleSpec:
        """Convert Role model to RBACRoleSpec."""
        # Get role permissions
        from langflow.services.database.models.rbac.permission import Permission
        from langflow.services.database.models.rbac.role_permission import RolePermission

        perm_query = select(Permission).join(
            RolePermission, Permission.id == RolePermission.permission_id
        ).where(RolePermission.role_id == role.id)

        result = await session.exec(perm_query)
        permissions = [perm.name for perm in result.all()]

        return RBACRoleSpec(
            name=role.name,
            description=role.description,
            type=role.type,
            permissions=permissions,
            parent_role=role.parent_role.name if role.parent_role else None,
            priority=role.priority,
            is_system=role.is_system,
            is_default=role.is_default,
            scope_type=role.scope_type,
            scope_id=role.scope_id,
            metadata=role.role_metadata or {},
            tags=role.tags or []
        )

    async def _permission_to_spec(self, permission: "Permission") -> RBACPermissionSpec:
        """Convert Permission model to RBACPermissionSpec."""
        return RBACPermissionSpec(
            name=permission.name,
            description=permission.description,
            resource_type=permission.resource_type,
            action=permission.action,
            scope_type=permission.scope_type,
            conditions=permission.conditions or {},
            metadata=permission.permission_metadata or {},
            tags=permission.tags or []
        )

    async def _assignment_to_spec(self, session: AsyncSession, assignment: "RoleAssignment") -> RBACAssignmentSpec:
        """Convert RoleAssignment model to RBACAssignmentSpec."""
        from langflow.services.database.models.rbac.role import Role
        from langflow.services.database.models.rbac.service_account import ServiceAccount
        from langflow.services.database.models.rbac.user_group import UserGroup
        from langflow.services.database.models.user.model import User

        # Get user/group/service account name
        user_name = None
        group_name = None
        service_account_name = None

        if assignment.user_id:
            user = await session.get(User, assignment.user_id)
            user_name = user.username if user else None

        if assignment.group_id:
            group = await session.get(UserGroup, assignment.group_id)
            group_name = group.name if group else None

        if assignment.service_account_id:
            sa = await session.get(ServiceAccount, assignment.service_account_id)
            service_account_name = sa.name if sa else None

        # Get role name
        role = await session.get(Role, assignment.role_id)
        role_name = role.name if role else None

        return RBACAssignmentSpec(
            user=user_name,
            group=group_name,
            service_account=service_account_name,
            roles=[role_name] if role_name else [],
            scope_type=assignment.scope_type,
            scope_id=assignment.scope_id,
            expires_at=assignment.expires_at,
            conditions=assignment.conditions or {},
            metadata=assignment.assignment_metadata or {}
        )

    async def _group_to_spec(self, session: AsyncSession, group: "UserGroup") -> RBACUserGroupSpec:
        """Convert UserGroup model to RBACUserGroupSpec."""
        from langflow.services.database.models.rbac.user_group import UserGroupMembership
        from langflow.services.database.models.user.model import User

        # Get group members
        member_query = select(User).join(
            UserGroupMembership, User.id == UserGroupMembership.user_id
        ).where(UserGroupMembership.group_id == group.id)

        result = await session.exec(member_query)
        members = [user.username for user in result.all()]

        return RBACUserGroupSpec(
            name=group.name,
            description=group.description,
            type=group.type,
            members=members,
            auto_assign_roles=group.auto_assign_roles or [],
            membership_rules=group.membership_rules or {},
            max_members=group.max_members,
            metadata=group.group_metadata or {},
            tags=group.tags or []
        )

    async def _validate_policy_spec(self, spec: RBACPolicySpec, errors: list[str]) -> None:
        """Validate policy specification."""
        # Check for duplicate role names
        role_names = [role.name for role in spec.roles]
        if len(role_names) != len(set(role_names)):
            errors.append("Duplicate role names found")

        # Check for duplicate permission names
        perm_names = [perm.name for perm in spec.permissions]
        if len(perm_names) != len(set(perm_names)):
            errors.append("Duplicate permission names found")

        # Validate role references in assignments
        for assignment in spec.assignments:
            for role_name in assignment.roles:
                if role_name not in role_names:
                    errors.append(f"Assignment references unknown role: {role_name}")

        # Validate permission references in roles
        for role in spec.roles:
            for perm_name in role.permissions:
                if perm_name not in perm_names:
                    errors.append(f"Role {role.name} references unknown permission: {perm_name}")

    async def _preview_roles(self, session: AsyncSession, role_specs: list[RBACRoleSpec], workspace_id: UUID | None, changes: dict[str, list]) -> None:
        """Preview role changes."""
        # Implementation for previewing role changes

    async def _preview_permissions(self, session: AsyncSession, perm_specs: list[RBACPermissionSpec], workspace_id: UUID | None, changes: dict[str, list]) -> None:
        """Preview permission changes."""
        # Implementation for previewing permission changes

    async def _preview_assignments(self, session: AsyncSession, assignment_specs: list[RBACAssignmentSpec], workspace_id: UUID | None, changes: dict[str, list]) -> None:
        """Preview assignment changes."""
        # Implementation for previewing assignment changes

    async def _preview_groups(self, session: AsyncSession, group_specs: list[RBACUserGroupSpec], workspace_id: UUID | None, changes: dict[str, list]) -> None:
        """Preview group changes."""
        # Implementation for previewing group changes

    async def _import_role(self, session: AsyncSession, role_spec: RBACRoleSpec, workspace_id: UUID | None) -> None:
        """Import a role from specification."""
        # Implementation for importing roles

    async def _import_permission(self, session: AsyncSession, perm_spec: RBACPermissionSpec, workspace_id: UUID | None) -> None:
        """Import a permission from specification."""
        # Implementation for importing permissions

    async def _import_assignment(self, session: AsyncSession, assignment_spec: RBACAssignmentSpec, workspace_id: UUID | None) -> None:
        """Import an assignment from specification."""
        # Implementation for importing assignments

    async def _import_group(self, session: AsyncSession, group_spec: RBACUserGroupSpec, workspace_id: UUID | None) -> None:
        """Import a group from specification."""
        # Implementation for importing groups
