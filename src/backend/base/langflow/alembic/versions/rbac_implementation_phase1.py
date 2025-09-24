"""Add RBAC tables for Phase 1 implementation.

Revision ID: rbac_implementation_phase1
Revises: 3162e83e485f
Create Date: 2025-09-16

This migration adds all RBAC-related tables for the Phase 1 implementation:
- Workspace, Project, Environment (hierarchical organization)
- Role, Permission, RolePermission (access control)
- RoleAssignment (user-role mapping with scope)
- UserGroup, UserGroupMembership (group management)
- ServiceAccount, ServiceAccountToken (automated access)
- AuditLog (compliance and security monitoring)
- Updates to existing tables (User, Flow, ApiKey, Variable)
"""

from __future__ import annotations

import sqlalchemy as sa
import sqlmodel
from alembic import op

# revision identifiers
revision = "rbac_implementation_phase1"
down_revision = "3162e83e485f"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create RBAC tables and update existing tables."""
    # Get database connection and inspector to check for existing tables
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    table_names = inspector.get_table_names()

    # Create Workspace table
    if "workspace" not in table_names:
        op.create_table(
            "workspace",
            sa.Column("id", sa.String(32), primary_key=True),
            sa.Column("name", sa.String(255), nullable=False, index=True),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("organization", sa.String(255), nullable=True, index=True),
            sa.Column("owner_id", sa.String(32), nullable=False, index=True),
            sa.Column("settings", sa.JSON(), nullable=True),
            sa.Column("workspace_metadata", sa.JSON(), nullable=True),
            sa.Column("tags", sa.JSON(), nullable=True),
            sa.Column("is_active", sa.Boolean(), default=True, nullable=False, index=True),
            sa.Column("is_deleted", sa.Boolean(), default=False, nullable=False),
            sa.Column("deletion_requested_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["owner_id"], ["user.id"], name="fk_workspace_owner"),
            sa.UniqueConstraint("owner_id", "name", name="unique_workspace_name_per_owner"),
        )

    # Create SSOConfiguration table
    if "sso_configuration" not in table_names:
        op.create_table(
            'sso_configuration',
            sa.Column('id', sa.String(32), primary_key=True),
            sa.Column('name', sa.String(255), nullable=False, index=True),
            sa.Column('provider_type', sa.String(50), nullable=False, index=True),
            sa.Column('status', sa.String(50), default='draft', nullable=False, index=True),
            sa.Column('workspace_id', sa.String(32), nullable=False, index=True),
            sa.Column('provider_config', sa.JSON(), nullable=False),
            sa.Column('metadata_url', sa.String(500), nullable=True),
            sa.Column('entity_id', sa.String(255), nullable=True, index=True),
            sa.Column('sso_url', sa.String(500), nullable=True),
            sa.Column('x509_cert', sa.Text(), nullable=True),
            sa.Column('attribute_mapping', sa.JSON(), nullable=True),
            sa.Column('group_mapping', sa.JSON(), nullable=True),
            sa.Column('auto_create_users', sa.Boolean(), default=True, nullable=False),
            sa.Column('auto_update_users', sa.Boolean(), default=True, nullable=False),
            sa.Column('default_role_id', sa.String(32), nullable=True),
            sa.Column('allowed_domains', sa.JSON(), nullable=True),
            sa.Column('session_timeout_minutes', sa.Integer(), nullable=True),
            sa.Column('force_authn', sa.Boolean(), default=False, nullable=False),
            sa.Column('sign_requests', sa.Boolean(), default=True, nullable=False),
            sa.Column('encrypt_assertions', sa.Boolean(), default=False, nullable=False),
            sa.Column('certificate_fingerprint', sa.String(128), nullable=True),
            sa.Column('test_configuration', sa.JSON(), nullable=True),
            sa.Column('last_test_date', sa.DateTime(timezone=True), nullable=True),
            sa.Column('last_test_result', sa.String(50), nullable=True),
            sa.Column('last_test_error', sa.Text(), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('created_by_id', sa.String(32), nullable=False),
            sa.Column('updated_by_id', sa.String(32), nullable=True),
            sa.ForeignKeyConstraint(['workspace_id'], ['workspace.id'], name='fk_sso_config_workspace'),
            sa.ForeignKeyConstraint(['created_by_id'], ['user.id'], name='fk_sso_config_created_by'),
            sa.ForeignKeyConstraint(['updated_by_id'], ['user.id'], name='fk_sso_config_updated_by'),
            # TODO: Add role FK after role table is created
            # sa.ForeignKeyConstraint(['default_role_id'], ['role.id'], name='fk_sso_config_default_role'),
            sa.UniqueConstraint('workspace_id', 'name', name='unique_sso_config_name_per_workspace'),
            sa.UniqueConstraint('workspace_id', 'entity_id', name='unique_sso_entity_id_per_workspace')
        )

    # Create Project table
    if "project" not in table_names:
        op.create_table(
            'project',
            sa.Column('id', sa.String(32), primary_key=True),
            sa.Column('name', sa.String(255), nullable=False, index=True),
            sa.Column('description', sa.Text(), nullable=True),
            sa.Column('workspace_id', sa.String(32), nullable=False, index=True),
            sa.Column('owner_id', sa.String(32), nullable=False, index=True),
            sa.Column('repository_url', sa.String(500), nullable=True),
            sa.Column('documentation_url', sa.String(500), nullable=True),
            sa.Column('tags', sa.JSON(), nullable=True),
            sa.Column('project_metadata', sa.JSON(), nullable=True),
            sa.Column('default_environment_id', sa.String(32), nullable=True),
            sa.Column('auto_deploy_enabled', sa.Boolean(), default=False, nullable=False),
            sa.Column('retention_days', sa.Integer(), default=30, nullable=False),
            sa.Column('is_active', sa.Boolean(), default=True, nullable=False, index=True),
            sa.Column('is_archived', sa.Boolean(), default=False, nullable=False),
            sa.Column('archived_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(['workspace_id'], ['workspace.id'], name='fk_project_workspace'),
            sa.ForeignKeyConstraint(['owner_id'], ['user.id'], name='fk_project_owner'),
            sa.UniqueConstraint('workspace_id', 'name', name='unique_project_name_per_workspace')
        )

    # Create Environment table
    if "environment" not in table_names:
        op.create_table(
            'environment',
            sa.Column('id', sa.String(32), primary_key=True),
            sa.Column('name', sa.String(100), nullable=False, index=True),
            sa.Column('description', sa.Text(), nullable=True),
            sa.Column('type', sa.String(50), nullable=False, index=True),
            sa.Column('project_id', sa.String(32), nullable=False, index=True),
            sa.Column('owner_id', sa.String(32), nullable=False, index=True),
            sa.Column('api_endpoint', sa.String(500), nullable=True),
            sa.Column('deployment_url', sa.String(500), nullable=True),
            sa.Column('config', sa.JSON(), nullable=True),
            sa.Column('secrets', sa.JSON(), nullable=True),
            sa.Column('max_instances', sa.Integer(), default=1, nullable=False),
            sa.Column('max_memory_mb', sa.Integer(), default=512, nullable=False),
            sa.Column('max_cpu_cores', sa.Float(), default=0.5, nullable=False),
            sa.Column('timeout_seconds', sa.Integer(), default=300, nullable=False),
            sa.Column('auto_scaling_enabled', sa.Boolean(), default=False, nullable=False),
            sa.Column('min_instances', sa.Integer(), default=0, nullable=False),
            sa.Column('scale_to_zero', sa.Boolean(), default=True, nullable=False),
            sa.Column('is_active', sa.Boolean(), default=True, nullable=False, index=True),
            sa.Column('is_locked', sa.Boolean(), default=False, nullable=False),
            sa.Column('locked_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('locked_by_id', sa.String(32), nullable=True),
            sa.Column('last_deployed_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('last_deployed_by_id', sa.String(32), nullable=True),
            sa.Column('deployment_count', sa.Integer(), default=0, nullable=False),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(['project_id'], ['project.id'], name='fk_environment_project'),
            sa.ForeignKeyConstraint(['owner_id'], ['user.id'], name='fk_environment_owner'),
            sa.ForeignKeyConstraint(['locked_by_id'], ['user.id'], name='fk_environment_locked_by'),
            sa.ForeignKeyConstraint(['last_deployed_by_id'], ['user.id'], name='fk_environment_deployed_by'),
            sa.UniqueConstraint('project_id', 'name', name='unique_environment_name_per_project'),
            sa.UniqueConstraint('project_id', 'type', name='unique_environment_type_per_project')
        )

    # Create Role table
    if "role" not in table_names:
        op.create_table(
            'role',
            sa.Column('id', sa.String(32), primary_key=True),
            sa.Column('name', sa.String(100), nullable=False, index=True),
            sa.Column('description', sa.Text(), nullable=True),
            sa.Column('type', sa.String(50), nullable=False, index=True),
            sa.Column('workspace_id', sa.String(32), nullable=True, index=True),
            sa.Column('created_by_id', sa.String(32), nullable=False, index=True),
            sa.Column('parent_role_id', sa.String(32), nullable=True),
            sa.Column('priority', sa.Integer(), default=0, nullable=False),
            sa.Column('is_system', sa.Boolean(), default=False, nullable=False),
            sa.Column('is_default', sa.Boolean(), default=False, nullable=False),
            sa.Column('is_active', sa.Boolean(), default=True, nullable=False, index=True),
            sa.Column('scope_type', sa.String(50), nullable=True),
            sa.Column('scope_id', sa.String(32), nullable=True),
            sa.Column('role_metadata', sa.JSON(), nullable=True),
            sa.Column('tags', sa.JSON(), nullable=True),
            sa.Column('version', sa.Integer(), default=1, nullable=False),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(['workspace_id'], ['workspace.id'], name='fk_role_workspace'),
            sa.ForeignKeyConstraint(['created_by_id'], ['user.id'], name='fk_role_created_by'),
            sa.ForeignKeyConstraint(['parent_role_id'], ['role.id'], name='fk_role_parent'),
            sa.UniqueConstraint('workspace_id', 'name', name='unique_role_name_per_workspace')
        )

    # Create Permission table
    if "permission" not in table_names:
        op.create_table(
            'permission',
            sa.Column('id', sa.String(32), primary_key=True),
            sa.Column('name', sa.String(200), nullable=False, index=True),
            sa.Column('description', sa.Text(), nullable=True),
            sa.Column('code', sa.String(100), nullable=False, unique=True, index=True),
            sa.Column('resource_type', sa.String(50), nullable=False, index=True),
            sa.Column('action', sa.String(50), nullable=False, index=True),
            sa.Column('scope', sa.String(255), nullable=True),
            sa.Column('conditions', sa.JSON(), nullable=True),
            sa.Column('category', sa.String(50), nullable=True, index=True),
            sa.Column('is_system', sa.Boolean(), default=False, nullable=False),
            sa.Column('is_dangerous', sa.Boolean(), default=False, nullable=False),
            sa.Column('requires_mfa', sa.Boolean(), default=False, nullable=False),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint('resource_type', 'action', 'scope', name='unique_permission_definition')
        )

    # Create RolePermission junction table
    if "role_permission" not in table_names:
        op.create_table(
            'role_permission',
            sa.Column('id', sa.String(32), primary_key=True),
            sa.Column('role_id', sa.String(32), nullable=False, index=True),
            sa.Column('permission_id', sa.String(32), nullable=False, index=True),
            sa.Column('is_granted', sa.Boolean(), default=True, nullable=False),
            sa.Column('conditions', sa.JSON(), nullable=True),
            sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('granted_by_id', sa.String(32), nullable=False),
            sa.Column('granted_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('reason', sa.Text(), nullable=True),
            sa.ForeignKeyConstraint(['role_id'], ['role.id'], name='fk_role_permission_role'),
            sa.ForeignKeyConstraint(['permission_id'], ['permission.id'], name='fk_role_permission_permission'),
            sa.ForeignKeyConstraint(['granted_by_id'], ['user.id'], name='fk_role_permission_granted_by'),
            sa.UniqueConstraint('role_id', 'permission_id', name='unique_role_permission')
        )

    # Create UserGroup table
    if "user_group" not in table_names:
        op.create_table(
            'user_group',
            sa.Column('id', sa.String(32), primary_key=True),
            sa.Column('name', sa.String(255), nullable=False, index=True),
            sa.Column('description', sa.Text(), nullable=True),
            sa.Column('type', sa.String(50), nullable=False, index=True),
            sa.Column('workspace_id', sa.String(32), nullable=False, index=True),
            sa.Column('created_by_id', sa.String(32), nullable=False),
            sa.Column('parent_group_id', sa.String(32), nullable=True),
            sa.Column('external_id', sa.String(255), nullable=True, index=True),
            sa.Column('external_provider', sa.String(100), nullable=True),
            sa.Column('membership_rules', sa.JSON(), nullable=True),
            sa.Column('auto_assign_roles', sa.JSON(), nullable=True),
            sa.Column('is_active', sa.Boolean(), default=True, nullable=False, index=True),
            sa.Column('is_system', sa.Boolean(), default=False, nullable=False),
            sa.Column('max_members', sa.Integer(), nullable=True),
            sa.Column('group_metadata', sa.JSON(), nullable=True),
            sa.Column('tags', sa.JSON(), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('last_synced_at', sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(['workspace_id'], ['workspace.id'], name='fk_user_group_workspace'),
            sa.ForeignKeyConstraint(['created_by_id'], ['user.id'], name='fk_user_group_created_by'),
            sa.ForeignKeyConstraint(['parent_group_id'], ['user_group.id'], name='fk_user_group_parent'),
            sa.UniqueConstraint('workspace_id', 'name', name='unique_group_name_per_workspace'),
            sa.UniqueConstraint('external_id', 'external_provider', name='unique_external_group')
        )

    # Create UserGroupMembership junction table
    if "user_group_membership" not in table_names:
        op.create_table(
            'user_group_membership',
            sa.Column('id', sa.String(32), primary_key=True),
            sa.Column('user_id', sa.String(32), nullable=False, index=True),
            sa.Column('group_id', sa.String(32), nullable=False, index=True),
            sa.Column('role', sa.String(50), nullable=True),
            sa.Column('is_active', sa.Boolean(), default=True, nullable=False),
            sa.Column('joined_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('added_by_id', sa.String(32), nullable=False),
            sa.Column('added_via', sa.String(50), nullable=True),
            sa.ForeignKeyConstraint(['user_id'], ['user.id'], name='fk_group_membership_user'),
            sa.ForeignKeyConstraint(['group_id'], ['user_group.id'], name='fk_group_membership_group'),
            sa.ForeignKeyConstraint(['added_by_id'], ['user.id'], name='fk_group_membership_added_by'),
            sa.UniqueConstraint('user_id', 'group_id', name='unique_user_group_membership')
        )

    # Create ServiceAccount table
    if "service_account" not in table_names:
        op.create_table(
            'service_account',
            sa.Column('id', sa.String(32), primary_key=True),
            sa.Column('name', sa.String(255), nullable=False, index=True),
            sa.Column('description', sa.Text(), nullable=True),
            sa.Column('workspace_id', sa.String(32), nullable=False, index=True),
            sa.Column('created_by_id', sa.String(32), nullable=False),
            sa.Column('service_type', sa.String(50), nullable=True, index=True),
            sa.Column('integration_name', sa.String(100), nullable=True),
            sa.Column('token_prefix', sa.String(20), nullable=True),
            sa.Column('max_tokens', sa.Integer(), default=5, nullable=False),
            sa.Column('token_expiry_days', sa.Integer(), nullable=True),
            sa.Column('allowed_ips', sa.JSON(), nullable=True),
            sa.Column('allowed_origins', sa.JSON(), nullable=True),
            sa.Column('rate_limit_per_minute', sa.Integer(), nullable=True),
            sa.Column('default_scope_type', sa.String(50), nullable=True),
            sa.Column('default_scope_id', sa.String(32), nullable=True),
            sa.Column('allowed_permissions', sa.JSON(), nullable=True),
            sa.Column('is_active', sa.Boolean(), default=True, nullable=False, index=True),
            sa.Column('is_locked', sa.Boolean(), default=False, nullable=False),
            sa.Column('locked_reason', sa.Text(), nullable=True),
            sa.Column('locked_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('usage_count', sa.Integer(), default=0, nullable=False),
            sa.Column('service_metadata', sa.JSON(), nullable=True),
            sa.Column('tags', sa.JSON(), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(['workspace_id'], ['workspace.id'], name='fk_service_account_workspace'),
            sa.ForeignKeyConstraint(['created_by_id'], ['user.id'], name='fk_service_account_created_by'),
            sa.UniqueConstraint('workspace_id', 'name', name='unique_service_account_name_per_workspace')
        )

    # Create ServiceAccountToken table
    if "service_account_token" not in table_names:
        op.create_table(
            'service_account_token',
            sa.Column('id', sa.String(32), primary_key=True),
            sa.Column('service_account_id', sa.String(32), nullable=False, index=True),
            sa.Column('name', sa.String(255), nullable=False, index=True),
            sa.Column('token_hash', sa.String(255), nullable=False, unique=True, index=True),
            sa.Column('token_prefix', sa.String(20), nullable=False),
            sa.Column('scoped_permissions', sa.JSON(), nullable=True),
            sa.Column('scope_type', sa.String(50), nullable=True),
            sa.Column('scope_id', sa.String(32), nullable=True),
            sa.Column('allowed_ips', sa.JSON(), nullable=True),
            sa.Column('is_active', sa.Boolean(), default=True, nullable=False, index=True),
            sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('usage_count', sa.Integer(), default=0, nullable=False),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('revoked_by_id', sa.String(32), nullable=True),
            sa.Column('revoke_reason', sa.Text(), nullable=True),
            sa.Column('created_by_id', sa.String(32), nullable=False),
            sa.ForeignKeyConstraint(['service_account_id'], ['service_account.id'], name='fk_token_service_account'),
            sa.ForeignKeyConstraint(['created_by_id'], ['user.id'], name='fk_token_created_by'),
            sa.ForeignKeyConstraint(['revoked_by_id'], ['user.id'], name='fk_token_revoked_by'),
            sa.UniqueConstraint('service_account_id', 'name', name='unique_token_name_per_service_account')
        )

    # Create RoleAssignment table
    if "role_assignment" not in table_names:
        op.create_table(
            'role_assignment',
            sa.Column('id', sa.String(32), primary_key=True),
            sa.Column('role_id', sa.String(32), nullable=False, index=True),
            sa.Column('assignment_type', sa.String(50), nullable=False, index=True),
            sa.Column('scope_type', sa.String(50), nullable=False, index=True),
            sa.Column('user_id', sa.String(32), nullable=True, index=True),
            sa.Column('group_id', sa.String(32), nullable=True, index=True),
            sa.Column('service_account_id', sa.String(32), nullable=True, index=True),
            sa.Column('workspace_id', sa.String(32), nullable=True, index=True),
            sa.Column('project_id', sa.String(32), nullable=True, index=True),
            sa.Column('environment_id', sa.String(32), nullable=True, index=True),
            sa.Column('flow_id', sa.String(32), nullable=True, index=True),
            sa.Column('component_id', sa.String(32), nullable=True, index=True),
            sa.Column('is_active', sa.Boolean(), default=True, nullable=False, index=True),
            sa.Column('is_inherited', sa.Boolean(), default=False, nullable=False),
            sa.Column('valid_from', sa.DateTime(timezone=True), nullable=True),
            sa.Column('valid_until', sa.DateTime(timezone=True), nullable=True),
            sa.Column('conditions', sa.JSON(), nullable=True),
            sa.Column('ip_restrictions', sa.JSON(), nullable=True),
            sa.Column('time_restrictions', sa.JSON(), nullable=True),
            sa.Column('reason', sa.Text(), nullable=True),
            sa.Column('assigned_by_id', sa.String(32), nullable=False),
            sa.Column('approved_by_id', sa.String(32), nullable=True),
            sa.Column('approval_date', sa.DateTime(timezone=True), nullable=True),
            sa.Column('assigned_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(['role_id'], ['role.id'], name='fk_assignment_role'),
            sa.ForeignKeyConstraint(['user_id'], ['user.id'], name='fk_assignment_user'),
            sa.ForeignKeyConstraint(['group_id'], ['user_group.id'], name='fk_assignment_group'),
            sa.ForeignKeyConstraint(['service_account_id'], ['service_account.id'], name='fk_assignment_service_account'),
            sa.ForeignKeyConstraint(['workspace_id'], ['workspace.id'], name='fk_assignment_workspace'),
            sa.ForeignKeyConstraint(['project_id'], ['project.id'], name='fk_assignment_project'),
            sa.ForeignKeyConstraint(['environment_id'], ['environment.id'], name='fk_assignment_environment'),
            sa.ForeignKeyConstraint(['flow_id'], ['flow.id'], name='fk_assignment_flow'),
            sa.ForeignKeyConstraint(['assigned_by_id'], ['user.id'], name='fk_assignment_assigned_by'),
            sa.ForeignKeyConstraint(['approved_by_id'], ['user.id'], name='fk_assignment_approved_by'),
            sa.UniqueConstraint('role_id', 'user_id', 'workspace_id', 'project_id', 'environment_id',
                               'flow_id', 'component_id', name='unique_role_assignment'),
            sa.Index('idx_user_workspace', 'user_id', 'workspace_id'),
            sa.Index('idx_user_project', 'user_id', 'project_id'),
            sa.Index('idx_group_workspace', 'group_id', 'workspace_id'),
            sa.Index('idx_active_assignments', 'is_active', 'assignment_type')
        )

    # Create AuditLog table
    if "audit_log" not in table_names:
        op.create_table(
            'audit_log',
            sa.Column('id', sa.String(32), primary_key=True),
            sa.Column('event_type', sa.String(50), nullable=False, index=True),
            sa.Column('action', sa.String(100), nullable=False, index=True),
            sa.Column('outcome', sa.String(50), nullable=False, index=True),
            sa.Column('actor_type', sa.String(50), nullable=False, index=True),
            sa.Column('actor_id', sa.String(32), nullable=True, index=True),
            sa.Column('actor_name', sa.String(255), nullable=True),
            sa.Column('actor_email', sa.String(255), nullable=True),
            sa.Column('resource_type', sa.String(50), nullable=True, index=True),
            sa.Column('resource_id', sa.String(32), nullable=True, index=True),
            sa.Column('resource_name', sa.String(255), nullable=True),
            sa.Column('workspace_id', sa.String(32), nullable=True, index=True),
            sa.Column('project_id', sa.String(32), nullable=True, index=True),
            sa.Column('environment_id', sa.String(32), nullable=True),
            sa.Column('ip_address', sa.String(45), nullable=True, index=True),
            sa.Column('user_agent', sa.String(500), nullable=True),
            sa.Column('session_id', sa.String(255), nullable=True, index=True),
            sa.Column('request_id', sa.String(255), nullable=True, index=True),
            sa.Column('api_endpoint', sa.String(500), nullable=True),
            sa.Column('http_method', sa.String(10), nullable=True),
            sa.Column('error_message', sa.Text(), nullable=True),
            sa.Column('event_metadata', sa.JSON(), nullable=True),
            sa.Column('retention_required', sa.Boolean(), default=True, nullable=False),
            sa.Column('sensitive_data_accessed', sa.Boolean(), default=False, nullable=False),
            sa.Column('compliance_tags', sa.JSON(), nullable=True),
            sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False, index=True),
            sa.ForeignKeyConstraint(['workspace_id'], ['workspace.id'], name='fk_audit_workspace'),
            sa.Index('idx_audit_timestamp', 'timestamp'),
            sa.Index('idx_audit_actor', 'actor_type', 'actor_id'),
            sa.Index('idx_audit_resource', 'resource_type', 'resource_id'),
            sa.Index('idx_audit_workspace', 'workspace_id', 'timestamp'),
            sa.Index('idx_audit_event', 'event_type', 'outcome'),
            sa.Index('idx_audit_compliance', 'retention_required', 'sensitive_data_accessed')
        )

    # Create EnvironmentDeployment table
    if "environment_deployment" not in table_names:
        op.create_table(
            'environment_deployment',
            sa.Column('id', sa.String(32), primary_key=True),
            sa.Column('environment_id', sa.String(32), nullable=False, index=True),
            sa.Column('version', sa.String(50), nullable=False, index=True),
            sa.Column('commit_hash', sa.String(40), nullable=True),
            sa.Column('deployment_type', sa.String(50), default='manual', nullable=False),
            sa.Column('status', sa.String(50), default='pending', nullable=False, index=True),
            sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('error_message', sa.Text(), nullable=True),
            sa.Column('deployed_by_id', sa.String(32), nullable=False),
            sa.Column('deployment_config', sa.JSON(), nullable=True),
            sa.Column('artifacts', sa.JSON(), nullable=True),
            sa.ForeignKeyConstraint(['environment_id'], ['environment.id'], name='fk_deployment_environment'),
            sa.ForeignKeyConstraint(['deployed_by_id'], ['user.id'], name='fk_deployment_user')
        )

    # Create WorkspaceInvitation table
    if "workspace_invitation" not in table_names:
        op.create_table(
            'workspace_invitation',
            sa.Column('id', sa.String(32), primary_key=True),
            sa.Column('workspace_id', sa.String(32), nullable=False, index=True),
            sa.Column('email', sa.String(255), nullable=False, index=True),
            sa.Column('role_id', sa.String(32), nullable=True),
            sa.Column('invited_by_id', sa.String(32), nullable=False),
            sa.Column('invitation_code', sa.String(100), nullable=False, unique=True, index=True),
            sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('is_accepted', sa.Boolean(), default=False, nullable=False),
            sa.Column('accepted_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('accepted_by_id', sa.String(32), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(['workspace_id'], ['workspace.id'], name='fk_invitation_workspace'),
            sa.ForeignKeyConstraint(['role_id'], ['role.id'], name='fk_invitation_role'),
            sa.ForeignKeyConstraint(['invited_by_id'], ['user.id'], name='fk_invitation_invited_by'),
            sa.ForeignKeyConstraint(['accepted_by_id'], ['user.id'], name='fk_invitation_accepted_by')
        )

    # Update existing Flow table to add RBAC relationships
    if "flow" in table_names:
        flow_columns = [column["name"] for column in inspector.get_columns("flow")]
        flow_indexes = [index["name"] for index in inspector.get_indexes("flow")]
        flow_foreign_keys = [fk["referred_table"] for fk in inspector.get_foreign_keys("flow")]

        if "project_id" not in flow_columns:
            op.add_column('flow', sa.Column('project_id', sa.String(32), nullable=True))
        if "environment_id" not in flow_columns:
            op.add_column('flow', sa.Column('environment_id', sa.String(32), nullable=True))
        if "ix_flow_project_id" not in flow_indexes:
            op.create_index('ix_flow_project_id', 'flow', ['project_id'])
        if "ix_flow_environment_id" not in flow_indexes:
            op.create_index('ix_flow_environment_id', 'flow', ['environment_id'])
        # TODO: Fix SQLite foreign key constraints using batch mode
        # if "project" not in flow_foreign_keys:
        #     op.create_foreign_key('fk_flow_project', 'flow', 'project', ['project_id'], ['id'])
        # if "environment" not in flow_foreign_keys:
        #     op.create_foreign_key('fk_flow_environment', 'flow', 'environment', ['environment_id'], ['id'])

    # Update existing ApiKey table to add service account relationships
    if "apikey" in table_names:
        api_key_columns = [column["name"] for column in inspector.get_columns("apikey")]
        api_key_indexes = [index["name"] for index in inspector.get_indexes("apikey")]
        api_key_foreign_keys = [fk["referred_table"] for fk in inspector.get_foreign_keys("apikey")]

        if "service_account_id" not in api_key_columns:
            op.add_column('apikey', sa.Column('service_account_id', sa.String(32), nullable=True))
        if "scoped_permissions" not in api_key_columns:
            op.add_column('apikey', sa.Column('scoped_permissions', sa.JSON(), nullable=True))
        if "scope_type" not in api_key_columns:
            op.add_column('apikey', sa.Column('scope_type', sa.String(50), nullable=True))
        if "scope_id" not in api_key_columns:
            op.add_column('apikey', sa.Column('scope_id', sa.String(32), nullable=True))
        if "workspace_id" not in api_key_columns:
            op.add_column('apikey', sa.Column('workspace_id', sa.String(32), nullable=True))
        if "ix_apikey_service_account_id" not in api_key_indexes:
            op.create_index('ix_apikey_service_account_id', 'apikey', ['service_account_id'])
        if "ix_apikey_workspace_id" not in api_key_indexes:
            op.create_index('ix_apikey_workspace_id', 'apikey', ['workspace_id'])
        # TODO: Fix SQLite foreign key constraints using batch mode
        # if "service_account" not in api_key_foreign_keys:
        #     op.create_foreign_key('fk_api_key_service_account', 'apikey', 'service_account', ['service_account_id'], ['id'])
        # if "workspace" not in api_key_foreign_keys:
        #     op.create_foreign_key('fk_api_key_workspace', 'apikey', 'workspace', ['workspace_id'], ['id'])

    # Update existing Variable table to add environment relationships
    if "variable" in table_names:
        variable_columns = [column["name"] for column in inspector.get_columns("variable")]
        variable_indexes = [index["name"] for index in inspector.get_indexes("variable")]
        variable_foreign_keys = [fk["referred_table"] for fk in inspector.get_foreign_keys("variable")]

        if "environment_id" not in variable_columns:
            op.add_column('variable', sa.Column('environment_id', sa.String(32), nullable=True))
        if "ix_variable_environment_id" not in variable_indexes:
            op.create_index('ix_variable_environment_id', 'variable', ['environment_id'])
        # TODO: Fix SQLite foreign key constraints using batch mode
        # if "environment" not in variable_foreign_keys:
        #     op.create_foreign_key('fk_variable_environment', 'variable', 'environment', ['environment_id'], ['id'])


def downgrade():
    """Remove RBAC tables and restore original table structure."""

    # Remove foreign keys and columns from existing tables
    op.drop_constraint('fk_variable_environment', 'variable', type_='foreignkey')
    op.drop_index('idx_variable_environment', 'variable')
    op.drop_column('variable', 'environment_id')

    op.drop_constraint('fk_api_key_workspace', 'api_key', type_='foreignkey')
    op.drop_constraint('fk_api_key_service_account', 'api_key', type_='foreignkey')
    op.drop_index('idx_api_key_workspace', 'api_key')
    op.drop_index('idx_api_key_service_account', 'api_key')
    op.drop_column('api_key', 'workspace_id')
    op.drop_column('api_key', 'scope_id')
    op.drop_column('api_key', 'scope_type')
    op.drop_column('api_key', 'scoped_permissions')
    op.drop_column('api_key', 'service_account_id')

    op.drop_constraint('fk_flow_environment', 'flow', type_='foreignkey')
    op.drop_constraint('fk_flow_project', 'flow', type_='foreignkey')
    op.drop_index('idx_flow_environment', 'flow')
    op.drop_index('idx_flow_project', 'flow')
    op.drop_column('flow', 'environment_id')
    op.drop_column('flow', 'project_id')

    # Drop all RBAC tables
    op.drop_table('workspace_invitation')
    op.drop_table('environment_deployment')
    op.drop_table('audit_log')
    op.drop_table('role_assignment')
    op.drop_table('service_account_token')
    op.drop_table('service_account')
    op.drop_table('user_group_membership')
    op.drop_table('user_group')
    op.drop_table('role_permission')
    op.drop_table('permission')
    op.drop_table('role')
    op.drop_table('environment')
    op.drop_table('project')
    op.drop_table('sso_configuration')
    op.drop_table('workspace')
