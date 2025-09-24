"""RBAC Phase 3: Business Logic Services & SSO Integration

Revision ID: rbac_phase3_services
Revises: rbac_implementation_phase1
Create Date: 2024-09-17 15:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import JSON, Text, Boolean, DateTime, String, ForeignKey

# revision identifiers, used by Alembic.
revision = 'rbac_phase3_services'
down_revision = 'rbac_implementation_phase1'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create Phase 3 business logic and SSO integration tables."""

    # Create SSO Configuration table
    op.create_table(
        'sso_configuration',
        sa.Column('id', sa.String(length=32), primary_key=True),
        sa.Column('name', sa.String(length=255), nullable=False, index=True),
        sa.Column('protocol', sa.String(length=50), nullable=False),  # OIDC, OAUTH2, SAML2
        sa.Column('provider_url', sa.String(length=500), nullable=False),
        sa.Column('client_id', sa.String(length=255), nullable=False),
        sa.Column('client_secret', sa.Text(), nullable=True),  # Encrypted
        sa.Column('scopes', JSON, nullable=True),
        sa.Column('attribute_mapping', JSON, nullable=True),
        sa.Column('is_active', sa.Boolean(), default=True, nullable=False),
        sa.Column('auto_provision_users', sa.Boolean(), default=False, nullable=False),
        sa.Column('enforce_sso', sa.Boolean(), default=False, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False),
        sa.Column('created_by_id', sa.String(length=32), sa.ForeignKey('user.id'), nullable=False),
        sa.Column('metadata', JSON, nullable=True),
    )

    # Create indexes for SSO configuration
    op.create_index('ix_sso_configuration_protocol', 'sso_configuration', ['protocol'])
    op.create_index('ix_sso_configuration_active', 'sso_configuration', ['is_active'])

    # Create SCIM Configuration table
    op.create_table(
        'scim_configuration',
        sa.Column('id', sa.String(length=32), primary_key=True),
        sa.Column('provider_name', sa.String(length=255), nullable=False, index=True),
        sa.Column('base_url', sa.String(length=500), nullable=False),
        sa.Column('bearer_token', sa.Text(), nullable=False),  # Encrypted
        sa.Column('user_endpoint', sa.String(length=100), default='/Users', nullable=False),
        sa.Column('group_endpoint', sa.String(length=100), default='/Groups', nullable=False),
        sa.Column('sync_interval_minutes', sa.Integer(), default=60, nullable=False),
        sa.Column('last_sync_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('sync_status', sa.String(length=50), default='pending', nullable=False),
        sa.Column('is_active', sa.Boolean(), default=True, nullable=False),
        sa.Column('user_attribute_mapping', JSON, nullable=True),
        sa.Column('group_attribute_mapping', JSON, nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False),
        sa.Column('created_by_id', sa.String(length=32), sa.ForeignKey('user.id'), nullable=False),
    )

    # Create indexes for SCIM configuration
    op.create_index('ix_scim_configuration_status', 'scim_configuration', ['sync_status'])
    op.create_index('ix_scim_configuration_active', 'scim_configuration', ['is_active'])

    # Create Enhanced Audit Log table for Phase 3
    op.create_table(
        'rbac_audit_log',
        sa.Column('id', sa.String(length=32), primary_key=True),
        sa.Column('event_id', sa.String(length=64), nullable=False, unique=True, index=True),
        sa.Column('event_type', sa.String(length=100), nullable=False, index=True),
        sa.Column('event_category', sa.String(length=50), nullable=False, index=True),  # authentication, authorization, role_management
        sa.Column('actor_type', sa.String(length=50), nullable=False),  # user, service_account, system
        sa.Column('actor_id', sa.String(length=32), nullable=True, index=True),
        sa.Column('actor_email', sa.String(length=255), nullable=True, index=True),
        sa.Column('subject_type', sa.String(length=50), nullable=True),  # user, role, workspace, etc.
        sa.Column('subject_id', sa.String(length=32), nullable=True, index=True),
        sa.Column('resource_type', sa.String(length=50), nullable=True, index=True),
        sa.Column('resource_id', sa.String(length=32), nullable=True, index=True),
        sa.Column('action', sa.String(length=100), nullable=False, index=True),
        sa.Column('outcome', sa.String(length=20), nullable=False, index=True),  # success, failure, denied
        sa.Column('reason', sa.String(length=500), nullable=True),
        sa.Column('session_id', sa.String(length=64), nullable=True, index=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True, index=True),  # IPv6 compatible
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('before_state', JSON, nullable=True),
        sa.Column('after_state', JSON, nullable=True),
        sa.Column('additional_data', JSON, nullable=True),
        sa.Column('compliance_flags', JSON, nullable=True),  # SOC2, GDPR, etc.
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('workspace_id', sa.String(length=32), sa.ForeignKey('workspace.id'), nullable=True, index=True),
        sa.Column('project_id', sa.String(length=32), sa.ForeignKey('project.id'), nullable=True, index=True),
    )

    # Create indexes for audit log performance
    op.create_index('ix_rbac_audit_log_timestamp', 'rbac_audit_log', ['created_at'])
    op.create_index('ix_rbac_audit_log_actor_time', 'rbac_audit_log', ['actor_id', 'created_at'])
    op.create_index('ix_rbac_audit_log_resource_time', 'rbac_audit_log', ['resource_type', 'resource_id', 'created_at'])
    op.create_index('ix_rbac_audit_log_workspace_time', 'rbac_audit_log', ['workspace_id', 'created_at'])
    op.create_index('ix_rbac_audit_log_category_time', 'rbac_audit_log', ['event_category', 'created_at'])

    # Service Account Token table already created in phase 1 migration
    # Adding additional indexes and constraints if needed

    # Create indexes for token management
    op.create_index('ix_service_account_token_expires', 'service_account_token', ['expires_at'])
    op.create_index('ix_service_account_token_active', 'service_account_token', ['is_active'])
    op.create_index('ix_service_account_token_scope', 'service_account_token', ['scope_type', 'scope_id'])

    # Create SSO Session table for session management
    op.create_table(
        'sso_session',
        sa.Column('id', sa.String(length=32), primary_key=True),
        sa.Column('session_id', sa.String(length=128), nullable=False, unique=True, index=True),
        sa.Column('sso_config_id', sa.String(length=32), sa.ForeignKey('sso_configuration.id'), nullable=False),
        sa.Column('user_id', sa.String(length=32), sa.ForeignKey('user.id'), nullable=True, index=True),
        sa.Column('external_user_id', sa.String(length=255), nullable=False, index=True),
        sa.Column('state', sa.String(length=128), nullable=False, unique=True),
        sa.Column('nonce', sa.String(length=128), nullable=True),
        sa.Column('redirect_uri', sa.String(length=500), nullable=True),
        sa.Column('status', sa.String(length=50), default='pending', nullable=False, index=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('claims', JSON, nullable=True),  # Store SSO claims
        sa.Column('error_code', sa.String(length=100), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
    )

    # Create indexes for SSO session management
    op.create_index('ix_sso_session_expires', 'sso_session', ['expires_at'])
    op.create_index('ix_sso_session_status', 'sso_session', ['status'])
    op.create_index('ix_sso_session_user', 'sso_session', ['user_id', 'created_at'])

    # Create Break-Glass Access Log table
    op.create_table(
        'break_glass_access',
        sa.Column('id', sa.String(length=32), primary_key=True),
        sa.Column('user_id', sa.String(length=32), sa.ForeignKey('user.id'), nullable=False, index=True),
        sa.Column('justification', sa.Text(), nullable=False),
        sa.Column('target_resource_type', sa.String(length=50), nullable=False),
        sa.Column('target_resource_id', sa.String(length=32), nullable=False, index=True),
        sa.Column('requested_action', sa.String(length=100), nullable=False),
        sa.Column('approved_by_id', sa.String(length=32), sa.ForeignKey('user.id'), nullable=True),
        sa.Column('approval_status', sa.String(length=20), default='pending', nullable=False, index=True),
        sa.Column('access_granted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('access_expires_at', sa.DateTime(timezone=True), nullable=True, index=True),
        sa.Column('access_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('session_id', sa.String(length=64), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('workspace_id', sa.String(length=32), sa.ForeignKey('workspace.id'), nullable=True, index=True),
        sa.Column('additional_context', JSON, nullable=True),
    )

    # Create indexes for break-glass access
    op.create_index('ix_break_glass_access_status', 'break_glass_access', ['approval_status'])
    op.create_index('ix_break_glass_access_expires', 'break_glass_access', ['access_expires_at'])
    op.create_index('ix_break_glass_access_resource', 'break_glass_access', ['target_resource_type', 'target_resource_id'])

    # Create Performance Metrics table for monitoring
    op.create_table(
        'rbac_performance_metrics',
        sa.Column('id', sa.String(length=32), primary_key=True),
        sa.Column('metric_type', sa.String(length=50), nullable=False, index=True),  # permission_check, cache_hit, etc.
        sa.Column('operation', sa.String(length=100), nullable=False, index=True),
        sa.Column('duration_ms', sa.Float(), nullable=False),
        sa.Column('cache_hit', sa.Boolean(), default=False, nullable=False),
        sa.Column('user_id', sa.String(length=32), nullable=True, index=True),
        sa.Column('resource_type', sa.String(length=50), nullable=True, index=True),
        sa.Column('workspace_id', sa.String(length=32), nullable=True, index=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('additional_data', JSON, nullable=True),
    )

    # Create indexes for performance monitoring
    op.create_index('ix_rbac_metrics_type_time', 'rbac_performance_metrics', ['metric_type', 'created_at'])
    op.create_index('ix_rbac_metrics_operation_time', 'rbac_performance_metrics', ['operation', 'created_at'])
    op.create_index('ix_rbac_metrics_duration', 'rbac_performance_metrics', ['duration_ms'])

    # Add new columns to existing user table for SSO integration
    op.add_column('user', sa.Column('sso_provider_id', sa.String(length=32), nullable=True))
    op.add_column('user', sa.Column('external_user_id', sa.String(length=255), nullable=True))
    op.add_column('user', sa.Column('sso_metadata', JSON, nullable=True))
    op.add_column('user', sa.Column('last_sso_login_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('user', sa.Column('force_password_change', sa.Boolean(), default=False, nullable=False))

    # Create indexes for SSO user lookup
    op.create_index('ix_user_sso_provider', 'user', ['sso_provider_id', 'external_user_id'])
    op.create_index('ix_user_external_id', 'user', ['external_user_id'])

    # Create foreign key constraint for SSO provider
    op.create_foreign_key(
        'fk_user_sso_provider',
        'user', 'sso_configuration',
        ['sso_provider_id'], ['id'],
        ondelete='SET NULL'
    )


def downgrade() -> None:
    """Remove Phase 3 business logic and SSO integration tables."""

    # Drop foreign key constraints first
    op.drop_constraint('fk_user_sso_provider', 'user', type_='foreignkey')

    # Drop indexes
    op.drop_index('ix_user_external_id', 'user')
    op.drop_index('ix_user_sso_provider', 'user')

    # Remove columns from user table
    op.drop_column('user', 'force_password_change')
    op.drop_column('user', 'last_sso_login_at')
    op.drop_column('user', 'sso_metadata')
    op.drop_column('user', 'external_user_id')
    op.drop_column('user', 'sso_provider_id')

    # Drop performance metrics table
    op.drop_index('ix_rbac_metrics_duration', 'rbac_performance_metrics')
    op.drop_index('ix_rbac_metrics_operation_time', 'rbac_performance_metrics')
    op.drop_index('ix_rbac_metrics_type_time', 'rbac_performance_metrics')
    op.drop_table('rbac_performance_metrics')

    # Drop break-glass access table
    op.drop_index('ix_break_glass_access_resource', 'break_glass_access')
    op.drop_index('ix_break_glass_access_expires', 'break_glass_access')
    op.drop_index('ix_break_glass_access_status', 'break_glass_access')
    op.drop_table('break_glass_access')

    # Drop SSO session table
    op.drop_index('ix_sso_session_user', 'sso_session')
    op.drop_index('ix_sso_session_status', 'sso_session')
    op.drop_index('ix_sso_session_expires', 'sso_session')
    op.drop_table('sso_session')

    # Drop service account token table
    op.drop_index('ix_service_account_token_scope', 'service_account_token')
    op.drop_index('ix_service_account_token_active', 'service_account_token')
    op.drop_index('ix_service_account_token_expires', 'service_account_token')
    op.drop_table('service_account_token')

    # Drop audit log table
    op.drop_index('ix_rbac_audit_log_category_time', 'rbac_audit_log')
    op.drop_index('ix_rbac_audit_log_workspace_time', 'rbac_audit_log')
    op.drop_index('ix_rbac_audit_log_resource_time', 'rbac_audit_log')
    op.drop_index('ix_rbac_audit_log_actor_time', 'rbac_audit_log')
    op.drop_index('ix_rbac_audit_log_timestamp', 'rbac_audit_log')
    op.drop_table('rbac_audit_log')

    # Drop SCIM configuration table
    op.drop_index('ix_scim_configuration_active', 'scim_configuration')
    op.drop_index('ix_scim_configuration_status', 'scim_configuration')
    op.drop_table('scim_configuration')

    # Drop SSO configuration table
    op.drop_index('ix_sso_configuration_active', 'sso_configuration')
    op.drop_index('ix_sso_configuration_protocol', 'sso_configuration')
    op.drop_table('sso_configuration')