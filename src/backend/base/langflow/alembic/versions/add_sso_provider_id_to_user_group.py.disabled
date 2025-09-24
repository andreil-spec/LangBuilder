"""Add sso_provider_id to user_group table

Revision ID: add_sso_provider_id_to_user_group
Revises: rbac_implementation_phase1
Create Date: 2025-09-19

This migration adds the sso_provider_id foreign key field to the user_group table
to enable proper SCIM provisioning sync tracking by SSO provider.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers
revision = "add_sso_provider_id_to_user_group"
down_revision = "rbac_implementation_phase1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add sso_provider_id column to user_group table."""
    # Get database connection and inspector to check for existing columns
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    # Check if user_group table exists
    table_names = inspector.get_table_names()
    if "user_group" not in table_names:
        # If table doesn't exist, skip this migration
        return

    # Check if sso_provider_id column already exists
    columns = [col["name"] for col in inspector.get_columns("user_group")]
    if "sso_provider_id" not in columns:
        # Add the sso_provider_id column
        op.add_column(
            "user_group",
            sa.Column(
                "sso_provider_id",
                sa.String(32),
                nullable=True,
                index=True
            )
        )

        # TODO: Fix SQLite foreign key constraints using batch mode
        # Create foreign key constraint to sso_configuration table if it exists
        # if "sso_configuration" in table_names:
        #     try:
        #         op.create_foreign_key(
        #             "fk_user_group_sso_provider_id",
        #             "user_group",
        #             "sso_configuration",
        #             ["sso_provider_id"],
        #             ["id"]
        #         )
        #     except Exception:
        #         # If foreign key creation fails, continue without it
        #         # This can happen if the sso_configuration table doesn't have the expected structure
        #         pass


def downgrade() -> None:
    """Remove sso_provider_id column from user_group table."""
    # Get database connection and inspector
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    # Check if user_group table exists
    table_names = inspector.get_table_names()
    if "user_group" not in table_names:
        return

    # Check if sso_provider_id column exists
    columns = [col["name"] for col in inspector.get_columns("user_group")]
    if "sso_provider_id" in columns:
        # Drop foreign key constraint first if it exists
        try:
            op.drop_constraint("fk_user_group_sso_provider_id", "user_group", type_="foreignkey")
        except Exception:
            # If constraint doesn't exist or can't be dropped, continue
            pass

        # Drop the column
        op.drop_column("user_group", "sso_provider_id")
