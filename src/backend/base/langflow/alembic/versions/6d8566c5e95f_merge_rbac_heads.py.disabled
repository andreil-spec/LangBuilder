"""merge_rbac_heads

Revision ID: 6d8566c5e95f
Revises: add_sso_provider_id_to_user_group, rbac_phase3_services
Create Date: 2025-09-22 20:55:57.145926

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel
from sqlalchemy.engine.reflection import Inspector
from langflow.utils import migration


# revision identifiers, used by Alembic.
revision: str = '6d8566c5e95f'
down_revision: Union[str, None] = ('add_sso_provider_id_to_user_group', 'rbac_phase3_services')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    pass


def downgrade() -> None:
    conn = op.get_bind()
    pass
