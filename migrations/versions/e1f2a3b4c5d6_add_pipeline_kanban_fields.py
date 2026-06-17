"""add pipeline/kanban fields

Adds:
  - workspaces.pipeline_config       (JSON; customizable stages + reply filters)
  - users.followup_view_mode         (String; 'table' | 'kanban' preference)
  - followup_contacts.pipeline_stage (Integer 1-5; Kanban column)

Revision ID: e1f2a3b4c5d6
Revises: d1e2f3a4b5c6
Create Date: 2026-06-17 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = 'e1f2a3b4c5d6'
down_revision = 'd1e2f3a4b5c6'
branch_labels = None
depends_on = None


def _has_column(table, column):
    """Idempotency guard: these columns may already be delivered by the inline
    startup migrations in app.py, so only ADD/DROP when state actually differs."""
    insp = sa.inspect(op.get_bind())
    return column in {c['name'] for c in insp.get_columns(table)}


def upgrade():
    if not _has_column('workspaces', 'pipeline_config'):
        with op.batch_alter_table('workspaces', schema=None) as batch_op:
            batch_op.add_column(sa.Column('pipeline_config', sa.JSON(), nullable=True))

    if not _has_column('users', 'followup_view_mode'):
        with op.batch_alter_table('users', schema=None) as batch_op:
            batch_op.add_column(sa.Column('followup_view_mode', sa.String(length=20),
                                          nullable=True, server_default='table'))

    if not _has_column('followup_contacts', 'pipeline_stage'):
        with op.batch_alter_table('followup_contacts', schema=None) as batch_op:
            batch_op.add_column(sa.Column('pipeline_stage', sa.Integer(),
                                          nullable=False, server_default='1'))


def downgrade():
    if _has_column('followup_contacts', 'pipeline_stage'):
        with op.batch_alter_table('followup_contacts', schema=None) as batch_op:
            batch_op.drop_column('pipeline_stage')

    if _has_column('users', 'followup_view_mode'):
        with op.batch_alter_table('users', schema=None) as batch_op:
            batch_op.drop_column('followup_view_mode')

    if _has_column('workspaces', 'pipeline_config'):
        with op.batch_alter_table('workspaces', schema=None) as batch_op:
            batch_op.drop_column('pipeline_config')
