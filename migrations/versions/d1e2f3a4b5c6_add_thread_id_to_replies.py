"""add thread_id to replies

Revision ID: d1e2f3a4b5c6
Revises: c83e5bf58a66
Create Date: 2026-04-08 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = 'd1e2f3a4b5c6'
down_revision = 'c83e5bf58a66'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('replies') as batch_op:
        batch_op.add_column(sa.Column('thread_id', sa.String(255), nullable=True))


def downgrade():
    with op.batch_alter_table('replies') as batch_op:
        batch_op.drop_column('thread_id')
