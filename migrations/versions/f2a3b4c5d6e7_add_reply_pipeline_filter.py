"""add reply pipeline-filter fields

Adds:
  - replies.reply_filter_key  (String; pipeline reply-filter tag, e.g. 'can_use')
  - replies.auto_advanced     (Boolean; set when the tag auto-advanced a contact)

Revision ID: f2a3b4c5d6e7
Revises: e1f2a3b4c5d6
Create Date: 2026-06-17 00:30:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = 'f2a3b4c5d6e7'
down_revision = 'e1f2a3b4c5d6'
branch_labels = None
depends_on = None


def _has_column(table, column):
    """Idempotency guard — columns may already exist via inline startup migrations."""
    insp = sa.inspect(op.get_bind())
    return column in {c['name'] for c in insp.get_columns(table)}


def upgrade():
    with op.batch_alter_table('replies', schema=None) as batch_op:
        if not _has_column('replies', 'reply_filter_key'):
            batch_op.add_column(sa.Column('reply_filter_key', sa.String(length=50), nullable=True))
        if not _has_column('replies', 'auto_advanced'):
            batch_op.add_column(sa.Column('auto_advanced', sa.Boolean(), nullable=False,
                                          server_default='0'))


def downgrade():
    with op.batch_alter_table('replies', schema=None) as batch_op:
        if _has_column('replies', 'auto_advanced'):
            batch_op.drop_column('auto_advanced')
        if _has_column('replies', 'reply_filter_key'):
            batch_op.drop_column('reply_filter_key')
