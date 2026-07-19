"""add send_jobs.kind and send_jobs.log_json

Adds:
  - send_jobs.kind      (String; 'outreach' | 'followup_bulk' — job type discriminator)
  - send_jobs.log_json  (Text; JSON list of per-contact failures/skips for bulk follow-up jobs)

Revision ID: a3b4c5d6e7f8
Revises: f2a3b4c5d6e7
Create Date: 2026-07-16 12:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = 'a3b4c5d6e7f8'
down_revision = 'f2a3b4c5d6e7'
branch_labels = None
depends_on = None


def _has_column(table, column):
    """Idempotency guard — columns may already exist via inline startup migrations."""
    insp = sa.inspect(op.get_bind())
    return column in {c['name'] for c in insp.get_columns(table)}


def upgrade():
    with op.batch_alter_table('send_jobs', schema=None) as batch_op:
        if not _has_column('send_jobs', 'kind'):
            batch_op.add_column(sa.Column('kind', sa.String(length=20), nullable=False,
                                          server_default='outreach'))
        if not _has_column('send_jobs', 'log_json'):
            batch_op.add_column(sa.Column('log_json', sa.Text(), nullable=True))


def downgrade():
    with op.batch_alter_table('send_jobs', schema=None) as batch_op:
        if _has_column('send_jobs', 'log_json'):
            batch_op.drop_column('log_json')
        if _has_column('send_jobs', 'kind'):
            batch_op.drop_column('kind')
