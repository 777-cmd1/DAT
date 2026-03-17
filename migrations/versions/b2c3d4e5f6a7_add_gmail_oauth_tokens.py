"""add gmail oauth token columns to email_accounts

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-03-17 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = 'b2c3d4e5f6a7'
down_revision = 'a1b2c3d4e5f6'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('email_accounts') as batch_op:
        batch_op.add_column(sa.Column('google_refresh_token', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('google_access_token',  sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('token_expiry', sa.DateTime(), nullable=True))


def downgrade():
    with op.batch_alter_table('email_accounts') as batch_op:
        batch_op.drop_column('token_expiry')
        batch_op.drop_column('google_access_token')
        batch_op.drop_column('google_refresh_token')
