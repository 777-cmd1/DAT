"""add password reset tokens

Revision ID: a1b2c3d4e5f6
Revises: 696891ea714f
Create Date: 2026-03-12 22:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a1b2c3d4e5f6'
down_revision = '696891ea714f'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    # Skip if already exists (dev SQLite may have been created by db.create_all())
    if 'password_reset_tokens' not in inspector.get_table_names():
        op.create_table(
            'password_reset_tokens',
            sa.Column('id',         sa.Integer(),     nullable=False),
            sa.Column('email',      sa.String(255),   nullable=False),
            sa.Column('token',      sa.String(86),    nullable=False),
            sa.Column('created_at', sa.DateTime(),    nullable=True),
            sa.Column('used_at',    sa.DateTime(),    nullable=True),
            sa.PrimaryKeyConstraint('id'),
            sa.UniqueConstraint('token'),
        )
        existing_indexes = [i['name'] for i in inspector.get_indexes('password_reset_tokens')] \
            if 'password_reset_tokens' in inspector.get_table_names() else []
        if 'ix_prt_email' not in existing_indexes:
            op.create_index('ix_prt_email', 'password_reset_tokens', ['email'], unique=False)


def downgrade():
    op.drop_index('ix_prt_email', table_name='password_reset_tokens')
    op.drop_table('password_reset_tokens')
