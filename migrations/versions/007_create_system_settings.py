"""Create system_settings table

Revision ID: 007_create_system_settings
Revises: 006_add_llm_advanced_fields
Create Date: 2026-04-11

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '007_create_system_settings'
down_revision = '006_add_llm_advanced_fields'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create system_settings table."""
    op.create_table(
        'system_settings',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('key', sa.String(length=255), nullable=False),
        sa.Column('value', sa.Text(), nullable=True),
        sa.Column('category', sa.String(length=50), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('key')
    )
    op.create_index('ix_system_settings_key', 'system_settings', ['key'])


def downgrade() -> None:
    """Drop system_settings table."""
    op.drop_index('ix_system_settings_key', table_name='system_settings')
    op.drop_table('system_settings')
