"""Add advanced LLM settings to llm_configs table

Revision ID: 006_add_llm_advanced_fields
Revises: 005_add_llm_configs
Create Date: 2026-04-11

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '006_add_llm_advanced_fields'
down_revision = '005_add_llm_configs'
branch_labels = None
depends_on = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add advanced LLM settings columns to llm_configs table."""
    # Add new columns for advanced LLM settings
    op.add_column('llm_configs',
                  sa.Column('max_retries', sa.Integer(), nullable=True))
    op.add_column('llm_configs',
                  sa.Column('max_concurrent_requests', sa.Integer(), nullable=True))
    op.add_column('llm_configs',
                  sa.Column('batch_max_chars', sa.Integer(), nullable=True))
    op.add_column('llm_configs',
                  sa.Column('batch_size', sa.Integer(), nullable=True))

    # Set default values for existing records
    op.execute("UPDATE llm_configs SET max_retries = 3 WHERE max_retries IS NULL")
    op.execute("UPDATE llm_configs SET max_concurrent_requests = 5 WHERE max_concurrent_requests IS NULL")
    op.execute("UPDATE llm_configs SET batch_max_chars = 12000 WHERE batch_max_chars IS NULL")
    op.execute("UPDATE llm_configs SET batch_size = 20 WHERE batch_size IS NULL")

    # Make columns NOT NULL with defaults
    op.alter_column('llm_configs', 'max_retries',
                    existing_type=sa.Integer(),
                    nullable=False,
                    server_default='3')
    op.alter_column('llm_configs', 'max_concurrent_requests',
                    existing_type=sa.Integer(),
                    nullable=False,
                    server_default='5')
    op.alter_column('llm_configs', 'batch_max_chars',
                    existing_type=sa.Integer(),
                    nullable=False,
                    server_default='12000')
    op.alter_column('llm_configs', 'batch_size',
                    existing_type=sa.Integer(),
                    nullable=False,
                    server_default='20')


def downgrade() -> None:
    """Remove advanced LLM settings columns from llm_configs table."""
    op.drop_column('llm_configs', 'batch_size')
    op.drop_column('llm_configs', 'batch_max_chars')
    op.drop_column('llm_configs', 'max_concurrent_requests')
    op.drop_column('llm_configs', 'max_retries')
