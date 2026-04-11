"""Add LLM configs table

Revision ID: 005_add_llm_configs
Revises: 004_add_task_id_to_scans
Create Date: 2026-04-11

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '005_add_llm_configs'
down_revision = '004_add_task_id'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create llm_configs table."""
    op.create_table(
        'llm_configs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('provider', sa.String(length=50), nullable=False, comment='openai/azure/ollama/custom'),
        sa.Column('api_key', sa.Text(), nullable=True),
        sa.Column('base_url', sa.Text(), nullable=True),
        sa.Column('model', sa.String(length=255), nullable=False),
        sa.Column('context_size', sa.Integer(), nullable=True, server_default='4096', comment='Model context window size'),
        sa.Column('temperature', sa.Float(), nullable=True, server_default='0.1'),
        sa.Column('max_tokens', sa.Integer(), nullable=True, server_default='4096'),
        sa.Column('timeout', sa.Integer(), nullable=True, server_default='120'),
        sa.Column('is_default', sa.Boolean(), nullable=True, server_default='false'),
        sa.Column('config_type', sa.String(length=50), nullable=True, server_default='both', comment='agent_scan/verification/both'),
        sa.Column('created_at', sa.DateTime(), nullable=True, server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.DateTime(), nullable=True, server_default=sa.text('NOW()')),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_llm_configs_provider', 'llm_configs', ['provider'])
    op.create_index('ix_llm_configs_is_default', 'llm_configs', ['is_default'])
    op.create_index('ix_llm_configs_config_type', 'llm_configs', ['config_type'])


def downgrade() -> None:
    """Drop llm_configs table."""
    op.drop_index('ix_llm_configs_config_type', table_name='llm_configs')
    op.drop_index('ix_llm_configs_is_default', table_name='llm_configs')
    op.drop_index('ix_llm_configs_provider', table_name='llm_configs')
    op.drop_table('llm_configs')
