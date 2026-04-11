"""Add P14 verification fields to scans and findings tables

Revision ID: 002_p14_verification
Revises: 001_init
Create Date: 2026-04-09

P14-07c: This migration adds new fields for:
- P14-01: Attack surface statistics
- P14-02: Exploitability verification
- P14-03: Adjudication summary
- P14-04: Adversarial verification
- P14-05: Token usage details
- P14-06: Incremental scan statistics

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '002_add_p14_verification_fields'
down_revision: Union[str, None] = '001_init'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add new columns to scans table (P14-01, P14-03, P14-04, P14-05, P14-06)
    op.add_column(
        'scans',
        sa.Column('attack_surface', sa.JSON(), nullable=True),
    )
    op.add_column(
        'scans',
        sa.Column('adjudication_summary', sa.JSON(), nullable=True),
    )
    op.add_column(
        'scans',
        sa.Column('adversarial_summary', sa.JSON(), nullable=True),
    )
    op.add_column(
        'scans',
        sa.Column('token_usage', sa.JSON(), nullable=True),
    )
    op.add_column(
        'scans',
        sa.Column('incremental_stats', sa.JSON(), nullable=True),
    )

    # Note: Finding model fields are added via the extra_metadata JSON column
    # The finding table already has a metadata JSON column that can store:
    # - exploitability (P14-02)
    # - exploitability_confidence
    # - exploitability_reasoning
    # - adversarial_verdict (P14-04)
    # - adversarial_confidence
    # - adversarial_reasoning
    # - adversarial_rounds
    # - report_status (P14-03)
    # - evidence_strength


def downgrade() -> None:
    # Remove columns from scans table
    op.drop_column('scans', 'incremental_stats')
    op.drop_column('scans', 'token_usage')
    op.drop_column('scans', 'adversarial_summary')
    op.drop_column('scans', 'adjudication_summary')
    op.drop_column('scans', 'attack_surface')
