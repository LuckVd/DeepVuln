"""Add task_id field to scans table for Celery task control

Revision ID: 004_add_task_id
Revises: 003_remove_projects
Create Date: 2026-04-09

This migration adds the task_id column to enable proper Celery task control:
- Store Celery task ID when scan is started
- Enable task cancellation via Celery control.revoke()
- Support pause/resume functionality

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '004_add_task_id'
down_revision: Union[str, None] = '003_remove_projects'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add task_id column to scans table
    op.add_column(
        'scans',
        sa.Column('task_id', sa.String(255), nullable=True),
    )


def downgrade() -> None:
    # Remove task_id column from scans table
    op.drop_column('scans', 'task_id')
