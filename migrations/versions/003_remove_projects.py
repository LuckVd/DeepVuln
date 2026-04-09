"""Remove projects table, add fields to scans

Revision ID: 003_remove_projects
Revises: 002_add_p14_verification_fields
Create Date: 2026-04-09

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '003_remove_projects'
down_revision: Union[str, None] = '002_p14_verification'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add new columns to scans table
    op.add_column('scans', sa.Column('name', sa.String(length=255), nullable=True))
    op.add_column('scans', sa.Column('source_type', sa.String(length=50), nullable=True))
    op.add_column('scans', sa.Column('source_path', sa.Text(), nullable=True))
    op.add_column('scans', sa.Column('branch', sa.String(length=255), nullable=True))

    # Drop foreign key constraint
    op.execute('ALTER TABLE scans DROP CONSTRAINT fk_scans_project')

    # Drop index on project_id
    op.drop_index('idx_scans_project', table_name='scans')

    # Drop project_id column
    op.drop_column('scans', 'project_id')

    # Drop projects table
    op.execute('DROP TRIGGER IF EXISTS update_projects_updated_at ON projects')
    op.execute('DROP FUNCTION IF EXISTS update_updated_at_column()')
    op.drop_table('projects')

    # Make new columns non-nullable after data migration (if needed)
    op.alter_column('scans', 'name', nullable=False)
    op.alter_column('scans', 'source_type', nullable=False)
    op.alter_column('scans', 'source_path', nullable=False)


def downgrade() -> None:
    # Re-create projects table
    op.create_table(
        'projects',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('source_type', sa.String(length=50), nullable=False),
        sa.Column('source_path', sa.Text(), nullable=False),
        sa.Column('branch', sa.String(length=255), nullable=True),
        sa.Column('commit_hash', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.TIMESTAMP(), server_default=sa.text('NOW()'), nullable=True),
        sa.Column('updated_at', sa.TIMESTAMP(), server_default=sa.text('NOW()'), nullable=True),
        sa.Column('last_scan_id', sa.Integer(), nullable=True),
        sa.Column('metadata', sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )

    # Re-create trigger function
    op.execute("""
        CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = NOW();
            RETURN NEW;
        END;
        $$ language 'plpgsql';
    """)

    # Re-create trigger
    op.execute("""
        CREATE TRIGGER update_projects_updated_at
            BEFORE UPDATE ON projects
            FOR EACH ROW
            EXECUTE FUNCTION update_updated_at_column();
    """)

    # Add project_id back to scans
    op.add_column('scans', sa.Column('project_id', sa.Integer(), nullable=False))

    # Re-create index
    op.create_index('idx_scans_project', 'scans', ['project_id'])

    # Re-create foreign key
    op.execute('ALTER TABLE scans ADD CONSTRAINT fk_scans_project FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE')

    # Drop new columns from scans
    op.drop_column('scans', 'branch')
    op.drop_column('scans', 'source_path')
    op.drop_column('scans', 'source_type')
    op.drop_column('scans', 'name')
