"""Initial schema for DeepVuln Web Service

Revision ID: 001_init
Revises:
Create Date: 2026-04-07

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '001_init'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create projects table
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
        sa.ForeignKeyConstraint(['last_scan_id'], ['scans.id'], name='fk_projects_last_scan')
    )

    # Create scans table
    op.create_table(
        'scans',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('scan_type', sa.String(length=50), nullable=False),
        sa.Column('config', sa.JSON(), nullable=False),
        sa.Column('current_phase', sa.String(length=50), nullable=True),
        sa.Column('current_step', sa.String(length=255), nullable=True),
        sa.Column('current_engine', sa.String(length=100), nullable=True),
        sa.Column('progress_percent', sa.Integer(), server_default='0', nullable=True),
        sa.Column('total_files', sa.Integer(), server_default='0', nullable=True),
        sa.Column('indexed_files', sa.Integer(), server_default='0', nullable=True),
        sa.Column('analyzed_files', sa.Integer(), server_default='0', nullable=True),
        sa.Column('files_scanned', sa.Integer(), server_default='0', nullable=True),
        sa.Column('files_with_findings', sa.Integer(), server_default='0', nullable=True),
        sa.Column('engines_completed', sa.Integer(), server_default='0', nullable=True),
        sa.Column('engines_total', sa.Integer(), server_default='5', nullable=True),
        sa.Column('tokens_used', sa.Integer(), server_default='0', nullable=True),
        sa.Column('tokens_budget', sa.Integer(), server_default='100000', nullable=True),
        sa.Column('llm_requests_count', sa.Integer(), server_default='0', nullable=True),
        sa.Column('findings_count', sa.Integer(), server_default='0', nullable=True),
        sa.Column('verified_count', sa.Integer(), server_default='0', nullable=True),
        sa.Column('false_positive_count', sa.Integer(), server_default='0', nullable=True),
        sa.Column('critical_count', sa.Integer(), server_default='0', nullable=True),
        sa.Column('high_count', sa.Integer(), server_default='0', nullable=True),
        sa.Column('medium_count', sa.Integer(), server_default='0', nullable=True),
        sa.Column('low_count', sa.Integer(), server_default='0', nullable=True),
        sa.Column('info_count', sa.Integer(), server_default='0', nullable=True),
        sa.Column('quality_score', sa.Float(), server_default='0.0', nullable=True),
        sa.Column('coverage_score', sa.Float(), server_default='0.0', nullable=True),
        sa.Column('created_at', sa.TIMESTAMP(), server_default=sa.text('NOW()'), nullable=True),
        sa.Column('started_at', sa.TIMESTAMP(), nullable=True),
        sa.Column('completed_at', sa.TIMESTAMP(), nullable=True),
        sa.Column('estimated_completion', sa.TIMESTAMP(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('failed_engines', sa.JSON(), nullable=True),
        sa.Column('checkpoint_data', sa.JSON(), nullable=True),
        sa.Column('report_path', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE', name='fk_scans_project')
    )
    op.create_index('idx_scans_status', 'scans', ['status'])
    op.create_index('idx_scans_project', 'scans', ['project_id'])

    # Create scan_phases table
    op.create_table(
        'scan_phases',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=False),
        sa.Column('phase_name', sa.String(length=100), nullable=False),
        sa.Column('engine_name', sa.String(length=100), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('current_step', sa.String(length=255), nullable=True),
        sa.Column('progress_percent', sa.Integer(), server_default='0', nullable=True),
        sa.Column('files_processed', sa.Integer(), server_default='0', nullable=True),
        sa.Column('findings_found', sa.Integer(), server_default='0', nullable=True),
        sa.Column('tokens_used', sa.Integer(), server_default='0', nullable=True),
        sa.Column('started_at', sa.TIMESTAMP(), nullable=True),
        sa.Column('completed_at', sa.TIMESTAMP(), nullable=True),
        sa.Column('duration_seconds', sa.Integer(), nullable=True),
        sa.Column('output_path', sa.Text(), nullable=True),
        sa.Column('output_data', sa.JSON(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.TIMESTAMP(), server_default=sa.text('NOW()'), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE', name='fk_scan_phases_scan')
    )
    op.create_index('idx_scan_phases_scan', 'scan_phases', ['scan_id'])
    op.create_index('idx_scan_phases_status', 'scan_phases', ['status'])

    # Create scan_events table
    op.create_table(
        'scan_events',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=False),
        sa.Column('phase_id', sa.Integer(), nullable=True),
        sa.Column('event_type', sa.String(length=50), nullable=False),
        sa.Column('event_level', sa.String(length=20), server_default='info', nullable=True),
        sa.Column('message', sa.Text(), nullable=True),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('engine_name', sa.String(length=100), nullable=True),
        sa.Column('agent_turn', sa.Integer(), server_default='0', nullable=True),
        sa.Column('agent_role', sa.String(length=50), nullable=True),
        sa.Column('agent_message', sa.Text(), nullable=True),
        sa.Column('agent_reasoning', sa.Text(), nullable=True),
        sa.Column('file_path', sa.Text(), nullable=True),
        sa.Column('file_index', sa.Integer(), server_default='0', nullable=True),
        sa.Column('file_total', sa.Integer(), server_default='0', nullable=True),
        sa.Column('tokens_used', sa.Integer(), server_default='0', nullable=True),
        sa.Column('tokens_input', sa.Integer(), server_default='0', nullable=True),
        sa.Column('tokens_output', sa.Integer(), server_default='0', nullable=True),
        sa.Column('finding_id', sa.Integer(), nullable=True),
        sa.Column('sequence', sa.Integer(), server_default='0', nullable=True),
        sa.Column('created_at', sa.TIMESTAMP(), server_default=sa.text('NOW()'), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE', name='fk_scan_events_scan'),
        sa.ForeignKeyConstraint(['phase_id'], ['scan_phases.id'], ondelete='CASCADE', name='fk_scan_events_phase'),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], ondelete='CASCADE', name='fk_scan_events_finding')
    )
    op.create_index('idx_scan_events_scan', 'scan_events', ['scan_id'])
    op.create_index('idx_scan_events_type', 'scan_events', ['event_type'])
    op.create_index('idx_scan_events_created', 'scan_events', ['created_at'])

    # Create findings table
    op.create_table(
        'findings',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=False),
        sa.Column('phase_id', sa.Integer(), nullable=True),
        sa.Column('vuln_type', sa.String(length=100), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=True),
        sa.Column('file_path', sa.Text(), nullable=False),
        sa.Column('line_start', sa.Integer(), nullable=True),
        sa.Column('line_end', sa.Integer(), nullable=True),
        sa.Column('function_name', sa.String(length=255), nullable=True),
        sa.Column('title', sa.Text(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('evidence', sa.Text(), nullable=True),
        sa.Column('remediation', sa.Text(), nullable=True),
        sa.Column('status', sa.String(length=50), server_default='pending', nullable=True),
        sa.Column('engine', sa.String(length=50), nullable=False),
        sa.Column('metadata', sa.JSON(), nullable=True),
        sa.Column('cpg_path', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.TIMESTAMP(), server_default=sa.text('NOW()'), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE', name='fk_findings_scan'),
        sa.ForeignKeyConstraint(['phase_id'], ['scan_phases.id'], ondelete='CASCADE', name='fk_findings_phase')
    )
    op.create_index('idx_findings_scan', 'findings', ['scan_id'])
    op.create_index('idx_findings_severity', 'findings', ['severity'])
    op.create_index('idx_findings_vuln_type', 'findings', ['vuln_type'])
    op.create_index('idx_findings_file_path', 'findings', ['file_path'])

    # Create scan_files table
    op.create_table(
        'scan_files',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=False),
        sa.Column('file_path', sa.Text(), nullable=False),
        sa.Column('file_hash', sa.String(length=64), nullable=True),
        sa.Column('scanned_at', sa.TIMESTAMP(), server_default=sa.text('NOW()'), nullable=True),
        sa.Column('findings_count', sa.Integer(), server_default='0', nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE', name='fk_scan_files_scan')
    )
    op.create_index('idx_scan_files_scan', 'scan_files', ['scan_id'])
    op.create_index('idx_scan_files_path', 'scan_files', ['file_path'])

    # Create api_keys table
    op.create_table(
        'api_keys',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('key_hash', sa.String(length=255), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('is_active', sa.Boolean(), server_default='true', nullable=True),
        sa.Column('created_at', sa.TIMESTAMP(), server_default=sa.text('NOW()'), nullable=True),
        sa.Column('last_used_at', sa.TIMESTAMP(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('key_hash', name='uq_api_keys_key_hash')
    )

    # Create updated_at trigger function
    op.execute("""
        CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = NOW();
            RETURN NEW;
        END;
        $$ language 'plpgsql';
    """)

    # Create trigger for projects table
    op.execute("""
        CREATE TRIGGER update_projects_updated_at
            BEFORE UPDATE ON projects
            FOR EACH ROW
            EXECUTE FUNCTION update_updated_at_column();
    """)


def downgrade() -> None:
    # Drop triggers
    op.execute("DROP TRIGGER IF EXISTS update_projects_updated_at ON projects")
    op.execute("DROP FUNCTION IF EXISTS update_updated_at_column()")

    # Drop tables in reverse order due to foreign keys
    op.drop_table('api_keys')
    op.drop_index('idx_scan_files_path', table_name='scan_files')
    op.drop_index('idx_scan_files_scan', table_name='scan_files')
    op.drop_table('scan_files')
    op.drop_index('idx_findings_file_path', table_name='findings')
    op.drop_index('idx_findings_vuln_type', table_name='findings')
    op.drop_index('idx_findings_severity', table_name='findings')
    op.drop_index('idx_findings_scan', table_name='findings')
    op.drop_table('findings')
    op.drop_index('idx_scan_events_created', table_name='scan_events')
    op.drop_index('idx_scan_events_type', table_name='scan_events')
    op.drop_index('idx_scan_events_scan', table_name='scan_events')
    op.drop_table('scan_events')
    op.drop_index('idx_scan_phases_status', table_name='scan_phases')
    op.drop_index('idx_scan_phases_scan', table_name='scan_phases')
    op.drop_table('scan_phases')
    op.drop_index('idx_scans_project', table_name='scans')
    op.drop_index('idx_scans_status', table_name='scans')
    op.drop_table('scans')
    op.drop_table('projects')
