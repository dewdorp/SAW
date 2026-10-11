"""processing runs, parser review, 64-bit sizes

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-10 00:35:32.066086
"""
from alembic import op
import sqlalchemy as sa


revision = '0004'
down_revision = '0003'
branch_labels = None
depends_on = None


def upgrade() -> None:
    insp = sa.inspect(op.get_bind())
    have_runs = 'ev_processing_run' in insp.get_table_names()
    parser_cols = {c['name'] for c in insp.get_columns('ps_parser')}
    _runs(have_runs)
    _sizes()
    if 'reviewed_by' not in parser_cols:  # development databases built by create_all may have them already
        _parser_review()


def _runs(exists: bool) -> None:
    if exists:
        return
    op.create_table('ev_processing_run',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('investigation_id', sa.String(length=36), nullable=False),
    sa.Column('evidence_id', sa.String(length=36), nullable=False),
    sa.Column('file_id', sa.String(length=36), nullable=False),
    sa.Column('job_id', sa.String(length=36), nullable=True),
    sa.Column('actor_id', sa.String(length=36), nullable=False),
    sa.Column('actor_name', sa.String(length=64), nullable=False),
    sa.Column('file_name', sa.String(length=512), nullable=False),
    sa.Column('input_sha256', sa.String(length=64), nullable=False),
    sa.Column('input_size', sa.BigInteger(), nullable=False),
    sa.Column('parser_id', sa.String(length=64), nullable=False),
    sa.Column('parser_version', sa.String(length=16), nullable=False),
    sa.Column('parser_digest', sa.String(length=64), nullable=False),
    sa.Column('settings', sa.JSON(), nullable=False),
    sa.Column('settings_digest', sa.String(length=64), nullable=False),
    sa.Column('events', sa.Integer(), nullable=False),
    sa.Column('failed', sa.Integer(), nullable=False),
    sa.Column('coverage', sa.JSON(), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('run_digest', sa.String(length=64), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('ev_processing_run', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_ev_processing_run_actor_id'), ['actor_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_ev_processing_run_file_id'), ['file_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_ev_processing_run_input_sha256'), ['input_sha256'], unique=False)
        batch_op.create_index(batch_op.f('ix_ev_processing_run_investigation_id'), ['investigation_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_ev_processing_run_settings_digest'), ['settings_digest'], unique=False)


def _sizes() -> None:
    with op.batch_alter_table('ev_evidence', schema=None) as batch_op:
        batch_op.alter_column('total_size',
               existing_type=sa.INTEGER(),
               type_=sa.BigInteger(),
               existing_nullable=False)

    with op.batch_alter_table('ev_file', schema=None) as batch_op:
        batch_op.alter_column('size',
               existing_type=sa.INTEGER(),
               type_=sa.BigInteger(),
               existing_nullable=False)

    with op.batch_alter_table('ev_upload_session', schema=None) as batch_op:
        batch_op.alter_column('declared_size',
               existing_type=sa.INTEGER(),
               type_=sa.BigInteger(),
               existing_nullable=False)
        batch_op.alter_column('received_bytes',
               existing_type=sa.INTEGER(),
               type_=sa.BigInteger(),
               existing_nullable=False)


def _parser_review() -> None:
    with op.batch_alter_table('ps_parser', schema=None) as batch_op:
        batch_op.add_column(sa.Column('reviewed_by', sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column('reviewed_by_name', sa.String(length=64), nullable=False, server_default=''))
        batch_op.add_column(sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('review_note', sa.Text(), nullable=False, server_default=''))



def downgrade() -> None:
    with op.batch_alter_table('ps_parser', schema=None) as batch_op:
        batch_op.drop_column('review_note')
        batch_op.drop_column('reviewed_at')
        batch_op.drop_column('reviewed_by_name')
        batch_op.drop_column('reviewed_by')

    with op.batch_alter_table('ev_upload_session', schema=None) as batch_op:
        batch_op.alter_column('received_bytes',
               existing_type=sa.BigInteger(),
               type_=sa.INTEGER(),
               existing_nullable=False)
        batch_op.alter_column('declared_size',
               existing_type=sa.BigInteger(),
               type_=sa.INTEGER(),
               existing_nullable=False)

    with op.batch_alter_table('ev_file', schema=None) as batch_op:
        batch_op.alter_column('size',
               existing_type=sa.BigInteger(),
               type_=sa.INTEGER(),
               existing_nullable=False)

    with op.batch_alter_table('ev_evidence', schema=None) as batch_op:
        batch_op.alter_column('total_size',
               existing_type=sa.BigInteger(),
               type_=sa.INTEGER(),
               existing_nullable=False)

    with op.batch_alter_table('ev_processing_run', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_ev_processing_run_settings_digest'))
        batch_op.drop_index(batch_op.f('ix_ev_processing_run_investigation_id'))
        batch_op.drop_index(batch_op.f('ix_ev_processing_run_input_sha256'))
        batch_op.drop_index(batch_op.f('ix_ev_processing_run_file_id'))
        batch_op.drop_index(batch_op.f('ix_ev_processing_run_actor_id'))

    op.drop_table('ev_processing_run')
