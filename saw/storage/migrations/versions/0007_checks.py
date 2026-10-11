"""confirmation records (inv_check)

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-10 20:00:00
"""
from alembic import op
import sqlalchemy as sa


revision = '0007'
down_revision = '0006'
branch_labels = None
depends_on = None


def upgrade() -> None:
    if 'inv_check' in sa.inspect(op.get_bind()).get_table_names():
        return  # development databases built by create_all may have it already
    op.create_table('inv_check',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('investigation_id', sa.String(length=36), nullable=False),
    sa.Column('target_type', sa.String(length=16), nullable=False),
    sa.Column('target_key', sa.String(length=512), nullable=False),
    sa.Column('target_label', sa.String(length=512), nullable=False),
    sa.Column('scope', sa.JSON(), nullable=False),
    sa.Column('questions', sa.JSON(), nullable=False),
    sa.Column('judgement', sa.String(length=16), nullable=True),
    sa.Column('note', sa.Text(), nullable=False),
    sa.Column('evidence', sa.JSON(), nullable=False),
    sa.Column('time_start', sa.String(length=40), nullable=True),
    sa.Column('time_end', sa.String(length=40), nullable=True),
    sa.Column('kind', sa.String(length=12), nullable=False),
    sa.Column('source_check_id', sa.String(length=36), nullable=True),
    sa.Column('source_state', sa.String(length=12), nullable=False),
    sa.Column('shared', sa.Boolean(), nullable=False),
    sa.Column('share', sa.JSON(), nullable=False),
    sa.Column('share_status', sa.String(length=16), nullable=False),
    sa.Column('valid_until', sa.DateTime(timezone=True), nullable=True),
    sa.Column('context', sa.JSON(), nullable=False),
    sa.Column('state', sa.String(length=12), nullable=False),
    sa.Column('state_note', sa.String(length=512), nullable=False),
    sa.Column('state_by', sa.String(length=64), nullable=False),
    sa.Column('supersedes_id', sa.String(length=36), nullable=True),
    sa.Column('author_id', sa.String(length=36), nullable=False),
    sa.Column('author_name', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['investigation_id'], ['inv_investigation.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('inv_check', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_inv_check_author_id'), ['author_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_inv_check_investigation_id'), ['investigation_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_inv_check_shared'), ['shared'], unique=False)
        batch_op.create_index(batch_op.f('ix_inv_check_source_check_id'), ['source_check_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_inv_check_state'), ['state'], unique=False)
        batch_op.create_index(batch_op.f('ix_inv_check_target_key'), ['target_key'], unique=False)


def downgrade() -> None:
    op.drop_table('inv_check')
