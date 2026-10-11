"""support requests (inv_support)

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-10 23:00:00
"""
from alembic import op
import sqlalchemy as sa


revision = '0009'
down_revision = '0008'
branch_labels = None
depends_on = None


def upgrade() -> None:
    if 'inv_support' in sa.inspect(op.get_bind()).get_table_names():
        return  # development databases built by create_all may have it already
    op.create_table('inv_support',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('investigation_id', sa.String(length=36), nullable=False),
    sa.Column('question', sa.String(length=500), nullable=False),
    sa.Column('scope_note', sa.Text(), nullable=False),
    sa.Column('helper_id', sa.String(length=36), nullable=False),
    sa.Column('helper_name', sa.String(length=128), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('result_note', sa.Text(), nullable=False),
    sa.Column('remaining', sa.Text(), nullable=False),
    sa.Column('requested_by', sa.String(length=36), nullable=False),
    sa.Column('requested_by_name', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['investigation_id'], ['inv_investigation.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('inv_support', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_inv_support_helper_id'), ['helper_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_inv_support_investigation_id'), ['investigation_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_inv_support_status'), ['status'], unique=False)


def downgrade() -> None:
    op.drop_table('inv_support')
