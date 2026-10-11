"""peer review requests (inv_review)

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-10 22:00:00
"""
from alembic import op
import sqlalchemy as sa


revision = '0008'
down_revision = '0007'
branch_labels = None
depends_on = None


def upgrade() -> None:
    if 'inv_review' in sa.inspect(op.get_bind()).get_table_names():
        return  # development databases built by create_all may have it already
    op.create_table('inv_review',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('investigation_id', sa.String(length=36), nullable=False),
    sa.Column('subject_type', sa.String(length=16), nullable=False),
    sa.Column('subject_id', sa.String(length=64), nullable=False),
    sa.Column('subject_label', sa.String(length=256), nullable=False),
    sa.Column('conclusion', sa.Text(), nullable=False),
    sa.Column('scope_note', sa.Text(), nullable=False),
    sa.Column('evidence', sa.JSON(), nullable=False),
    sa.Column('limits', sa.JSON(), nullable=False),
    sa.Column('required', sa.Boolean(), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('snapshot', sa.String(length=32), nullable=False),
    sa.Column('requested_by', sa.String(length=36), nullable=False),
    sa.Column('requested_by_name', sa.String(length=64), nullable=False),
    sa.Column('reviewer_id', sa.String(length=36), nullable=True),
    sa.Column('reviewer_name', sa.String(length=128), nullable=False),
    sa.Column('outcome_note', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('decided_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['investigation_id'], ['inv_investigation.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('inv_review', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_inv_review_investigation_id'), ['investigation_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_inv_review_requested_by'), ['requested_by'], unique=False)
        batch_op.create_index(batch_op.f('ix_inv_review_reviewer_id'), ['reviewer_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_inv_review_status'), ['status'], unique=False)


def downgrade() -> None:
    op.drop_table('inv_review')
