"""signature switches (det_signature_setting)

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-11 22:00:00
"""
from alembic import op
import sqlalchemy as sa


revision = '0010'
down_revision = '0009'
branch_labels = None
depends_on = None


def upgrade() -> None:
    if 'det_signature_setting' in sa.inspect(op.get_bind()).get_table_names():
        return  # development databases built by create_all may have it already
    op.create_table('det_signature_setting',
    sa.Column('sig_id', sa.String(length=96), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('note', sa.String(length=512), nullable=False),
    sa.Column('updated_by', sa.String(length=64), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('sig_id')
    )


def downgrade() -> None:
    op.drop_table('det_signature_setting')
