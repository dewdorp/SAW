"""report summary edits (inv_briefing)

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-10 18:30:00
"""
from alembic import op
import sqlalchemy as sa


revision = '0006'
down_revision = '0005'
branch_labels = None
depends_on = None


def upgrade() -> None:
    if 'inv_briefing' in sa.inspect(op.get_bind()).get_table_names():
        return  # development databases built by create_all may have it already
    op.create_table('inv_briefing',
    sa.Column('investigation_id', sa.String(length=36), nullable=False),
    sa.Column('fields', sa.JSON(), nullable=False),
    sa.Column('rev', sa.Integer(), nullable=False),
    sa.Column('updated_by', sa.String(length=36), nullable=False),
    sa.Column('updated_by_name', sa.String(length=64), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['investigation_id'], ['inv_investigation.id'], ),
    sa.PrimaryKeyConstraint('investigation_id')
    )


def downgrade() -> None:
    op.drop_table('inv_briefing')
