"""parser library (analyst-defined parser definitions)

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-09 12:00:00
"""
from alembic import op
import sqlalchemy as sa


revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    if 'ps_parser' in sa.inspect(op.get_bind()).get_table_names():
        return  # already built by create_all (development databases)
    op.create_table(
        'ps_parser',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('slug', sa.String(length=48), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('version', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('spec', sa.JSON(), nullable=False),
        sa.Column('note', sa.Text(), nullable=False),
        sa.Column('created_by', sa.String(length=36), nullable=False),
        sa.Column('created_by_name', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('slug', 'version', name='uq_ps_parser_slug_version'),
    )
    with op.batch_alter_table('ps_parser', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_ps_parser_slug'), ['slug'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('ps_parser', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_ps_parser_slug'))
    op.drop_table('ps_parser')
