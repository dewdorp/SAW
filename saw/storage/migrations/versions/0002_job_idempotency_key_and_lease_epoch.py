"""job idempotency key and lease epoch

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-08 00:25:46.798958
"""
from alembic import op
import sqlalchemy as sa


revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('an_job', schema=None) as batch_op:
        batch_op.add_column(sa.Column('idempotency_key', sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column('attempt', sa.Integer(), nullable=False, server_default='0'))
        batch_op.create_unique_constraint('uq_an_job_idempotency', ['requested_by', 'idempotency_key'])



def downgrade() -> None:
    with op.batch_alter_table('an_job', schema=None) as batch_op:
        batch_op.drop_constraint('uq_an_job_idempotency', type_='unique')
        batch_op.drop_column('attempt')
        batch_op.drop_column('idempotency_key')

