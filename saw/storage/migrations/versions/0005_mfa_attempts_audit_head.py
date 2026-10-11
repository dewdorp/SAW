"""MFA attempt limit / code replay, audit chain head

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-10 12:00:00
"""
from alembic import op
import sqlalchemy as sa


revision = '0005'
down_revision = '0004'
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    user_cols = {c['name'] for c in insp.get_columns('iam_user')}
    if 'mfa_failed_count' not in user_cols:  # development databases built by create_all may have them already
        with op.batch_alter_table('iam_user', schema=None) as batch_op:
            batch_op.add_column(sa.Column('mfa_failed_count', sa.Integer(), server_default='0', nullable=False))
            batch_op.add_column(sa.Column('mfa_last_step', sa.BigInteger(), nullable=True))
    if 'audit_head' not in insp.get_table_names():
        op.create_table('audit_head',
        sa.Column('id', sa.Integer(), autoincrement=False, nullable=False),
        sa.Column('last_id', sa.Integer(), nullable=False),
        sa.Column('last_hash', sa.String(length=64), nullable=False),
        sa.Column('entries', sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint('id')
        )
    # The head starts at the chain as it is at upgrade time; entries removed before the upgrade cannot be recovered.
    if bind.execute(sa.text("SELECT COUNT(*) FROM audit_head")).scalar() == 0:
        n = bind.execute(sa.text("SELECT COUNT(*) FROM audit_event")).scalar() or 0
        last = bind.execute(sa.text("SELECT id, hash FROM audit_event ORDER BY id DESC LIMIT 1")).first()
        bind.execute(sa.text("INSERT INTO audit_head (id, last_id, last_hash, entries) VALUES (1, :i, :h, :n)"),
                     {"i": last[0] if last else 0, "h": last[1] if last else "0" * 64, "n": n})


def downgrade() -> None:
    op.drop_table('audit_head')
    with op.batch_alter_table('iam_user', schema=None) as batch_op:
        batch_op.drop_column('mfa_last_step')
        batch_op.drop_column('mfa_failed_count')
