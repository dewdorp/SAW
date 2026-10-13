"""Durable administrator cleanup receipts.

Revision ID: 0012
Revises: 0011
"""
import sqlalchemy as sa
from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade():
    if "admin_data_deletion" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table("admin_data_deletion",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("target_type", sa.String(16), nullable=False),
        sa.Column("target_id", sa.String(36), nullable=False),
        sa.Column("investigation_id", sa.String(36), nullable=True),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("step", sa.String(16), nullable=False),
        sa.Column("plan", sa.JSON(), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("actor_id", sa.String(36), nullable=False),
        sa.Column("actor_name", sa.String(64), nullable=False),
        sa.Column("error_code", sa.String(48), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_admin_data_deletion_target_id", "admin_data_deletion", ["target_id"])
    op.create_index("ix_admin_data_deletion_investigation_id", "admin_data_deletion", ["investigation_id"])


def downgrade():
    op.drop_table("admin_data_deletion")
