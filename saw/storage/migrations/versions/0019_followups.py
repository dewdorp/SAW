"""Immutable Check snapshots and versioned analyst follow-ups.

Revision ID: 0019
Revises: 0018
"""
from alembic import op
import sqlalchemy as sa

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade():
    existing = set(sa.inspect(op.get_bind()).get_table_names())
    if "inv_check_revision" not in existing:
        op.create_table("inv_check_revision",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("check_id", sa.String(36), sa.ForeignKey("inv_check.id"), nullable=False),
            sa.Column("investigation_id", sa.String(36), sa.ForeignKey("inv_investigation.id"), nullable=False),
            sa.Column("revision", sa.Integer(), nullable=False),
            sa.Column("payload", sa.JSON(), nullable=False),
            sa.Column("payload_sha256", sa.String(64), nullable=False),
            sa.Column("source_investigation_ids", sa.JSON(), nullable=False),
            sa.Column("created_by", sa.String(36), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("capture_reason", sa.String(64), nullable=False),
            sa.Column("origin", sa.String(32), nullable=False),
            sa.UniqueConstraint("check_id", "revision"))
        op.create_index("ix_inv_check_revision_check_id", "inv_check_revision", ["check_id"])
        op.create_index("ix_inv_check_revision_investigation_id", "inv_check_revision", ["investigation_id"])
    if "inv_followup" not in existing:
        op.create_table("inv_followup",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("investigation_id", sa.String(36), sa.ForeignKey("inv_investigation.id"), nullable=False),
            sa.Column("current_version_id", sa.String(36), nullable=True),
            sa.Column("current_revision", sa.Integer(), nullable=False),
            sa.Column("created_by", sa.String(36), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
        op.create_index("ix_inv_followup_investigation_id", "inv_followup", ["investigation_id"])
    if "inv_followup_version" not in existing:
        op.create_table("inv_followup_version",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("followup_id", sa.String(36), sa.ForeignKey("inv_followup.id"), nullable=False),
            sa.Column("revision", sa.Integer(), nullable=False),
            sa.Column("payload", sa.JSON(), nullable=False),
            sa.Column("payload_sha256", sa.String(64), nullable=False),
            sa.Column("source_investigation_ids", sa.JSON(), nullable=False),
            sa.Column("created_by", sa.String(36), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("action", sa.String(32), nullable=False),
            sa.UniqueConstraint("followup_id", "revision"))
        op.create_index("ix_inv_followup_version_followup_id", "inv_followup_version", ["followup_id"])


    # A prior interrupted migration or create_all may have left tables without indexes.
    for table, columns in (("inv_check_revision", ("check_id", "investigation_id")),
                           ("inv_followup", ("investigation_id",)),
                           ("inv_followup_version", ("followup_id",))):
        present = {item["name"] for item in sa.inspect(op.get_bind()).get_indexes(table)}
        for column in columns:
            name = "ix_" + table + "_" + column
            if name not in present:
                op.create_index(name, table, [column])


def downgrade():
    raise RuntimeError("Follow-up history requires an explicit retention migration.")
