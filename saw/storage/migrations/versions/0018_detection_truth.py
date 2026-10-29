"""Immutable selected detection truth.
Revision ID: 0018
Revises: 0017
"""
from alembic import op
import sqlalchemy as sa
revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade():
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "det_case" not in tables:
        op.create_table("det_case",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("investigation_id", sa.String(36), sa.ForeignKey("inv_investigation.id"), nullable=False),
            sa.Column("current_version", sa.Integer(), nullable=False),
            sa.Column("created_by", sa.String(36), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
        op.create_index("ix_det_case_investigation_id", "det_case", ["investigation_id"])
    if "det_case_version" not in tables:
        op.create_table("det_case_version",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("case_id", sa.String(36), sa.ForeignKey("det_case.id"), nullable=False),
            sa.Column("version", sa.Integer(), nullable=False),
            sa.Column("investigation_id", sa.String(36), nullable=False),
            sa.Column("payload", sa.JSON(), nullable=False),
            sa.Column("sha256", sa.String(64), nullable=False),
            sa.Column("source_manifest", sa.JSON(), nullable=False),
            sa.Column("input_sha256", sa.String(64), nullable=False),
            sa.Column("input_count", sa.Integer(), nullable=False),
            sa.Column("contributor_ids", sa.JSON(), nullable=False),
            sa.Column("created_by", sa.String(36), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("case_id", "version"))
        op.create_index("ix_det_case_version_case_id", "det_case_version", ["case_id"])
        op.create_index("ix_det_case_version_investigation_id", "det_case_version", ["investigation_id"])


def downgrade():
    op.drop_table("det_case_version")
    op.drop_table("det_case")
