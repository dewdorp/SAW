"""Immutable scoped behavior results.

Revision ID: 0014
Revises: 0013
"""
from alembic import op
import sqlalchemy as sa

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade():
    if "an_behavior_result" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table("an_behavior_result",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("investigation_id", sa.String(36), sa.ForeignKey("inv_investigation.id"), nullable=False),
        sa.Column("job_id", sa.String(36), sa.ForeignKey("an_job.id"), nullable=False, unique=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.Column("result_sha256", sa.String(64), nullable=False),
        sa.UniqueConstraint("investigation_id", "version"))
    op.create_index("ix_an_behavior_result_investigation_id", "an_behavior_result", ["investigation_id"])


def downgrade():
    op.drop_table("an_behavior_result")
