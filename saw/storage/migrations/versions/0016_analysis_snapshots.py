"""Immutable analysis execution, finding and report snapshots.

Revision ID: 0016
Revises: 0015
"""
from alembic import op
import sqlalchemy as sa

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade():
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "an_analysis_run" not in tables:
        op.create_table("an_analysis_run",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("investigation_id", sa.String(36), sa.ForeignKey("inv_investigation.id"), nullable=False),
            sa.Column("version", sa.Integer(), nullable=False),
            sa.Column("job_id", sa.String(36)),
            sa.Column("created_by", sa.String(36), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("finished_at", sa.DateTime(timezone=True)),
            sa.Column("status", sa.String(24), nullable=False),
            sa.Column("input_manifest", sa.JSON(), nullable=False),
            sa.Column("input_sha256", sa.String(64), nullable=False),
            sa.Column("scope", sa.JSON(), nullable=False),
            sa.Column("engine_version", sa.String(32), nullable=False),
            sa.Column("summary", sa.JSON(), nullable=False),
            sa.UniqueConstraint("investigation_id", "version"))
        op.create_index("ix_an_analysis_run_investigation_id", "an_analysis_run", ["investigation_id"])
        op.create_index("ix_an_analysis_run_job_id", "an_analysis_run", ["job_id"])
    if "an_detector_execution" not in tables:
        op.create_table("an_detector_execution",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("run_id", sa.String(36), sa.ForeignKey("an_analysis_run.id"), nullable=False),
            sa.Column("detector_id", sa.String(128), nullable=False),
            sa.Column("detector_version", sa.String(64), nullable=False),
            sa.Column("status", sa.String(24), nullable=False),
            sa.Column("input_count", sa.Integer()),
            sa.Column("match_count", sa.Integer()),
            sa.Column("elapsed_ms", sa.Integer(), nullable=False),
            sa.Column("effective_config", sa.JSON(), nullable=False),
            sa.Column("detail", sa.JSON(), nullable=False),
            sa.UniqueConstraint("run_id", "detector_id"))
        op.create_index("ix_an_detector_execution_run_id", "an_detector_execution", ["run_id"])
    if "an_finding_snapshot" not in tables:
        op.create_table("an_finding_snapshot",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("run_id", sa.String(36), sa.ForeignKey("an_analysis_run.id"), nullable=False),
            sa.Column("finding_id", sa.String(36), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("payload", sa.JSON(), nullable=False),
            sa.Column("payload_sha256", sa.String(64), nullable=False),
            sa.UniqueConstraint("run_id", "finding_id"))
        op.create_index("ix_an_finding_snapshot_run_id", "an_finding_snapshot", ["run_id"])
        op.create_index("ix_an_finding_snapshot_finding_id", "an_finding_snapshot", ["finding_id"])
    if "an_report_version" not in tables:
        op.create_table("an_report_version",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("investigation_id", sa.String(36), sa.ForeignKey("inv_investigation.id"), nullable=False),
            sa.Column("version", sa.Integer(), nullable=False),
            sa.Column("created_by", sa.String(36), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("source_investigation_ids", sa.JSON(), nullable=False),
            sa.Column("content", sa.JSON(), nullable=False),
            sa.Column("content_sha256", sa.String(64), nullable=False),
            sa.UniqueConstraint("investigation_id", "version"))
        op.create_index("ix_an_report_version_investigation_id", "an_report_version", ["investigation_id"])


def downgrade():
    for table in ("an_report_version", "an_finding_snapshot", "an_detector_execution", "an_analysis_run"):
        op.drop_table(table)
