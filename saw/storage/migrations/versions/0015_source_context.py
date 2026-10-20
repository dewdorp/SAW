"""Add stable source context registry and immutable evidence snapshots.

Revision ID: 0015
Revises: 0014
"""
import sqlalchemy as sa
from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def _add_column(table, column, referent=None):
    bind = op.get_bind()
    if column.name not in {c["name"] for c in sa.inspect(bind).get_columns(table)}:
        with op.batch_alter_table(table) as batch:
            batch.add_column(column)
    if referent and not any(column.name in f["constrained_columns"] for f in sa.inspect(bind).get_foreign_keys(table)):
        with op.batch_alter_table(table) as batch:
            batch.create_foreign_key(f"fk_{table}_{column.name}", referent, [column.name], ["id"])


def upgrade():
    # Frozen declarations: later model changes must never change this migration.
    meta = sa.MetaData()
    sa.Table("inv_investigation", meta, sa.Column("id", sa.String(36), primary_key=True))
    org = sa.Table("sc_org_unit", meta,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("display_name", sa.String(64), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    assignment = sa.Table("sc_org_assignment", meta,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("investigation_id", sa.String(36), nullable=False),
        sa.Column("legacy_value", sa.String(64), nullable=False),
        sa.Column("org_unit_id", sa.String(36), sa.ForeignKey("sc_org_unit.id"), nullable=True),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    device = sa.Table("sc_device", meta,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("investigation_id", sa.String(36), nullable=False),
        sa.Column("display_name", sa.String(128), nullable=False),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    profile = sa.Table("sc_device_profile", meta,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("device_id", sa.String(36), sa.ForeignKey("sc_device.id"), nullable=False),
        sa.Column("version", sa.Integer, nullable=False),
        sa.Column("payload", sa.JSON, nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("device_id", "version"))
    snapshot = sa.Table("sc_evidence_context", meta,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("evidence_id", sa.String(36), nullable=False, unique=True),
        sa.Column("investigation_id", sa.String(36), nullable=False),
        sa.Column("device_profile_version_id", sa.String(36), sa.ForeignKey("sc_device_profile.id"), nullable=True),
        sa.Column("snapshot", sa.JSON, nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    for table in (org, assignment, device, profile, snapshot):
        table.create(op.get_bind(), checkfirst=True)
    _add_column("inv_investigation", sa.Column("org_unit_id", sa.String(36), nullable=True), "sc_org_unit")
    _add_column("ev_evidence", sa.Column("context_snapshot_id", sa.String(36), nullable=True), "sc_evidence_context")
    for table, column in (("inv_investigation", "org_unit_id"), ("sc_org_assignment", "investigation_id"),
                          ("sc_device", "investigation_id"), ("sc_device_profile", "device_id"),
                          ("sc_evidence_context", "investigation_id")):
        name = f"ix_{table}_{column}"
        if name not in {i["name"] for i in sa.inspect(op.get_bind()).get_indexes(table)}:
            op.create_index(name, table, [column])


def downgrade():
    for table, column in (("ev_evidence", "context_snapshot_id"), ("inv_investigation", "org_unit_id")):
        with op.batch_alter_table(table) as batch:
            batch.drop_column(column)
    for table in ("sc_evidence_context", "sc_device_profile", "sc_device", "sc_org_assignment", "sc_org_unit"):
        op.drop_table(table)