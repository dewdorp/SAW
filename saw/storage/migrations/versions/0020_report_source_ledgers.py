"""Source ledgers for immutable reports and export jobs.

Revision ID: 0020
Revises: 0019
"""
import sqlalchemy as sa
from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade():
    from saw.reports.source_scope import content_source_ids

    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    for name, parent, column in (
        ("an_report_source_investigation", "an_report_version.id", "report_id"),
        ("an_job_source_investigation", "an_job.id", "job_id"),
    ):
        if name not in tables:
            op.create_table(name,
                sa.Column(column, sa.String(36), sa.ForeignKey(parent, ondelete="CASCADE"), primary_key=True),
                sa.Column("investigation_id", sa.String(36), primary_key=True))
        indexes = {x["name"] for x in sa.inspect(bind).get_indexes(name)}
        index = "ix_" + name + "_investigation_id"
        if index not in indexes:
            op.create_index(index, name, ["investigation_id"])
    reports = sa.Table("an_report_version", sa.MetaData(), autoload_with=bind)
    ledger = sa.Table("an_report_source_investigation", sa.MetaData(), autoload_with=bind)
    for row in bind.execute(sa.select(reports.c.id, reports.c.investigation_id,
                                      reports.c.source_investigation_ids, reports.c.content)).mappings():
        # Repair only the authority ledger; historical content and its hash stay exact.
        sources = content_source_ids(row["content"], base_sources={
            row["investigation_id"], *(row["source_investigation_ids"] or [])})
        for source in sorted(sources):
            found = bind.execute(sa.select(ledger.c.report_id).where(
                ledger.c.report_id == row["id"], ledger.c.investigation_id == source)).first()
            if found is None:
                bind.execute(ledger.insert().values(report_id=row["id"], investigation_id=source))


def downgrade():
    op.drop_table("an_job_source_investigation")
    op.drop_table("an_report_source_investigation")
