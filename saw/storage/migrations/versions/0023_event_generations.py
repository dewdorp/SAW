"""Add immutable event generations and durable requester rotation without rewriting history."""
import sqlalchemy as sa
from alembic import op

from saw.event_generations.models import generation_tables
from saw.workers.queue_models import QueueCursor

revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    for table in [*generation_tables(), QueueCursor.__table__]:
        table.create(bind, checkfirst=True)
        existing = {item["name"] for item in sa.inspect(bind).get_indexes(table.name)}
        for index in table.indexes:
            if index.name not in existing:
                index.create(bind)
    existing = {item["name"] for item in sa.inspect(bind).get_indexes("an_job")}
    if "ix_an_job_queue_due" not in existing:
        op.create_index("ix_an_job_queue_due", "an_job", ["state", "requested_by", "created_at", "id"])
    cursor = QueueCursor.__table__
    if bind.scalar(sa.select(cursor.c.id).where(cursor.c.id == "heavy")) is None:
        bind.execute(cursor.insert().values(id="heavy", revision=0))


def downgrade():
    raise RuntimeError("Retained event generations require an explicit retention migration.")
