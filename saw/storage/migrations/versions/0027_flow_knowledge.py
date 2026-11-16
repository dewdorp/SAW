"""Add business-meaning knowledge, flow analysis runs and per-incident flow judgements (additive only)."""
import sqlalchemy as sa
from alembic import op

from saw.flows.models import FlowJudgement, FlowKnowledge, FlowKnowledgeVersion, FlowRun

revision = "0027"
down_revision = "0026"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    for model in (FlowKnowledge, FlowKnowledgeVersion, FlowRun, FlowJudgement):
        table = model.__table__
        table.create(bind, checkfirst=True)  # idempotent: create_all may already have built it
        existing = {item["name"] for item in sa.inspect(bind).get_indexes(table.name)}
        for index in table.indexes:
            if index.name not in existing:
                index.create(bind)


def downgrade():
    raise RuntimeError("Analyst knowledge and flow runs are retained; remove them with an explicit data migration.")
