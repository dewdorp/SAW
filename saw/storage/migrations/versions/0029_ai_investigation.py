"""Add AI investigation records (additive only)."""
import sqlalchemy as sa
from alembic import op

from saw.llm.investigator import AiInvestigation

revision = "0029"
down_revision = "0028"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    table = AiInvestigation.__table__
    table.create(bind, checkfirst=True)  # idempotent: create_all may already have built it
    existing = {item["name"] for item in sa.inspect(bind).get_indexes(table.name)}
    for index in table.indexes:
        if index.name not in existing:
            index.create(bind)


def downgrade():
    raise RuntimeError("AI investigation records are retained; remove them with an explicit data migration.")
