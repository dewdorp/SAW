"""Add the golden-set candidate inbox (pointers to casebook cases and investigations)."""
import sqlalchemy as sa
from alembic import op

from saw.internal_kb.models import GoldenCandidate

revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    table = GoldenCandidate.__table__
    table.create(bind, checkfirst=True)  # idempotent: create_all may already have built it
    existing = {item["name"] for item in sa.inspect(bind).get_indexes(table.name)}
    for index in table.indexes:
        if index.name not in existing:
            index.create(bind)


def downgrade():
    raise RuntimeError("Golden-set candidates are retained; remove them with an explicit data migration.")
