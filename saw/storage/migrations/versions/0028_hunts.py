"""Add hunt runs and activity reviews (additive only)."""
import sqlalchemy as sa
from alembic import op

from saw.hunts.models import HuntReview, HuntRun

revision = "0028"
down_revision = "0027"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    for model in (HuntRun, HuntReview):
        table = model.__table__
        table.create(bind, checkfirst=True)  # idempotent: create_all may already have built it
        existing = {item["name"] for item in sa.inspect(bind).get_indexes(table.name)}
        for index in table.indexes:
            if index.name not in existing:
                index.create(bind)


def downgrade():
    raise RuntimeError("Hunt runs and reviews are retained; remove them with an explicit data migration.")
