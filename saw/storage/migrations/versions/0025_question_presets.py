"""Add saved question conditions (current rows plus append-only versions)."""
import sqlalchemy as sa
from alembic import op

from saw.question_presets.models import QuestionPreset, QuestionPresetVersion

revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    for table in (QuestionPreset.__table__, QuestionPresetVersion.__table__):
        table.create(bind, checkfirst=True)  # idempotent: create_all may already have built it
        existing = {item["name"] for item in sa.inspect(bind).get_indexes(table.name)}
        for index in table.indexes:
            if index.name not in existing:
                index.create(bind)


def downgrade():
    raise RuntimeError("Saved question conditions are retained; remove them with an explicit data migration.")
