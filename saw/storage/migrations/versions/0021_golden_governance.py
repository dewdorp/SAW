"""Additive Golden governance history, preserving all existing snapshot bytes."""
from alembic import op
import sqlalchemy as sa
from saw.knowledge import golden_governance_models as models

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None

TABLES = [models.GoldenProfileVersion, models.GoldenValidation, models.GoldenRelease,
          models.GoldenReleaseVersion, models.GoldenReleaseDecision, models.GoldenReleasePreview,
          models.GoldenReleaseSource, models.GoldenHoldoutAttempt, models.GoldenHoldoutUse]


def upgrade():
    bind = op.get_bind()
    for model in TABLES:
        table = model.__table__
        table.create(bind, checkfirst=True)
        existing = {x["name"] for x in sa.inspect(bind).get_indexes(table.name)}
        for index in table.indexes:
            if index.name not in existing:
                index.create(bind)


def downgrade():
    raise RuntimeError("Golden release history requires an explicit retention migration.")
