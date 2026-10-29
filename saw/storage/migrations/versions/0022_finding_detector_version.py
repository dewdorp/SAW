"""Widen Finding provenance to match immutable detector executions without rewriting history."""
import sqlalchemy as sa
from alembic import op

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    column = next(column for column in sa.inspect(bind).get_columns("an_finding")
                  if column["name"] == "detector_version")
    existing_type = column["type"]
    # An already upgraded/create_all schema (or a wider legacy type) needs no rebuild.
    if isinstance(existing_type, sa.String) and (existing_type.length is None or existing_type.length >= 64):
        return
    with op.batch_alter_table("an_finding") as batch:
        batch.alter_column("detector_version", existing_type=existing_type,
                           type_=sa.String(64), existing_nullable=column["nullable"])


def downgrade():
    raise RuntimeError("Detector provenance cannot be narrowed without an explicit retention migration.")
