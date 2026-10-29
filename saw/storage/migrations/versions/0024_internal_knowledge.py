"""Add internal golden records and device alert-name meanings (current rows plus append-only versions)."""
import sqlalchemy as sa
from alembic import op

from saw.internal_kb.models import DeviceSignature, DeviceSignatureVersion, InternalGolden, InternalGoldenVersion

revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    for table in (InternalGolden.__table__, InternalGoldenVersion.__table__,
                  DeviceSignature.__table__, DeviceSignatureVersion.__table__):
        table.create(bind, checkfirst=True)  # idempotent: create_all may already have built it
        existing = {item["name"] for item in sa.inspect(bind).get_indexes(table.name)}
        for index in table.indexes:
            if index.name not in existing:
                index.create(bind)


def downgrade():
    raise RuntimeError("Internal knowledge records are retained; remove them with an explicit data migration.")
