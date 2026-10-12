"""Local CPU model pack registry and transactional selection.

Revision ID: 0011
Revises: 0010
"""
import sqlalchemy as sa
from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade():
    tables = sa.inspect(op.get_bind()).get_table_names()
    if "ai_local_model_pack" not in tables:
        op.create_table("ai_local_model_pack",
            sa.Column("pack_id", sa.String(64), primary_key=True),
            sa.Column("manifest_sha256", sa.String(64), nullable=False),
            sa.Column("summary", sa.JSON(), nullable=False),
            sa.Column("validated_by", sa.String(36), nullable=False),
            sa.Column("validated_at", sa.DateTime(timezone=True), nullable=False))
    if "ai_local_model_selection" not in tables:
        op.create_table("ai_local_model_selection",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("pack_id", sa.String(64), nullable=True),
            sa.Column("epoch", sa.Integer(), nullable=False))


def downgrade():
    op.drop_table("ai_local_model_selection")
    op.drop_table("ai_local_model_pack")