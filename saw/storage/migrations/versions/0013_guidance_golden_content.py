"""Immutable golden cases and staged offline content packages.

Revision ID: 0013
Revises: 0012
"""
from alembic import op
import sqlalchemy as sa

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade():
    existing = set(sa.inspect(op.get_bind()).get_table_names())
    if "cp_binding" not in existing:
        op.create_table('cp_binding',
        sa.Column('kind', sa.String(length=16), nullable=False),
        sa.Column('source_id', sa.String(length=47), nullable=False),
        sa.Column('target_id', sa.String(length=64), nullable=False),
        sa.Column('source_version', sa.Integer(), nullable=False),
        sa.Column('max_source_version', sa.Integer(), nullable=False),
        sa.Column('payload_digest', sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint('kind', 'source_id')
        )
    if "cp_package" not in existing:
        op.create_table('cp_package',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('package_id', sa.String(length=64), nullable=False),
        sa.Column('revision', sa.Integer(), nullable=False),
        sa.Column('digest', sa.String(length=64), nullable=False),
        sa.Column('document', sa.JSON(), nullable=False),
        sa.Column('imported_by', sa.String(length=36), nullable=False),
        sa.Column('imported_by_name', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('baseline', sa.JSON(), nullable=False),
        sa.Column('test_result', sa.JSON(), nullable=False),
        sa.Column('receipt', sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('package_id', 'revision', name='uq_cp_package_revision')
        )
    if "cp_validation" not in existing:
        op.create_table('cp_validation',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('detection_id', sa.String(length=36), nullable=False),
        sa.Column('version', sa.Integer(), nullable=False),
        sa.Column('package_record_id', sa.String(length=36), nullable=False),
        sa.Column('source_id', sa.String(length=47), nullable=False),
        sa.Column('payload_digest', sa.String(length=64), nullable=False),
        sa.Column('kind', sa.String(length=32), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('detection_id', 'version', name='uq_cp_validation_version')
        )
        op.create_index(op.f('ix_cp_validation_detection_id'), 'cp_validation', ['detection_id'], unique=False)
    if "kn_golden_blob" not in existing:
        op.create_table('kn_golden_blob',
        sa.Column('sha256', sa.String(length=64), nullable=False),
        sa.Column('content', sa.JSON(), nullable=False),
        sa.Column('size_bytes', sa.Integer(), nullable=False),
        sa.Column('masking_version', sa.String(length=32), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('sha256')
        )
    if "kn_golden_family" not in existing:
        op.create_table('kn_golden_family',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('split', sa.String(length=16), nullable=False),
        sa.Column('created_by', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
        )
    if "kn_golden_family_member" not in existing:
        op.create_table('kn_golden_family_member',
        sa.Column('investigation_id', sa.String(length=36), nullable=False),
        sa.Column('family_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['family_id'], ['kn_golden_family.id'], ),
        sa.PrimaryKeyConstraint('investigation_id')
        )
        op.create_index(op.f('ix_kn_golden_family_member_family_id'), 'kn_golden_family_member', ['family_id'], unique=False)
    if "kn_golden_version" not in existing:
        op.create_table('kn_golden_version',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('experience_id', sa.String(length=36), nullable=False),
        sa.Column('experience_rev', sa.Integer(), nullable=False),
        sa.Column('version', sa.Integer(), nullable=False),
        sa.Column('source_investigation_id', sa.String(length=36), nullable=False),
        sa.Column('family_id', sa.String(length=36), nullable=True),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('methodology_version', sa.String(length=64), nullable=False),
        sa.Column('as_of', sa.DateTime(timezone=True), nullable=False),
        sa.Column('input', sa.JSON(), nullable=False),
        sa.Column('answers', sa.JSON(), nullable=False),
        sa.Column('manifest', sa.JSON(), nullable=False),
        sa.Column('metadata_json', sa.JSON(), nullable=False),
        sa.Column('content_sha256', sa.String(length=64), nullable=False),
        sa.Column('author_id', sa.String(length=36), nullable=False),
        sa.Column('contributor_ids', sa.JSON(), nullable=False),
        sa.Column('reviewer_id', sa.String(length=36), nullable=True),
        sa.Column('reviewer_name', sa.String(length=64), nullable=True),
        sa.Column('confirmations', sa.JSON(), nullable=False),
        sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['experience_id'], ['kn_experience.id'], ),
        sa.ForeignKeyConstraint(['family_id'], ['kn_golden_family.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('experience_id', 'version')
        )
        op.create_index(op.f('ix_kn_golden_version_experience_id'), 'kn_golden_version', ['experience_id'], unique=False)
        op.create_index(op.f('ix_kn_golden_version_source_investigation_id'), 'kn_golden_version', ['source_investigation_id'], unique=False)


def downgrade():
    for name in ("kn_golden_version", "kn_golden_family_member", "kn_golden_family", "kn_golden_blob", "cp_validation", "cp_package", "cp_binding"):
        op.drop_table(name)
