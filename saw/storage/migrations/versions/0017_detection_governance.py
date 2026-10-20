"""Separate draft, approved and active detection versions; immutable policy history.

Revision ID: 0017
Revises: 0016
"""
from datetime import datetime, timezone
from hashlib import sha256
import json
from uuid import uuid4
from alembic import op
import sqlalchemy as sa

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None

FIELDS = ("title", "description", "data_source", "format", "logic", "threshold", "exceptions",
          "false_positive", "severity", "confidence", "test_events", "attack")


def _digest(value):
    return sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _add(table, column):
    if column.name not in {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}:
        with op.batch_alter_table(table) as batch:
            batch.add_column(column)


def _create():
    bind = op.get_bind()
    meta = sa.MetaData()
    sa.Table("det_detection", meta, sa.Column("id", sa.String(36), primary_key=True))
    binding = sa.Table("det_policy_binding", meta,
        sa.Column("id", sa.String(36), primary_key=True), sa.Column("detector_id", sa.String(128), nullable=False),
        sa.Column("scope_key", sa.String(128), nullable=False), sa.Column("scope", sa.JSON(), nullable=False),
        *[sa.Column(k, sa.String(36)) for k in ("draft_version_id", "approved_version_id", "active_version_id",
                                               "approved_approval_id", "active_approval_id")],
        sa.Column("activation_revision", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_by", sa.String(36), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("detector_id", "scope_key"))
    version = sa.Table("det_policy_version", meta,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("binding_id", sa.String(36), sa.ForeignKey("det_policy_binding.id"), nullable=False, index=True),
        sa.Column("version", sa.Integer(), nullable=False), sa.Column("parent_version_id", sa.String(36)),
        sa.Column("spec_id", sa.String(128), nullable=False), sa.Column("spec_version", sa.String(64), nullable=False),
        sa.Column("spec_sha256", sa.String(64), nullable=False), sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("payload_sha256", sa.String(64), nullable=False), sa.Column("contributor_ids", sa.JSON(), nullable=False),
        sa.Column("legacy_contributor_names", sa.JSON(), nullable=False), sa.Column("contributor_resolution", sa.String(32), nullable=False),
        sa.Column("created_by", sa.String(36), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("binding_id", "version"))
    approval = sa.Table("det_approval", meta,
        sa.Column("id", sa.String(36), primary_key=True), sa.Column("subject_kind", sa.String(16), nullable=False, index=True),
        sa.Column("subject_id", sa.String(36), nullable=False, index=True),
        sa.Column("subject_version_id", sa.String(36), nullable=False, index=True),
        sa.Column("payload_sha256", sa.String(64), nullable=False), sa.Column("reviewer_id", sa.String(36), nullable=False),
        sa.Column("reviewer_name", sa.String(64), nullable=False), sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("proof", sa.JSON(), nullable=False), sa.Column("proof_sha256", sa.String(64), nullable=False),
        sa.Column("contributor_ids", sa.JSON(), nullable=False), sa.Column("source_investigation_ids", sa.JSON(), nullable=False),
        sa.Column("provenance", sa.String(32), nullable=False))
    activation = sa.Table("det_activation", meta,
        sa.Column("id", sa.String(36), primary_key=True), sa.Column("subject_kind", sa.String(16), nullable=False, index=True),
        sa.Column("subject_id", sa.String(36), nullable=False, index=True), sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("from_version_id", sa.String(36)), sa.Column("to_version_id", sa.String(36)), sa.Column("approval_id", sa.String(36)),
        sa.Column("action", sa.String(32), nullable=False), sa.Column("actor_id", sa.String(36), nullable=False),
        sa.Column("actor_name", sa.String(64), nullable=False), sa.Column("reason", sa.String(2000), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("snapshot", sa.JSON(), nullable=False),
        sa.UniqueConstraint("subject_kind", "subject_id", "revision"))
    for table in (binding, version, approval, activation):
        table.create(bind, checkfirst=True)



def _package_evidence(bind, d, version, users, ids):
    """Replay retained exact fixtures; never turn an unknown legacy actor into an approval."""
    from saw.content_packages import format as fmt
    reviewer = users.get(version["reviewed_by"])
    people = set(version["contributor_ids"])
    if (version["format"] != "sigma" or version["status_at_version"] not in {"approved", "deployed"}
            or version["legacy_contributor_names"] or not reviewer or reviewer["status"] != "active"
            or reviewer["id"] in people or not set(reviewer["roles"]) & {"soc_manager", "senior_analyst"}
            or any(i not in ids or ids[i]["status"] != "active" for i in people)):
        return None
    if not {"cp_validation", "cp_package"} <= set(sa.inspect(bind).get_table_names()):
        return None
    validation_table = sa.Table("cp_validation", sa.MetaData(), autoload_with=bind)
    package_table = sa.Table("cp_package", sa.MetaData(), autoload_with=bind)
    validation = bind.execute(sa.select(validation_table).where(
        validation_table.c.detection_id == d["id"], validation_table.c.version == version["version"])).mappings().first()
    package = bind.execute(sa.select(package_table).where(
        package_table.c.id == validation["package_record_id"])).mappings().first() if validation else None
    if not package or validation["kind"] != "package_fixture" or package["status"] not in {"applied", "rolled_back"}:
        return None
    try:
        result, receipt = package["test_result"], package["receipt"]
        entry = next(e for e in package["document"]["entries"] if e["kind"] == "sigma"
                     and e["source_id"] == validation["source_id"])
        item = next(i for i in receipt["items"] if i["kind"] == "sigma" and i["source_id"] == validation["source_id"])
        live = item["after"]["live"]
        same = (result.get("passed") and result.get("kind") == "package_fixture"
                and result.get("engine") == fmt.ENGINE and result.get("digest") == package["digest"]
                and fmt.payload_hash(package["document"]) == package["digest"] == package["document"]["payload_sha256"]
                and receipt.get("digest") == package["digest"] and receipt.get("validation_kind") == "package_fixture"
                and receipt.get("applied_by_id") == reviewer["id"] and receipt.get("applied_by") == reviewer["username"]
                and item["target_id"] == d["id"] == live["target_id"]
                and live["current_version"] == version["version"] and live["reviewer"] == reviewer["username"]
                and fmt.digest(fmt.normalized(entry)) == validation["payload_digest"]
                == fmt.digest({key: version[key] for key in fmt.SIGMA_KEYS}) == fmt.digest(live["payload"]))
        importer = ids.get(package["imported_by"])
        if (not same or not importer or importer["status"] != "active" or importer["id"] == reviewer["id"]
                or not set(importer["roles"]) & {"analyst", "senior_analyst", "soc_manager"}):
            return None
        checked = fmt.run_fixtures(package["document"])
        if not checked.get("passed"):
            return None
        people.add(importer["id"])
        proof = {"method": "package_fixture", "package_record_id": package["id"],
                 "package_sha256": package["digest"], "source_id": validation["source_id"],
                 "payload_sha256": version["payload_sha256"], "engine": fmt.ENGINE,
                 "legacy_receipt_adapter": "package-receipt/0014-to-0017/1",
                 "legacy_receipt_sha256": _digest(receipt),
                 "source_investigation_ids": [d["source"]["investigation_id"]] if d["source"].get("investigation_id") else []}
        return proof, people
    except (ValueError, TypeError, KeyError, StopIteration):
        return None


def _backfill_package_history():
    """Admit proven historical package versions without inventing activations or rewriting receipts."""
    bind = op.get_bind()
    meta = sa.MetaData()
    tables = {name: sa.Table(name, meta, autoload_with=bind) for name in
              ("det_detection", "det_version", "iam_user", "det_approval")}
    users = {u["username"]: dict(u) for u in bind.execute(sa.select(tables["iam_user"])).mappings()}
    ids = {u["id"]: u for u in users.values()}
    for d in bind.execute(sa.select(tables["det_detection"])).mappings().all():
        for version in bind.execute(sa.select(tables["det_version"]).where(
                tables["det_version"].c.detection_id == d["id"])).mappings().all():
            if bind.execute(sa.select(tables["det_approval"].c.id).where(
                    tables["det_approval"].c.subject_kind == "rule",
                    tables["det_approval"].c.subject_id == d["id"],
                    tables["det_approval"].c.subject_version_id == version["id"])).first():
                continue
            admitted = _package_evidence(bind, d, version, users, ids)
            if admitted is None:
                continue
            proof, people = admitted
            reviewer = users[version["reviewed_by"]]
            bind.execute(tables["det_approval"].insert().values(id=str(uuid4()), subject_kind="rule",
                subject_id=d["id"], subject_version_id=version["id"], payload_sha256=version["payload_sha256"],
                reviewer_id=reviewer["id"], reviewer_name=reviewer["username"], reviewed_at=datetime.now(timezone.utc),
                proof=proof, proof_sha256=_digest(proof), contributor_ids=sorted(people),
                source_investigation_ids=proof["source_investigation_ids"], provenance="legacy_admission"))

def _backfill():
    """Admit only a current approved head with complete, identifiable prior evidence."""
    bind = op.get_bind()
    meta = sa.MetaData()
    tables = {name: sa.Table(name, meta, autoload_with=bind) for name in
              ("det_detection", "det_version", "det_test_run", "iam_user", "det_approval", "det_activation")}
    dtable, vtable = tables["det_detection"], tables["det_version"]
    users = {u["username"]: dict(u) for u in bind.execute(sa.select(tables["iam_user"])).mappings()}
    ids = {u["id"]: u for u in users.values()}
    now = datetime.now(timezone.utc)
    for d in bind.execute(sa.select(dtable)).mappings().all():
        versions = [dict(v) for v in bind.execute(sa.select(vtable).where(vtable.c.detection_id == d["id"])
                                                 .order_by(vtable.c.version)).mappings()]
        if not versions:
            continue
        people, unresolved, parent = {d["created_by"]}, set(), None
        for v in versions:
            author = users.get(v["created_by"])
            if author:
                people.add(author["id"])
            else:
                unresolved.add(v["created_by"])
            payload_hash = _digest({key: v[key] for key in FIELDS})
            if not v.get("payload_sha256"):
                bind.execute(vtable.update().where(vtable.c.id == v["id"]).values(
                    parent_version_id=parent, author_id=author["id"] if author else None,
                    payload_sha256=payload_hash, contributor_ids=sorted(people),
                    legacy_contributor_names=sorted(unresolved), contributor_resolution="unresolved" if unresolved else "resolved"))
            v.update(payload_sha256=payload_hash, contributor_ids=sorted(people), legacy_contributor_names=sorted(unresolved))
            parent = v["id"]
        head = versions[-1]
        if d["draft_version_id"] or d["approved_version_id"] or d["active_version_id"] or d["activation_revision"]:
            continue
        if d["status"] in {"draft", "test"}:
            bind.execute(dtable.update().where(dtable.c.id == d["id"]).values(draft_version_id=head["id"]))
            continue
        reviewer = users.get(head["reviewed_by"])
        if (d["status"] not in {"approved", "deployed"} or head["status_at_version"] not in {"approved", "deployed"}
                or d["current_version"] != head["version"] or head["format"] != "sigma" or unresolved
                or not reviewer or reviewer["status"] != "active" or reviewer["id"] in people
                or not set(reviewer["roles"]) & {"soc_manager", "senior_analyst"}
                or any(i not in ids or ids[i]["status"] != "active" for i in people)):
            continue
        trials = bind.execute(sa.select(tables["det_test_run"]).where(tables["det_test_run"].c.detection_id == d["id"],
                               tables["det_test_run"].c.version == head["version"], tables["det_test_run"].c.passed.is_(True))).mappings()
        trial = next((t for t in trials if t["result"].get("execution") == "complete"
                      and t["result"].get("scanned", 0) > 0 and not t["result"].get("truncated")
                      and not t["result"].get("evaluation_errors")), None)
        package_proof = None
        if trial is None:
            admitted = _package_evidence(bind, d, head, users, ids)
            if admitted is None:
                continue
            package_proof, package_people = admitted
            people.update(package_people)
        try:
            from saw.detection.sigma_eval import compile_rule, validate_threshold
            compile_rule(head["logic"])
            validate_threshold(head["threshold"])
        except (ValueError, TypeError):
            continue
        proof = package_proof or {"method": "legacy_admission", "historical_test_run_id": trial["id"],
                 "payload_sha256": head["payload_sha256"], "result_sha256": _digest(trial["result"]),
                 "legacy_status": d["status"], "source_investigation_ids": sorted(set(
                     trial["scope"].get("investigations", []) + ([d["source"]["investigation_id"]] if d["source"].get("investigation_id") else [])))}
        aid = str(uuid4())
        bind.execute(tables["det_approval"].insert().values(id=aid, subject_kind="rule", subject_id=d["id"],
            subject_version_id=head["id"], payload_sha256=head["payload_sha256"], reviewer_id=reviewer["id"],
            reviewer_name=reviewer["username"], reviewed_at=now, proof=proof, proof_sha256=_digest(proof),
            contributor_ids=sorted(people), source_investigation_ids=proof["source_investigation_ids"], provenance="legacy_admission"))
        bind.execute(dtable.update().where(dtable.c.id == d["id"]).values(approved_version_id=head["id"],
            active_version_id=head["id"], approved_approval_id=aid, active_approval_id=aid, activation_revision=1))
        bind.execute(tables["det_activation"].insert().values(id=str(uuid4()), subject_kind="rule", subject_id=d["id"],
            revision=1, to_version_id=head["id"], approval_id=aid, action="legacy_admission", actor_id=reviewer["id"],
            actor_name=reviewer["username"], reason="Preserved exact current approved legacy head", created_at=now,
            snapshot={"legacy_status": d["status"], "proof_sha256": _digest(proof)}))


def upgrade():
    bind = op.get_bind()
    duplicates = bind.execute(sa.text("SELECT detection_id, version FROM det_version GROUP BY detection_id, version HAVING COUNT(*) > 1")).first()
    if duplicates:
        raise RuntimeError("Duplicate detection version numbers require manual reconciliation before migration")
    for name in ("draft_version_id", "approved_version_id", "active_version_id", "approved_approval_id", "active_approval_id"):
        _add("det_detection", sa.Column(name, sa.String(36), nullable=True))
    _add("det_detection", sa.Column("activation_revision", sa.Integer(), nullable=False, server_default="0"))
    for name in ("parent_version_id", "author_id"):
        _add("det_version", sa.Column(name, sa.String(36), nullable=True))
    _add("det_version", sa.Column("payload_sha256", sa.String(64), nullable=False, server_default=""))
    for name in ("contributor_ids", "legacy_contributor_names"):
        _add("det_version", sa.Column(name, sa.JSON(), nullable=False, server_default="[]"))
    _add("det_version", sa.Column("contributor_resolution", sa.String(32), nullable=False, server_default="resolved"))
    if not any(set(u["column_names"]) == {"detection_id", "version"} for u in sa.inspect(bind).get_unique_constraints("det_version")):
        with op.batch_alter_table("det_version") as batch:
            batch.create_unique_constraint("uq_det_version_number", ["detection_id", "version"])
    _create()
    _backfill()
    _backfill_package_history()


def downgrade():
    raise RuntimeError("Detection governance history is retained; restore a reviewed database backup to downgrade")
