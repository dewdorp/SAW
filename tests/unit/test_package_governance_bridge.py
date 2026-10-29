"""Real 0014 receipts survive 0017 without rewriting history or inventing approval."""
import copy
import importlib
from alembic.migration import MigrationContext
from alembic.operations import Operations
from datetime import UTC, datetime
import json

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session

from saw.content_packages import format as fmt, service as packages
from saw.content_packages.models import ContentPackage
from saw.core.application.identity import principal_of
from saw.detection import service as detection
from saw.detection.policy_models import Approval
from saw.storage.db import make_engine
from saw.storage.migrate import upgrade
from saw.storage.models import User

NOW = datetime.now(UTC)
LOGIC = "title: Synthetic\nlogsource: {category: webserver}\ndetection:\n  s: {cs-uri-stem: /synthetic-sensitive}\n  condition: s\n"


def document(number):
    doc = {"schema": fmt.SCHEMA, "package_id": "synthetic-legacy", "revision": number,
           "requires": {"content_engine": fmt.ENGINE}, "entries": [
               {"kind": "sigma", "source_id": "synthetic-rule", "source_version": number,
                "content": {"title": "Synthetic " + str(number), "logic": LOGIC, "data_source": "web"},
                "fixtures": [
                    {"name": "positive", "expected": "match",
                     "events": [{"data_source": "web", "url_path": "/synthetic-sensitive"}]},
                    {"name": "benign", "expected": "no_match",
                     "events": [{"data_source": "web", "url_path": "/health"}]}]}]}
    doc["payload_sha256"] = fmt.payload_hash(doc)
    return doc


def seed(tmp_path, *, first_reviewer="reviewer", bad_fixture=False):
    engine = make_engine(f"sqlite:///{(tmp_path / 'legacy-package.db').as_posix()}")
    upgrade(engine, "0014")
    with engine.begin() as c:
        meta = sa.MetaData()
        tables = {name: sa.Table(name, meta, autoload_with=c) for name in
                  ("iam_user", "det_detection", "det_version", "cp_package", "cp_binding", "cp_validation")}
        for ident, roles in (("author", ["analyst"]), ("reviewer", ["soc_manager"]), ("rollbacker", ["soc_manager"])):
            c.execute(tables["iam_user"].insert().values(id=ident, username=ident, display_name="",
                      password_hash="", roles=roles, mfa_enabled=False, status="active",
                      failed_count=0, created_at=NOW))
        c.execute(tables["det_detection"].insert().values(id="det", display_id="DET-synthetic",
                  status="approved", current_version=2, created_by="author", created_by_name="author",
                  deployments=[], source={"content_source_id": "synthetic-rule"}, created_at=NOW, updated_at=NOW))
        previous = {"kind": "sigma", "source_id": "synthetic-rule", "binding": None, "live": None}
        for number in (1, 2):
            doc = document(number)
            if number == 1 and bad_fixture:
                doc["entries"][0]["fixtures"][1]["events"][0]["url_path"] = "/synthetic-sensitive"
                doc["payload_sha256"] = fmt.payload_hash(doc)
            content = fmt.normalized(doc["entries"][0])
            reviewer = first_reviewer if number == 1 else "reviewer"
            c.execute(tables["det_version"].insert().values(id=f"v{number}", detection_id="det", version=number,
                      **content, test_events=[], created_by="author", reviewed_by=reviewer,
                      status_at_version="approved", created_at=NOW))
            binding = {"kind": "sigma", "source_id": "synthetic-rule", "target_id": "det",
                       "source_version": number, "max_source_version": number, "payload_digest": fmt.digest(content)}
            after = {"kind": "sigma", "source_id": "synthetic-rule", "binding": binding,
                     "live": {"target_id": "det", "current_version": number, "latest_version": number,
                              "status": "approved", "payload": content, "author": "author", "reviewer": reviewer,
                              "creator_id": "author", "version_status": "approved"}}
            receipt = {"digest": doc["payload_sha256"], "applied_by_id": "reviewer", "applied_by": reviewer,
                       "imported_by": "author", "applied_at": NOW.isoformat(), "reason": "Synthetic review",
                       "validation_kind": "package_fixture", "items": [
                           {"kind": "sigma", "source_id": "synthetic-rule", "target_id": "det",
                            "before": previous, "after": after}]}
            result = fmt.run_fixtures(doc)
            result["passed"] = True  # A stored flag must not replace a fresh actual fixture execution.
            c.execute(tables["cp_package"].insert().values(id=f"pkg{number}", package_id=doc["package_id"],
                      revision=number, digest=doc["payload_sha256"], document=doc, imported_by="author",
                      imported_by_name="author", created_at=NOW, status="applied", baseline=[previous],
                      test_result=result, receipt=receipt))
            c.execute(tables["cp_validation"].insert().values(id=f"proof{number}", detection_id="det",
                      version=number, package_record_id=f"pkg{number}", source_id="synthetic-rule",
                      payload_digest=fmt.digest(content), kind="package_fixture", created_at=NOW))
            previous = copy.deepcopy(after)
        c.execute(tables["cp_binding"].insert().values(**binding))
        raw = c.exec_driver_sql("SELECT receipt FROM cp_package WHERE id='pkg2'").scalar_one()
    upgrade(engine, "0017")
    return engine, raw


def test_0014_package_migrates_and_rolls_back_exact_previous_version(tmp_path):
    engine, original_bytes = seed(tmp_path)
    with engine.begin() as c:
        migration = importlib.import_module("saw.storage.migrations.versions.0017_detection_governance")
        with Operations.context(MigrationContext.configure(c)):
            migration.upgrade()
            migration.upgrade()
        assert c.exec_driver_sql("SELECT receipt FROM cp_package WHERE id='pkg2'").scalar_one() == original_bytes
    with Session(engine) as s:
        p = principal_of(s.get(User, "rollbacker"))
        d = s.get(detection.Detection, "det")
        assert d.active_version_id == "v2"
        assert packages.rollback_preview(s, p, "pkg2")["can_rollback"] is True
        result = packages.rollback_package(s, p, "pkg2", s.get(ContentPackage, "pkg2").digest, "Synthetic revert")
        s.commit()
        assert result["status"] == "rolled_back"
        assert d.active_version_id == "v1" and d.current_version == 2
        assert s.scalar(sa.select(sa.func.count()).select_from(detection.DetectionVersion)) == 2
        assert s.scalar(sa.select(sa.func.count()).select_from(Approval)) == 2
        assert s.get(ContentPackage, "pkg2").receipt["items"] == json.loads(original_bytes)["items"]
        assert d.activation_revision == 2
    engine.dispose()


@pytest.mark.parametrize("mode", ["unknown_reviewer", "self_reviewer", "bad_fixture"])
def test_unproven_legacy_previous_version_requires_review(tmp_path, mode):
    engine, original_bytes = seed(tmp_path, first_reviewer={"unknown_reviewer": "missing", "self_reviewer": "author"}.get(mode, "reviewer"),
                                  bad_fixture=mode == "bad_fixture")
    with Session(engine) as s:
        p = principal_of(s.get(User, "rollbacker"))
        preview = packages.rollback_preview(s, p, "pkg2")
        assert preview["can_rollback"] is False
        assert any("legacy_receipt_requires_review" in reason for reason in preview["rollback_blocked_reasons"])
        with pytest.raises(packages.Conflict, match="legacy_receipt_requires_review"):
            packages.rollback_package(s, p, "pkg2", s.get(ContentPackage, "pkg2").digest, "Synthetic revert")
        assert s.get(detection.Detection, "det").active_version_id == "v2"
        assert s.get(ContentPackage, "pkg2").receipt["items"] == json.loads(original_bytes)["items"]
    engine.dispose()


def test_legacy_adapter_cannot_follow_later_activation_revision(tmp_path):
    engine, _ = seed(tmp_path)
    with engine.begin() as c:
        c.exec_driver_sql("UPDATE det_detection SET activation_revision=2 WHERE id='det'")
    with Session(engine) as s:
        p = principal_of(s.get(User, "rollbacker"))
        assert packages.rollback_preview(s, p, "pkg2")["can_rollback"] is False
        with pytest.raises(packages.Conflict):
            packages.rollback_package(s, p, "pkg2", s.get(ContentPackage, "pkg2").digest, "Synthetic revert")
    engine.dispose()


def test_legacy_receipt_payload_tamper_cannot_choose_other_approved_bytes(tmp_path):
    engine, _ = seed(tmp_path)
    with Session(engine) as s:
        package = s.get(ContentPackage, "pkg2")
        altered = copy.deepcopy(package.receipt)
        altered["items"][0]["before"]["live"]["payload"]["title"] = "Tampered"
        package.receipt = altered
        s.commit()
        p = principal_of(s.get(User, "rollbacker"))
        assert packages.rollback_preview(s, p, "pkg2")["can_rollback"] is False
        with pytest.raises(packages.Conflict, match="legacy_receipt_requires_review"):
            packages.rollback_package(s, p, "pkg2", package.digest, "Synthetic revert")
    engine.dispose()
