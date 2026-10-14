"""Offline packages are inert until an independent reviewer explicitly applies exact tested bytes."""
from __future__ import annotations

import copy
import hashlib
import json

from sqlalchemy import func, select

from saw.detection.service import Detection, DetectionVersion, TestRun
from saw.parsers.library import ParserDefinition
from saw.storage.db import session_scope

LOGIC = """title: Synthetic package rule
logsource: {category: webserver}
detection:
  selected: {cs-uri-stem: /synthetic-sensitive}
  condition: selected
level: medium
"""


def seal(document):
    doc = copy.deepcopy(document)
    doc.pop("payload_sha256", None)
    doc["payload_sha256"] = hashlib.sha256(json.dumps(doc, sort_keys=True, ensure_ascii=False,
                                                       separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    return doc


def document(revision=1):
    return seal({
        "schema": "saw.content-package/1", "package_id": "synthetic-demo", "revision": revision,
        "requires": {"content_engine": "saw-content-v1"},
        "entries": [
            {"kind": "sigma", "source_id": "synthetic-rule", "source_version": revision,
             "content": {"title": "합성 규칙", "logic": LOGIC, "data_source": "web"},
             "fixtures": [
                 {"name": "positive", "expected": "match", "events": [{"data_source": "web", "url_path": "/synthetic-sensitive"}]},
                 {"name": "benign", "expected": "no_match", "events": [{"data_source": "web", "url_path": "/health"}]},
             ]},
            {"kind": "parser", "source_id": "synthetic-parser", "source_version": revision,
             "content": {"name": "합성 파서", "spec": {
                 "format": "regex", "pattern": r"^demo src=(?P<ip>\S+) path=(?P<path>\S+)$",
                 "mapping": {"ip": "src_ip", "path": "uri"}, "auto_map": False, "data_source": "web",
                 "detect": {"line_regex": "^demo src="}}},
             "fixtures": [
                 {"name": "positive", "expected": "parsed", "sample": "demo src=192.0.2.10 path=/health",
                  "fields": [{"src_ip": "192.0.2.10", "uri": "/health"}]},
                 {"name": "benign", "expected": "no_match", "sample": "unrelated synthetic line"},
             ]},
        ],
    })


def upload(api, doc):
    return api.post("/content-packages/stage", json={"text": json.dumps(doc, ensure_ascii=False)})


def prepared(analyst, doc=None):
    r = upload(analyst, doc or document())
    assert r.status_code == 201, r.text
    p = r.json()
    r = analyst.post(f"/content-packages/{p['id']}/test", json={"digest": p["digest"]})
    assert r.status_code == 200, r.text
    assert r.json()["test_result"]["passed"] is True
    return r.json()


def apply(api, package):
    return api.post(f"/content-packages/{package['id']}/apply",
                    json={"digest": package["digest"], "reason": "합성 양성·정상 예제 검토"})


def test_stage_and_verify_never_mutate_live_content(analyst):
    doc = document()
    r = analyst.post("/content-packages/verify", json={"text": json.dumps(doc)})
    assert r.status_code == 200, r.text
    assert r.json()["integrity"] == "sha256_verified"
    assert r.json()["origin"] == "not_authenticated"
    p = prepared(analyst, doc)
    assert p["status"] == "staged"
    with session_scope() as s:
        assert s.scalar(select(func.count()).select_from(Detection)) == 0
        assert s.scalar(select(func.count()).select_from(ParserDefinition)) == 0
        assert s.scalar(select(func.count()).select_from(TestRun)) == 0


def test_reject_tamper_unknown_code_version_and_limits(analyst):
    doc = document()
    doc["entries"][0]["content"]["title"] = "changed without checksum"
    assert upload(analyst, doc).status_code == 400
    for mutate in (
        lambda d: d["entries"][0].update(kind="python"),
        lambda d: d["requires"].update(content_engine="future"),
        lambda d: d.update(install_script="run.exe"),
        lambda d: d["entries"][1]["content"]["spec"].update(python="print(1)"),
        lambda d: d["entries"].extend([d["entries"][0]] * 20),
        lambda d: d["entries"][0]["fixtures"].pop(),
    ):
        bad = document()
        mutate(bad)
        assert upload(analyst, seal(bad)).status_code == 400
    text = json.dumps(document())
    assert analyst.post("/content-packages/verify", json={"text": text[:-1] + ',"revision":1}'}).status_code == 400
    assert analyst.post("/content-packages/verify", json={"text": " " * (1024 * 1024 + 1)}).status_code == 413


def test_same_person_cannot_apply_and_fixture_proof_is_not_historical(analyst, senior):
    p = prepared(senior)
    assert apply(senior, p).status_code == 403
    assert apply(analyst, p).status_code == 403


def test_apply_is_explicit_atomic_and_idempotent(analyst, senior):
    p = prepared(analyst)
    r = apply(senior, p)
    assert r.status_code == 200, r.text
    receipt = r.json()["receipt"]
    assert r.json()["status"] == "applied"
    assert receipt["applied_by"] == "senior1"
    assert len(receipt["items"]) == 2
    assert apply(senior, p).status_code == 200
    with session_scope() as s:
        from saw.content_packages.service import has_package_validation
        assert s.scalar(select(func.count()).select_from(Detection)) == 1
        assert s.scalar(select(func.count()).select_from(DetectionVersion)) == 1
        assert s.scalar(select(func.count()).select_from(TestRun)) == 0
        d = s.scalar(select(Detection))
        v = s.scalar(select(DetectionVersion))
        assert d.status == "approved" and v.created_by == "analyst1" and v.reviewed_by == "senior1"
        assert has_package_validation(s, d.id, 1)
        parser = s.scalar(select(ParserDefinition))
        assert parser.status == "active" and parser.created_by_name == "analyst1"
    assert upload(analyst, document()).json()["id"] == p["id"]
    exported = analyst.get(f"/content-packages/{p['id']}/export")
    assert exported.status_code == 200 and exported.json() == document()


def test_apply_requires_current_digest_test_and_passing_benign_case(analyst, senior):
    doc = document()
    doc["entries"][0]["fixtures"][1]["events"][0]["url_path"] = "/synthetic-sensitive"
    p = upload(analyst, seal(doc)).json()
    assert apply(senior, p).status_code == 400
    tested = analyst.post(f"/content-packages/{p['id']}/test", json={"digest": p["digest"]})
    assert tested.status_code == 200 and tested.json()["test_result"]["passed"] is False
    assert apply(senior, p).status_code == 400
    assert analyst.post(f"/content-packages/{p['id']}/test", json={"digest": "0" * 64}).status_code == 409


def test_stale_stage_and_live_edit_block_apply_without_partial_changes(analyst, senior):
    first = prepared(analyst)
    assert apply(senior, first).status_code == 200
    newer = document(2)
    newer["entries"][0]["content"]["title"] = "second"
    p2 = prepared(analyst, seal(newer))
    other = document(3)
    other["package_id"] = "other-change"
    p3 = prepared(analyst, seal(other))
    assert apply(senior, p2).status_code == 200
    assert apply(senior, p3).status_code == 409
    with session_scope() as s:
        assert s.scalar(select(func.count()).select_from(DetectionVersion)) == 2
        assert s.scalar(select(func.count()).select_from(ParserDefinition)) == 2
    p4 = prepared(analyst, document(4))
    with session_scope() as s:
        d = s.scalar(select(Detection))
        det_id = d.id
    assert analyst.patch(f"/detections/{det_id}", json={"title": "manual change"}).status_code == 200
    assert apply(senior, p4).status_code == 409


def test_apply_failure_rolls_back_every_item_and_audit(analyst, senior, monkeypatch):
    p = prepared(analyst)
    from saw.content_packages import service
    real = service._apply_item
    count = 0

    def fail_second(*args, **kwargs):
        nonlocal count
        count += 1
        if count == 2:
            raise ValueError("synthetic apply failure")
        return real(*args, **kwargs)

    monkeypatch.setattr(service, "_apply_item", fail_second)
    assert apply(senior, p).status_code == 400
    with session_scope() as s:
        from saw.content_packages.models import ContentBinding, ContentValidation
        from saw.storage.models import AuditEvent
        for table in (Detection, DetectionVersion, ParserDefinition, ContentBinding, ContentValidation):
            assert s.scalar(select(func.count()).select_from(table)) == 0
        assert s.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "content_package.apply")) == 0
    assert analyst.get(f"/content-packages/{p['id']}").json()["status"] == "staged"


def test_rollback_restores_only_previous_approved_content_with_new_version(analyst, senior, manager):
    first = prepared(analyst)
    assert apply(senior, first).status_code == 200
    doc = document(2)
    doc["entries"][0]["content"]["title"] = "new synthetic title"
    doc["entries"][1]["content"]["name"] = "new synthetic parser"
    second = prepared(analyst, seal(doc))
    assert apply(senior, second).status_code == 200
    args = {"digest": second["digest"], "reason": "합성 회귀 확인"}
    assert senior.post(f"/content-packages/{second['id']}/rollback", json=args).status_code == 403
    r = manager.post(f"/content-packages/{second['id']}/rollback", json=args)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "rolled_back"
    assert manager.post(f"/content-packages/{second['id']}/rollback", json=args).status_code == 200
    with session_scope() as s:
        versions = s.scalars(select(DetectionVersion).order_by(DetectionVersion.version)).all()
        assert [v.version for v in versions] == [1, 2, 3]
        assert versions[-1].title == "합성 규칙" and versions[-1].reviewed_by == "manager1"
        active = s.scalars(select(ParserDefinition).where(ParserDefinition.status == "active")).all()
        assert len(active) == 1 and active[0].version == 1
        from saw.content_packages.service import has_package_validation
        assert has_package_validation(s, versions[-1].detection_id, 3)
    assert apply(senior, second).status_code == 409


def test_first_apply_rollback_disables_new_content_and_drift_blocks_rollback(analyst, senior, manager):
    p = prepared(analyst)
    applied = apply(senior, p).json()
    det_id = applied["receipt"]["items"][0]["target_id"]
    assert analyst.patch(f"/detections/{det_id}", json={"title": "manual changed"}).status_code == 200
    r = manager.post(f"/content-packages/{p['id']}/rollback", json={"digest": p["digest"], "reason": "복구"})
    assert r.status_code == 409
    with session_scope() as s:
        assert s.scalar(select(ParserDefinition)).status == "active"


def test_applied_fixture_rule_runs_in_another_analyst_investigation_and_tamper_blocks_it(analyst, senior):
    from saw import container
    from saw.detection.auto import run_approved
    from saw.detectors.base import DetectorContext

    p = prepared(analyst)
    assert apply(senior, p).status_code == 200
    inv = senior.post("/investigations", json={"title": "Independent synthetic case"}).json()
    events = [
        {"event_id": "synthetic-positive", "investigation_id": inv["id"], "timestamp": "2026-10-01T00:00:00Z",
         "data_source": "web", "url_path": "/synthetic-sensitive", "src_ip": "192.0.2.10"},
        {"event_id": "synthetic-benign", "investigation_id": inv["id"], "timestamp": "2026-10-01T00:00:01Z",
         "data_source": "web", "url_path": "/health", "src_ip": "192.0.2.10"},
    ]
    container.get().events.index(events)
    with session_scope() as s:
        ctx = DetectorContext(inv["id"], container.get().events, data_sources={"web"})
        drafts, _ = run_approved(s, ctx)
        assert len(drafts) == 1 and drafts[0].sample_event_ids == ["synthetic-positive"]
        assert any(c["value"] == "package_fixture" for c in drafts[0].checks)
        version = s.scalar(select(DetectionVersion))
        version.title = "tampered content"
        s.flush()
        assert not run_approved(s, ctx)[0]


def test_concurrent_reviewers_apply_one_staged_change_without_partial_second(analyst, senior, manager):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    initial = prepared(analyst)
    assert apply(senior, initial).status_code == 200
    left = document(2)
    left["package_id"] = "concurrent-left"
    left["entries"][0]["content"]["title"] = "left candidate"
    right = document(3)
    right["package_id"] = "concurrent-right"
    right["entries"][0]["content"]["title"] = "right candidate"
    p_left = prepared(analyst, seal(left))
    p_right = prepared(analyst, seal(right))
    ready = Barrier(2)

    def attempt(api, package):
        ready.wait(timeout=10)
        return apply(api, package).status_code

    with ThreadPoolExecutor(max_workers=2) as workers:
        left_run = workers.submit(attempt, senior, p_left)
        right_run = workers.submit(attempt, manager, p_right)
        assert sorted([left_run.result(timeout=30), right_run.result(timeout=30)]) == [200, 409]
    with session_scope() as s:
        assert s.scalar(select(func.count()).select_from(DetectionVersion)) == 2
        assert s.scalar(select(func.count()).select_from(ParserDefinition)) == 2
        assert s.scalar(select(func.count()).select_from(ParserDefinition).where(ParserDefinition.status == "active")) == 1
        from saw.content_packages.models import ContentPackage, ContentValidation
        assert s.scalar(select(func.count()).select_from(ContentPackage).where(ContentPackage.status == "applied")) == 2
        assert s.scalar(select(func.count()).select_from(ContentValidation)) == 2


def test_first_rollback_keeps_history_and_next_revision_can_reactivate(analyst, senior, manager):
    p = prepared(analyst)
    assert apply(senior, p).status_code == 200
    assert manager.post(f"/content-packages/{p['id']}/rollback", json={"digest": p["digest"], "reason": "합성 최초 반입 취소"}).status_code == 200
    with session_scope() as s:
        assert s.scalar(select(Detection)).status == "deprecated"
        assert s.scalar(select(ParserDefinition)).status == "disabled"
        assert s.scalar(select(func.count()).select_from(DetectionVersion)) == 1
    next_package = prepared(analyst, document(2))
    assert apply(senior, next_package).status_code == 200
    with session_scope() as s:
        assert s.scalar(select(func.count()).select_from(ParserDefinition).where(ParserDefinition.status == "active")) == 1


def test_strict_json_rejects_nonfinite_numbers_and_fixture_timeout_cannot_apply(analyst, senior, monkeypatch):
    text = json.dumps(document())
    for suffix in (',"revision":NaN}', ',"revision":Infinity}', ',"revision":-Infinity}'):
        assert analyst.post("/content-packages/verify", json={"text": text[:-1] + suffix}).status_code == 400
    p = upload(analyst, document()).json()
    from saw.content_packages import format as package_format
    monkeypatch.setattr(package_format, "MAX_TEST_SECONDS", 0)
    result = analyst.post(f"/content-packages/{p['id']}/test", json={"digest": p["digest"]})
    assert result.status_code == 200 and result.json()["test_result"]["passed"] is False
    assert apply(senior, p).status_code == 400


def test_rollback_does_not_reuse_source_version_or_overwrite_manual_reactivation(analyst, senior, manager):
    first = prepared(analyst)
    assert apply(senior, first).status_code == 200
    second = prepared(analyst, document(2))
    assert apply(senior, second).status_code == 200
    assert manager.post(f"/content-packages/{second['id']}/rollback",
                        json={"digest": second["digest"], "reason": "합성 이전 승인본 복구"}).status_code == 200
    reused = document(2)
    reused["package_id"] = "reused-source-version"
    assert upload(analyst, seal(reused)).status_code == 409

    next_doc = document(3)
    next_doc["entries"] = [next_doc["entries"][1]]
    next_pack = prepared(analyst, seal(next_doc))
    assert apply(senior, next_pack).status_code == 200
    # The API rejects any live changes after staging, including operator enable/disable.
    later = document(4)
    later["entries"] = [later["entries"][1]]
    later_pack = prepared(analyst, seal(later))
    assert senior.post("/parser-library/synthetic-parser/disable").status_code == 200
    assert apply(senior, later_pack).status_code == 409


def test_parser_benign_regex_timeout_is_not_a_successful_rejection(analyst):
    doc = document()
    doc["entries"] = [doc["entries"][1]]
    entry = doc["entries"][0]
    entry["content"]["spec"] = {
        "format": "regex", "pattern": r"^(?P<name>(a|aa)+)$", "mapping": {"name": "user"},
        "auto_map": False, "data_source": "web", "detect": {"line_regex": r"^(a|aa)+$"},
    }
    entry["fixtures"] = [
        {"name": "positive", "expected": "parsed", "sample": "a", "fields": [{"user": "a"}]},
        {"name": "benign", "expected": "no_match", "sample": "a" * 100 + "!"},
    ]
    p = upload(analyst, seal(doc)).json()
    r = analyst.post(f"/content-packages/{p['id']}/test", json={"digest": p["digest"]})
    assert r.status_code == 200
    assert r.json()["test_result"]["passed"] is False
    assert r.json()["test_result"]["results"][1]["passed"] is False


def test_manual_edit_and_package_apply_serialize_before_reading_live_version(analyst, senior, monkeypatch):
    """Separate DB sessions isolate the race from API authentication's session write."""
    from concurrent.futures import ThreadPoolExecutor, wait
    from threading import Event, local
    from saw.content_packages import service as packages
    from saw.core.application.identity import principal_of
    from saw.detection import service as detection_service
    from saw.storage.models import User

    initial = prepared(analyst)
    response = apply(senior, initial)
    det_id = response.json()["receipt"]["items"][0]["target_id"]
    pending = prepared(analyst, document(2))
    with session_scope() as s:
        author = principal_of(s.scalar(select(User).where(User.username == "analyst1")))
        reviewer = principal_of(s.scalar(select(User).where(User.username == "senior1")))
    read_live, release_editor = Event(), Event()
    editing = local()
    real_latest = detection_service._latest

    def pause_after_real_read(*args, **kwargs):
        result = real_latest(*args, **kwargs)
        if getattr(editing, "active", False) and not read_live.is_set():
            read_live.set()
            assert release_editor.wait(timeout=15)
        return result

    def manual_edit():
        editing.active = True
        with session_scope() as s:
            detection_service.update(s, author, det_id, {"title": "concurrent manual edit"})

    def package_apply():
        try:
            with session_scope() as s:
                packages.apply_package(s, reviewer, pending["id"], pending["digest"], "concurrent review")
            return "applied"
        except packages.Conflict:
            return "conflict"

    monkeypatch.setattr(detection_service, "_latest", pause_after_real_read)
    with ThreadPoolExecutor(max_workers=2) as workers:
        manual = workers.submit(manual_edit)
        try:
            assert read_live.wait(timeout=10)
            package = workers.submit(package_apply)
            # Before the fix the package commits while the stale manual read is paused.
            # With shared locking it waits until the manual edit invalidates its baseline.
            wait([package], timeout=3)
        finally:
            release_editor.set()
        manual.result(timeout=20)
        assert package.result(timeout=20) == "conflict"
    with session_scope() as s:
        versions = s.scalars(select(DetectionVersion).order_by(DetectionVersion.version)).all()
        assert [(v.version, v.title) for v in versions] == [(1, "합성 규칙"), (2, "concurrent manual edit")]
        parsers = s.scalars(select(ParserDefinition)).all()
        assert len(parsers) == 1 and parsers[0].status == "active"


def test_package_responses_never_disclose_another_authors_private_parser_draft(analyst, senior, manager):
    initial = prepared(analyst)
    assert apply(senior, initial).status_code == 200
    private = copy.deepcopy(document()["entries"][1]["content"])
    private["name"] = "private-draft-name-marker"
    private["slug"] = "synthetic-parser"
    private["spec"]["pattern"] = r"^private-draft-pattern-marker=(?P<ip>\S+)$"
    response = analyst.post("/parser-library", json=private)
    assert response.status_code == 201, response.text
    assert "private-draft-name-marker" not in senior.get("/parser-library/synthetic-parser").text

    pending = prepared(senior, document(2))
    responses = [
        manager.get(f"/content-packages/{pending['id']}"),
        manager.get("/content-packages"),
        apply(manager, pending),
        senior.get(f"/content-packages/{pending['id']}/rollback-preview"),
        senior.post(f"/content-packages/{pending['id']}/rollback",
                    json={"digest": pending["digest"], "reason": "restore approved synthetic parser"}),
        manager.get(f"/content-packages/{pending['id']}"),
        manager.get("/content-packages"),
    ]
    for response in responses:
        assert response.status_code == 200, response.text
        assert "private-draft-name-marker" not in response.text
        assert "private-draft-pattern-marker" not in response.text
    # The private row still participates in server-side drift checks; it was not deleted or edited.
    with session_scope() as s:
        row = s.scalar(select(ParserDefinition).where(ParserDefinition.status == "draft"))
        assert row.name == "private-draft-name-marker"

def test_rolled_back_binding_rejects_manual_reactivation_before_new_import(analyst, senior, manager):
    first = prepared(analyst)
    assert apply(senior, first).status_code == 200
    assert manager.post(f"/content-packages/{first['id']}/rollback",
                        json={"digest": first["digest"], "reason": "synthetic initial rollback"}).status_code == 200
    assert senior.post("/parser-library/synthetic-parser/enable").status_code == 200
    assert upload(analyst, document(2)).status_code == 409


def test_library_enable_cannot_make_two_active_versions_after_package_upgrade(analyst, senior):
    first = prepared(analyst)
    assert apply(senior, first).status_code == 200
    # A disabled older row can remain in history after a later independently approved parser.
    assert senior.post("/parser-library/synthetic-parser/disable").status_code == 200
    private = copy.deepcopy(document()["entries"][1]["content"])
    private["slug"] = "synthetic-parser"
    saved = analyst.post("/parser-library", json=private)
    assert saved.status_code == 201
    version = saved.json()["version"]
    assert analyst.post(f"/parser-library/synthetic-parser/versions/{version}/share").status_code == 200
    assert senior.post(f"/parser-library/synthetic-parser/versions/{version}/review",
                       json={"approve": True, "note": "synthetic replacement"}).status_code == 200
    assert senior.post("/parser-library/synthetic-parser/enable").status_code == 400
    with session_scope() as s:
        rows = s.scalars(select(ParserDefinition).where(ParserDefinition.status == "active")).all()
        assert len(rows) == 1 and rows[0].version == version

def test_action_requests_reject_duplicate_keys_nonfinite_and_oversized_bodies(analyst, senior):
    package = prepared(analyst)
    endpoint = f"/content-packages/{package['id']}/apply"
    valid = json.dumps({"digest": package["digest"], "reason": "synthetic review"})
    for malformed in (
        valid[:-1] + ',"reason":"duplicate"}',
        valid[:-1] + ',"unknown":NaN}',
        valid[:-1] + ',"unknown":Infinity}',
    ):
        response = senior.post(endpoint, content=malformed, headers={"Content-Type": "application/json"})
        assert response.status_code == 400
    response = senior.post(endpoint, content=" " * 9000, headers={"Content-Type": "application/json"})
    assert response.status_code == 413
    with session_scope() as s:
        assert s.scalar(select(func.count()).select_from(Detection)) == 0
        assert s.scalar(select(func.count()).select_from(ParserDefinition)) == 0



def test_rollback_capability_matches_prior_sigma_author_restriction(manager, senior, analyst, app):
    from tests.conftest import Api, make_user

    first = prepared(manager)
    assert apply(senior, first).status_code == 200
    # Disabling a first import does not approve a prior authored rule.
    assert manager.get(f"/content-packages/{first['id']}").json()["can_rollback"] is True
    second = prepared(manager, document(2))
    assert apply(senior, second).status_code == 200
    endpoint = f"/content-packages/{second['id']}"
    detail = manager.get(endpoint).json()
    preview = manager.get(endpoint + "/rollback-preview").json()
    assert detail["can_rollback"] is False
    assert preview["can_rollback"] is False
    assert detail["rollback_blocked_reasons"] == preview["rollback_blocked_reasons"]
    assert any("직전 룰 작성자" in reason for reason in preview["rollback_blocked_reasons"])
    assert manager.post(endpoint + "/rollback", json={"digest": second["digest"], "reason": "synthetic restore"}).status_code == 403
    assert senior.get(endpoint + "/rollback-preview").json()["can_rollback"] is False
    assert analyst.get(endpoint + "/rollback-preview").json()["can_rollback"] is False
    make_user("third-reviewer", ["soc_manager"])
    third = Api(app, "third-reviewer")
    allowed = third.get(endpoint + "/rollback-preview").json()
    assert allowed["can_rollback"] is True
    assert allowed["rollback_blocked_reasons"] == []
    assert third.post(endpoint + "/rollback", json={"digest": second["digest"], "reason": "independent restore"}).status_code == 200
