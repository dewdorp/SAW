"""Approved Sigma executes only its reviewed version inside authorized investigations."""
from __future__ import annotations

import pytest
from sqlalchemy import select

from saw import container
from saw.core.application import identity, investigations
from saw.core.application.analysis import _drop_unsupported, _finding_from_draft
from saw.detection import service
from saw.detectors.base import DetectorContext
from saw.storage.db import session_scope
from saw.storage.models import InvestigationMember, User
from tests.conftest import make_user

LOGIC = "title: Synthetic\nlogsource: {category: webserver}\ndetection:\n  s:\n    cs-uri|startswith: /selected\n  condition: s\n"


def setup_rule(s, *, data=None, expected_hits=("0", "2"), event_ext=None):
    from saw.detection import governance, testing
    creator = s.execute(select(User).where(User.username == "analyst1")).scalar_one()
    reviewer = s.execute(select(User).where(User.username == "manager1")).scalar_one()
    principal = identity.principal_of(creator)
    inv = investigations.create(s, principal, "Synthetic authorized scope")
    det = service.create(s, principal, {"title": "Synthetic selected", "logic": LOGIC, **(data or {})})
    s.flush()
    version = service._latest(s, det.id)
    events = [{"event_id": str(i), "investigation_id": inv.id, "data_source": "web",
               "timestamp": f"2026-01-01T00:00:0{i}Z", "src_ip": "192.0.2.1", "uri": uri,
               "status_code": 200, **({"ext": event_ext} if event_ext else {})}
              for i, uri in enumerate(("/selected/a", "/ordinary", "/selected/b"))]
    container.get().events.index(events)
    case = testing.create_case(s, principal, {"title": "Synthetic selected fixture", "investigation_id": inv.id,
        "units": [{"unit_id": e["event_id"], "unit_kind": "event", "event_ids": [e["event_id"]],
                   "detection_truth": "expected_match" if e["event_id"] in expected_hits else "expected_no_match",
                   "investigation_truth": "undetermined", "basis": "Explicit synthetic expected behavior"} for e in events]})
    trial = testing.run_selected(s, principal, det.id, {"method": "selected_truth_v1", "version_id": version.id,
        "payload_sha256": version.payload_sha256, "units": [{"case_version_id": case.id, "unit_id": e["event_id"]} for e in events]})
    assert trial.passed
    proof = testing.serialized_test(s, principal, trial)["proof"]
    manager = identity.principal_of(reviewer)
    governance.approve_rule(s, manager, det.id, {"version_id": version.id, "payload_sha256": version.payload_sha256,
        "test_run_id": trial.id, "rule_policy_sha256": proof["rule_policy_sha256"], "expected_proof_sha256": proof["proof_sha256"],
        "expected_draft_version_id": version.id, "reason": "Synthetic independent approval"})
    governance.activate_rule(s, manager, det.id, {"version_id": version.id, "approval_id": det.approved_approval_id,
        "expected_active_version_id": None, "expected_activation_revision": 0, "reason": "Synthetic explicit activation"})
    return inv, det, version, DetectorContext(inv.id, container.get().events, data_sources={"web"})


def test_historical_truncation_cannot_approve_a_partial_pass(analyst, manager):
    with session_scope() as s:
        inv, det, _version, _ctx = setup_rule(s)
        creator = s.execute(select(User).where(User.username == "analyst1")).scalar_one()
        result = service.run_test(s, identity.principal_of(creator), det.id, [inv.id], max_events=1)
        assert result.result["truncated"] and not result.passed


def test_only_approved_exact_version_yields_matched_evidence_and_reanalyzes_idempotently(analyst, manager):
    from saw.detection.auto import run_approved

    with session_scope() as s:
        inv, det, version, ctx = setup_rule(s)
        drafts, settled = run_approved(s, ctx)
        assert len(drafts) == 1 and drafts[0].total_events == 2
        assert drafts[0].sample_event_ids == ["0", "2"]
        assert drafts[0].detector_version == str(version.version)
        assert drafts[0].detector_id in settled and drafts[0].success_signal is False
        finding = _finding_from_draft(s, inv.id, drafts[0])
        s.flush()
        first_id = finding.id
        second, _ = run_approved(s, ctx)
        assert _finding_from_draft(s, inv.id, second[0]).id == first_id
        creator = s.get(User, det.created_by)
        service.update(s, identity.principal_of(creator), det.id, {"title": "Unapproved synthetic draft"})
        drafts, settled = run_approved(s, ctx)
        assert len(drafts) == 1 and drafts[0].detector_version == "1"
        assert finding.detector_id in settled


def test_deprecated_rule_cleans_untouched_results_but_preserves_reviewed_result(analyst, manager):
    from saw.detection.auto import run_approved

    with session_scope() as s:
        inv, det, _version, ctx = setup_rule(s)
        drafts, _ = run_approved(s, ctx)
        finding = _finding_from_draft(s, inv.id, drafts[0])
        s.flush()
        det.active_version_id, det.active_approval_id = None, None
        drafts, settled = run_approved(s, ctx)
        assert not drafts
        finding.status = "valid"
        assert _drop_unsupported(s, inv.id, settled, set()) == 0
        finding.status = "new"
        assert _drop_unsupported(s, inv.id, settled, set()) == 1


def test_creator_without_target_membership_cannot_share_rule_into_other_investigation(analyst, manager):
    from saw.detection.auto import run_approved

    with session_scope() as s:
        inv, _det, _version, ctx = setup_rule(s)
        creator = s.execute(select(User).where(User.username == "analyst1")).scalar_one()
        s.delete(s.get(InvestigationMember, (inv.id, creator.id)))
        s.flush()
        drafts, _ = run_approved(s, ctx)
        assert not drafts


def test_current_version_author_must_also_have_investigation_access(analyst, manager):
    from saw.detection.auto import run_approved

    make_user("outside-author", ["analyst"])
    with session_scope() as s:
        _inv, _det, version, ctx = setup_rule(s)
        with pytest.raises(ValueError, match="immutable"):
            version.created_by = "outside-author"
            s.flush()
        s.rollback()


def test_exceptions_and_threshold_apply_before_finding(analyst, manager):
    from saw.detection.auto import run_approved

    with session_scope() as s:
        _inv, _det, version, ctx = setup_rule(s, data={
            "threshold": {"group_by": ["src_ip"], "count_gte": 2, "timespan_sec": 5},
            "exceptions": [{"field": "event_id", "op": "is", "value": "0"}]}, expected_hits=())
        drafts, _ = run_approved(s, ctx)
        assert not drafts


def test_budget_limit_is_visible_and_does_not_settle_prior_findings(analyst, manager):
    from saw.detection.auto import run_approved

    with session_scope() as s:
        _inv, det, _version, ctx = setup_rule(s)
        ctx.params["sigma_max_events"] = 1
        drafts, settled = run_approved(s, ctx)
        assert all(d.category != "sigma.approved" for d in drafts)
        assert any(r["status"] == "partial" for r in ctx.params["execution_reports"])
        assert "sigma.approved:" + det.id not in settled


def test_candidate_limit_also_bounds_compilation(analyst, manager, monkeypatch):
    from saw.detection import auto

    with session_scope() as s:
        _inv, _det, _version, ctx = setup_rule(s)
        setup_rule(s)
        count = []
        actual_compile = auto.compile_rule

        def compile_once(text):
            count.append(1)
            return actual_compile(text)
        monkeypatch.setattr(auto, "MAX_RULES", 1)
        monkeypatch.setattr(auto, "compile_rule", compile_once)
        drafts, _ = auto.run_approved(s, ctx)
        assert len(count) == 1
        assert any(r["status"] == "partial" for r in ctx.params["execution_reports"])


def test_disabled_creator_and_inaccessible_source_are_not_applied(analyst, manager):
    from saw.detection.auto import run_approved

    outside_id = make_user("source-owner", ["analyst"])
    with session_scope() as s:
        _inv, det, _version, ctx = setup_rule(s)
        creator = s.get(User, det.created_by)
        creator.status = "disabled"
        assert run_approved(s, ctx)[0] == []
        creator.status = "active"
        source = investigations.create(s, identity.principal_of(s.get(User, outside_id)), "Private source")
        det.source = {"investigation_id": source.id}
        assert run_approved(s, ctx)[0] == []


def test_regex_timeout_is_reported_without_settling_old_results(analyst, manager):
    from saw.detection.auto import run_approved

    with session_scope() as s:
        inv, det, version, ctx = setup_rule(s, data={"logic": "title: Synthetic\nlogsource: {category: webserver}\ndetection:\n  s:\n    cs-uri|re: '(a|aa)+$'\n  condition: s\n"}, expected_hits=("0",))
        ctx.events.index([{"event_id": "regex", "investigation_id": inv.id, "data_source": "web",
                           "timestamp": "2026-01-01T00:00:04Z", "uri": "a" * 2000 + "!"}])
        drafts, settled = run_approved(s, ctx)
        assert any(r["status"] == "partial" for r in ctx.params["execution_reports"])
        assert "sigma.approved:" + det.id not in settled


@pytest.mark.parametrize("result", [{"truncated": True}, {"evaluation_errors": 1}, {"execution": "partial"}])
def test_legacy_partial_pass_cannot_authorize_approval_or_automatic_execution(analyst, manager, result):
    from saw.detection.auto import run_approved

    with session_scope() as s:
        _inv, det, _version, ctx = setup_rule(s)
        test = s.execute(select(service.TestRun).where(service.TestRun.detection_id == det.id)).scalar_one()
        test.result = result
        reviewer = s.execute(select(User).where(User.username == "manager1")).scalar_one()
        det.active_version_id, det.active_approval_id = None, None
        with pytest.raises(ValueError, match="exact_test_proof_required"):
            service.approve(s, identity.principal_of(reviewer), det.id)
        drafts, _ = run_approved(s, ctx)
        assert not [d for d in drafts if d.category == "sigma.approved"]


@pytest.mark.parametrize("missing", ["src_ip", "timestamp"])
def test_missing_threshold_inputs_are_incomplete_and_cannot_settle_or_pass(analyst, manager, missing):
    from saw.detection.auto import run_approved

    with session_scope() as s:
        inv, det, version, ctx = setup_rule(s, data={"threshold": {"group_by": ["src_ip"], "count_gte": 2}})
        events = list(ctx.events.iterate(inv.id, []))
        for event in events:
            event.pop(missing, None)
        ctx.events.index(events)
        drafts, settled = run_approved(s, ctx)
        assert any(r["status"] == "partial" for r in ctx.params["execution_reports"])
        assert "sigma.approved:" + det.id not in settled
        creator = s.get(User, det.created_by)
        result = service.run_test(s, identity.principal_of(creator), det.id, [inv.id])
        assert not result.passed and result.result["evaluation_errors"]


def test_nested_threshold_projection_keeps_only_required_leaves(analyst, manager, monkeypatch):
    from saw.detection import auto

    with session_scope() as s:
        inv, _det, version, ctx = setup_rule(s, data={"threshold": {"group_by": ["ext.ndr.service"], "count_gte": 2}},
                                            event_ext={"ndr": {"service": "web"}})
        events = list(ctx.events.iterate(inv.id, []))
        for event in events:
            event["ext"] = {"ndr": {"service": "web", "body": "x" * 60000}, "unused": "payload"}
        ctx.events.index(events)
        real_threshold = auto.apply_threshold
        projections = []

        def inspect_projection(hits, threshold):
            projections.extend(hits)
            return real_threshold(hits, threshold)

        monkeypatch.setattr(auto, "apply_threshold", inspect_projection)
        drafts, _ = auto.run_approved(s, ctx)
        assert any(d.category == "sigma.approved" for d in drafts)
        assert projections and all(hit["ext"] == {"ndr": {"service": "web"}} for hit in projections)


def test_matching_metadata_budget_preserves_prior_result(analyst, manager, monkeypatch):
    from saw.detection import auto

    with session_scope() as s:
        _inv, det, _version, ctx = setup_rule(s)
        monkeypatch.setattr(auto, "MAX_METADATA_BYTES", 1, raising=False)
        drafts, settled = auto.run_approved(s, ctx)
        assert any(r["status"] == "partial" for r in ctx.params["execution_reports"])
        assert "sigma.approved:" + det.id not in settled
