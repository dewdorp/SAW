"""Keep scoped completion and inherited source authority when results are derived."""
from copy import deepcopy
from datetime import UTC, datetime
import pytest
from saw import container
from saw.core.application import identity
from saw.core.application.analysis import _flows, _finding_from_draft, _run_pinned_sigma, finding_dict
from saw.core.application.investigations import Forbidden
from saw.detection import auto, governance
from saw.detection.derived_access import source_ids
from saw.detectors.base import DetectorContext
from saw.storage.db import session_scope
from saw.storage.models import User, InvestigationMember
from tests.api.test_derived_finding_access import generated
from tests.api.test_sigma_auto import setup_rule
from tests.conftest import make_user


def test_one_unfinished_scope_prevents_settling_the_same_rule(analyst, manager, monkeypatch):
    with session_scope() as s:
        inv, detection, _v, _ctx = setup_rule(s)
        p = identity.principal_of(s.get(User, detection.created_by))
        pinset = governance.pin_runtime(s, p, inv.id, [{"kind": "group"}])
        assert len(pinset["rules"]) == 1
        extra = deepcopy(pinset["rules"][0])
        extra["context_scope"] = {"kind": "org", "org_unit_id": "synthetic-org"}
        pinset["rules"].append(extra)
        monkeypatch.setattr(auto, "MAX_EVALUATIONS", 3)
        ctx = DetectorContext(inv.id, container.get().events, data_sources={"web"})
        drafts, settled, reports = _run_pinned_sigma(s, ctx, pinset, auto.run_approved)
        assert drafts
        assert any(r["status"] == "complete" for r in reports)
        assert any(r["status"] == "partial" for r in reports)
        assert "sigma.approved:" + detection.id not in settled


def test_attack_flow_and_serializer_keep_private_source_lineage(analyst, manager):
    uid = make_user("lineage-review-reader", ["analyst"])
    with session_scope() as s:
        source, target, finding, _run = generated(s)
        # The actual flow matcher consumes two ordered stages sharing a source address.
        finding.stage = "EXPLOITATION"
        finding.risk_level = "high"
        finding.entities = ["ip:192.0.2.50"]
        finding.time_start = finding.time_end = datetime(2026, 10, 1, tzinfo=UTC)
        # Use the existing evaluator to produce a distinct second finding, not a fake matcher.
        p = identity.principal_of(s.get(User, target.owner_id))
        pin = governance.pin_runtime(s, p, target.id, [{"kind": "group"}])
        ctx = DetectorContext(target.id, container.get().events, data_sources={"web"})
        actual, _, _ = _run_pinned_sigma(s, ctx, pin, auto.run_approved)
        second = actual[0]
        second.dedup_key += "-second"
        second.stage = "EXECUTION"
        second.entities = ["ip:192.0.2.50"]
        second.time_start = second.time_end = "2026-10-01T00:01:00+00:00"
        second_row = _finding_from_draft(s, target.id, second)
        s.flush()
        finding.stage, finding.risk_level = "EXPLOITATION", "high"
        finding.entities = ["ip:192.0.2.50"]
        finding.time_start = finding.time_end = datetime(2026, 10, 1, tzinfo=UTC)
        second_row.time_start = second_row.time_end = datetime(2026, 10, 1, 0, 1, tzinfo=UTC)
        flows = _flows(s, target.id)
        assert flows
        flow = _finding_from_draft(s, target.id, flows[0])
        assert source.id in source_ids(flow)
        s.add(InvestigationMember(investigation_id=target.id, user_id=uid, access="read"))
        s.flush()
        s.info["principal"] = identity.principal_of(s.get(User, uid))
        with pytest.raises(Forbidden):
            finding_dict(flow)


def test_distinct_complete_rule_scopes_are_both_settled(analyst, manager):
    with session_scope() as s:
        inv, first, _v, _ctx = setup_rule(s)
        _other, second, _v2, _ctx2 = setup_rule(s, data={"title": "Synthetic second scoped rule"})
        p = identity.principal_of(s.get(User, first.created_by))
        pinset = governance.pin_runtime(s, p, inv.id, [{"kind": "group"}])
        assert len(pinset["rules"]) == 2
        for pin in pinset["rules"]:
            if pin["rule"]["id"] == second.id:
                pin["context_scope"] = {"kind": "org", "org_unit_id": "synthetic-org"}
        ctx = DetectorContext(inv.id, container.get().events, data_sources={"web"})
        _drafts, settled, reports = _run_pinned_sigma(s, ctx, pinset, auto.run_approved)
        assert {"sigma.approved:" + first.id, "sigma.approved:" + second.id} <= settled
        assert len([r for r in reports if r["status"] == "complete"]) == 2


def test_source_revoked_after_capture_blocks_success_but_allows_failure_sealing(analyst, manager):
    from saw.analysis_runs import service as history
    from saw.analysis_runs.models import AnalysisRun
    with session_scope() as s:
        source, target, finding, _old = generated(s)
        new = history.start(s, target.id)
        history.capture_findings(s, new, [finding])
        source_id, actor_id, run_id = source.id, target.owner_id, new.id
    with session_scope() as s:
        s.delete(s.get(InvestigationMember, (source_id, actor_id)))
    with session_scope() as s:
        run = s.get(AnalysisRun, run_id)
        with pytest.raises(Forbidden):
            history.finish(s, run)
        assert run.status == "running" and run.finished_at is None
        history.finish(s, run, status="failed", detail={"reason": "source_access_revoked"})
        assert run.status == "failed" and run.finished_at is not None
