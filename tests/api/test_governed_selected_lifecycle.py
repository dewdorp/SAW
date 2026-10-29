"""Approval, activation and rollback use real selected-unit evaluation."""
from sqlalchemy import select
from saw.detection.policy_models import Activation, Approval
from saw.storage.db import session_scope
from tests.api.test_selected_detection_truth import setup_case, rule, run_selected


def approval_body(d, test, **overrides):
    v = d["pointers"]["draft"]
    return {"version_id": v["id"], "payload_sha256": v["payload_sha256"], "test_run_id": test["id"],
            "rule_policy_sha256": test["proof"]["rule_policy_sha256"],
            "expected_proof_sha256": test["proof"]["proof_sha256"], "expected_draft_version_id": v["id"],
            "context_scope": {"kind": "group"}, "reason": "Synthetic independent review", **overrides}


def activate_body(d, **overrides):
    return {"version_id": d["pointers"]["approved"]["id"], "approval_id": d["pointers"]["approved_approval_id"],
            "expected_active_version_id": d["pointers"]["active"]["id"] if d["pointers"]["active"] else None,
            "expected_activation_revision": d["pointers"]["activation_revision"],
            "reason": "Synthetic explicit activation", **overrides}


def approved(analyst, manager):
    inv, _, case = setup_case(analyst)
    d = rule(analyst)
    tested = run_selected(analyst, d, case)
    assert tested.status_code == 200, tested.text
    r = manager.post(f"/detections/{d['id']}/approve", json=approval_body(d, tested.json()))
    assert r.status_code == 200, r.text
    return inv, case, r.json()


def test_approve_does_not_activate_and_stale_activation_cas_is_rejected(analyst, manager):
    _, _, d = approved(analyst, manager)
    assert d["pointers"]["active"] is None
    request = activate_body(d)
    r = manager.post(f"/detections/{d['id']}/activate", json=request)
    assert r.status_code == 200, r.text
    assert r.json()["pointers"]["active"] == d["pointers"]["approved"]
    assert manager.post(f"/detections/{d['id']}/activate", json=request).status_code == 409
    with session_scope() as s:
        assert len(list(s.scalars(select(Approval)))) == 1
        assert len(list(s.scalars(select(Activation)))) == 1


def test_all_ancestor_editors_are_excluded_from_review(analyst, senior, manager):
    _, _, case = setup_case(manager)
    d = rule(senior)
    d = analyst.patch(f"/detections/{d['id']}", json={"title": "Synthetic editor two"}).json()
    # Manager's truth contribution is also part of the independent-review restriction.
    tested = run_selected(manager, d, case).json()
    assert tested["proof"]
    assert senior.post(f"/detections/{d['id']}/approve", json=approval_body(d, tested)).status_code == 403
    assert manager.post(f"/detections/{d['id']}/approve", json=approval_body(d, tested)).status_code == 403


def test_active_version_survives_draft_and_review_requires_current_comparison(analyst, manager):
    _, case, d = approved(analyst, manager)
    d = manager.post(f"/detections/{d['id']}/activate", json=activate_body(d)).json()
    old = d["pointers"]["active"]
    draft = analyst.patch(f"/detections/{d['id']}", json={"title": "Synthetic version two"}).json()
    assert draft["pointers"]["active"] == old
    no_comparison = run_selected(analyst, draft, case).json()
    assert manager.post(f"/detections/{d['id']}/approve", json=approval_body(draft, no_comparison)).status_code == 409
    tested = run_selected(analyst, draft, case, reference_version_id=old["id"]).json()
    reviewed = manager.post(f"/detections/{d['id']}/approve", json=approval_body(draft, tested))
    assert reviewed.status_code == 200, reviewed.text
    assert reviewed.json()["pointers"]["active"] == old


def test_rollback_restores_original_version_without_cloning_history(analyst, manager):
    _, case, d = approved(analyst, manager)
    d = manager.post(f"/detections/{d['id']}/activate", json=activate_body(d)).json()
    previous, approval = d["pointers"]["active"], d["pointers"]["active_approval_id"]
    draft = analyst.patch(f"/detections/{d['id']}", json={"title": "Synthetic v2"}).json()
    tested = run_selected(analyst, draft, case, reference_version_id=previous["id"]).json()
    d = manager.post(f"/detections/{d['id']}/approve", json=approval_body(draft, tested)).json()
    applied = manager.post(f"/detections/{d['id']}/activate", json=activate_body(d))
    assert applied.status_code == 200, applied.text
    d = applied.json()
    response = manager.post(f"/detections/{d['id']}/rollback",
        json=activate_body(d, version_id=previous["id"], approval_id=approval))
    assert response.status_code == 200, response.text
    assert response.json()["pointers"]["active"] == previous
    assert len(response.json()["versions"]) == 2


def test_private_test_rows_are_omitted_without_principal(analyst):
    from saw.detection import service
    _, _, case = setup_case(analyst)
    d = rule(analyst)
    assert run_selected(analyst, d, case).json()["proof"]
    with session_scope() as s:
        row = service.to_dict(s, s.get(service.Detection, d["id"]), full=True)
        assert row["test_runs"] == []


def test_author_with_review_permission_cannot_offer_apply_or_restore(senior, manager):
    _, _, d = approved(senior, manager)
    author_view = senior.get(f"/detections/{d['id']}").json()
    assert author_view["eligibility"]["activate"] is False
    assert author_view["eligibility"]["reasons"]["activate"]
    assert manager.get(f"/detections/{d['id']}").json()["eligibility"]["activate"] is True
    assert senior.post(f"/detections/{d['id']}/activate", json=activate_body(d)).status_code == 403
    applied = manager.post(f"/detections/{d['id']}/activate", json=activate_body(d))
    assert applied.status_code == 200, applied.text
    author_view = senior.get(f"/detections/{d['id']}").json()
    assert author_view["eligibility"]["rollback"] is False
    assert not author_view["rollback_targets"]


def test_independent_review_reason_is_preserved_in_audit(analyst, manager):
    from saw.storage.models import AuditEvent
    _, _, d = approved(analyst, manager)
    with session_scope() as s:
        row = s.scalar(select(AuditEvent).where(AuditEvent.action == "detection.approve", AuditEvent.target_id == d["id"]))
        assert row.detail["reason"] == "Synthetic independent review"
        assert row.detail["approval_id"] == d["pointers"]["approved_approval_id"]
