"""AI context and generated output are checked before exposure to an analyst."""
from __future__ import annotations

import json
from datetime import timedelta

import pytest
from sqlalchemy import select

from saw import container
from saw.llm import service
from saw.llm.providers import LLMResponse
from saw.storage.db import session_scope, utcnow
from saw.storage.models import User


class CapturingProvider:
    name, model, is_llm = "test_capture", "synthetic-test-provider", True

    def __init__(self, text='{"answer_md":"확인할 근거가 부족합니다.","citations":[]}'):
        self.text = text
        self.requests = []

    def generate(self, req):
        self.requests.append(req)
        return LLMResponse(self.text, self.model)


def test_context_excludes_private_investigations_and_unusable_experience(analyst, senior, monkeypatch):
    from saw.knowledge.models import Experience
    from saw.knowledge import similar

    own = analyst.post("/investigations", json={"title": "Synthetic context boundary"}).json()
    private = senior.post("/investigations", json={"title": "Synthetic private case"}).json()
    with session_scope() as s:
        users = {u.username: u.id for u in s.execute(select(User)).scalars()}
        similar._upsert(s, "investigation", private["id"], "INV-PRIVATE-MARKER", "Synthetic context boundary", "attack", {})
        for index, kind in enumerate(("general", "private-source", "expired", "deprecated", "unapproved", "self-approved")):
            marker = f"EXP-{kind.upper()}"
            e = Experience(display_id=marker, status="approved", data={}, approved_data={"title": marker},
                           analyst_id=users["analyst1"], reviewer_id=users["senior1"], approved_rev=1,
                           source_investigation_id=private["id"] if kind == "private-source" else None,
                           expires_at=utcnow() + timedelta(days=-1 if kind == "expired" else 1),
                           deprecated=kind == "deprecated")
            s.add(e)
            s.flush()
            similar._upsert(s, "experience", e.id, marker, "Synthetic context boundary", "attack", {},
                            extra={"recommended_checks": [f"CHECK-{kind.upper()}"]})
            if kind == "unapproved":
                e.approved_data = None
            if kind == "self-approved":
                e.reviewer_id = e.analyst_id
    capture = CapturingProvider()
    monkeypatch.setattr(service, "provider", lambda: capture)
    result = analyst.post("/ai/actions", json={"investigation_id": own["id"], "action": "compare_cases"})
    assert result.status_code == 200
    prompt = capture.requests[0].user
    assert "EXP-GENERAL" in prompt
    for marker in ("INV-PRIVATE-MARKER", "PRIVATE-SOURCE", "EXPIRED", "DEPRECATED", "UNAPPROVED", "SELF-APPROVED"):
        assert marker not in prompt
    assert "CHECK-GENERAL" in prompt


@pytest.mark.parametrize("text,reason", [
    ("not json", "invalid_structure"),
    ("[]", "invalid_structure"),
    ('{"answer_md":[],"citations":[]}', "invalid_structure"),
    ('{"answer_md":"guess","citations":"evt:visible-event"}', "invalid_structure"),
    ('{"answer_md":"guess","citations":["evt:hidden-event"]}', "invalid_citations"),
    ('{"answer_md":"guess","citations":[]}', "invalid_citations"),
])
def test_invalid_llm_output_is_not_published_as_an_answer(analyst, monkeypatch, text, reason):
    inv = analyst.post("/investigations", json={"title": "Synthetic output boundary"}).json()
    container.get().events.index([{"event_id": "visible-event", "investigation_id": inv["id"],
                                   "timestamp": "2026-10-12T00:00:00Z", "data_source": "web", "url_path": "/"}])
    monkeypatch.setattr(service, "provider", lambda: CapturingProvider(text))
    result = analyst.post("/ai/actions", json={"investigation_id": inv["id"], "action": "ask"})
    assert result.status_code == 200
    body = result.json()
    assert body["answer_md"] == ""
    assert body["query"] is None
    assert body["citation_valid"] is False
    assert body["output_status"] == "rejected"
    assert body["output_reason"] == reason
    assert body["execution_status"] == "executed"
    assert body["claim_support"] == "NOT_VALIDATED"


def test_cited_output_is_still_an_unverified_draft(analyst, monkeypatch):
    inv = analyst.post("/investigations", json={"title": "Synthetic cited draft"}).json()
    container.get().events.index([{"event_id": "visible-event", "investigation_id": inv["id"],
                                   "timestamp": "2026-10-12T00:00:00Z", "data_source": "web", "url_path": "/"}])
    text = json.dumps({"answer_md": "추가 확인이 필요합니다. [evt:visible-event]", "citations": ["evt:visible-event"]})
    monkeypatch.setattr(service, "provider", lambda: CapturingProvider(text))
    body = analyst.post("/ai/actions", json={"investigation_id": inv["id"], "action": "ask"}).json()
    assert body["answer_md"]
    assert body["citation_valid"] is True
    assert body["output_status"] == "validated_draft"
    assert body["claim_support"] == "NOT_VALIDATED"

def test_revoked_membership_during_generation_prevents_output_storage(analyst, monkeypatch):
    from sqlalchemy import delete
    from saw.storage.models import InvestigationMember

    inv = analyst.post("/investigations", json={"title": "Synthetic revocation boundary"}).json()

    class RevokingProvider(CapturingProvider):
        def generate(self, req):
            with session_scope() as s:
                s.execute(delete(InvestigationMember).where(InvestigationMember.investigation_id == inv["id"]))
            return super().generate(req)

    monkeypatch.setattr(service, "provider", lambda: RevokingProvider())
    response = analyst.post("/ai/actions", json={"investigation_id": inv["id"], "action": "ask"})
    assert response.status_code == 403
    with session_scope() as s:
        assert s.execute(select(service.LlmInteraction).where(service.LlmInteraction.investigation_id == inv["id"])).first() is None


def test_synthetic_only_provider_rejects_unapproved_investigation_before_generation(analyst, monkeypatch):
    inv = analyst.post("/investigations", json={"title": "Synthetic-looking title is not authorization"}).json()
    capture = CapturingProvider()
    capture.synthetic_only = True
    monkeypatch.setattr(service, "provider", lambda: capture)
    response = analyst.post("/ai/actions", json={"investigation_id": inv["id"], "action": "ask"})
    assert response.status_code == 403
    assert capture.requests == []

def test_synthetic_provider_never_receives_global_experience_or_playbooks(analyst, senior, monkeypatch):
    from saw.knowledge import similar
    from saw.knowledge.models import Experience, Playbook

    inv = analyst.post("/investigations", json={"title": "Synthetic only"}).json()
    container.get().settings.llm_synthetic_investigation_ids = [inv["id"]]
    with session_scope() as s:
        users = {u.username: u.id for u in s.execute(select(User)).scalars()}
        e = Experience(display_id="EXP-EXTERNAL", approved_data={"title": "external sentinel"}, approved_rev=1,
                       analyst_id=users["analyst1"], reviewer_id=users["senior1"])
        s.add(e)
        s.flush()
        similar._upsert(s, "experience", e.id, e.display_id, "external sentinel", "attack", {},
                        extra={"recommended_checks": ["EXTERNAL-EXPERIENCE-SENTINEL"]})
        s.add(Playbook(title="External", status="approved", applies_to=["*"],
                       steps=[{"check": "EXTERNAL-PLAYBOOK-SENTINEL"}]))
    capture = CapturingProvider()
    capture.synthetic_only = True
    monkeypatch.setattr(service, "provider", lambda: capture)
    response = analyst.post("/ai/actions", json={"investigation_id": inv["id"], "action": "next_steps"})
    assert response.status_code == 200
    assert "EXTERNAL" not in capture.requests[0].user


def test_experience_revoked_during_generation_prevents_output_storage(analyst, senior, monkeypatch):
    from saw.knowledge import similar
    from saw.knowledge.models import Experience

    inv = analyst.post("/investigations", json={"title": "Synthetic experience revocation"}).json()
    with session_scope() as s:
        users = {u.username: u.id for u in s.execute(select(User)).scalars()}
        e = Experience(display_id="EXP-REVOKED", approved_data={"title": "Synthetic approved"}, approved_rev=1,
                       analyst_id=users["analyst1"], reviewer_id=users["senior1"])
        s.add(e)
        s.flush()
        eid = e.id
        similar._upsert(s, "experience", eid, e.display_id, "Synthetic approved", "attack", {})

    class RevokingProvider(CapturingProvider):
        def generate(self, req):
            assert "EXP-REVOKED" in req.user
            with session_scope() as s:
                s.get(Experience, eid).deprecated = True
            return LLMResponse('{"answer_md":"가설 [EXP-REVOKED]","citations":["EXP-REVOKED"]}', self.model)

    monkeypatch.setattr(service, "provider", lambda: RevokingProvider())
    response = analyst.post("/ai/actions", json={"investigation_id": inv["id"], "action": "compare_cases"})
    assert response.status_code == 403
    with session_scope() as s:
        assert s.execute(select(service.LlmInteraction).where(service.LlmInteraction.investigation_id == inv["id"])).first() is None

def test_native_failure_records_execution_state_without_output(analyst, manager, monkeypatch):
    from saw.llm.cpu_provider import CPUExecutionError

    inv = analyst.post("/investigations", json={"title": "Synthetic native failure"}).json()

    class FailingProvider(CapturingProvider):
        def generate(self, req):
            raise CPUExecutionError("cpu_output_integrity", actual_inference="EXECUTED_OUTPUT_UNVERIFIED")

    monkeypatch.setattr(service, "provider", lambda: FailingProvider())
    response = analyst.post("/ai/actions", json={"investigation_id": inv["id"], "action": "ask"})
    assert response.status_code == 400
    rows = manager.get("/admin/audit?action=ai.failure").json()
    assert rows
    assert rows[0]["detail"]["actual_inference"] == "EXECUTED_OUTPUT_UNVERIFIED"
    assert rows[0]["detail"]["code"] == "cpu_output_integrity"
    assert "prompt" not in rows[0]["detail"]

@pytest.mark.parametrize("mutation", ["revoked", "expired", "mfa"])
def test_session_revoked_during_generation_prevents_output_storage(analyst, monkeypatch, mutation):
    from datetime import timedelta
    from saw.storage.db import utcnow
    from saw.storage.models import UserSession

    inv = analyst.post("/investigations", json={"title": "Synthetic session boundary"}).json()

    class SessionChangingProvider(CapturingProvider):
        def generate(self, req):
            with session_scope() as s:
                session = s.scalars(select(UserSession)).first()
                if mutation == "revoked":
                    session.revoked_at = utcnow()
                elif mutation == "expired":
                    session.expires_at = utcnow() - timedelta(seconds=1)
                else:
                    session.mfa_passed = False
            return super().generate(req)

    monkeypatch.setattr(service, "provider", lambda: SessionChangingProvider())
    response = analyst.post("/ai/actions", json={"investigation_id": inv["id"], "action": "ask"})
    assert response.status_code == 403
    with session_scope() as s:
        assert s.execute(select(service.LlmInteraction).where(service.LlmInteraction.investigation_id == inv["id"])).first() is None
