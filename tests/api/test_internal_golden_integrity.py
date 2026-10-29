"""Internal golden records keep source access, the first-known state and every open question intact."""
import uuid

from saw import container
from tests.conftest import Api, make_user


def _inv(api, title):
    org = api.post("/source-context/org-units", json={"display_name": f"G {uuid.uuid4().hex[:6]}"}).json()
    return api.post("/investigations", json={"title": title, "org_unit_id": org["id"],
                                            "period_start": "2026-10-01T00:00:00+09:00",
                                            "period_end": "2026-10-31T23:59:59+09:00"}).json()


def _event(inv_id, event_id, **extra):
    event = {"event_id": event_id, "investigation_id": inv_id, "timestamp": "2026-10-13T01:01:00Z",
             "src_ip": "198.51.100.23", "dst_ip": "10.20.1.10", "dst_port": 443, "data_source": "synthetic", **extra}
    container.get().events.index([event])
    return {"investigation_id": inv_id, "event_id": event_id}


def _check(api, inv_id, **extra):
    body = {"target_type": "entity", "target_key": "ip:198.51.100.23", "questions": ["nature"],
            "judgement": "suspicious", "note": "Path discovery burst from one source", **extra}
    response = api.post(f"/investigations/{inv_id}/checks", json=body)
    assert response.status_code == 201, response.text
    return response.json()


def _followup(api, inv_id, check_id, question="Was this an authorized assessment?"):
    response = api.post(f"/investigations/{inv_id}/follow-ups", json={
        "check_id": check_id, "question": question, "reason": "Scanner traffic",
        "target": {"src_ips": ["198.51.100.23"], "dst_ips": ["10.20.1.10"], "dst_ports": [443]},
        "period": {"start": "2026-10-13T10:00:00+09:00", "end": "2026-10-13T10:05:00+09:00"}})
    assert response.status_code == 201, response.text
    return response.json()


def _reply(api, inv_id, fu, evidence, note="Assessment team confirmed", **extra):
    response = api.post(f"/investigations/{inv_id}/follow-ups/{fu['id']}/reply", json={
        "expected_version_id": fu["current"]["id"], "reason": "reply", "note": note, "evidence": evidence, **extra})
    assert response.status_code == 200, response.text
    return response.json()


def test_reply_citing_an_unreadable_investigation_stays_hidden_in_golden_paths(senior, app):
    """GOLD-01: what the follow-up detail hides from a reader of A must not reappear through A's golden record."""
    a, b = _inv(senior, "A"), _inv(senior, "B")
    hidden = _event(b["id"], f"b-{uuid.uuid4().hex[:6]}")
    fu = _followup(senior, a["id"], _check(senior, a["id"])["id"])
    _reply(senior, a["id"], fu, [hidden], note="SECRET-B-REPLY")
    reader_id = make_user(f"gold-reader-{uuid.uuid4().hex[:4]}", ["analyst"])
    senior.post(f"/investigations/{a['id']}/members", json={"user_id": reader_id, "access": "viewer"}).raise_for_status()
    with_name = [u for u in [reader_id]]
    from saw.storage.db import session_scope
    from saw.storage.models import User
    with session_scope() as s:
        reader = Api(app, s.get(User, with_name[0]).username)
    assert reader.get(f"/investigations/{a['id']}/follow-ups/{fu['id']}").status_code == 403

    draft = reader.get(f"/investigations/{a['id']}/internal-golden/draft")
    assert draft.status_code == 200, draft.text
    assert "SECRET-B-REPLY" not in draft.text and b["id"] not in draft.text

    full = senior.get(f"/investigations/{a['id']}/internal-golden/draft").json()["content"]
    assert any(item["reply"] == "SECRET-B-REPLY" for item in full["followups"])
    saved = senior.post(f"/investigations/{a['id']}/internal-golden", json={"content": full, "change_note": "v1"})
    assert saved.status_code == 201, saved.text
    record_id = saved.json()["id"]
    assert b["id"] in saved.json()["content"]["provenance"]["source_investigation_ids"]

    assert reader.get(f"/knowledge/internal-golden/{record_id}").status_code == 403
    assert reader.get(f"/knowledge/internal-golden/{record_id}", params={"version": 1}).status_code == 403
    assert all(x["id"] != record_id for x in reader.get("/knowledge/internal-golden").json()["items"])
    current = reader.get(f"/investigations/{a['id']}/internal-golden")
    assert current.status_code == 200 and "SECRET-B-REPLY" not in current.text
    record = current.json()["record"]
    assert record["restricted"] is True and "content" not in record
    # Editing the reference text out client-side does not shrink what the server records as sources.
    trimmed = {**full, "followups": [{**item, "evidence_refs": []} for item in full["followups"]]}
    again = senior.post(f"/investigations/{a['id']}/internal-golden",
                         json={"content": trimmed, "expected_version": 1})
    assert again.status_code == 201 and b["id"] in again.json()["content"]["provenance"]["source_investigation_ids"]


def test_first_known_state_stays_initial_after_replies_and_changed_judgement(senior):
    """GOLD-02: replies, later files and a changed judgement go to the later section, never the initial one."""
    inv = _inv(senior, "cutoff")
    first_ref = _event(inv["id"], f"e1-{uuid.uuid4().hex[:6]}")
    check = _check(senior, inv["id"], evidence=[first_ref["event_id"]])
    fu = _followup(senior, inv["id"], check["id"])
    late_ref = _event(inv["id"], f"e2-{uuid.uuid4().hex[:6]}")
    _reply(senior, inv["id"], fu, [late_ref])
    changed = senior.put(f"/investigations/{inv['id']}/checks/{check['id']}", json={
        "judgement": "normal", "note": "Assessment team confirmed the schedule", "evidence": [first_ref["event_id"], late_ref["event_id"]]})
    assert changed.status_code == 200, changed.text

    content = senior.get(f"/investigations/{inv['id']}/internal-golden/draft").json()["content"]
    assert content["initial_judgement"]["status"] == "insufficient_evidence"
    assert content["initial_judgement"]["rationale"] == "Path discovery burst from one source"
    assert content["initial_evidence_refs"] == [f"{inv['id']}/{first_ref['event_id']}"]
    assert f"{inv['id']}/{late_ref['event_id']}" in content["later_evidence_refs"]
    assert any("normal" in fact or "정상" in fact for fact in content["later_facts"])
    assert content["provenance"]["cutoff"]

    leaked = {**content, "initial_judgement": {**content["initial_judgement"], "status": "normal"}}
    assert senior.post(f"/investigations/{inv['id']}/internal-golden", json={"content": leaked}).status_code == 400
    moved = {**content, "initial_evidence_refs": content["initial_evidence_refs"] + [f"{inv['id']}/{late_ref['event_id']}"]}
    assert senior.post(f"/investigations/{inv['id']}/internal-golden", json={"content": moved}).status_code == 400
    assert senior.post(f"/investigations/{inv['id']}/internal-golden", json={"content": content}).status_code == 201


def test_two_first_drafts_cannot_both_become_the_latest_version(senior):
    """GOLD-03: the first save also carries a version condition."""
    inv = _inv(senior, "first save")
    _check(senior, inv["id"])
    content = senior.get(f"/investigations/{inv['id']}/internal-golden/draft").json()["content"]
    first = senior.post(f"/investigations/{inv['id']}/internal-golden",
                         json={"content": content, "expected_version": None})
    assert first.status_code == 201
    second = senior.post(f"/investigations/{inv['id']}/internal-golden",
                          json={"content": {**content, "notes": "stale screen"}, "expected_version": None})
    assert second.status_code == 400
    record = senior.get(f"/investigations/{inv['id']}/internal-golden").json()["record"]
    assert record["version"] == 1 and record["content"]["notes"] == ""


def test_verified_but_unanswered_questions_stay_unresolved_and_long_replies_fit(senior):
    """GOLD-04 and GOLD-05."""
    inv = _inv(senior, "unresolved")
    check = _check(senior, inv["id"])
    ref = _event(inv["id"], f"e-{uuid.uuid4().hex[:6]}")
    short = _followup(senior, inv["id"], check["id"], "Which job ran at 10:00?")
    replied = _reply(senior, inv["id"], short, [ref], note="Logs rotated; no record")
    verified = senior.post(f"/investigations/{inv['id']}/follow-ups/{short['id']}/verify", json={
        "expected_version_id": replied["current"]["id"], "reason": "check", "outcome": "insufficient_data",
        "basis": "No job log retained", "evidence": [ref]})
    assert verified.status_code == 200, verified.text
    long = _followup(senior, inv["id"], check["id"], "Describe the full assessment scope")
    _reply(senior, inv["id"], long, [ref], note="x" * 7999)

    content = senior.get(f"/investigations/{inv['id']}/internal-golden/draft")
    assert content.status_code == 200, content.text
    content = content.json()["content"]
    assert any(u.startswith("Which job ran at 10:00?") for u in content["unresolved"])
    assert any(len(item["reply"]) == 7999 for item in content["followups"])
    assert senior.post(f"/investigations/{inv['id']}/internal-golden", json={"content": content}).status_code == 201


def test_export_keeps_first_known_input_apart_from_answers_and_lineage_apart_from_splits(senior):
    """F10/F11: agent input carries only what was known at the first question; variants share one split."""
    import json

    inv = _inv(senior, "export")
    ref = _event(inv["id"], f"e-{uuid.uuid4().hex[:6]}")
    check = _check(senior, inv["id"], evidence=[ref["event_id"]])
    fu = _followup(senior, inv["id"], check["id"])
    _reply(senior, inv["id"], fu, [ref], note="ANSWER-ONLY-REPLY")
    content = senior.get(f"/investigations/{inv['id']}/internal-golden/draft").json()["content"]
    group = f"case-{uuid.uuid4().hex[:6]}"
    content["lineage"] = {**content["lineage"], "variant_group_id": group, "split": "test"}
    content["final_judgement"] = {"status": "normal", "rationale": "ANSWER-ONLY-FINAL", "scope": ""}
    assert senior.post(f"/investigations/{inv['id']}/internal-golden", json={"content": content}).status_code == 201

    agent = senior.get("/knowledge/internal-golden-export", params={"audience": "agent", "split": "test"})
    assert agent.status_code == 200 and agent.headers["content-disposition"].endswith('agent-input.jsonl"')
    lines = [json.loads(x) for x in agent.text.splitlines()]
    mine = [x for x in lines if x["observations"]["title"] == "export"]
    assert len(mine) == 1 and "ANSWER-ONLY" not in json.dumps(mine[0], ensure_ascii=False)
    answers = [json.loads(x) for x in senior.get("/knowledge/internal-golden-export",
                                                 params={"audience": "evaluator", "split": "test"}).text.splitlines()]
    answer = next(x for x in answers if x["example_id"] == mine[0]["example_id"])
    assert answer["answers"]["final_judgement"]["rationale"] == "ANSWER-ONLY-FINAL"
    assert any(f["reply"] == "ANSWER-ONLY-REPLY" for f in answer["answers"]["followups"])

    # A variant of the same case placed in another split is refused, not silently exported on both sides.
    other = _inv(senior, "export variant")
    _check(senior, other["id"])
    variant = senior.get(f"/investigations/{other['id']}/internal-golden/draft").json()["content"]
    variant["lineage"] = {**variant["lineage"], "variant_group_id": group, "split": "train"}
    assert senior.post(f"/investigations/{other['id']}/internal-golden", json={"content": variant}).status_code == 201
    refused = senior.get("/knowledge/internal-golden-export", params={"audience": "agent"})
    assert refused.status_code == 400 and group in refused.text


def test_uploaded_files_split_into_first_and_later_logs(senior):
    """A file uploaded before the first question is an initial log; one uploaded after it is later material."""
    from saw.devtools.security_csv_samples import fw_csv, ndr_csv
    from tests.api.test_text_uploads import _process

    inv = _inv(senior, "files")
    _process(senior, inv["id"], "fw.csv", fw_csv())
    check = _check(senior, inv["id"])
    _followup(senior, inv["id"], check["id"])
    _process(senior, inv["id"], "ndr.csv", ndr_csv("chain"))
    response = senior.get(f"/investigations/{inv['id']}/internal-golden/draft")
    assert response.status_code == 200, response.text
    content = response.json()["content"]
    assert [f["file"] for f in content["initial_logs"]] == ["fw.csv"]
    assert [f["file"] for f in content["later_logs"]] == ["ndr.csv"]
    assert senior.post(f"/investigations/{inv['id']}/internal-golden", json={"content": content}).status_code == 201

