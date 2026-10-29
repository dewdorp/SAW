"""A reply's evidence must show the same endpoints the request asked about; a widened period needs a new check."""
import uuid

from saw import container
from saw.followups.scope import compare, requested_scope


ASKED = {"target": {"src_ips": ["198.51.100.23"], "dst_ips": ["10.20.1.10"], "dst_ports": [443]},
         "period": {"start": "2026-10-13T01:00:00+00:00", "end": "2026-10-13T01:05:00+00:00"}}
REPLY = {"org_unit_id": "aff-a", "src_ips": ["198.51.100.23"], "dst_ips": ["10.20.1.10"], "dst_ports": [443],
         "start": "2026-10-13T00:59:00+00:00", "end": "2026-10-13T01:06:00+00:00"}


def _ev(**kw):
    return {"investigation_id": "inv", "timestamp": "2026-10-13T01:01:00Z", "src_ip": "198.51.100.23",
            "dst_ip": "10.20.1.10", "dst_port": 443, **kw}


def run(events):
    return compare(requested_scope(ASKED, "aff-a", (None, None)), REPLY, events, "inv")


def test_evidence_with_other_endpoints_is_not_a_match_even_inside_the_period():
    """FOLLOW-01: same investigation and time is not enough; the records must be about the asked endpoints."""
    assert run([_ev()])["result"] == "matches"
    other = run([_ev(src_ip="192.0.2.99", dst_ip="10.99.9.99", dst_port=22)])
    assert other["result"] == "mismatch" and "evidence" in other["components"]
    assert run([_ev(), _ev(dst_port=22)])["result"] == "partial"
    # Correspondence is per record: a source from one record and a port from another is not a match.
    crossed = run([_ev(dst_port=22), _ev(src_ip="192.0.2.99")])
    assert crossed["result"] == "mismatch"
    # A record without the fields asked about cannot confirm them.
    blank = run([{"investigation_id": "inv", "timestamp": "2026-10-13T01:01:00Z"}])
    assert blank["result"] == "partial" and any("확인할 수 없" in u for u in blank["uncovered"])


def _setup(senior):
    org = senior.post("/source-context/org-units", json={"display_name": f"F {uuid.uuid4().hex[:6]}"}).json()
    inv = senior.post("/investigations", json={"title": "follow", "org_unit_id": org["id"],
                                              "period_start": "2026-10-01T00:00:00+09:00",
                                              "period_end": "2026-10-15T23:59:59+09:00"}).json()
    check = senior.post(f"/investigations/{inv['id']}/checks", json={
        "target_type": "entity", "target_key": "ip:198.51.100.23", "questions": ["nature"], "note": "probe"}).json()
    return org, inv, check


def _event(inv_id, **kw):
    eid = f"e-{uuid.uuid4().hex[:8]}"
    container.get().events.index([{"event_id": eid, "investigation_id": inv_id, "timestamp": "2026-10-13T01:01:00Z",
                                   "src_ip": "198.51.100.23", "dst_ip": "10.20.1.10", "dst_port": 443,
                                   "data_source": "synthetic", **kw}])
    return {"investigation_id": inv_id, "event_id": eid}


def test_confirming_with_records_about_other_endpoints_is_refused(senior):
    org, inv, check = _setup(senior)
    url = f"/investigations/{inv['id']}/follow-ups"
    fu = senior.post(url, json={"check_id": check["id"], "question": "Approved?", "reason": "r", **ASKED}).json()
    wrong = _event(inv["id"], src_ip="192.0.2.99", dst_ip="10.99.9.99", dst_port=22)
    reply = senior.post(f"{url}/{fu['id']}/reply", json={"expected_version_id": fu["current"]["id"], "reason": "r",
        "note": "Approved job", "evidence": [wrong], "scope": {**REPLY, "org_unit_id": org["id"]}}).json()
    assert reply["current"]["payload"]["reply"]["scope_check"]["result"] == "mismatch"
    verify = senior.post(f"{url}/{fu['id']}/verify", json={"expected_version_id": reply["current"]["id"],
        "reason": "r", "outcome": "confirmed", "basis": "job record", "evidence": [wrong]})
    assert verify.status_code == 400


def test_a_verification_of_the_inherited_period_does_not_cover_a_widened_investigation(senior):
    """FOLLOW-02: a request without its own period checked the period of the time; widening it reopens the gap."""
    org, inv, check = _setup(senior)
    url = f"/investigations/{inv['id']}/follow-ups"
    fu = senior.post(url, json={"check_id": check["id"], "question": "Approved all month?", "reason": "r",
                                "target": {"src_ips": ["198.51.100.23"]}}).json()
    ev = _event(inv["id"])
    scope = {"org_unit_id": org["id"], "src_ips": ["198.51.100.23"],
             "start": "2026-09-30T15:00:00+00:00", "end": "2026-10-15T15:00:00+00:00"}
    reply = senior.post(f"{url}/{fu['id']}/reply", json={"expected_version_id": fu["current"]["id"], "reason": "r",
        "note": "Approved for the whole period", "evidence": [ev], "scope": scope}).json()
    ok = senior.post(f"{url}/{fu['id']}/verify", json={"expected_version_id": reply["current"]["id"], "reason": "r",
        "outcome": "confirmed", "basis": "approval", "evidence": [ev]})
    assert ok.status_code == 200, ok.text
    close = {"verdict": "normal", "reason": "approved"}
    widened = senior.patch(f"/investigations/{inv['id']}", json={"period_start": "2026-10-01T00:00:00+09:00",
                                                                  "period_end": "2026-10-31T23:59:59+09:00"})
    assert widened.status_code == 200, widened.text
    blocked = senior.post(f"/investigations/{inv['id']}/close", json=close)
    assert blocked.status_code == 400 and "기간" in blocked.text

    # A request that fixed its own narrow period stays valid when the investigation widens.
    org2, inv2, check2 = _setup(senior)
    url2 = f"/investigations/{inv2['id']}/follow-ups"
    fixed = senior.post(url2, json={"check_id": check2["id"], "question": "Approved?", "reason": "r", **ASKED}).json()
    ev2 = _event(inv2["id"])
    r2 = senior.post(f"{url2}/{fixed['id']}/reply", json={"expected_version_id": fixed["current"]["id"], "reason": "r",
        "note": "Approved", "evidence": [ev2], "scope": {**REPLY, "org_unit_id": org2["id"]}}).json()
    assert senior.post(f"{url2}/{fixed['id']}/verify", json={"expected_version_id": r2["current"]["id"], "reason": "r",
        "outcome": "confirmed", "basis": "approval", "evidence": [ev2]}).status_code == 200
    senior.patch(f"/investigations/{inv2['id']}", json={"period_start": "2026-10-01T00:00:00+09:00",
                                                        "period_end": "2026-10-31T23:59:59+09:00"})
    assert senior.post(f"/investigations/{inv2['id']}/close", json=close).status_code == 200


def test_a_request_is_prefilled_from_the_check_records_without_copying_addresses(senior):
    """F05: target, port and period come from the records the check points at."""
    org, inv, _ = _setup(senior)
    a = _event(inv["id"], timestamp="2026-10-13T01:01:00Z")
    b = _event(inv["id"], timestamp="2026-10-13T01:04:00Z", dst_port=8443)
    check = senior.post(f"/investigations/{inv['id']}/checks", json={
        "target_type": "entity", "target_key": "ip:198.51.100.23", "questions": ["nature"], "note": "Burst of requests",
        "evidence": [a["event_id"], b["event_id"]]}).json()
    draft = senior.get(f"/investigations/{inv['id']}/follow-ups/draft", params={"check_id": check["id"]})
    assert draft.status_code == 200, draft.text
    d = draft.json()
    assert d["target"]["src_ips"] == ["198.51.100.23"] and d["target"]["dst_ips"] == ["10.20.1.10"]
    assert sorted(d["target"]["dst_ports"]) == [443, 8443]
    assert d["period"] == {"start": "2026-10-13T01:01:00Z", "end": "2026-10-13T01:04:00Z"} or \
        d["period"]["start"].startswith("2026-10-13T01:01:00")
    assert d["evidence_records"] == 2 and len(d["observed_pairs"]) == 2
    created = senior.post(f"/investigations/{inv['id']}/follow-ups", json={
        "check_id": check["id"], "question": d["question"], "reason": d["reason"], "target": d["target"],
        "period": d["period"], "needed_data": d["needed_data"]})
    assert created.status_code == 201, created.text


def test_a_request_about_a_suggested_item_is_prefilled_from_its_representative_records(analyst):
    """F05 on the common path: a check on a suggestion uses the suggestion's kept records and title."""
    from tests.api.test_text_uploads import _process
    from saw.devtools.security_csv_samples import ndr_csv

    inv = analyst.post("/investigations", json={"title": "suggestion draft"}).json()
    _process(analyst, inv["id"], "ndr.csv", ndr_csv("chain"))
    finding = next(f for f in analyst.get(f"/investigations/{inv['id']}/findings").json() if f.get("entities"))
    check = analyst.post(f"/investigations/{inv['id']}/checks", json={
        "target_type": "finding", "target_key": finding["id"], "questions": ["nature"], "note": "Needs owner confirmation"}).json()
    d = analyst.get(f"/investigations/{inv['id']}/follow-ups/draft", params={"check_id": check["id"]}).json()
    assert d["evidence_records"] > 0 and d["target"]["src_ips"] and d["period"]
    assert finding["title"] in d["question"]
