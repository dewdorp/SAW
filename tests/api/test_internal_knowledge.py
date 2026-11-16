"""Internal golden records save directly with history; device alert names are matched exactly."""
import csv
import io
import uuid

from saw.devtools.security_csv_samples import NDR_COLUMNS
from tests.api.test_text_uploads import _process
from tests.conftest import Api, make_user


def _org(api):
    return api.post("/source-context/org-units", json={"display_name": f"Golden {uuid.uuid4().hex[:6]}"}).json()


def test_analyst_saves_and_edits_an_internal_golden_record_without_any_approval(senior, app):
    org = _org(senior)
    inv = senior.post("/investigations", json={"title": "golden direct", "org_unit_id": org["id"],
                                              "period_start": "2026-10-01T00:00:00+09:00",
                                              "period_end": "2026-10-31T23:59:59+09:00"}).json()
    check = senior.post(f"/investigations/{inv['id']}/checks", json={
        "target_type": "entity", "target_key": "ip:198.51.100.23", "questions": ["nature"],
        "judgement": "suspicious", "note": "Path discovery burst from one source"}).json()
    senior.post(f"/investigations/{inv['id']}/follow-ups", json={
        "check_id": check["id"], "question": "Was this an authorized assessment?", "reason": "Scanner traffic",
        "target": {"src_ips": ["198.51.100.23"], "dst_ports": [443]},
        "period": {"start": "2026-10-13T10:00:00+09:00", "end": "2026-10-13T10:05:00+09:00"}})
    draft = senior.get(f"/investigations/{inv['id']}/internal-golden/draft")
    assert draft.status_code == 200, draft.text
    content = draft.json()["content"]
    assert content["scope"]["org_unit_id"] == org["id"] and content["scope"]["period_start"]
    assert content["questions"] == ["Was this an authorized assessment?"]
    assert content["followups"][0]["target"].startswith("출발지 198.51.100.23")
    assert any("회신" in u for u in content["unresolved"])  # unanswered request is listed as still open
    assert content["initial_judgement"]["status"] == "insufficient_evidence"

    content["final_judgement"] = {"status": "insufficient_evidence", "rationale": "No reply yet", "scope": "13 Oct 10:00-10:05"}
    content["scope"]["org_unit_id"] = "someone-else"  # never trusted from the edited text
    saved = senior.post(f"/investigations/{inv['id']}/internal-golden", json={"content": content, "change_note": "first"})
    assert saved.status_code == 201, saved.text
    assert saved.json()["version"] == 1 and saved.json()["content"]["scope"]["org_unit_id"] == org["id"]

    content["final_judgement"]["rationale"] = "Reply pending; activity limited to one source"
    edited = senior.post(f"/investigations/{inv['id']}/internal-golden",
                         json={"content": content, "change_note": "clarified", "expected_version": 1})
    assert edited.status_code == 201 and edited.json()["version"] == 2
    stale = senior.post(f"/investigations/{inv['id']}/internal-golden",
                        json={"content": content, "expected_version": 1})
    assert stale.status_code == 400

    record = senior.get(f"/investigations/{inv['id']}/internal-golden").json()["record"]
    assert [v["version"] for v in record["versions"]] == [2, 1]
    first = senior.get(f"/knowledge/internal-golden/{record['id']}", params={"version": 1}).json()
    assert first["content"]["final_judgement"]["rationale"] == "No reply yet"
    listed = senior.get("/knowledge/internal-golden", params={"org_unit_id": org["id"]}).json()["items"]
    assert [x["id"] for x in listed] == [record["id"]]

    # Access follows the source investigation: a non-member cannot read or list it.
    make_user("golden-outsider", ["analyst"])
    outsider = Api(app, "golden-outsider")
    assert outsider.get(f"/knowledge/internal-golden/{record['id']}").status_code == 403
    assert all(x["id"] != record["id"] for x in outsider.get("/knowledge/internal-golden").json()["items"])
    assert outsider.post(f"/investigations/{inv['id']}/internal-golden", json={"content": content}).status_code == 403


def _ndr(names):
    out = io.StringIO(newline="")
    w = csv.writer(out, lineterminator="\r\n")
    w.writerow(NDR_COLUMNS)
    for i, name in enumerate(names):
        w.writerow([f"2026-10-01 10:{i:02d}:00", "HTTP", "가상", "192.0.2.2", "탐지", "198.51.100.9", 40000 + i, "NL",
                    "10.20.1.10", 443, "TCP", f"S-{i}", 100, 200, "GET /a HTTP/1.1", "h.example.test", "404", "ua", name])
    return out.getvalue().encode("cp949")


def test_alert_names_are_matched_exactly_and_unregistered_names_stay_open(senior, analyst):
    name = f"Synthetic Web Scan {uuid.uuid4().hex[:4]}"
    created = senior.post("/knowledge/device-signatures", json={
        "original_name": name, "meaning": "Path discovery signature of the synthetic sensor",
        "checks": ["Compare with the approved assessment schedule"], "false_positive_cases": ["Uptime monitors"]})
    assert created.status_code == 201, created.text
    assert analyst.post("/knowledge/device-signatures", json={"original_name": "x", "meaning": "y"}).status_code == 403
    duplicate = senior.post("/knowledge/device-signatures", json={"original_name": name, "meaning": "other"})
    assert duplicate.status_code == 400
    unconfirmed = senior.post("/knowledge/device-signatures", json={"original_name": name + " v2", "meaning": ""})
    assert unconfirmed.status_code == 422  # a confirmed entry needs the meaning the analyst confirmed

    inv = senior.post("/investigations", json={"title": "alerts"}).json()
    _process(senior, inv["id"], "ndr.csv", _ndr([name, name, name.lower(), name + " ", "Unknown Vendor Label"]))
    out = senior.get(f"/investigations/{inv['id']}/alert-names").json()
    status = {x["alert_name"]: x["registry"] for x in out["items"]}
    assert status[name] == "name_only"  # registered without any device: shown as a name-only match
    assert status[name.lower()] == "needs_confirmation"  # similar is not the same
    assert status["Unknown Vendor Label"] == "needs_confirmation"
    entry = next(x for x in out["items"] if x["alert_name"] == name)["applied"]
    assert entry["original_name"] == name and entry["meaning"].startswith("Path discovery")

    sid = created.json()["id"]
    renamed = senior.put(f"/knowledge/device-signatures/{sid}", json={
        "original_name": "Renamed", "meaning": "m", "expected_version": 1})
    assert renamed.status_code == 400  # the device's own wording is never overwritten
    updated = senior.put(f"/knowledge/device-signatures/{sid}", json={
        "original_name": name, "meaning": "Path discovery (confirmed with sensor docs)", "expected_version": 1})
    assert updated.status_code == 200 and updated.json()["version"] == 2
    history = senior.get(f"/knowledge/device-signatures/{sid}/history").json()["items"]
    assert [h["version"] for h in history] == [2, 1]


def test_a_meaning_applies_only_to_the_same_device_and_validity_period(senior):
    """SIG-01: an expired meaning registered for vendor A is never applied to vendor B's records of the same name."""
    from saw import container

    name = f"Shared Label {uuid.uuid4().hex[:4]}"
    expired_a = senior.post("/knowledge/device-signatures", json={
        "vendor": "Vendor A", "product": "Sensor", "original_name": name, "meaning": "A: path discovery",
        "valid_from": "2019-01-01", "valid_to": "2020-12-31"})
    assert expired_a.status_code == 201, expired_a.text
    inv = senior.post("/investigations", json={"title": "vendors"}).json()

    def index(vendor, ts, n=3):
        container.get().events.index([{"event_id": f"{vendor}-{uuid.uuid4().hex[:6]}", "investigation_id": inv["id"],
                                       "timestamp": ts, "alert_name": name, "src_ip": "198.51.100.9",
                                       "ext": {"cef_vendor": vendor, "cef_product": "Sensor"}} for _ in range(n)])
    index("Vendor B", "2026-10-13T01:00:00Z")
    index("Vendor A", "2026-10-13T01:00:00Z", 2)
    out = senior.get(f"/investigations/{inv['id']}/alert-names").json()["items"]
    by_vendor = {x["vendor"]: x for x in out}
    assert by_vendor["Vendor B"]["registry"] == "needs_confirmation" and by_vendor["Vendor B"]["applied"] is None
    assert "다릅니다" in by_vendor["Vendor B"]["entries"][0]["not_applied_reason"]
    assert by_vendor["Vendor A"]["registry"] == "needs_confirmation"  # same vendor, but 2026 is outside 2019-2020
    assert "유효기간" in by_vendor["Vendor A"]["entries"][0]["not_applied_reason"]

    current_b = senior.post("/knowledge/device-signatures", json={
        "vendor": "Vendor B", "product": "Sensor", "original_name": name, "meaning": "B: brute force counter",
        "valid_from": "2026-01-01"})
    assert current_b.status_code == 201, current_b.text
    out = senior.get(f"/investigations/{inv['id']}/alert-names").json()["items"]
    b = next(x for x in out if x["vendor"] == "Vendor B")
    assert b["registry"] == "confirmed" and b["applied"]["meaning"] == "B: brute force counter"
    assert b["applied"]["version"] == 1
    assert next(x for x in out if x["vendor"] == "Vendor A")["registry"] == "needs_confirmation"


def test_an_alert_meaning_records_what_it_observes_cannot_prove_and_which_questions_it_feeds(senior):
    body = {"vendor": "가상벤더", "product": "WAF", "original_name": "SYNTH-SQLI-PROBE", "signature_id": "9001",
            "meaning": "요청 값에 SQL 구문 형태", "log_source": "WAF 차단 로그", "action_values": ["block", "alert"],
            "observes": ["요청 값의 구문 형태"], "cannot_prove": ["DB에서 실행됐는지", "데이터가 나갔는지"],
            "followup_data": ["애플리케이션 오류 로그", "DB 감사 로그"], "linked_questions": ["Q02", "Q09"],
            "scope_note": "가상 관계사 A는 점검 서버 예외"}
    created = senior.post("/knowledge/device-signatures", json=body)
    assert created.status_code == 201, created.text
    row = next(x for x in senior.get("/knowledge/device-signatures", params={"q": "SYNTH-SQLI-PROBE"}).json()["items"]
               if x["id"] == created.json()["id"])
    for key in ("log_source", "action_values", "observes", "cannot_prove", "followup_data", "linked_questions", "scope_note"):
        assert row[key] == body[key], key
    bad = senior.post("/knowledge/device-signatures", json={**body, "original_name": "SYNTH-2", "linked_questions": ["Q11"]})
    assert bad.status_code == 422
