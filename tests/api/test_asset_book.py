"""Assets: register with a name and one identifier, refresh from a file with a preview, time-valid addresses."""
from tests.api.test_flow_knowledge import _inv, _org
from tests.api.test_hunts import _walk
from tests.api.test_text_uploads import _process

FILE = """자산 ID,이름,IP 주소,담당자,업무,중요도
CRM-001,고객관리 웹,10.50.9.77,김담당,고객 상담 조회,높음
CRM-002,정산 배치,10.50.9.78,,야간 정산,보통
,이름만 있는 행,10.50.9.77,,,
CRM-003,잘못된 주소,999.1.1.1,,,
"""


def test_register_with_a_name_and_one_identifier_then_complete_later(senior):
    org = _org(senior)
    a = senior.post("/asset-book", json={"name": "회원 포털", "identifier": "10.40.1.10", "org_unit_id": org["id"]})
    assert a.status_code == 201, a.text
    asset = a.json()
    assert asset["asset_id"].endswith("-001") and asset["ip"] == ["10.40.1.10"] and asset["addresses"][0]["kind"] == "ip"
    assert set(asset["review"]) >= {"담당자 미확인", "업무 설명 없음"}
    done = senior.put(f"/asset-book/{asset['id']}", json={"expected_rev": asset["rev"], "data": {
        "owner": "박담당", "business": "회원 인증·조회", "last_confirmed": "2026-11-01", "next_review": "2027-05-01"}}).json()
    assert done["rev"] == asset["rev"] + 1 and done["review"] == []
    stale = senior.put(f"/asset-book/{asset['id']}", json={"expected_rev": asset["rev"], "data": {"owner": "x"}})
    assert stale.status_code == 400 and "먼저 고쳤습니다" in stale.json()["detail"]
    assert [r["rev"] for r in senior.get(f"/asset-book/{asset['id']}/history").json()["revisions"]][:2] == [2, 1]


def test_file_refresh_previews_and_never_overwrites_by_ip_or_deletes(senior):
    """Acceptance 16, 17: new/changed/conflict/error before applying; the same file twice makes no duplicates."""
    org = _org(senior)
    body = {"text": FILE, "org_unit_id": org["id"]}
    first = senior.post("/asset-book/import/preview", json=body).json()
    assert first["counts"] == {"new": 3, "changed": 0, "unchanged": 0, "conflict": 0, "error": 1}
    assert first["columns"] == ["asset_id", "name", "ip", "owner", "business", "criticality"]
    assert "999.1.1.1" in first["rows"][3]["reason"] or "address" in first["rows"][3]["reason"]
    # Nothing was written by the preview.
    assert senior.get("/asset-book", params={"org_unit_id": org["id"]}).json()["items"] == []
    # Remove the key-less row that would collide once CRM-001 exists, then apply.
    clean = "\n".join(line for line in FILE.splitlines() if "이름만" not in line) + "\n"
    applied = senior.post("/asset-book/import/apply", json={**body, "text": clean}).json()
    assert applied == {"applied": {"new": 2, "changed": 0}, "skipped": {"unchanged": 0, "conflict": 0, "error": 1}}
    again = senior.post("/asset-book/import/preview", json={**body, "text": clean}).json()
    assert again["counts"] == {"new": 0, "changed": 0, "unchanged": 2, "conflict": 0, "error": 1}
    senior.post("/asset-book/import/apply", json={**body, "text": clean})
    items = senior.get("/asset-book", params={"org_unit_id": org["id"]}).json()["items"]
    assert sorted(i["asset_id"] for i in items) == ["CRM-001", "CRM-002"]  # the same file twice: no duplicates
    # A row without a key that names an owned address is a conflict, not an update.
    collide = senior.post("/asset-book/import/preview", json=body).json()
    row = next(r for r in collide["rows"] if r["name"] == "이름만 있는 행")
    assert row["action"] == "conflict" and "IP만으로는 덮어쓰지 않습니다" in row["reason"]
    # A blank cell keeps the value; a missing asset is not deleted; a changed cell is shown as a change.
    update = "자산 ID,이름,담당자,업무\nCRM-001,고객관리 웹,,상담 조회와 민원 처리\n"
    preview = senior.post("/asset-book/import/preview", json={**body, "text": update}).json()
    assert preview["counts"]["changed"] == 1 and preview["rows"][0]["changes"] == [{"field": "business", "from": "고객 상담 조회", "to": "상담 조회와 민원 처리"}]
    senior.post("/asset-book/import/apply", json={**body, "text": update})
    items = {i["asset_id"]: i for i in senior.get("/asset-book", params={"org_unit_id": org["id"]}).json()["items"]}
    assert items["CRM-001"]["owner"] == "김담당" and items["CRM-001"]["business"] == "상담 조회와 민원 처리" and "CRM-002" in items
    cleared = senior.post("/asset-book/import/preview", json={**body, "text": update, "clear_blank": True}).json()
    assert {"field": "owner", "from": "김담당", "to": ""} in cleared["rows"][0]["changes"]


def test_the_same_private_address_in_two_affiliates_and_a_reassigned_address(senior):
    """Acceptance 17: affiliates are separate; a reassigned address belongs to whoever held it at the event's time."""
    from saw.assets import service as assets

    a_org, b_org = _org(senior, "A"), _org(senior, "B")
    first = senior.post("/asset-book", json={"name": "A사 결제", "identifier": "10.9.9.9", "org_unit_id": a_org["id"]}).json()
    other = senior.post("/asset-book", json={"name": "B사 인사", "identifier": "10.9.9.9", "org_unit_id": b_org["id"]}).json()
    listing = senior.get("/asset-book").json()
    assert not [t for t in listing["to_review"] if t["kind"] == "address_conflict"]  # different affiliates do not conflict
    # The address moves to a new asset of affiliate A on 2026-11-01.
    senior.put(f"/asset-book/{first['id']}", json={"expected_rev": first["rev"], "data": {"addresses": [
        {"value": "10.9.9.9", "kind": "ip", "valid_from": "2026-01-01", "valid_to": "2026-10-31", "source": "IPAM"}]}})
    new = senior.post("/asset-book", json={"name": "A사 신규 배치", "identifier": "10.9.9.9", "org_unit_id": a_org["id"]}).json()
    senior.put(f"/asset-book/{new['id']}", json={"expected_rev": new["rev"], "data": {"addresses": [
        {"value": "10.9.9.9", "kind": "ip", "valid_from": "2026-11-01", "valid_to": "", "source": "IPAM"}]}})
    rows = senior.get("/asset-book").json()["items"]
    at = lambda day, org: (assets.match_at(rows, org_unit_id=org, value="10.9.9.9", at=day) or {}).get("name")  # noqa: E731
    assert at("2026-10-20T03:00:00Z", a_org["id"]) == "A사 결제" and at("2026-11-05T03:00:00Z", a_org["id"]) == "A사 신규 배치"
    assert at("2026-10-20T03:00:00Z", b_org["id"]) == other["name"] == "B사 인사"
    assert not [t for t in senior.get("/asset-book").json()["to_review"] if t["kind"] == "address_conflict"]
    # Two assets of one affiliate holding the address at the same time is something to review.
    senior.post("/asset-book", json={"name": "A사 중복", "identifier": "10.9.9.9", "org_unit_id": a_org["id"]})
    conflicts = [t for t in senior.get("/asset-book").json()["to_review"] if t["kind"] == "address_conflict"]
    assert len(conflicts) == 1 and "동시에 배정" in conflicts[0]["text"]


def test_a_registered_asset_explains_an_activity_but_never_hides_it(senior):
    """Acceptance 19: a trusted or stale asset description is shown next to the activity; the activity stays."""
    org = _org(senior)
    senior.post("/asset-book", json={"name": "정산 배치 서버", "identifier": "10.50.9.77", "org_unit_id": org["id"]})
    inv = _inv(senior, org, "asset context")
    _process(senior, inv["id"], "ndr.csv", _walk().encode())
    run = senior.get(f"/investigations/{inv['id']}/hunt").json()["run"]
    walker = next(a for a in run["activities"] if a["method"] == "target_variation")
    assert walker["assets"][0]["name"] == "정산 배치 서버" and "담당자 미확인" in walker["assets"][0]["stale"]
    assert any("등록 자산 '정산 배치 서버'" in line and "등록 정보가 약합니다" in line and "실제로 맞는지 비교" in line for line in walker["normal"])
    assert walker["review"]["state"] == "unreviewed"
    # Observed but unregistered targets are proposed, not registered.
    cand = senior.get(f"/investigations/{inv['id']}/asset-candidates").json()
    assert {"value": "crm.example.test", "kind": "서비스 호스트", "records": 832} in cand["items"]
    assert any(c["value"] == "10.40.1.10" for c in cand["items"]) and "자동으로 자산이 되지 않습니다" in cand["note"]
    assert len(senior.get("/asset-book").json()["items"]) == 1
