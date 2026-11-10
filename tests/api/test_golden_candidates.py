"""The golden-set candidate inbox: one candidate per source version, access-bound, saved and exported by selection."""
import json
import uuid

from saw.devtools.en_security_samples import fw_csv
from saw.internal_kb import candidates, golden
from tests.api.test_text_uploads import _process
from tests.conftest import Api, make_user


def _inv(api, title="Candidate investigation"):
    org = api.post("/source-context/org-units", json={"display_name": f"Cand {uuid.uuid4().hex[:6]}"}).json()
    inv = api.post("/investigations", json={"title": title, "org_unit_id": org["id"],
                                           "period_start": "2026-10-13T00:00:00+09:00",
                                           "period_end": "2026-10-13T23:59:59+09:00"}).json()
    _process(api, inv["id"], "spread.csv", fw_csv("spread"))
    return inv


def _reader(app, roles=("analyst",)):
    from saw.storage.db import session_scope
    from saw.storage.models import User

    user_id = make_user(f"cand-{uuid.uuid4().hex[:6]}", list(roles))
    with session_scope() as s:
        return Api(app, s.get(User, user_id).username)


def _lines(response):
    assert response.status_code == 200, response.text
    return [json.loads(line) for line in response.text.splitlines() if line.strip()]


def test_adding_the_same_case_twice_keeps_one_candidate_and_removal_keeps_saved_versions(senior):
    first = senior.post("/knowledge/golden-candidates", json={"source_kind": "casebook", "source_id": "W26", "note": "랜섬웨어"})
    assert first.status_code == 201, first.text
    again = senior.post("/knowledge/golden-candidates", json={"source_kind": "casebook", "source_id": "W26"})
    assert first.json()["created"] is True and again.json()["created"] is False
    assert again.json()["item"]["id"] == first.json()["item"]["id"]
    items = senior.get("/knowledge/golden-candidates", params={"source_id": "W26"}).json()["items"]
    assert len(items) == 1 and items[0]["origin_label"] == "합성 예제" and items[0]["status"] == "candidate"
    assert items[0]["source_refs"]["archive"].endswith("W26.zip") and len(items[0]["source_version"]) == 64
    cid = items[0]["id"]
    saved = senior.post("/knowledge/golden-candidates/save", json={"ids": [cid]}).json()["items"][0]
    assert saved["status"] == "saved" and saved["golden_version"] == 1
    assert senior.delete(f"/knowledge/golden-candidates/{cid}").status_code == 204
    assert senior.get("/knowledge/golden-candidates", params={"source_id": "W26"}).json()["items"] == []
    # The saved golden version stays after the pointer is gone; adding again starts a new candidate.
    from saw.internal_kb.models import InternalGolden, InternalGoldenVersion
    from saw.storage.db import session_scope
    with session_scope() as s:
        record = s.get(InternalGolden, saved["golden_record_id"])
        assert record is not None and record.investigation_id == "casebook:W26"
        assert s.query(InternalGoldenVersion).filter_by(record_id=record.id).count() == 1


def test_a_reader_without_access_sees_neither_the_title_nor_the_logs(senior, app):
    inv = _inv(senior, "Restricted lateral movement")
    added = senior.post("/knowledge/golden-candidates", json={"source_kind": "investigation", "source_id": inv["id"]})
    assert added.status_code == 201, added.text
    cid = added.json()["item"]["id"]
    assert added.json()["item"]["source_refs"]["evidence_files"][0]["sha256"]
    outsider = _reader(app)
    listing = outsider.get("/knowledge/golden-candidates")
    assert listing.status_code == 200 and "Restricted lateral movement" not in listing.text and inv["id"] not in listing.text
    assert outsider.patch(f"/knowledge/golden-candidates/{cid}", json={"note": "x"}).status_code == 404
    assert outsider.delete(f"/knowledge/golden-candidates/{cid}").status_code == 404
    assert outsider.post("/knowledge/golden-candidates/save", json={"ids": [cid]}).status_code == 404
    refused = outsider.post("/knowledge/golden-candidates/export", params={"audience": "agent"}, json={"ids": [cid]})
    assert refused.status_code == 404 and "Restricted" not in refused.text
    assert outsider.post("/knowledge/golden-candidates", json={"source_kind": "investigation",
                                                               "source_id": inv["id"]}).status_code == 403


def test_only_the_selected_saved_case_is_exported_with_first_known_input_and_answers(senior):
    inv = _inv(senior)
    before = (senior.get(f"/investigations/{inv['id']}").json(), senior.get(f"/investigations/{inv['id']}/checks").json(),
              senior.get(f"/investigations/{inv['id']}/findings").json())
    case = senior.post("/knowledge/golden-candidates", json={"source_kind": "casebook", "source_id": "W26"}).json()["item"]
    other = senior.post("/knowledge/golden-candidates", json={"source_kind": "investigation", "source_id": inv["id"]}).json()["item"]
    unsaved = senior.post("/knowledge/golden-candidates/export", params={"audience": "agent"}, json={"ids": [case["id"]]})
    assert unsaved.status_code == 400 and "저장한 후보만" in unsaved.text
    senior.post("/knowledge/golden-candidates/save", json={"ids": [case["id"], other["id"]]}).raise_for_status()
    agent = _lines(senior.post("/knowledge/golden-candidates/export", params={"audience": "agent"}, json={"ids": [case["id"]]}))
    answer = _lines(senior.post("/knowledge/golden-candidates/export", params={"audience": "evaluator"}, json={"ids": [case["id"]]}))
    assert len(agent) == len(answer) == 1 and agent[0]["example_id"] == answer[0]["example_id"]
    text = json.dumps(agent[0], ensure_ascii=False)
    # The first-known input: the lead and the original rows; never the case title, the follow-up evidence or the verdict.
    assert "10.80.26.15" in text and "fw.csv 60,192행" in text
    assert "공유 폴더의 대량 확장자 변경" not in text and "W26-E1" not in text and "침해 확인" not in text
    assert "followup.json" not in text and "locksvc.exe" not in text and inv["title"] not in text
    assert "W26" not in text and "case_id" not in text
    answers = answer[0]["answers"]
    assert answers["final_judgement"]["status"] == "compromise_confirmed"
    assert any("W26-E2" in item["evidence_refs"] for item in answers["followups"])
    assert answer[0]["lineage"]["synthetic"] is True and answer[0]["lineage"]["split"] == "unassigned"
    assert agent[0]["synthetic"] is True
    # Nominating, saving and exporting leave the investigation's verdict, checks and findings as they were.
    after = (senior.get(f"/investigations/{inv['id']}").json(), senior.get(f"/investigations/{inv['id']}/checks").json(),
             senior.get(f"/investigations/{inv['id']}/findings").json())
    assert after[0].get("verdict") == before[0].get("verdict") and after[0].get("status") == before[0].get("status")
    assert after[1] == before[1] and after[2] == before[2]


def test_cases_from_one_source_cannot_be_exported_in_different_splits(senior):
    case = senior.post("/knowledge/golden-candidates", json={"source_kind": "casebook", "source_id": "W03"}).json()["item"]
    senior.post("/knowledge/golden-candidates/save", json={"ids": [case["id"]]}).raise_for_status()
    # The split shown in the inbox is the split exported, without saving again.
    senior.patch(f"/knowledge/golden-candidates/{case['id']}", json={"split": "test"}).raise_for_status()
    saved = senior.get("/knowledge/golden-candidates", params={"source_id": "W03"}).json()["items"][0]
    assert saved["golden_version"] == 1 and saved["split"] == "test"
    lines = _lines(senior.post("/knowledge/golden-candidates/export", params={"audience": "evaluator"},
                               json={"ids": [case["id"]]}))
    assert lines[0]["lineage"]["split"] == "test" and lines[0]["lineage"]["variant_group_id"] == "casebook:W03"


def test_a_withheld_case_keeps_its_status_and_reason():
    case, _version, _raw = candidates._casebook_case(
        next(c["id"] for c in json.loads((candidates.casebook_dir() / "index.json").read_text("utf-8"))
             if c["classification"] == "판단 보류"))
    content = candidates.casebook_content(case)
    assert content["final_judgement"]["status"] == "insufficient_evidence"
    assert content["final_judgement"]["rationale"] and "판단 보류" in content["final_judgement"]["scope"]


def test_every_casebook_case_maps_to_a_valid_golden_record():
    index = json.loads((candidates.casebook_dir() / "index.json").read_text("utf-8"))
    assert [c["id"] for c in index] == [f"W{n:02d}" for n in range(1, 61)]
    for item in index:
        case, version, _raw = candidates._casebook_case(item["id"])
        content = candidates.casebook_content(case)
        assert content["final_judgement"]["status"] not in ("", "unknown"), item["id"]
        first = json.dumps({k: content[k] for k in ("scope", "initial_logs", "observed_facts")}, ensure_ascii=False)
        assert case["classification"] not in first and "followup" not in first and "회신" not in first, item["id"]


def test_saving_an_investigation_candidate_keeps_a_hand_edited_golden_version(senior):
    inv = _inv(senior)
    item = senior.post("/knowledge/golden-candidates", json={"source_kind": "investigation", "source_id": inv["id"]}).json()["item"]
    first = senior.post("/knowledge/golden-candidates/save", json={"ids": [item["id"]]}).json()["items"][0]
    record = senior.get(f"/investigations/{inv['id']}/internal-golden").json()["record"]
    content = record["content"]
    content["unresolved"] = ["curated by hand"]
    edited = senior.post(f"/investigations/{inv['id']}/internal-golden",
                         json={"content": content, "change_note": "hand edit", "expected_version": record["version"]})
    assert edited.status_code == 201, edited.text
    again = senior.post("/knowledge/golden-candidates/save", json={"ids": [item["id"]]}).json()["items"][0]
    assert again["golden_version"] == first["golden_version"] + 1
    line = _lines(senior.post("/knowledge/golden-candidates/export", params={"audience": "evaluator"},
                              json={"ids": [item["id"]]}))[0]
    assert line["answers"]["unresolved"] == ["curated by hand"]


def test_no_casebook_agent_input_names_its_case():
    index = json.loads((candidates.casebook_dir() / "index.json").read_text("utf-8"))
    for item in index:
        case, _version, _raw = candidates._casebook_case(item["id"])
        content = candidates.casebook_content(case)
        first = json.dumps({k: content[k] for k in golden.INITIAL_FIELDS}, ensure_ascii=False)
        assert "case_id" not in first and "casebook:" not in first and item["id"] not in first, item["id"]
