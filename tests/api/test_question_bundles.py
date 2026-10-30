"""The four investigation questions work on English NDR/FW exports with no policy, rule or scenario written."""
import pytest

from saw.devtools.en_security_samples import EXPECTED, fw_csv, ndr_csv
from tests.api.test_text_uploads import _process


def _bundles(api, kind, case):
    inv = api.post("/investigations", json={"title": f"{kind} {case}"}).json()
    job = _process(api, inv["id"], f"{kind}.csv", ndr_csv(case) if kind == "ndr" else fw_csv(case))
    assert job["files"][0]["parser_id"] == ("en_ndr_http_csv" if kind == "ndr" else "en_fw_csv")
    out = api.get(f"/investigations/{inv['id']}/question-bundles")
    assert out.status_code == 200, out.text
    return inv, {b["id"]: b for b in out.json()["bundles"]}


@pytest.mark.parametrize("kind,case", sorted(EXPECTED))
def test_each_question_bundle_answers_from_the_logs(analyst, kind, case):
    _, bundles = _bundles(analyst, kind, case)
    for bundle, status in EXPECTED[(kind, case)].items():
        assert bundles[bundle]["status"] == status, (bundle, bundles[bundle])


def test_an_item_says_what_was_seen_why_what_is_unknown_and_what_to_ask(analyst):
    inv, bundles = _bundles(analyst, "ndr", "large_response_out")
    item = bundles["transfer"]["items"][0]
    assert "외부 반출 후보" in item["title"] and item["records"] == 12
    assert item["basis"]["threshold_bytes"] and item["unknown"] and item["normal_possibilities"] and item["next_questions"]
    assert item["entities"] == ["ip:198.51.100.50", "ip:10.20.1.10"]
    # The item's evidence filter finds exactly its records in the full log.
    found = analyst.post(f"/investigations/{inv['id']}/query/events", json={"filters": item["filters"], "limit": 50}).json()
    assert len(found["events"]) == 12
    # The investigation guidance reads the same records as large responses (one convention for web bytes).
    guide = analyst.post(f"/investigations/{inv['id']}/guidance/preview", json={
        "target_type": "entity", "target_key": "ip:198.51.100.50", "role": "either", "filters": [], "time": None,
        "as_of": None, "methodology_version": "soc-guidance/1.0"})
    assert guide.status_code == 200, guide.text
    assert next(f["value"] for f in guide.json()["facts"] if f["id"] == "large_response") == 12
    _, download = _bundles(analyst, "ndr", "download_in")
    assert "다운로드 후보" in download["transfer"]["items"][0]["title"]


def test_nothing_found_and_no_data_are_not_normal(analyst):
    _, bundles = _bundles(analyst, "fw", "periodic")
    assert bundles["web_attack"]["status"] == "insufficient_data" and bundles["web_attack"]["missing"]
    _, web = _bundles(analyst, "ndr", "web_normal")
    assert web["web_attack"]["items"] == [] and web["web_attack"]["status"] == "looked_none"
    out = analyst.get(f"/investigations/{_bundles(analyst, 'fw', 'spread')[0]['id']}/question-bundles",
                      params={"sensitivity": "low"}).json()
    assert out["thresholds"]["targets"] == 20 and "정상이라는 뜻이 아닙니다" in out["note"]


def test_field_meanings_say_what_each_column_is_how_it_was_used_and_how_often_it_was_filled(analyst):
    inv, _ = _bundles(analyst, "ndr", "no_bytes")
    out = analyst.get(f"/investigations/{inv['id']}/field-meanings").json()
    ndr = next(f for f in out["formats"] if f["parser"] == "en_ndr_http_csv")
    by = {f["column"]: f for f in ndr["fields"]}
    assert by["dest_ip"]["common_field"] == "dst_ip" and by["dest_ip"]["records_with_value"] == ndr["records"] == 10
    assert by["query"]["common_field"] == "url_query" and by["sc_bytes"]["state"] == "candidate"
    assert by["sc_bytes"]["records_with_value"] == 0  # this export carried no byte counts
    assert by["uuid"]["state"] == "raw" and by["uuid"]["records_with_value"] == 10

