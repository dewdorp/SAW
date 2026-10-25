"""Same-header synthetic uploads reach real detectors and retained history."""
import pytest

from saw.core.schemas.query import Filter
from saw.devtools.security_csv_samples import fw_csv, ndr_csv
from tests.api.test_generation_reprocessing import read_events
from tests.api.test_text_uploads import _process


def latest(api, inv):
    runs = api.get(f"/investigations/{inv}/analysis-runs").json()["runs"]
    result = api.get(f"/investigations/{inv}/analysis-runs/{runs[0]['id']}").json()
    return result, {row["detector_id"]: row for row in result["executions"]}


def test_repeated_uploads_preserve_prior_readiness_and_real_chain(analyst):
    inv = analyst.post("/investigations", json={"title": "가상 반복 CSV 검증"}).json()["id"]
    first = _process(analyst, inv, "synthetic-fw.csv", fw_csv())
    assert first["files"][0]["parser_id"] == "ko_fw_csv"
    old, old_ex = latest(analyst, inv)
    ready = old_ex["csv.readiness"]["detail"]
    assert ready["input_records"] == ready["counts"]["records"] == 12
    assert ready["formats"][0]["source_devices"] == 2
    assert old_ex["fw.observation"]["status"] == "insufficient_data"
    second = _process(analyst, inv, "synthetic-ndr.csv", ndr_csv())
    assert second["files"][0]["parser_id"] == "ko_ndr_csv"
    current, ex = latest(analyst, inv)
    assert current["id"] != old["id"]
    assert ex["csv.readiness"]["detail"]["counts"]["records"] == 59
    flow = ex["scenario.flow"]["detail"]
    chain = next(row for row in flow["scenarios"] if row["id"] == "web_intrusion")
    assert chain["status"] == "matched_candidate" and chain["match_count"] >= 1
    assert ex["scenario.flow"]["detector_version"] == flow["engine_version"]
    assert all(row["eligible_findings"] for row in chain["steps"])
    again = analyst.get(f"/investigations/{inv}/analysis-runs/{old['id']}").json()
    assert again["executions"] == old["executions"]
    events = read_events().search(inv, [Filter(field="parser", value="ko_ndr_csv")], limit=100)["events"]
    assert len(events) == 47 and all(e["raw_ref"]["length"] > 0 for e in events)
    assert all(e["dst_ip"] == "익명-대상-A" for e in events)


@pytest.mark.parametrize("case", ["normal", "label_only"])
def test_normal_or_reported_label_is_not_an_attack_chain(analyst, case):
    inv = analyst.post("/investigations", json={"title": "가상 대조군"}).json()["id"]
    _process(analyst, inv, "synthetic-control.csv", ndr_csv(case))
    _, ex = latest(analyst, inv)
    flow = next(row for row in ex["scenario.flow"]["detail"]["scenarios"] if row["id"] == "web_intrusion")
    assert flow["status"] == "insufficient_evidence" and flow["match_count"] == 0
    ready = ex["csv.readiness"]["detail"]["formats"][0]
    assert ready["fields"]["http_request"] == 40
    assert ready["fields"]["reported_alert"] == (1 if case == "label_only" else 0)


def test_missing_response_does_not_invent_success_or_normality(analyst):
    inv = analyst.post("/investigations", json={"title": "가상 응답 미수집"}).json()["id"]
    _process(analyst, inv, "synthetic-no-response.csv", ndr_csv("missing_response"))
    _, ex = latest(analyst, inv)
    ready = ex["csv.readiness"]["detail"]["formats"][0]
    assert ready["fields"]["http_request"] == 47
    assert ready["fields"]["http_response"] == 0
    events = read_events().search(inv, [Filter(field="parser", value="ko_ndr_csv")], limit=100)["events"]
    assert len(events) == 47 and all(not event.get("status_code") for event in events)
    flows = ex["scenario.flow"]["detail"]["scenarios"]
    success_required = next(row for row in flows if row["id"] == "recon_then_success")
    assert success_required["status"] == "insufficient_evidence"
    assert success_required["match_count"] == 0
