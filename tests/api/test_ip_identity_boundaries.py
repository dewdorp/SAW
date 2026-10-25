"""Real upload pipeline retains opaque values without promoting them to IP identities."""
import pytest

from saw.core.schemas.query import Filter
from tests.api.test_generation_reprocessing import read_events
from tests.api.test_security_csv_scenarios import latest
from tests.api.test_text_uploads import _process
from tests.unit.test_security_csv import FW, NDR, document, row


@pytest.mark.parametrize("field,column", [("src_ip", "출발지IP"), ("dst_ip", "목적지IP")])
@pytest.mark.parametrize("value,valid", [
    ("SYNTHETIC-OPAQUE-DEST", False), ("192.0.2.40", True), ("2001:db8::40", True)])
def test_csv_pipeline_correlates_only_valid_ip_without_changing_source(analyst, field, column, value, valid):
    inv = analyst.post("/investigations", json={"title": "가상 주소 상관 경계"}).json()["id"]
    source = row(**{column: value})
    _process(analyst, inv, "synthetic-fw.csv", document(FW, source).encode("utf-8"))
    previous, _ = latest(analyst, inv)
    previous_story = analyst.get(f"/investigations/{inv}/story").json()["story"]
    _process(analyst, inv, "synthetic-ndr.csv", document(NDR, source).encode("utf-8"))
    result = analyst.get(f"/investigations/{inv}/correlations").json()
    related = [item for item in result if item["kind"] == "same_ip_cross_source"
               and "ip:" + value in item["entity_keys"]]
    assert bool(related) is valid
    if valid:
        assert related[0]["strength"] == "strong"
        assert {role for step in related[0]["steps"] for role in step["role"]} == {field}
    events = read_events().search(inv, [Filter(field=field, value=value)], limit=10)["events"]
    assert len(events) == 2
    assert all(event[field] == value and event["ext"]["security_csv"][column] == value
               and event["raw_ref"]["length"] > 0 for event in events)
    retained = analyst.get(f"/investigations/{inv}/analysis-runs/{previous['id']}").json()
    assert retained["executions"] == previous["executions"]
    historical = analyst.get(f"/investigations/{inv}/story?version={previous_story['version']}").json()["story"]
    assert historical == previous_story
