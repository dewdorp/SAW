from __future__ import annotations

from datetime import datetime, timezone

from saw.detectors.base import DetectorContext
from saw.storage.eventstore import SQLiteEventStore


def event(i, source, *, port=443, stamp="2026-10-14T01:00:00Z", suspect=False):
    return {"event_id": f"event-{i}", "investigation_id": "inv", "data_source": "web",
            "timestamp": stamp, "src_ip": source, "dst_ip": "192.0.2.200", "dst_port": port,
            "url_path": f"/private/{i}" if suspect else "/normal", "status_code": 404 if suspect else 200,
            "bytes_out": 100000 if suspect else 200}


def normal():
    return [event(i, f"198.51.{i // 10000}.{i // 20 % 250 + 1}") for i in range(20000)]


def run(tmp_path, rows, **limits):
    from saw.detectors.peer_behavior import PeerBehavior
    store = SQLiteEventStore(str(tmp_path / "peer.db"))
    store.index(rows)
    return PeerBehavior().run(DetectorContext("inv", store, params={"peer_limits": limits}))


def test_minority_anomaly_has_comparable_baseline_and_exact_evidence(tmp_path):
    rows = normal() + [event(20000 + i, "203.0.113.99", suspect=True) for i in range(80)]
    found = run(tmp_path, rows)
    abnormal = [f for f in found if f.category == "anomaly.peer"]
    assert len(abnormal) == 1
    f = abnormal[0]
    assert f.entities == ["ip:203.0.113.99"] and not f.success_signal and not f.attack
    assert f.total_events == 80 and len(f.sample_event_ids) == 20
    assert f.evidence_query["time"]["end"] == "2026-10-14T01:14:59.999999+00:00"
    assert any(m["name"] == "peer_sources" and m["observed"] >= 20 for m in f.metrics)
    assert len([m for m in f.metrics if "baseline" in m]) >= 2


def test_unrelated_bulk_service_and_single_rare_value_do_not_trigger(tmp_path):
    rows = normal() + [event(21000 + i, "203.0.113.99", port=8443, suspect=True) for i in range(80)]
    rows.append(event(22000, "203.0.113.77", suspect=True))
    assert not [f for f in run(tmp_path, rows) if f.category == "anomaly.peer"]


def test_evidence_does_not_include_normal_window_or_another_investigation(tmp_path):
    rows = normal() + [event(20000 + i, "203.0.113.99", suspect=True) for i in range(80)]
    rows += [event(30000 + i, "203.0.113.99", stamp="2026-10-14T02:00:00Z") for i in range(40)]
    rows.append({**event(40000, "203.0.113.1", suspect=True), "investigation_id": "other"})
    f, = [f for f in run(tmp_path, rows) if f.category == "anomaly.peer"]
    assert f.total_events == 80 and all(int(x.split("-")[1]) < 30000 for x in f.sample_event_ids)
    assert f.evidence_query["time"]["start"] == "2026-10-14T01:00:00+00:00"


def test_limits_and_missing_destination_emit_coverage_not_normal_verdict(tmp_path):
    rows = [event(i, "198.51.100.1") for i in range(6)]
    rows[0].pop("dst_ip")
    fs = run(tmp_path, rows, max_events=3)
    coverage, = [f for f in fs if f.category == "anomaly.peer.coverage"]
    assert not coverage.success_signal
    metrics = {m["name"]: m["observed"] for m in coverage.metrics}
    assert metrics["scanned_events"] == 3 and metrics["excluded_events"] == 1
    assert metrics["partial"] == 1


def test_ipv6_evidence_filters_keep_original_indexed_text(tmp_path):
    rows = [event(i, f"2001:db8::{i // 5 + 1}") for i in range(105)]
    rows += [event(1000 + i, "2001:0db8:0000::99", suspect=True) for i in range(20)]
    f, = [f for f in run(tmp_path, rows) if f.category == "anomaly.peer"]
    assert {x["value"] for x in f.evidence_query["filters"] if x["field"] == "src_ip"} == {"2001:0db8:0000::99"}


def test_unknown_measurements_cannot_supply_two_anomaly_signals(tmp_path):
    rows = [event(i, f"198.51.100.{i // 5 + 1}") for i in range(105)]
    for i in range(20):
        row = event(1000 + i, "203.0.113.99", suspect=True)
        row.pop("url_path")
        if i:
            row.pop("status_code")
            row.pop("bytes_out")
        rows.append(row)
    assert not [f for f in run(tmp_path, rows) if f.category == "anomaly.peer"]


def test_event_limit_does_not_infer_from_a_truncated_cohort(tmp_path):
    rows = [event(i, f"198.51.100.{i // 5 + 1}") for i in range(105)]
    rows += [event(1000 + i, "203.0.113.99", suspect=True) for i in range(20)]
    fs = run(tmp_path, rows, max_events=110)
    assert not [f for f in fs if f.category == "anomaly.peer"]
    assert any(f.category == "anomaly.peer.coverage" for f in fs)


def test_leave_one_out_median_and_mad_do_not_include_candidate():
    from saw.detectors.peer_behavior import PeerBaselines
    features = {str(i): {"requests": i, "error_ratio": 0, "unique_paths": 1, "bytes_per_event": 200} for i in range(5, 25)}
    features["outlier"] = {"requests": 100, "error_ratio": 1, "unique_paths": 20, "bytes_per_event": 100000}
    baseline = PeerBaselines(features)
    assert baseline.baseline("requests", 100) == (14.5, 5.0, 20)
    assert baseline.baseline("requests", 5) == (15.5, 5.0, 20)


def test_ipv6_spelling_variants_do_not_inflate_peer_population(tmp_path):
    rows = []
    # Twenty-one spellings still represent exactly one source address.
    for k in range(21):
        spell = f"2001:db8:{1:0{(k % 3) + 1}x}:{2:0{(k // 3 % 3) + 1}x}:{3:0{(k // 9 % 3) + 1}x}:4:5:6"
        rows.extend(event(k * 5 + i, spell) for i in range(5))
    rows.extend(event(1000 + i, "2001:db8::99", suspect=True) for i in range(20))
    assert not [f for f in run(tmp_path, rows) if f.category == "anomaly.peer"]


def test_equivalent_destination_spellings_share_peers_and_preserve_alias_evidence(tmp_path):
    rows = []
    for k in range(21):
        destination = "2001:db8::200" if k % 2 else "2001:0db8:0000::200"
        rows.extend({**event(k * 5 + i, f"198.51.100.{k+1}"), "dst_ip": destination} for i in range(5))
    for i in range(20):
        source = "2001:db8::99" if i % 2 else "2001:0db8::99"
        rows.append({**event(1000 + i, source, suspect=True), "dst_ip": "2001:db8::200"})
    f, = [f for f in run(tmp_path, rows) if f.category == "anomaly.peer"]
    source_filter, = [x for x in f.evidence_query["filters"] if x["field"] == "src_ip"]
    destination_filter, = [x for x in f.evidence_query["filters"] if x["field"] == "dst_ip"]
    assert source_filter["op"] == "in" and set(source_filter["value"]) == {"2001:db8::99", "2001:0db8::99"}
    assert destination_filter["op"] == "in" and set(destination_filter["value"]) == {"2001:db8::200", "2001:0db8:0000::200"}
    assert f.total_events == 20
