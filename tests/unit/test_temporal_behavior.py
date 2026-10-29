from datetime import datetime, timedelta, timezone
from uuid import uuid4

from saw.detectors.base import DetectorContext
from saw.storage.eventstore import SQLiteEventStore


def rows(*, burst=7, count_only=False, windows=9):
    out = []
    start = datetime(2026, 10, 14, tzinfo=timezone.utc)
    for window in range(windows):
        suspect = window == burst
        for i in range(40 if suspect else 10):
            out.append({"event_id": f"e-{window}-{i}", "investigation_id": "inv", "data_source": "web",
                "timestamp": (start + timedelta(minutes=15 * window, seconds=i)).isoformat(),
                "src_ip": "198.51.100.1", "dst_ip": "192.0.2.1", "dst_port": 443,
                "status_code": 404 if suspect and not count_only else 200,
                "bytes_out": 100000 if suspect and not count_only else 200})
    return out


def run(tmp_path, events, **limits):
    from saw.detectors.temporal_behavior import TemporalBehavior
    store = SQLiteEventStore(str(tmp_path / (str(uuid4()) + ".db")))
    store.index(events)
    return TemporalBehavior().run(DetectorContext("inv", store, params={"temporal_limits": limits}))


def candidates(found):
    return [f for f in found if f.category == "anomaly.temporal"]


def test_two_changes_use_six_strictly_earlier_windows_and_exact_evidence(tmp_path):
    f, = candidates(run(tmp_path, rows()))
    assert not f.success_signal and not f.attack
    assert f.total_events == 40 and len(f.sample_event_ids) == 20
    assert f.time_start == "2026-10-14T01:45:00+00:00"
    assert f.time_end == "2026-10-14T01:59:59.999999+00:00"
    baselines = [m["baseline"] for m in f.metrics if "baseline" in m]
    assert len(baselines) == 3 and all(b["windows"] == 6 for b in baselines)
    assert all(b["median"] in (10, 0, 200) for b in baselines)
    assert all(e.startswith("e-7-") for e in f.sample_event_ids)


def test_count_only_and_boundary_bursts_do_not_trigger(tmp_path):
    assert not candidates(run(tmp_path, rows(count_only=True)))
    assert not candidates(run(tmp_path, rows(burst=8)))


def test_future_values_cannot_change_candidate_baseline(tmp_path):
    original = rows(windows=11)
    changed = [{**e, "bytes_out": 99999999, "status_code": 500} if e["event_id"].startswith(("e-8-", "e-9-", "e-10-")) else e for e in original]
    a = next(f for f in candidates(run(tmp_path, original)) if f.time_start.endswith("01:45:00+00:00"))
    b = next(f for f in candidates(run(tmp_path, changed)) if f.time_start == a.time_start)
    assert a.metrics == b.metrics


def test_gaps_missing_metrics_and_unstable_counts_do_not_infer_normal(tmp_path):
    datasets = [
        [e for e in rows() if not e["event_id"].startswith("e-3-")],
        [{k: v for k, v in e.items() if k not in ("status_code", "bytes_out")} for e in rows()],
        [e for e in rows() if not (e["event_id"].startswith("e-2-") and int(e["event_id"].split("-")[-1]) >= 4)],
    ]
    for data in datasets:
        found = run(tmp_path, data)
        assert not candidates(found)
        assert any(f.category == "anomaly.temporal.coverage" for f in found)


def test_caps_fail_closed(tmp_path):
    for limits in ({"max_events": 70}, {"max_groups": 5}, {"max_series": 1}):
        data = rows()
        if "max_series" in limits:
            data += [{**e, "event_id": "other-" + e["event_id"], "dst_ip": "192.0.2.2"} for e in rows()]
        found = run(tmp_path, data, **limits)
        assert not candidates(found)
        coverage, = [f for f in found if f.category.endswith(".coverage")]
        assert next(m["observed"] for m in coverage.metrics if m["name"] == "partial") == 1


def test_services_investigations_and_order_remain_scoped(tmp_path):
    data = rows()
    extra = [{**e, "event_id": "other-" + e["event_id"], "investigation_id": "other"} for e in rows()]
    extra += [{**e, "event_id": "port-" + e["event_id"], "dst_port": 8443, "bytes_out": 200, "status_code": 200} for e in rows()]
    f, = candidates(run(tmp_path, list(reversed(data + extra))))
    assert f.total_events == 40
    assert any(x["field"] == "dst_port" and x["value"] == 443 for x in f.evidence_query["filters"])


def test_ipv6_aliases_preserved_and_missing_identity_reported(tmp_path):
    data = [{**e, "src_ip": "2001:db8::1" if i % 2 else "2001:0db8::1"} for i, e in enumerate(rows())]
    data.append({**rows()[0], "event_id": "invalid", "timestamp": "no-time"})
    f, = candidates(run(tmp_path, data))
    condition, = [x for x in f.evidence_query["filters"] if x["field"] == "src_ip"]
    assert set(condition["value"]) == {"2001:db8::1", "2001:0db8::1"}
    assert any(x.category.endswith(".coverage") for x in run(tmp_path, data))


def test_at_least_nine_observed_windows_needed(tmp_path):
    assert not candidates(run(tmp_path, rows(burst=6, windows=8)))
    assert candidates(run(tmp_path, rows(windows=9)))


def test_each_window_metric_requires_eighty_percent_valid_samples(tmp_path):
    data = rows()
    for e in data:
        if e["event_id"].startswith("e-3-") and int(e["event_id"].split("-")[-1]) < 3:
            e["bytes_out"] = None
        if e["event_id"].startswith("e-7-"):
            e["status_code"] = True
    found = run(tmp_path, data)
    assert not candidates(found)
    assert any(m["name"] == "missing_metric_windows" and m["observed"] > 0
               for f in found for m in f.metrics)


def test_unstable_but_adequate_baseline_is_excluded(tmp_path):
    data = rows()
    data += [{**data[20], "event_id": f"extra-{i}"} for i in range(20)]
    found = run(tmp_path, data)
    assert not candidates(found)
    assert any(m["name"] == "unstable_baseline_windows" and m["observed"] > 0
               for f in found for m in f.metrics)


def test_missing_timezones_and_alias_limit_report_scope(tmp_path):
    data = [{**e, "timestamp": e["timestamp"].replace("+00:00", "")} for e in rows()]
    assert not candidates(run(tmp_path, data))
    data = [{**e, "src_ip": "2001:db8::1" if i % 2 else "2001:0db8::1"} for i, e in enumerate(rows())]
    assert not candidates(run(tmp_path, data, max_aliases=1))


def test_finding_limit_reports_omitted_candidates(tmp_path):
    data = rows()
    data += [{**e, "event_id": "second-" + e["event_id"], "src_ip": "198.51.100.2"} for e in rows()]
    found = run(tmp_path, data, max_findings=1)
    assert len(candidates(found)) == 1
    assert any(m["name"] == "omitted_findings" and m["observed"] == 1 for f in found for m in f.metrics)


def test_timezone_offsets_and_original_aliases_have_exact_store_query(tmp_path):
    from saw.core.schemas.query import Filter, TimeRange
    from saw.detectors.temporal_behavior import TemporalBehavior
    data = rows()
    for i, e in enumerate(data):
        dt = datetime.fromisoformat(e["timestamp"])
        e["timestamp"] = dt.astimezone(timezone(timedelta(hours=9 if i % 2 else -5))).isoformat()
        e["dst_ip"] = "2001:db8::2" if i % 2 else "2001:0db8::2"
    store = SQLiteEventStore(str(tmp_path / "offset.db"))
    store.index(data)
    f, = candidates(TemporalBehavior().run(DetectorContext("inv", store)))
    filters = [Filter(**x) for x in f.evidence_query["filters"]]
    time = TimeRange(**f.evidence_query["time"])
    assert store.count("inv", filters, time=time) == 40
    assert {e["event_id"] for e in store.iterate("inv", filters, time=time)} == {f"e-7-{i}" for i in range(40)}


def test_two_measurements_can_change_without_volume_spike(tmp_path):
    data = [e for e in rows() if not (e['event_id'].startswith('e-7-') and int(e['event_id'].split('-')[-1]) >= 10)]
    for e in data:
        if int(e['event_id'].split('-')[-1]) < 2:
            e['status_code'] = None
            e['bytes_out'] = None
    f, = candidates(run(tmp_path, data))
    assert {m['name'] for m in f.metrics if 'baseline' in m} == {'error_ratio', 'bytes_per_event'}
    assert f.total_events == 10

def test_long_ranges_are_evaluated_with_bounded_memory(tmp_path):
    # 200 windows (about two days) with a held-window budget of 50: earlier this exhausted the budget and
    # suppressed every candidate; windows are now evaluated as soon as a later window appears.
    found = run(tmp_path, rows(burst=150, windows=200), max_groups=50)
    f, = candidates(found)
    assert f.time_start == (datetime(2026, 10, 14, tzinfo=timezone.utc) + timedelta(minutes=15 * 150)).isoformat()
    assert all(m["baseline"]["windows"] == 6 for m in f.metrics if "baseline" in m)


def test_input_limit_keeps_completed_windows_and_names_the_analysed_range(tmp_path):
    found = run(tmp_path, rows(burst=7, windows=12), max_events=9 * 10 + 40 + 5)
    f, = candidates(found)
    assert f.total_events == 40
    coverage, = [x for x in found if x.category.endswith(".coverage")]
    assert next(m["observed"] for m in coverage.metrics if m["name"] == "partial") == 1
    assert "분석한 기록 범위" in coverage.checks[0]["detail"] and "90분" in coverage.explanation
