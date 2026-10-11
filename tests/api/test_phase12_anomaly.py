from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from tests.api.test_phase5_bulk import upload

KST = timezone(timedelta(hours=9))


def _line(ip, ts, method, uri, status, size, ua):
    return f'{ip} - - [{ts.astimezone(KST).strftime("%d/%b/%Y:%H:%M:%S +0900")}] "{method} {uri} HTTP/1.1" {status} {size} "-" "{ua}"'


def _normal_web(rnd, base, n_sessions=60, ua="Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/129.0 Safari/537.36"):
    lines = []
    for k in range(n_sessions):
        ip = f"121.130.{k // 200}.{k % 200 + 1}"
        t = base + timedelta(minutes=rnd.randint(0, 115))
        for step in ("/login", "/search", f"/detail/{rnd.randint(1, 999)}", "/logout"):
            t += timedelta(seconds=rnd.randint(2, 20))
            lines.append(_line(ip, t, "GET", step, 200, rnd.randint(300, 900), ua))
        for _ in range(rnd.randint(0, 3)):
            t += timedelta(seconds=rnd.randint(5, 30))
            lines.append(_line(ip, t, "GET", "/api/x?id=1", 200, 500, ua))
    return lines


def _ingest(api, inv, lines, name="a.log"):
    up = upload(api, inv, name, ("\n".join(lines) + "\n").encode())
    api.post(f"/evidence/{up['evidence_id']}/process")


def test_volume_sequence_entity_and_rare(analyst):
    rnd = random.Random(5)
    base = datetime(2026, 10, 5, 1, 0, tzinfo=KST)
    # history: a closed-as-normal investigation provides the known UA baseline
    hist = analyst.post("/investigations", json={"title": "baseline week"}).json()
    _ingest(analyst, hist["id"], _normal_web(rnd, base - timedelta(days=7)))
    analyst.post(f"/investigations/{hist['id']}/close", json={"verdict": "normal", "reason": "정상 업무 트래픽"})
    inv = analyst.post("/investigations", json={"title": "anomaly"}).json()
    lines = _normal_web(rnd, base)
    burst = base + timedelta(minutes=70)
    for i in range(400):  # volume spike on /api/x within one 5-min bucket, new UA, single outlier source
        lines.append(_line("43.201.5.5", burst + timedelta(milliseconds=i * 500), "GET", "/api/x?id=1", 404 if i % 3 else 200, 120, "Go-http-client/1.1"))
    t = base + timedelta(minutes=30)
    for step in ("/detail/1", "/export", "/admin/users", "/export", "/admin/delete", "/export"):
        t += timedelta(seconds=3)
        lines.append(_line("121.130.9.9", t, "GET", step, 200, 400, "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/129.0 Safari/537.36"))
    _ingest(analyst, inv["id"], lines)
    fs = analyst.get(f"/investigations/{inv['id']}/findings").json()
    cats = {f["category"] for f in fs}
    assert {"anomaly.volume", "anomaly.sequence", "anomaly.entity", "anomaly.rare"} <= cats, cats
    vol = next(f for f in fs if f["category"] == "anomaly.volume")
    rate = next(m for m in vol["metrics"] if m["name"] == "requests_per_min")
    assert rate["baseline"]["source"].startswith("relative:") and any(m["name"] == "rate_series" for m in vol["metrics"])
    seq = next(f for f in fs if f["category"] == "anomaly.sequence")
    sm = next(m for m in seq["metrics"] if m["name"] == "sequence")
    assert "/export" in sm["observed_path"] and sm["normal_path"][:2] == ["/login", "/search"]
    rare = next(f for f in fs if f["category"] == "anomaly.rare")
    assert "Go-http-client" in " ".join(rare["entities"])
    ent = next(f for f in fs if f["category"] == "anomaly.entity")
    assert "43.201.5.5" in " ".join(ent["entities"])


def test_attack_investigations_never_become_baseline(analyst):
    """T-20: a confirmed-attack investigation must not teach the baseline that its UA is normal."""
    rnd = random.Random(9)
    base = datetime(2026, 10, 5, 1, 0, tzinfo=KST)
    atk = analyst.post("/investigations", json={"title": "attack"}).json()
    _ingest(analyst, atk["id"], _normal_web(rnd, base, 40, ua="EvilBot/9.9"))
    analyst.post(f"/investigations/{atk['id']}/close", json={"verdict": "attack", "reason": "confirmed"})
    norm = analyst.post("/investigations", json={"title": "normal"}).json()
    _ingest(analyst, norm["id"], _normal_web(rnd, base, 40))
    analyst.post(f"/investigations/{norm['id']}/close", json={"verdict": "normal", "reason": "ok"})
    new = analyst.post("/investigations", json={"title": "new"}).json()
    _ingest(analyst, new["id"], _normal_web(rnd, base, 40, ua="EvilBot/9.9"))
    fs = analyst.get(f"/investigations/{new['id']}/findings").json()
    assert any(f["category"] == "anomaly.rare" and "EvilBot" in " ".join(f["entities"]) for f in fs)


def test_sequence_source_positions_survive_adapter_projection_and_changed_ids(analyst):
    from saw import container
    from saw.detectors.anomaly import SequenceAnomaly
    from saw.detectors.base import DetectorContext

    expected = ["/z-start", "/export", "/admin/users", "/export", "/admin/delete", "/export"]
    content = []
    for session in range(3):
        for step, path in enumerate(("/login", "/search", "/detail", "/logout")):
            content.append({"session_id": f"normal-{session}", "timestamp": f"2026-10-11T00:00:0{step}Z",
                            "url_path": path})
    for step, path in enumerate(expected):
        content.append({"session_id": "suspect", "timestamp": "2026-10-11T00:00:10Z",
                        "url_path": path, "raw_ref": {"offset": step * 100, "line_no": step + 1}})
    results = []
    for run in range(2):
        inv = analyst.post("/investigations", json={"title": f"Synthetic stable sequence {run}"}).json()
        events = []
        for index, row in enumerate(content):
            event = {**row, "data_source": "web", "investigation_id": inv["id"],
                     "event_id": f"sequence-{run}-{index if run == 0 else len(content) - index:04d}"}
            if "raw_ref" in event:
                event["raw_ref"] = {**event["raw_ref"], "object_key": f"synthetic/source-{run}.log"}
            events.append(event)
        store = container.get().events
        assert store.index(events) == len(events)
        finding, = SequenceAnomaly().run(DetectorContext(inv["id"], store, params={"min_sessions": 3}))
        assert finding.category == "anomaly.sequence"
        assert next(m["observed_path"] for m in finding.metrics if m["name"] == "sequence") == expected
        results.append((finding.dedup_key, finding.metrics, finding.checks))
    assert results[0] == results[1]
