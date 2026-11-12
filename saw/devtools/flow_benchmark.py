"""Measure the flow analysis on synthetic records (no real data).

python -m saw.devtools.flow_benchmark --sessions 20000 --days 30 --mode store --out result.json
python -m saw.devtools.flow_benchmark --sessions 200000 --days 90 --mode engine --out result.json

store : upload through the real API into a throw-away SQLite installation, then read the run the product made
        (ingest + detectors + flow analysis; the flow analysis time is reported on its own).
engine: parse with the real parsers and run the real engine in memory, without the event store
        (what the analysis itself costs at a size where a full ingest would take hours on this PC).
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import tempfile
import time
from ctypes import wintypes
from pathlib import Path

from saw.devtools import flow_samples


def peak_mb() -> float | None:
    if os.name != "nt":
        return None

    class Counters(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD), ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t), ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t), ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t), ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t)]

    c = Counters()
    c.cb = ctypes.sizeof(c)
    ctypes.windll.kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    ctypes.windll.psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
    ctypes.windll.psapi.GetProcessMemoryInfo(ctypes.windll.kernel32.GetCurrentProcess(), ctypes.byref(c), c.cb)
    return round(c.PeakWorkingSetSize / 1024 / 1024, 1)


def _expected(sample: dict, sessions: int) -> dict:
    return {"flows": sessions + 7, "ndr_rows": sample["rows"]["ndr"]}


def engine_mode(sessions: int, days: int) -> dict:
    from saw.flows.engine import Compiled, analyze
    from saw.parsers.registry import parse_text

    t0 = time.monotonic()
    sample = flow_samples.build(seed=91, background_sessions=sessions, days=days)
    t_gen = time.monotonic() - t0
    items = [{"id": f"k{i}", "version": 1, "org_unit_id": None, "title": "", **b} for i, b in enumerate(flow_samples.knowledge())]
    t0 = time.monotonic()
    events = {n: parse_text(sample[n], max_lines=100_000_000)["events"] for n in ("ndr.csv", "app.csv", "waf.csv", "ips.csv", "ddos.csv")}
    t_parse = time.monotonic() - t0
    t0 = time.monotonic()
    web = sorted(events["ndr.csv"], key=lambda e: (e["timestamp"], e["event_id"]))
    t_sort = time.monotonic() - t0
    t0 = time.monotonic()
    result = analyze(web, app_events=events["app.csv"], alerts=events["waf.csv"] + events["ips.csv"], ddos=events["ddos.csv"],
                     compiled=Compiled(items))
    t_run = time.monotonic() - t0
    return {"mode": "engine", "sessions": sessions, "days": days, "rows": sample["rows"], "expected": _expected(sample, sessions),
            "seconds": {"generate": round(t_gen, 1), "parse": round(t_parse, 1), "sort": round(t_sort, 1), "analyze": round(t_run, 1)},
            "status": result["status"], "counts": result["counts"], "flows_total": result["completeness"]["flows_total"],
            "attention": sum(1 for f in result["flows"] if f["attention"] > 0), "peak_working_set_mb": peak_mb(),
            "note": "파서와 엔진만 측정했습니다(저장소·업로드 제외). 메모리에는 파싱한 전체 이벤트가 포함되어 제품 실행보다 큽니다."}


def store_mode(sessions: int, days: int, readers: int) -> dict:
    import threading

    import pyotp
    from fastapi.testclient import TestClient

    from saw.config import Settings

    work = Path(tempfile.mkdtemp(prefix="saw-flow-bench-"))
    settings = Settings(data_dir=work, database_url=f"sqlite:///{work / 'saw.db'}", event_store_path=str(work / "events.db"),
                        object_store_root=str(work / "objects"))
    from saw.apps.api.main import create_app
    from saw.core.application import identity
    from saw.storage.db import session_scope
    from saw.storage.models import User

    app = create_app(settings, synchronous_jobs=True)
    password = "Bench!" + os.urandom(9).hex()
    with session_scope() as s:
        identity.create_user(s, "bench", password, ["senior_analyst"])

    def login() -> tuple[TestClient, dict]:
        c = TestClient(app)
        r = c.post("/api/v1/auth/login", json={"username": "bench", "password": password})
        headers = {"x-csrf-token": r.json()["csrf_token"]}
        with session_scope() as s:
            u = s.query(User).filter_by(username="bench").one()
            secret, u.mfa_last_step = u.mfa_secret, None
        assert c.post("/api/v1/auth/mfa/verify", json={"code": pyotp.TOTP(secret).now()}, headers=headers).status_code == 200
        return c, headers

    c, h = login()
    for body in flow_samples.knowledge():
        assert c.post("/api/v1/knowledge/flow-items", json=body, headers=h).status_code == 201
    org = c.post("/api/v1/source-context/org-units", json={"display_name": "Bench"}, headers=h).json()
    inv = c.post("/api/v1/investigations", json={"title": "bench", "org_unit_id": org["id"]}, headers=h).json()
    sample = flow_samples.build(seed=91, background_sessions=sessions, days=days)
    timings = {}
    from tests.api.test_ingest import upload  # the same chunked upload the product tests use

    class Api:
        def post(self, url, **kw):
            kw.setdefault("headers", {}).update(h)
            return c.post("/api/v1" + url, **kw)

        def put(self, url, **kw):
            kw.setdefault("headers", {}).update(h)
            return c.put("/api/v1" + url, **kw)

        def get(self, url, **kw):
            return c.get("/api/v1" + url, **kw)

    api = Api()
    for name in ("app.csv", "waf.csv", "ips.csv", "ddos.csv", "fw.csv", "ndr.csv"):
        t0 = time.monotonic()
        up = upload(api, inv["id"], name, sample[name].encode(), kind="auto")
        job = api.post(f"/evidence/{up['evidence_id']}/process").json()
        state = api.get(f"/jobs/{job['id']}").json()
        timings[name] = {"seconds": round(time.monotonic() - t0, 1), "state": state["state"]}
    latest = api.get(f"/investigations/{inv['id']}/flows").json()["run"]
    # Screen responsiveness while another analyst re-runs the analysis.
    lat, stop = [], threading.Event()

    def reader():
        rc, _ = login()
        while not stop.is_set():
            t0 = time.monotonic()
            rc.get(f"/api/v1/investigations/{inv['id']}/flows")
            lat.append(time.monotonic() - t0)

    threads = [threading.Thread(target=reader) for _ in range(readers)]
    for t in threads:
        t.start()
    t0 = time.monotonic()
    again = api.post(f"/investigations/{inv['id']}/flows/run", json={"force": True}).json()
    rerun = time.monotonic() - t0
    stop.set()
    for t in threads:
        t.join()
    lat.sort()
    res = latest["result"]
    return {"mode": "store", "sessions": sessions, "days": days, "rows": sample["rows"], "expected": _expected(sample, sessions),
            "ingest": timings, "flow_run_ms_after_last_upload": latest["elapsed_ms"], "forced_rerun_seconds": round(rerun, 1),
            "forced_rerun_ms": again["elapsed_ms"], "status": latest["status"], "counts": res["counts"],
            "flows_total": res["completeness"]["flows_total"], "attention": sum(1 for f in res["flows"] if f["attention"] > 0),
            "readers": readers, "reads_during_rerun": len(lat),
            "read_latency_seconds": {"median": round(lat[len(lat) // 2], 3), "max": round(lat[-1], 3)} if lat else None,
            "peak_working_set_mb": peak_mb(), "store": "SQLite event store + SQLite database (development profile)",
            "work_dir": str(work)}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sessions", type=int, default=2000)
    p.add_argument("--days", type=int, default=30)
    p.add_argument("--mode", choices=("store", "engine"), default="engine")
    p.add_argument("--readers", type=int, default=3)
    p.add_argument("--out", type=Path)
    a = p.parse_args()
    out = engine_mode(a.sessions, a.days) if a.mode == "engine" else store_mode(a.sessions, a.days, a.readers)
    text = json.dumps(out, ensure_ascii=False, indent=1)
    if a.out:
        a.out.write_text(text + "\n", encoding="utf-8")
    print(text)
