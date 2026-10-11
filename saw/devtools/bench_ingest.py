"""Measure ingest + analysis speed for one file on this PC, isolated from real data.

    python -m saw.devtools.bench_ingest <file> [--store opensearch|sqlite]

Metadata goes to a throw-away SQLite DB in a temp folder; with --store opensearch the configured OpenSearch is used
under a separate index prefix (sawbench-*) that is deleted afterwards. Real investigations are never touched.
"""
from __future__ import annotations

import argparse
import shutil
import tempfile
import time
from pathlib import Path

from saw import container
from saw.config import Settings, get_settings


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("file", type=Path)
    ap.add_argument("--store", choices=["opensearch", "sqlite"], default=None,
                    help="default: the configured event store")
    a = ap.parse_args(argv)
    base = get_settings()
    store = a.store or base.event_store
    tmp = Path(tempfile.mkdtemp(prefix="saw-bench-", dir=str(base.data_dir) if base.data_dir.exists() else None))
    kw = {"data_dir": tmp, "database_url": f"sqlite:///{(tmp / 'bench.db').as_posix()}", "schema_mode": "create_all",
          "event_store_path": str(tmp / "events.db"), "object_store": "local", "object_store_root": str(tmp / "objects")}
    if store == "opensearch":
        kw.update(event_store="opensearch", opensearch_index_prefix="sawbench")
    else:
        kw.update(event_store="sqlite")
    c = container.build(Settings(**{**base.model_dump(), **kw}), synchronous_jobs=True)
    try:
        if store == "opensearch":
            c.events.client.indices.delete(index="sawbench-*", ignore=[404])
            c.events.ensure_template()
        import saw.workers.pipeline as pl
        from saw.storage.db import session_scope
        from saw.storage.models import Evidence, EvidenceFile, Investigation, Job, User

        with session_scope() as s:
            u = User(username="bench", password_hash="!")
            s.add(u)
            s.flush()
            inv = Investigation(title="bench", display_id="INV-BENCH", owner_id=u.id)
            s.add(inv)
            s.flush()
            ev = Evidence(investigation_id=inv.id, kind="auto", title="bench", tz_assumed="Asia/Seoul", uploaded_by=u.id)
            s.add(ev)
            s.flush()
            key = f"{inv.id}/{ev.id}/bench"
            with open(a.file, "rb") as fh:
                size, _ = c.objects.put_stream(pl.ORIGINAL, key, fh)
            s.add(EvidenceFile(evidence_id=ev.id, display_name=a.file.name, object_key=key, size=size))
            job = Job(investigation_id=inv.id, evidence_id=ev.id, kind="ingest", state="QUEUED", requested_by=u.id)
            s.add(job)
            s.flush()
            jid = job.id
        marks: dict[str, float] = {}
        orig = pl.analyze_job

        def timed(*args, **kwargs):
            marks["parsed"] = time.time()
            return orig(*args, **kwargs)

        pl.analyze_job = timed
        t0 = time.time()
        pl.ingest_run(jid)
        t1 = time.time()
        pl.analyze_job = orig
        with session_scope() as s:
            j = s.get(Job, jid)
            files = s.query(EvidenceFile).filter_by(evidence_id=j.evidence_id).all()
            parser = next((f.parser_id for f in files if f.parser_id), "-")
            parsed = marks.get("parsed", t1)
            print(f"file      {a.file.name} ({size / 2**20:.1f} MB), parser {parser}, store {store}")
            print(f"state     {j.state} {j.error or ''}")
            print(f"events    {j.events_done:,}")
            print(f"parse+idx {parsed - t0:.1f}s ({j.events_done / max(0.001, parsed - t0):,.0f} events/s)")
            print(f"analysis  {t1 - parsed:.1f}s")
            print(f"total     {t1 - t0:.1f}s")
            if size >= 50 * 2**20:  # fixed costs dominate small files
                print(f"estimate  about {(t1 - t0) / size * 2**30 / 60:.0f} min per GB of this kind of log on this PC")
    finally:
        if store == "opensearch":
            c.events.client.indices.delete(index="sawbench-*", ignore=[404])
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
