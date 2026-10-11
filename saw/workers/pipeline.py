"""Ingest/analyze job DAG (docs/10 §3). Idempotent: deterministic event ids, re-runs upsert."""
from __future__ import annotations

import contextvars
import logging
import shutil
import tempfile
import time
import traceback
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select

from saw import container
from saw.core.application import analysis, provenance
from saw.parsers.base import Parsed, Skip
from saw.parsers.registry import detect, get_parser, iter_lines, sniff_encoding, to_ces
from saw.storage.db import session_scope, utcnow
from saw.storage.models import Evidence, EvidenceFile, Job
from saw.workers.runner import task
from saw.workers.safe_extract import ExtractionError, Limits, extract, sniff

log = logging.getLogger("saw.pipeline")
ORIGINAL, EXTRACTED = "saw-evidence-original", "saw-evidence-extracted"
BATCH = 5000
DETECT_MIN = 0.5
DETECT_AUTO = 0.8
TEXT_KINDS = {"text"}
# structured sources: fields carry the meaning, the raw line is read from the evidence file on demand
SLIM_SOURCES = frozenset({"web", "waf", "zeek_conn", "zeek_dns", "zeek_ssl", "zeek_http", "zeek_files", "suricata",
                          "pcap_auth", "pcap_arp", "ndr_http"})


class Cancelled(Exception):
    pass


class StaleLease(Exception):
    """Another worker claimed this job (restart recovery or duplicate submit); this one must stop writing."""


_lease: contextvars.ContextVar[tuple[str, int] | None] = contextvars.ContextVar("saw_job_lease", default=None)


def claim(job_id: str) -> int:
    """Take the job lease for this worker: bump the epoch and remember it for every later _job_update."""
    with session_scope() as s:
        j = s.get(Job, job_id)
        j.attempt = (j.attempt or 0) + 1
        epoch = j.attempt
    _lease.set((job_id, epoch))
    return epoch


def _job_update(job_id: str, **kw) -> None:
    with session_scope() as s:
        j = s.get(Job, job_id)
        lease = _lease.get()
        if lease and lease[0] == job_id and (j.attempt or 0) != lease[1]:
            raise StaleLease(f"job {job_id}: lease {lease[1]} superseded by {j.attempt}")
        stages = dict(j.stages or {})
        for k in list(kw):
            if k.startswith("stage_"):
                name = k[6:]
                stages[name] = {**stages.get(name, {}), **kw.pop(k)}
        j.stages = stages
        for k, v in kw.items():
            setattr(j, k, v)


def _cancelled(job_id: str) -> bool:
    with session_scope() as s:
        return bool(s.get(Job, job_id).cancel_requested)


def _file_encoding(path: Path) -> str:
    with open(path, "rb") as f:
        return sniff_encoding(f.read(256 * 1024))


def _checkpoint(job_id: str) -> dict:
    with session_scope() as s:
        return dict(((s.get(Job, job_id).stages or {}).get("parse") or {}).get("ckpt") or {})


def _sample_lines(path: Path, n: int = 200) -> list[str]:
    out = []
    enc = _file_encoding(path)
    with open(path, "rb") as f:
        for raw in f:
            out.append(raw.decode(enc, errors="replace").rstrip("\r\n").lstrip("﻿"))
            if len(out) >= n:
                break
    return out


@task("ingest.run")
def ingest_run(job_id: str) -> None:
    c = container.get()
    claim(job_id)
    try:
        with session_scope() as s:
            j = s.get(Job, job_id)
            ev = s.get(Evidence, j.evidence_id)
            inv_id, ev_id, tz, ev_kind = ev.investigation_id, ev.id, ev.tz_assumed, ev.kind
            files = [(f.id, f.object_key, f.display_name) for f in s.execute(
                select(EvidenceFile).where(EvidenceFile.evidence_id == ev_id, EvidenceFile.parent_file_id.is_(None))
            ).scalars()]
            j.started_at = j.started_at or utcnow()
            j.state = "PARSING"
        _job_update(job_id, stage_extract={"pct": 0})
        # 1) safe decompress + type/parser detection
        cfg = c.settings
        limits = Limits(cfg.decompress_max_ratio, cfg.decompress_max_total_bytes, cfg.decompress_max_entries,
                        cfg.decompress_max_depth)
        leaves: list[str] = []
        for i, (fid, key, disp) in enumerate(files):
            src = c.objects.local_path(ORIGINAL, key)
            with session_scope() as s:
                f = s.get(EvidenceFile, fid)
                existing = s.execute(select(EvidenceFile).where(EvidenceFile.parent_file_id == fid)).scalars().all()
                f.type_detected = sniff(src)
                if existing:  # idempotent re-run: reuse extracted children
                    leaves += [x.id for x in existing]
                    continue
            work = Path(tempfile.mkdtemp(prefix="saw-x-", dir=str(cfg.data_dir)))
            try:
                kind = sniff(src)
                if kind in ("gzip", "zip", "bzip2", "xz", "tar"):
                    for leaf in extract(src, disp, work, limits):
                        with session_scope() as s:
                            child = EvidenceFile(evidence_id=ev_id, parent_file_id=fid, display_name=leaf.display_name,
                                                 object_key="", size=leaf.size)
                            s.add(child)
                            s.flush()
                            ckey = f"{inv_id}/{child.id}"
                            with open(leaf.path, "rb") as fh:
                                n, sha = c.objects.put_stream(EXTRACTED, ckey, fh)
                            child.object_key, child.sha256, child.size = ckey, sha, n
                            child.type_detected = sniff(leaf.path)
                            leaves.append(child.id)
                else:
                    leaves.append(fid)
            except ExtractionError as e:
                with session_scope() as s:
                    f = s.get(EvidenceFile, fid)
                    f.parse_status, f.message = "failed", str(e)
            finally:
                shutil.rmtree(work, ignore_errors=True)
            _job_update(job_id, stage_extract={"pct": round(100 * (i + 1) / len(files))})
        _job_update(job_id, stage_extract={"pct": 100, "done": True})
        # 2) parser detection
        waiting = False
        total_est = 0
        for lid in leaves:
            with session_scope() as s:
                f = s.get(EvidenceFile, lid)
                bucket = ORIGINAL if f.parent_file_id is None else EXTRACTED
                path = c.objects.local_path(bucket, f.object_key)
                if f.type_detected in ("pcap", "pcapng"):
                    f.parser_id, f.parse_status = "pcap", "pending"
                    continue
                if ev_kind == "ioc_list" and f.type_detected in TEXT_KINDS:
                    n = _register_iocs(s, inv_id, ev_id, path)
                    f.parser_id, f.parse_status, f.message = "ioc_list", "done", f"IOC {n}건 등록 (탐지 시 대조)"
                    continue
                if f.type_detected not in TEXT_KINDS:
                    f.parse_status, f.message = "skipped", f"unsupported content type: {f.type_detected}"
                    continue
                if f.parser_id is None:
                    sample = _sample_lines(path)
                    det = detect(sample)
                    f.parser_confidence = det.confidence
                    f.error_samples = [{"candidates": det.candidates}]
                    if det.confidence >= DETECT_AUTO:
                        f.parser_id = det.parser_id
                    elif det.confidence >= DETECT_MIN:
                        f.parser_id, f.parse_status = None, "waiting_input"
                        waiting = True
                    else:
                        f.parse_status, f.message = "waiting_input", "no parser matched (custom parser required)"
                        waiting = True
                    avg = max(80, sum(len(x) for x in sample) / max(1, len(sample)))
                    total_est += int(f.size / avg)
                else:
                    total_est += int(f.size / 200)
        _job_update(job_id, events_total_est=total_est)
        if waiting:
            _job_update(job_id, state="WAITING_INPUT", current_item="parser confirmation required")
            return
        parse_files(job_id, leaves, inv_id, ev_id, tz)
    except Cancelled:
        _job_update(job_id, state="CANCELLED", finished_at=utcnow())
    except Exception as e:  # noqa: BLE001
        log.error("ingest failed: %s", traceback.format_exc())
        _job_update(job_id, state="FAILED", error={"message": str(e)[:500]}, finished_at=utcnow())


def _register_iocs(s, inv_id: str, ev_id: str, path: Path, max_bytes: int = 5 * 1024 * 1024) -> int:
    """IOC list evidence → investigation entities flagged as IOCs (matched by the pcap/IOC detectors)."""
    from saw.analyzers.ioc.observables import extract as extract_iocs
    from saw.analyzers.ioc.observables import refang
    from saw.storage.models import Entity

    with open(path, "rb") as fh:
        text = refang(fh.read(max_bytes).decode("utf-8", errors="replace"))
    types = {"ipv4": "ip", "ipv6": "ip", "domain": "domain", "url": "url", "md5": "hash", "sha1": "hash",
             "sha256": "hash", "email": "email", "cidr": "cidr"}
    n = 0
    for o in extract_iocs(text):
        et = types.get(o.type)
        if not et:
            continue
        value = o.value.lower() if et in ("domain", "hash", "email") else o.value
        row = s.execute(select(Entity).where(Entity.investigation_id == inv_id, Entity.type == et,
                                             Entity.value == value)).scalar_one_or_none()
        if row is None:
            row = Entity(investigation_id=inv_id, type=et, value=value, attrs={})
            s.add(row)
        row.attrs = {**(row.attrs or {}), "ioc": True, "source": "ioc_list", "evidence_id": ev_id}
        n += 1
    return n


class CheckpointMismatch(Exception):
    """The file or parser changed since the checkpoint: skipping by count would drop or duplicate events."""


@dataclass(frozen=True)
class FileJob:
    job_id: str
    file_id: str
    bucket: str
    key: str
    name: str
    inv_id: str
    ev_id: str
    tz: str
    idx: int
    nfiles: int
    t0: float


def _parser_tag(parser) -> str:
    return f"{parser.id}@{parser.version}"


def _parse_file(c, job: FileJob, parser, path: Path, done_events: int, resume: dict) -> dict:
    """Parse one text file into the event store. Coverage counts every physical line of the file.

    Restart recovery: events are emitted in a deterministic order, so the ones indexed before an interruption are
    re-parsed (cheap) but not re-indexed (expensive on small PCs). The checkpoint pins the parser version and the
    id of the last indexed event; any difference means the order cannot be trusted (CheckpointMismatch).
    """
    from saw.core.security.masking import mask_text

    parser.reset()
    batch: list[dict] = []
    samples: list[dict] = []
    cov = {"lines": 0, "blank_lines": 0, "skipped_lines": 0, "failed_lines": 0, "continuation_lines": 0, "events": 0,
           "rejected_events": int(resume.get("rejected", 0))}
    first_ts = last_ts = None
    enc = _file_encoding(path)
    size = max(1, path.stat().st_size)
    skip, expect = resume.get("emitted", 0), resume.get("last_event_id")
    emitted = 0
    slim = c.settings.raw_store == "auto"

    def lines():
        with open(path, "rb") as fh:
            for rl in iter_lines(iter(lambda: fh.read(1024 * 1024), b""), enc):
                cov["lines"] += 1
                if rl.text.strip():
                    yield rl
                else:
                    cov["blank_lines"] += 1

    def store(events: list[dict]) -> int:
        """Only what the event store confirms counts as done; refused events are reported, never silently dropped."""
        stored = c.events.index(events)
        if stored < len(events):
            cov["rejected_events"] += len(events) - stored
            by_id = {e["event_id"]: e for e in events}
            for err in getattr(c.events, "last_errors", []):
                if len(samples) >= 50:
                    break
                ev = by_id.get(err.get("event_id")) or {}
                samples.append({"line_no": (ev.get("raw_ref") or {}).get("line_no"),
                                "reason": f"검색엔진이 저장을 거부함: {err.get('reason')}", "raw": ""})
        return stored

    rl = None
    for rl, r in parser.parse(lines()):  # parser-driven so stateful parsers can pair records (NDR req/resp)
        if isinstance(r, Skip):
            cov["skipped_lines"] += 1  # headers, records folded into another event (NDR responses)
            continue
        cov["continuation_lines"] += rl.text.count("\n")  # multi-line CSV record: extra physical lines
        if isinstance(r, Parsed):
            # structured events keep fields + raw_ref; the line is read back from the evidence file on demand
            ev = to_ces(parser, rl, r, investigation_id=job.inv_id, evidence_id=job.ev_id, file_id=job.file_id,
                        source_file=job.name, object_key=f"{job.bucket}/{job.key}", assumed_tz=job.tz,
                        slim_sources=SLIM_SOURCES if slim else frozenset())
            ts = ev.get("timestamp")
            if ts:
                first_ts = ts if first_ts is None or ts < first_ts else first_ts
                last_ts = ts if last_ts is None or ts > last_ts else last_ts
            cov["events"] += 1
            emitted += 1
            if emitted <= skip:
                if emitted == skip and expect and ev["event_id"] != expect:
                    raise CheckpointMismatch(job.name)
                continue
            if enc != "utf-8":
                ev["raw_ref"]["enc"] = enc
            batch.append(ev)
        else:
            cov["failed_lines"] += 1
            if len(samples) < 50:
                samples.append({"line_no": rl.line_no, "reason": r.reason, "raw": mask_text(rl.text[:300]).text})
        if len(batch) >= BATCH:
            done_events += store(batch)
            last_id = batch[-1]["event_id"]
            batch = []
            el = max(0.001, time.time() - job.t0)
            frac = min(0.999, (job.idx + rl.offset / size) / max(1, job.nfiles))  # by bytes: honest on huge files
            _job_update(job.job_id, events_done=done_events, current_item=job.name,
                        stage_parse={"pct": round(frac * 100, 1), "eps": round(done_events / el),
                                     "eta_sec": round(el / max(frac, 1e-3) - el),
                                     "ckpt": {"file": job.file_id, "emitted": emitted, "last_event_id": last_id,
                                              "parser": _parser_tag(parser), "rejected": cov["rejected_events"]}},
                        stage_index={"pct": round(frac * 100, 1)})
            if _cancelled(job.job_id):
                raise Cancelled()
    if emitted < skip:
        raise CheckpointMismatch(job.name)  # the file now yields fewer events than were indexed
    if batch:
        done_events += store(batch)
    cov["events"] -= cov["rejected_events"]  # events = what can actually be searched
    return {"done_events": done_events, "ok": cov["events"], "failed": cov["failed_lines"] + cov["rejected_events"],
            "samples": samples, "encoding": enc, "warnings": list(getattr(parser, "warnings", []) or []),
            "coverage": cov, "first_ts": first_ts, "last_ts": last_ts}


def parse_files(job_id: str, leaves: list[str], inv_id: str, ev_id: str, tz: str) -> None:
    c = container.get()
    _job_update(job_id, state="PARSING")
    done_events = 0
    pcap_files = []
    t0 = time.time()
    for idx, lid in enumerate(leaves):
        with session_scope() as s:
            f = s.get(EvidenceFile, lid)
            if f.parse_status in ("skipped", "failed", "done"):
                done_events += f.events_parsed if f.parse_status == "done" else 0
                continue
            if f.parser_id == "pcap":
                pcap_files.append(lid)
                continue
            bucket = ORIGINAL if f.parent_file_id is None else EXTRACTED
            key, disp, pid = f.object_key, f.display_name, f.parser_id
            f.parse_status = "parsing"
        parser = get_parser(pid)
        path = c.objects.local_path(bucket, key)
        job = FileJob(job_id, lid, bucket, key, disp, inv_id, ev_id, tz, idx, len(leaves), t0)
        ckpt = _checkpoint(job_id)
        resume = ckpt if ckpt.get("file") == lid and ckpt.get("parser") in (None, _parser_tag(parser)) else {}
        started = utcnow()
        try:
            res = _parse_file(c, job, parser, path, done_events, resume)
        except CheckpointMismatch:
            log.warning("checkpoint for %s no longer matches the file/parser: re-indexing it from the start", disp)
            res = _parse_file(c, job, parser, path, done_events, {})
        done_events = res["done_events"]
        ok, failed = res["ok"], res["failed"]
        from datetime import datetime

        with session_scope() as s:
            f = s.get(EvidenceFile, lid)
            f.events_parsed, f.events_failed = ok, failed
            f.error_samples = res["samples"] + [{"coverage": res["coverage"]}]
            f.parse_status = "degraded" if ok and failed / max(1, ok + failed) > 0.05 else ("done" if ok else "failed")
            notes = list(res["warnings"])
            if res["coverage"]["rejected_events"]:
                notes.append(f"검색엔진이 {res['coverage']['rejected_events']:,}건의 저장을 거부함: 이 이벤트는 검색·탐지에서 빠짐")
            if not ok:
                notes.insert(0, "no lines parsed")
            f.message = " · ".join(notes)[:1000]
            f.parser_version = parser.version
            if res["first_ts"]:
                f.first_ts = datetime.fromisoformat(res["first_ts"].replace("Z", "+00:00"))
                f.last_ts = datetime.fromisoformat(res["last_ts"].replace("Z", "+00:00"))
            # provenance: who processed which input with which parser/settings, and the result fingerprint
            provenance.record_run(s, job=s.get(Job, job_id), f=f, investigation_id=inv_id, parser_id=parser.id,
                                  parser_version=parser.version, parser_fp=provenance.parser_digest(parser),
                                  settings={"encoding": res["encoding"], "assumed_tz": tz,
                                            "raw_store": c.settings.raw_store},
                                  events=ok, failed=failed, coverage=res["coverage"], status=f.parse_status,
                                  started_at=started)
        pct = round(100 * (idx + 1) / max(1, len(leaves)))
        _job_update(job_id, events_done=done_events, stage_parse={"pct": pct}, stage_index={"pct": pct})
    _job_update(job_id, stage_parse={"pct": 100, "done": True}, stage_index={"pct": 100, "done": True},
                state="INDEXING")
    if pcap_files:
        from saw.integrations.pcap import process_pcap_files

        process_pcap_files(job_id, pcap_files, inv_id, ev_id)
    analyze_job(job_id, inv_id, ev_id)


def analyze_job(job_id: str, inv_id: str, ev_id: str | None) -> None:
    _job_update(job_id, state="ANALYZING", current_item="detectors")

    with session_scope() as s:
        def prog(name: str, frac: float) -> None:  # same session: avoids a second SQLite writer
            j = s.get(Job, job_id)
            j.current_item = name
            j.stages = {**(j.stages or {}), "analyze": {"pct": round(frac * 100)}}
            s.commit()

        analysis.run_all(s, inv_id, prog)
        if ev_id:
            s.get(Evidence, ev_id).status = "processed"
    _job_update(job_id, state="COMPLETED", stage_analyze={"pct": 100, "done": True}, finished_at=utcnow(),
                current_item="")


@task("ingest.resume")
def ingest_resume(job_id: str) -> None:
    with session_scope() as s:
        j = s.get(Job, job_id)
        ev = s.get(Evidence, j.evidence_id)
        inv_id, ev_id, tz = ev.investigation_id, ev.id, ev.tz_assumed
        leaves = [f.id for f in s.execute(select(EvidenceFile).where(EvidenceFile.evidence_id == ev_id)).scalars()
                  if not s.execute(select(EvidenceFile).where(EvidenceFile.parent_file_id == f.id)).first()]
    try:
        parse_files(job_id, leaves, inv_id, ev_id, tz)
    except Cancelled:
        _job_update(job_id, state="CANCELLED", finished_at=utcnow())
    except Exception as e:  # noqa: BLE001
        log.error("resume failed: %s", traceback.format_exc())
        _job_update(job_id, state="FAILED", error={"message": str(e)[:500]}, finished_at=utcnow())


@task("analyze.run")
def analyze_run(job_id: str) -> None:
    claim(job_id)
    with session_scope() as s:
        j = s.get(Job, job_id)
        inv_id, ev_id = j.investigation_id, j.evidence_id
    try:
        analyze_job(job_id, inv_id, ev_id)
    except StaleLease as e:
        log.warning("%s", e)
    except Exception as e:  # noqa: BLE001
        log.error("analyze failed: %s", traceback.format_exc())
        _job_update(job_id, state="FAILED", error={"message": str(e)[:500]}, finished_at=utcnow())
