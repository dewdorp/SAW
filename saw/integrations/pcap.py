"""PCAP processing (docs/20 Option A, ADR-0004, ADR-0016).

Flow/protocol logs: Zeek when installed (Linux), otherwise the built-in pure-Python analyzer (saw.integrations.pcapkit),
which emits Zeek-compatible JSON — so Windows servers without Zeek still get conn/dns/http/ssl(JA4) analysis.
IDS alerts: Suricata when installed (optional; Windows MSI or Linux), configured via SAW_SURICATA_PATH/CONFIG.

External tools run as separate processes (GPL tools are never linked), in a temp scratch dir, with timeouts and — on
Linux — without network (`unshare -n` when available). All outputs go through the regular Zeek/Suricata parsers so
uploaded logs and PCAP-derived logs share one normalization/detection path.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from saw import container
from saw.integrations.pcapkit import PRODUCER, analyze_pcap
from saw.integrations.pcapkit.reader import PcapError
from saw.parsers.base import Parsed, Skip
from saw.parsers.network import SuricataEveParser, ZeekJsonParser
from saw.parsers.registry import iter_lines, to_ces
from saw.storage.db import session_scope
from saw.storage.models import EvidenceFile

ARTIFACTS = "saw-artifacts"
TIMEOUT_PER_GB = 600


def _tool(name: str) -> str | None:
    configured = getattr(container.get().settings, f"{name}_path", "") or ""
    if configured:
        return configured if Path(configured).is_file() else None
    return shutil.which(name)


def tools_available() -> dict[str, str | None]:
    return {t: _tool(t) for t in ("zeek", "suricata", "tshark", "capinfos")} | {"builtin": PRODUCER}


def _sandbox_prefix() -> list[str]:
    if os.name != "nt" and shutil.which("unshare"):
        return ["unshare", "-n", "--"]  # no network namespace (ENV-07: verify on target host)
    return []


def _run(cmd: list[str], cwd: Path, size: int) -> subprocess.CompletedProcess:  # pragma: no cover - ENV-06
    timeout = max(120, int(TIMEOUT_PER_GB * size / 1024**3))
    env = {"PATH": os.environ.get("PATH", ""), "LANG": "C"}
    if os.name == "nt":  # Windows processes need these to start (DLL search, temp files)
        env |= {k: os.environ[k] for k in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PROGRAMDATA") if k in os.environ}
    return subprocess.run(_sandbox_prefix() + cmd, cwd=cwd, capture_output=True, timeout=timeout, check=False, env=env)


def capinfos(path: Path) -> dict:  # pragma: no cover - ENV-06
    exe = shutil.which("capinfos")
    if not exe:
        return {}
    r = _run([exe, "-M", "-T", "-r", "-a", "-e", "-c", "-u", str(path)], path.parent, path.stat().st_size)
    out = r.stdout.decode(errors="replace").strip().split("\t")
    return {"raw": out[:12], "returncode": r.returncode}


def _index_log(log: Path, parser, inv_id: str, ev_id: str, file_id: str, src_name: str, key: str, tz: str) -> int:
    c = container.get()
    batch, n = [], 0
    parser.reset()
    with open(log, "rb") as fh:
        for rl in iter_lines(iter(lambda: fh.read(1024 * 1024), b"")):
            if not rl.text.strip():
                continue
            r = parser.parse_line(rl.text)
            if isinstance(r, (Skip,)) or not isinstance(r, Parsed):
                continue
            batch.append(to_ces(parser, rl, r, investigation_id=inv_id, evidence_id=ev_id, file_id=f"{file_id}:{log.name}",
                                source_file=f"{src_name}:{log.name}", object_key=f"{ARTIFACTS}/{key}", assumed_tz=tz))
            if len(batch) >= 5000:
                n += c.events.index(batch)
                batch = []
    if batch:
        n += c.events.index(batch)
    return n


def capture_notes(summary: dict) -> list[str]:
    """What the analyst must know about the capture itself before trusting what was derived from it."""
    cap = summary.get("capture") or {}
    notes = []
    if cap.get("damaged"):
        notes.append(f"⚠ 파일이 손상되어 읽을 수 있는 {summary.get('packets', 0):,}개 패킷까지만 분석함")
    elif cap.get("cut_off"):
        notes.append(f"⚠ 파일이 중간에 끊겨 있음(마지막 패킷이 온전하지 않음): 그 앞 {summary.get('packets', 0):,}개 패킷만 분석함")
    if cap.get("skipped_blocks"):
        notes.append(f"읽지 못해 건너뛴 블록 {cap['skipped_blocks']:,}개")
    if cap.get("snapped_packets"):
        notes.append(f"패킷 {cap['snapped_packets']:,}개는 앞부분만 저장된 캡처(snaplen): 본문·파일이 빠질 수 있음")
    if summary.get("incomplete_flows"):
        notes.append(f"패킷이 빠진 세션 {summary['incomplete_flows']:,}개: 그 세션의 HTTP·TLS 해석은 불완전할 수 있고 "
                     "해당 이벤트에 '패킷 빠짐' 표시가 붙음")
    return notes


def files_key(inv_id: str, sha256: str) -> str:
    """Object key of an extracted file: one copy per investigation and content hash."""
    return f"{inv_id}/extracted-files/{sha256}"


def _store_and_index(log: Path, parser, inv_id: str, ev_id: str, fid: str, name: str, sub: str) -> int:
    key = f"{inv_id}/{ev_id}/{fid}/{sub}/{log.name}"
    with open(log, "rb") as fh:
        container.get().objects.put_stream(ARTIFACTS, key, fh)
    return _index_log(log, parser, inv_id, ev_id, fid, name, key, "UTC")


def _suricata_cmd(exe: str, pcap: Path, out: Path) -> list[str]:
    st = container.get().settings
    cmd = [exe, "-r", str(pcap), "-l", str(out), "-k", "none"]
    if st.suricata_config:
        cmd += ["-c", st.suricata_config]
    if st.suricata_rules:
        cmd += ["-S", st.suricata_rules]
    return cmd


def process_pcap_files(job_id: str, file_ids: list[str], inv_id: str, ev_id: str) -> None:
    c = container.get()
    tools = tools_available()
    for fid in file_ids:
        with session_scope() as s:
            f = s.get(EvidenceFile, fid)
            bucket = "saw-evidence-original" if f.parent_file_id is None else "saw-evidence-extracted"
            path, name, size = c.objects.local_path(bucket, f.object_key), f.display_name, f.size
            f.parse_status = "parsing"
        work = Path(tempfile.mkdtemp(prefix="saw-pcap-", dir=str(c.settings.data_dir)))
        total, used, notes, summary = 0, [], [], None
        try:
            if tools["zeek"]:  # pragma: no cover - ENV-06 (Linux)
                zdir = work / "zeek"
                zdir.mkdir()
                _run([tools["zeek"], "-C", "-r", str(path), "LogAscii::use_json=T", "local"], zdir, size)
                for log in sorted(zdir.glob("*.log")):
                    total += _store_and_index(log, ZeekJsonParser(), inv_id, ev_id, fid, name, "zeek")
                used.append("zeek")
            else:
                bdir = work / "builtin"
                try:
                    summary = analyze_pcap(path, bdir)
                    notes.append(f"packets={summary['packets']} decoded={summary['decoded']} "
                                 f"duplicates={summary['duplicates']} files={summary['files_extracted']}")
                    notes += capture_notes(summary)
                except PcapError as e:
                    notes.append(f"pcap 형식 오류: {e}")
                for log in sorted(bdir.glob("*.log")):
                    total += _store_and_index(log, ZeekJsonParser(), inv_id, ev_id, fid, name, "builtin")
                for obj in sorted((bdir / "files").glob("*")):  # extracted transferred files (never executed)
                    with open(obj, "rb") as fh:
                        c.objects.put_stream(ARTIFACTS, files_key(inv_id, obj.name), fh)
                if summary:
                    with session_scope() as s:
                        s.get(EvidenceFile, fid).error_samples = [{"pcap_summary": summary}]
                used.append("builtin")
            if tools["suricata"]:  # pragma: no cover - ENV-06 (Suricata install)
                sdir = work / "suricata"
                sdir.mkdir()
                r = _run(_suricata_cmd(tools["suricata"], path, sdir), sdir, size)
                eve = sdir / "eve.json"
                if eve.exists():
                    total += _store_and_index(eve, SuricataEveParser(), inv_id, ev_id, fid, name, "suricata")
                    used.append("suricata")
                else:
                    notes.append(f"suricata rc={r.returncode}: {r.stderr.decode(errors='replace')[-300:]}")
            else:
                notes.append("IDS 경보 없음: Suricata 미설치 (선택 구성, SAW_SURICATA_PATH)")
            with session_scope() as s:
                from saw.core.application import provenance
                from saw.storage.models import Job

                f = s.get(EvidenceFile, fid)
                cap = (summary or {}).get("capture") or {}
                partial = bool(cap.get("cut_off") or cap.get("damaged"))  # analysed only up to where the file breaks
                f.events_parsed, f.parse_status = total, ("degraded" if partial else "done") if total else "failed"
                f.parser_id, f.message = f"pcap({'+'.join(used)})", " · ".join(notes)[:1000]
                provenance.record_run(
                    s, job=s.get(Job, job_id), f=f, investigation_id=inv_id, parser_id=f.parser_id,
                    parser_version=str((summary or {}).get("producer", "")).rpartition("/")[2],
                    parser_fp=provenance.pcap_engine_digest() if "builtin" in used else "",
                    settings={"engines": used, "tools": {k: bool(v) for k, v in tools.items()}},
                    events=total, failed=0, coverage={"packets": (summary or {}).get("packets"),
                                                      "decoded": (summary or {}).get("decoded"),
                                                      "duplicates": (summary or {}).get("duplicates"),
                                                      "incomplete_flows": (summary or {}).get("incomplete_flows"),
                                                      "cut_off": bool(cap.get("cut_off")),
                                                      "damaged": bool(cap.get("damaged"))},
                    status=f.parse_status, started_at=None)
        finally:
            shutil.rmtree(work, ignore_errors=True)
