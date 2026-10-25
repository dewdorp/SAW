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
from saw.integrations.pcapkit import PRODUCER
from saw.integrations.pcapkit.reader import PcapError
from saw.parsers.base import Parsed, Skip
from saw.parsers.network import SuricataEveParser, ZeekJsonParser
from saw.parsers.registry import iter_lines, to_ces

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


def _suricata_cmd(exe: str, pcap: Path, out: Path) -> list[str]:
    st = container.get().settings
    cmd = [exe, "-r", str(pcap), "-l", str(out), "-k", "none"]
    if st.suricata_config:
        cmd += ["-c", st.suricata_config]
    if st.suricata_rules:
        cmd += ["-S", st.suricata_rules]
    return cmd


def _fingerprint(path):
    import hashlib
    path = Path(path).resolve(strict=True)
    digest, length = hashlib.sha256(), 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            length += len(chunk)
    return {"path": str(path), "sha256": digest.hexdigest(), "byte_length": length}


def runtime_pins(*, tools=None, settings=None):
    """Server-only capture, outside SQL locks. No version command executes during verification."""
    from saw.storage.generations import GenerationVerificationError
    tools = tools if tools is not None else tools_available()
    settings = settings if settings is not None else container.get().settings
    pins = {"format": "saw-pcap-runtime/1", "builtin": PRODUCER, "engines": {}}
    for name in ("zeek", "suricata"):
        executable = tools.get(name)
        if not executable:
            continue
        binary = _fingerprint(executable)
        result = subprocess.run([executable, "--version"], capture_output=True, timeout=15, check=False)
        if result.returncode:
            raise GenerationVerificationError("pcap_runtime_version_unavailable")
        version = (result.stdout or result.stderr).decode(errors="replace").strip()[:1024]
        if not version:
            raise GenerationVerificationError("pcap_runtime_version_unavailable")
        engine = {"executable": binary, "version": version, "files": []}
        if name == "suricata":
            if not settings.suricata_config or not settings.suricata_rules:
                raise GenerationVerificationError("pcap_suricata_explicit_config_and_rules_required")
            engine["config"] = _fingerprint(settings.suricata_config)
            engine["rules"] = _fingerprint(settings.suricata_rules)
        else:
            scripts = Path(executable).resolve().parent.parent / "share" / "zeek"
            if not scripts.is_dir():
                raise GenerationVerificationError("pcap_zeek_runtime_unavailable")
            for source in sorted(scripts.rglob("*.zeek")):
                engine["files"].append(_fingerprint(source))
                if len(engine["files"]) > 4096:
                    raise GenerationVerificationError("pcap_runtime_closure_too_large")
            if not engine["files"]:
                raise GenerationVerificationError("pcap_zeek_runtime_unavailable")
        pins["engines"][name] = engine
    return pins


def verify_runtime_pins(pins):
    from saw.storage.generations import GenerationVerificationError
    if not isinstance(pins, dict) or pins.get("format") != "saw-pcap-runtime/1" or pins.get("builtin") != PRODUCER:
        raise GenerationVerificationError("pcap_runtime_pins_invalid")
    for engine in pins["engines"].values():
        for source in [engine["executable"], *engine.get("files", []),
                       *[engine[k] for k in ("config", "rules") if k in engine]]:
            try:
                actual = _fingerprint(source["path"])
            except OSError as error:
                raise GenerationVerificationError("pcap_runtime_unavailable") from error
            if actual != source:
                raise GenerationVerificationError("pcap_runtime_changed")


def analyze_generation_pcap(src, out_dir, check):
    """The existing decoder/limits with bounded producer cancellation and source checks."""
    from saw.integrations.pcapkit.analyzer import PcapAnalyzer
    from saw.integrations.pcapkit.reader import iter_packets, new_quality
    check()
    out_dir.mkdir(parents=True, exist_ok=True)
    analyzer, quality = PcapAnalyzer(out_dir), new_quality()
    try:
        with open(src, "rb") as stream:
            for index, (stamp, linktype, data, _) in enumerate(iter_packets(stream, quality)):
                if index % 500 == 0:
                    check()
                analyzer.feed(float(stamp), linktype, data)
        check()
    except PcapError:
        if not quality["packets"]:
            analyzer.close(quality)
            raise
    except BaseException:
        analyzer.close(quality)
        raise
    result = analyzer.close(quality)
    check()
    return result


def produce_generation(producer, identity, evidence, source, context):
    """All protocol logs enter one full-generation writer; raw names belong to this attempt."""
    from saw.storage.generations import GenerationVerificationError
    c = producer.c
    pins = producer.input.get("runtime_pins")
    verify_runtime_pins(pins)
    path = c.objects.local_path(source["object_bucket"], source["object_key"])
    work = Path(tempfile.mkdtemp(prefix="saw-pcap-", dir=str(c.settings.data_dir)))
    summary, notes, logs, used = {}, [], [], []
    failed, first, last = 0, None, None
    try:
        engines = pins["engines"]
        if "zeek" in engines:
            zdir = work / "zeek"
            zdir.mkdir()
            result = _run([engines["zeek"]["executable"]["path"], "-C", "-r", str(path),
                           "LogAscii::use_json=T", "local"], zdir, source["size"])
            if result.returncode:
                raise GenerationVerificationError("pcap_zeek_execution_failed")
            logs.extend((p, ZeekJsonParser(), "zeek") for p in sorted(zdir.glob("*.log")))
            used.append("zeek")
        else:
            bdir = work / "builtin"
            try:
                import json
                summary = json.loads(json.dumps(analyze_generation_pcap(path, bdir, producer.check)))
                notes += capture_notes(summary)
            except PcapError as error:
                notes.append(f"pcap 형식 오류: {error}")
                failed += 1
            logs.extend((p, ZeekJsonParser(), "builtin") for p in sorted(bdir.glob("*.log")))
            for obj in sorted((bdir / "files").glob("*")):
                producer.raw_object(identity, obj, "files/" + obj.name)
            used.append("builtin")
        producer.check()
        if "suricata" in engines:
            engine = engines["suricata"]
            sdir = work / "suricata"
            sdir.mkdir()
            command = [engine["executable"]["path"], "-r", str(path), "-l", str(sdir), "-k", "none",
                       "-c", engine["config"]["path"], "-S", engine["rules"]["path"]]
            result = _run(command, sdir, source["size"])
            if result.returncode or not (sdir / "eve.json").exists():
                raise GenerationVerificationError("pcap_suricata_execution_failed")
            logs.append((sdir / "eve.json", SuricataEveParser(), "suricata"))
            used.append("suricata")
        else:
            notes.append("IDS 경보 없음: Suricata 미설치 (선택 구성, SAW_SURICATA_PATH)")
        for log, parser, engine in logs:
            raw = producer.raw_object(identity, log, engine + "/" + log.name)
            parser.reset()
            with log.open("rb") as stream:
                for index, line in enumerate(iter_lines(iter(lambda: stream.read(1024 * 1024), b""))):
                    if index % 500 == 0:
                        producer.check()
                    parsed = parser.parse_line(line.text)
                    if isinstance(parsed, Skip) or not line.text.strip():
                        continue
                    if not isinstance(parsed, Parsed):
                        failed += 1
                        continue
                    event = to_ces(parser, line, parsed, investigation_id=producer.ref.investigation_id,
                        evidence_id=identity[0], file_id=identity[1] + ":" + log.name,
                        source_file=source["display_name"] + ":" + log.name,
                        object_key=raw["bucket"] + "/" + raw["key"], assumed_tz="UTC", context_snapshot=context)
                    producer.spool.add(identity, event)
                    stamp = event.get("timestamp")
                    if stamp:
                        first = stamp if first is None or stamp < first else first
                        last = stamp if last is None or stamp > last else last
        producer.check()
        cap = summary.get("capture") or {}
        total = producer.spool.stats(identity, check=producer.check)[0]
        partial = bool(cap.get("cut_off") or cap.get("damaged"))
        coverage = {key: summary.get(key) for key in ("packets", "decoded", "duplicates", "incomplete_flows")}
        coverage.update(cut_off=bool(cap.get("cut_off")), damaged=bool(cap.get("damaged")))
        return {"status": ("degraded" if partial or failed else "done") if total else "failed",
                "coverage": coverage, "samples": [{"pcap_summary": summary}], "failed": failed,
                "first_ts": first, "last_ts": last, "message": " · ".join(notes)[:1000],
                "settings": {"engines": used, "runtime_pins": pins, "source_context": context}}
    finally:
        shutil.rmtree(work, ignore_errors=True)
