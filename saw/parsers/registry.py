"""Parser registry, detection and CES conversion (docs/19 §2)."""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from saw.analyzers.log.normalize import event_id, finalize
from saw.core.security.masking import mask_text
from saw.parsers.base import RAW_MAX, BaseParser, Failed, Parsed, RawLine
from saw.parsers.ndr import NdrMetaCsvParser
from saw.parsers.network import SuricataEveParser, ZeekJsonParser, ZeekTsvParser
from saw.parsers.security_csv import EnFirewallCsvParser, EnNdrHttpCsvParser, KoFirewallCsvParser, KoNdrCsvParser
from saw.parsers.security_profiles import (
    AppEventCsvProfileParser,
    DdosCsvProfileParser,
    IpsCsvProfileParser,
    WafCsvProfileParser,
)
from saw.parsers.structured import (
    CloudflareParser,
    CsvParser,
    GenericJsonWafParser,
    GenericWafParser,
    JsonLinesParser,
    KeyValueParser,
    SyslogParser,
)
from saw.parsers.web import ApacheParser, IISParser, NginxParser


def builtin_parsers() -> list[BaseParser]:
    return [KoFirewallCsvParser(), KoNdrCsvParser(), EnFirewallCsvParser(), EnNdrHttpCsvParser(), WafCsvProfileParser(), IpsCsvProfileParser(),
            DdosCsvProfileParser(), AppEventCsvProfileParser(), NdrMetaCsvParser(), NginxParser(), ApacheParser(), IISParser(), ZeekJsonParser(), ZeekTsvParser(),
            SuricataEveParser(), CloudflareParser(), GenericJsonWafParser(),
            GenericWafParser(), JsonLinesParser(), SyslogParser(), CsvParser(), KeyValueParser()]


# Analyst-defined parsers (saw.parsers.library) are supplied by the application layer: the parser package itself
# never touches the database.
_user_parsers: Callable[[], list[BaseParser]] | None = None
_user_parser_by_id: Callable[[str], BaseParser | None] | None = None


def set_user_parser_provider(fn: Callable[[], list[BaseParser]] | None,
                             by_id: Callable[[str], BaseParser | None] | None = None) -> None:
    global _user_parsers, _user_parser_by_id
    _user_parsers, _user_parser_by_id = fn, by_id


def user_parsers() -> list[BaseParser]:
    if _user_parsers is None:
        return []
    try:
        return _user_parsers()
    except Exception:  # noqa: BLE001 - a broken definition store must not stop built-in parsing
        return []


def all_parsers() -> list[BaseParser]:
    return user_parsers() + builtin_parsers()


def get_parser(pid: str) -> BaseParser:
    if pid.startswith("u:") and "@" in pid and _user_parser_by_id is not None:
        p = _user_parser_by_id(pid)  # an exact (possibly draft) version
        if p is not None:
            return p
        raise KeyError(f"unknown parser {pid}")
    for p in (user_parsers() if pid.startswith("u:") else builtin_parsers()):
        if p.id == pid:
            return p
    raise KeyError(f"unknown parser {pid}")


@dataclass
class Detection:
    parser_id: str
    confidence: float
    candidates: list[dict]


def detect(sample: list[str]) -> Detection:
    scored = []
    for p in all_parsers():
        try:
            sc = p.detect(sample)
        except Exception:  # noqa: BLE001 - a buggy parser must not break detection
            sc = 0.0
        scored.append({"parser_id": p.id, "confidence": round(sc, 3), "data_source": p.data_source})
    scored.sort(key=lambda x: -x["confidence"])
    best = scored[0]
    if best["confidence"] <= 0:  # the order of the list is not an opinion: no parser claimed this sample
        return Detection("", 0.0, [])
    return Detection(best["parser_id"], best["confidence"], [c for c in scored[:4] if c["confidence"] > 0])


def to_ces(parser: BaseParser, rl: RawLine, res: Parsed, *, investigation_id: str, evidence_id: str | None,
           file_id: str, source_file: str, object_key: str | None, assumed_tz: str,
           slim_sources: set[str] | frozenset[str] = frozenset(),
           context_snapshot: dict | None = None) -> dict[str, Any]:
    """slim_sources: data sources stored without raw_event (read back from the evidence file by raw_ref)."""
    f = dict(res.fields)
    tz_override = f.pop("_tz", None)  # analyst parser with a fixed source time zone
    ev: dict[str, Any] = {
        "event_id": event_id(file_id, rl.offset),
        "investigation_id": investigation_id,
        "evidence_id": evidence_id,
        "data_source": f.pop("data_source", None) or parser.data_source,
        "product": parser.product,
        "event_type": f.pop("event_type", None) or parser.event_type,
        "parser": parser.id,
        "parser_version": parser.version,
        "source_file": source_file,
        "raw_event": None,
        "raw_ref": {"object_key": object_key, "offset": rl.offset,
                    "length": rl.length if rl.length >= 0 else len(rl.text.encode("utf-8")), "line_no": rl.line_no},
    }
    if res.redact or res.raw is not None:
        ev["raw_redacted"] = True
    if ev["data_source"] not in slim_sources:  # masking only when the line is actually stored (it is costly)
        raw = res.raw if res.raw is not None else (mask_text(rl.text).text if res.redact else rl.text)
        ev["raw_event"] = raw[:RAW_MAX]
        if len(raw) > RAW_MAX:
            ev["raw_truncated"] = True
    ev.update(f)
    if res.ext:
        ev["ext"] = {parser.product: {k: v for k, v in list(res.ext.items())[:200]}}
    if ev.get("timestamp_raw") is None:
        ev["timestamp_quality"] = "missing"  # no time in the record; nothing (not even ingest time) is substituted
    return finalize(ev, assumed_tz=tz_override or assumed_tz, observation=res.observation, context_snapshot=context_snapshot)


def parse_text(text: str, *, investigation_id: str = "adhoc", parser_id: str | None = None,
               assumed_tz: str = "Asia/Seoul", max_lines: int = 50_000) -> dict:
    """Synchronous single-log analysis (docs FR-LOG-01): parse pasted lines into CES events."""
    lines = text.splitlines()[:max_lines]
    det = detect(lines[:200]) if parser_id is None else Detection(parser_id, 1.0, [])
    if not det.parser_id:  # nothing recognised the text: say so instead of running an arbitrary parser over it
        return {"parser": None, "confidence": 0.0, "candidates": det.candidates, "events": [],
                "failed": sum(1 for ln in lines if ln.strip()), "failure_samples": []}
    parser = get_parser(det.parser_id)
    events, failures = [], []

    def raw_lines() -> Iterable[RawLine]:
        offset = 0
        for i, ln in enumerate(lines, 1):
            rl = RawLine(ln, offset, i)
            offset += len(ln.encode("utf-8")) + 1
            if ln.strip():
                yield rl

    # parser-driven, like file ingest: records spanning lines (quoted CSV) and paired records (NDR) work in a paste too
    for rl, r in parser.parse(iter(raw_lines())):
        if isinstance(r, Parsed):
            try:
                events.append(to_ces(parser, rl, r, investigation_id=investigation_id, evidence_id=None,
                                     file_id="paste", source_file="paste", object_key=None, assumed_tz=assumed_tz))
            except (ValueError, TypeError, OverflowError, ArithmeticError, KeyError) as exc:
                failures.append({"line_no": rl.line_no, "reason": f"이 행의 값을 정규화하지 못했습니다({type(exc).__name__})",
                                 "raw": rl.text[:300]})
        elif isinstance(r, Failed):
            failures.append({"line_no": rl.line_no, "reason": r.reason, "raw": rl.text[:300]})
    return {"parser": det.parser_id, "confidence": det.confidence, "candidates": det.candidates,
            "events": events, "failed": len(failures), "failure_samples": failures[:20]}


def iter_lines(stream: Iterable[bytes], encoding: str = "utf-8") -> Iterable[RawLine]:
    """Byte-accurate line iterator (offsets refer to the decompressed file)."""
    offset, no = 0, 0
    buf = b""
    for chunk in stream:
        buf += chunk
        start = 0  # scan with an index: slicing the remainder per line made this O(chunk × lines)
        while True:
            i = buf.find(b"\n", start)
            if i < 0:
                break
            line = buf[start: i + 1]
            start = i + 1
            no += 1
            body = line.rstrip(b"\r\n")
            text = body.decode(encoding, errors="replace")
            yield RawLine(text.lstrip("\ufeff") if no == 1 else text, offset, no, len(body))
            offset += len(line)
        buf = buf[start:]
    if buf:
        no += 1
        body = buf.rstrip(b"\r\n")
        text = body.decode(encoding, errors="replace")
        yield RawLine(text.lstrip("\ufeff") if no == 1 else text, offset, no, len(body))


def sniff_encoding(head: bytes) -> str:
    """utf-8 (with/without BOM) unless the sample is not valid UTF-8 and is valid CP949 (Korean Windows/Excel exports)."""
    if head.startswith(b"\xef\xbb\xbf"):
        return "utf-8"
    cut = head[: head.rfind(b"\n") + 1] or head  # never judge on a character split at the sample boundary
    try:
        cut.decode("utf-8")
        return "utf-8"
    except UnicodeDecodeError:
        pass
    try:
        cut.decode("cp949")
        return "cp949"
    except UnicodeDecodeError:
        return "utf-8"
