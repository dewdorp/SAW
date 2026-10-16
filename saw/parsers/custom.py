"""Analyst-defined parsers: a declarative spec (no code), validated, versioned and auto-detected like built-ins.

Formats: delimited (CSV/TSV/|/;), regex (named groups, timeout-bounded), kv (key=value pairs) and json.
Every format yields a {source field: value} record; then `expand` unfolds `k=v;k=v` cells (NDR-style), `drop` /
`mask` remove or hide sensitive fields (cookies, resident numbers ...), `mapping` names the CES field of a source
field, and unmapped fields fall back to the built-in alias recognition (English variants and Korean headers).
"""
from __future__ import annotations

import csv
import io
import re
from datetime import datetime
from typing import Any, Literal
from zoneinfo import ZoneInfo

import orjson
import regex
from pydantic import BaseModel, Field, field_validator, model_validator

from saw.parsers.base import BaseParser, Failed, Parsed, ParseResult, Skip, unique_names
from saw.parsers.structured import (
    FIELD_ALIASES, _fit_row, _flatten, duplicate_columns_note, map_fields, parse_kv,
)

CES_TARGETS = sorted(FIELD_ALIASES)  # fields a source column can be mapped to
DATA_SOURCES = ["custom", "web", "waf", "zeek_conn", "zeek_dns", "linux", "windows"]
SLUG = re.compile(r"^[a-z0-9][a-z0-9_-]{1,46}$")
REGEX_TIMEOUT = 0.05  # seconds per line: a catastrophic pattern fails the line instead of hanging the job


class ExpandSpec(BaseModel):
    column: str = Field(min_length=1, max_length=128)
    pair_sep: str = Field(default=";", min_length=1, max_length=4)
    kv_sep: str = Field(default="=", min_length=1, max_length=4)
    prefix: str = Field(default="", max_length=32)


class DetectSpec(BaseModel):
    header_contains: list[str] = Field(default_factory=list, max_length=20)  # all must appear in the first line
    line_regex: str = Field(default="", max_length=1000)  # >= 90% of sample lines must match

    @field_validator("line_regex")
    @classmethod
    def _compiles(cls, v: str) -> str:
        if v:
            regex.compile(v)
        return v


class ParserSpec(BaseModel):
    format: Literal["delimited", "regex", "kv", "json"]
    delimiter: str = Field(default=",", min_length=1, max_length=1)
    has_header: bool = True
    columns: list[str] = Field(default_factory=list, max_length=256)
    pattern: str = Field(default="", max_length=4000)
    pair_sep: str = Field(default=" ", min_length=1, max_length=4)  # kv: between pairs (" " = whitespace, quotes ok)
    kv_sep: str = Field(default="=", min_length=1, max_length=4)
    expand: list[ExpandSpec] = Field(default_factory=list, max_length=8)
    mapping: dict[str, str] = Field(default_factory=dict)  # source field -> CES field
    auto_map: bool = True
    drop: list[str] = Field(default_factory=list, max_length=256)
    mask: list[str] = Field(default_factory=list, max_length=256)
    time_format: str = Field(default="", max_length=64)  # strptime, e.g. %Y%m%d%H%M%S; empty = automatic
    timezone: str = Field(default="", max_length=64)  # e.g. Asia/Seoul; empty = investigation default
    data_source: str = "custom"
    event_type: str = Field(default="log", max_length=32)
    detect: DetectSpec = Field(default_factory=DetectSpec)

    @model_validator(mode="after")
    def _valid(self) -> ParserSpec:
        if self.format == "regex":
            if not self.pattern:
                raise ValueError("regex format needs a pattern")
            if not regex.compile(self.pattern).groupindex:
                raise ValueError("the pattern needs named groups, e.g. (?P<src_ip>\\S+)")
        if self.format == "delimited" and not self.has_header and not self.columns:
            raise ValueError("without a header line the column names are required")
        bad = sorted({t for t in self.mapping.values() if t not in CES_TARGETS and t != "ignore"})
        if bad:
            raise ValueError(f"unknown target fields: {', '.join(bad)}")
        if self.data_source not in DATA_SOURCES:
            raise ValueError(f"data_source must be one of {', '.join(DATA_SOURCES)}")
        if self.timezone:
            try:
                ZoneInfo(self.timezone)
            except (KeyError, ValueError) as e:  # ZoneInfoNotFoundError is a KeyError
                raise ValueError(f"unknown time zone {self.timezone!r}") from e
        if self.time_format:
            datetime(2000, 1, 2, 3, 4, 5).strftime(self.time_format)  # noqa: DTZ001 - format check only
        return self


def _split_pairs(text: str, pair_sep: str, kv_sep: str, prefix: str = "") -> dict[str, str]:
    """k=v<sep>k=v; a segment without kv_sep continues the previous value (`q=0.9` in Accept-Language ...)."""
    out: dict[str, str] = {}
    last = None
    for seg in text.split(pair_sep):
        k, eq, v = seg.partition(kv_sep)
        k = k.strip()
        if eq and k and len(k) <= 64:
            out[prefix + k] = v
            last = prefix + k
        elif last is not None:
            out[last] += pair_sep + seg
    return out


class DefinedParser(BaseParser):
    def __init__(self, slug: str, version: int, spec: ParserSpec, name: str = "", pid: str | None = None):
        self.id = pid or f"u:{slug}"  # u:<slug> = the approved version, u:<slug>@<n> = that exact version
        self.version = str(version)
        self.product = f"u_{slug}"
        self.name = name or slug
        self.spec = spec
        self.data_source = spec.data_source
        self.event_type = spec.event_type
        self.stateful = spec.format == "delimited" and spec.has_header
        self.rx = regex.compile(spec.pattern) if spec.format == "regex" else None
        self.line_rx = regex.compile(spec.detect.line_regex) if spec.detect.line_regex else None
        self.header: list[str] | None = None
        self.drop = set(spec.drop)
        self.mask = set(spec.mask)

    def reset(self) -> None:
        self.header = None
        self.warnings = []

    # ------------------------------------------------------------------ detection
    def detect(self, sample: list[str]) -> float:
        lines = [s.lstrip("﻿") for s in sample if s.strip()]
        if not lines:
            return 0.0
        d = self.spec.detect
        if d.header_contains:
            first = lines[0].lower()
            if not all(h.lower() in first for h in d.header_contains):
                return 0.0
            self.reset()
            body = lines[:51]
            ok = sum(1 for s in body if isinstance(self.parse_line(s), (Parsed, Skip)))
            self.reset()
            return 0.995 if ok >= 0.8 * len(body) else 0.6
        if self.line_rx:
            hits = 0
            for s in lines[:200]:
                try:
                    hits += bool(self.line_rx.search(s, timeout=REGEX_TIMEOUT))
                except TimeoutError:
                    pass
            return 0.98 if hits >= 0.9 * min(len(lines), 200) else 0.0
        return 0.0  # no condition: chosen by the analyst only, never auto-selected

    # ------------------------------------------------------------------ record extraction
    def _record(self, line: str) -> dict[str, Any] | ParseResult:
        sp = self.spec
        if sp.format == "delimited":
            if self.header is None and sp.has_header:
                row = next(csv.reader([line.lstrip("﻿")], delimiter=sp.delimiter), [])
                self.header = [h.strip() or f"col{i + 1}" for i, h in enumerate(row)]
                while len(self.header) > 1 and re.fullmatch(r"col\d+", self.header[-1]):
                    self.header.pop()
                self.header, repeated = unique_names(self.header)
                if repeated:
                    self.warnings = [duplicate_columns_note(repeated)]
                return Skip()
            cols = self.header if sp.has_header else sp.columns
            row = _fit_row(next(csv.reader(io.StringIO(line), delimiter=sp.delimiter), []), len(cols))
            if row is None:
                return Failed("column count mismatch")
            return dict(zip(cols, row, strict=True))
        if sp.format == "regex":
            try:
                m = self.rx.search(line, timeout=REGEX_TIMEOUT)
            except TimeoutError:
                return Failed("regex timeout")
            if not m:
                return Failed("pattern did not match")
            return {k: v for k, v in m.groupdict().items() if v is not None}
        if sp.format == "kv":
            d = parse_kv(line) if sp.pair_sep == " " else _split_pairs(line, sp.pair_sep, sp.kv_sep)
            return d if d else Failed("no key=value pairs")
        try:
            d = orjson.loads(line)
        except orjson.JSONDecodeError:
            return Failed("invalid JSON")
        return _flatten(d) if isinstance(d, dict) else Failed("not a JSON object")

    def parse_line(self, line: str) -> ParseResult:
        rec = self._record(line)
        if not isinstance(rec, dict):
            return rec
        for ex in self.spec.expand:
            cell = rec.pop(ex.column, None)
            if isinstance(cell, str) and cell:
                for k, v in _split_pairs(cell, ex.pair_sep, ex.kv_sep, ex.prefix).items():
                    rec.setdefault(k, v)
        for k in self.drop & rec.keys():
            del rec[k]
        for k in self.mask & rec.keys():
            v = str(rec[k])
            rec[k] = f"●●●●[len={len(v)}]" if v else v
        ordered: dict[str, Any] = {}
        rest: dict[str, Any] = {}
        for k, v in rec.items():
            t = self.spec.mapping.get(k)
            if t == "ignore":
                continue
            if t:  # explicit mapping wins: name it by the target's first alias so map_fields keeps its normalizers
                ordered[FIELD_ALIASES[t][0]] = v
            else:
                rest[k] = v
        if self.spec.auto_map:
            ordered.update({k: v for k, v in rest.items() if k not in ordered})
            f, ext = map_fields(ordered)
        else:
            f, ext = map_fields(ordered)
            ext.update(rest)
        if self.spec.time_format and f.get("timestamp_raw"):
            try:
                dt = datetime.strptime(str(f["timestamp_raw"]).strip(), self.spec.time_format)  # noqa: DTZ007 - zone below
            except ValueError:
                return Failed(f"time does not match {self.spec.time_format}")
            if self.spec.timezone and dt.tzinfo is None:
                dt = dt.replace(tzinfo=ZoneInfo(self.spec.timezone))
            f["timestamp_raw"] = dt.isoformat()
        elif self.spec.timezone and f.get("timestamp_raw"):
            f["_tz"] = self.spec.timezone
        f["data_source"], f["event_type"] = self.spec.data_source, self.spec.event_type
        result = Parsed(f, ext, redact=bool(self.mask or self.drop))
        if self.spec.time_format and f.get("timestamp_raw"):
            result.observation["timestamp_precision"] = (
                "subseconds" if "%f" in self.spec.time_format else
                "seconds" if "%S" in self.spec.time_format else "unknown")
        return result


# ---------------------------------------------------------------------- suggestions for the wizard
def suggest(sample: list[str]) -> dict:
    """Best-effort starting spec from sample lines: format, delimiter, header, mappings, expandable cells."""
    from saw.parsers.structured import alias_for, infer_source, sniff_delimiter

    lines = [s.lstrip("﻿") for s in sample if s.strip()][:200]
    if not lines:
        return {"spec": {"format": "kv"}, "columns": [], "notes": ["샘플이 비어 있습니다."]}
    notes: list[str] = []
    first = lines[0].strip()
    if first.startswith("{"):
        keys: list[str] = []
        for s in lines[:50]:
            try:
                d = orjson.loads(s)
            except orjson.JSONDecodeError:
                continue
            if isinstance(d, dict):
                keys += [k for k in _flatten(d) if k not in keys]
        spec = {"format": "json"}
        cols = keys[:256]
    else:
        delim = sniff_delimiter(lines)
        if delim:
            head = next(csv.reader([first], delimiter=delim))
            cols = [h.strip() or f"col{i + 1}" for i, h in enumerate(head)]
            while len(cols) > 1 and re.fullmatch(r"col\d+", cols[-1]):
                cols.pop()
            known = [c for c in cols if alias_for(c)]
            looks_header = len(known) >= 1 or all(not re.fullmatch(r"[\d.:/\- ]+", c) for c in cols if c)
            spec = {"format": "delimited", "delimiter": delim, "has_header": looks_header}
            if not looks_header:
                cols = [f"col{i + 1}" for i in range(len(cols))]
                spec["columns"] = cols
                notes.append("첫 줄이 머리글이 아닌 것 같아 열 이름을 col1, col2 … 로 붙였습니다.")
            else:
                distinctive = [c for c in cols if len(c) >= 3][:3]
                spec["detect"] = {"header_contains": distinctive}
            spec["data_source"] = infer_source(cols)[0]
        elif sum("=" in s for s in lines) >= 0.9 * len(lines):
            spec = {"format": "kv", "pair_sep": " ", "kv_sep": "="}
            cols = []
            for s in lines[:50]:
                cols += [k for k in parse_kv(s) if k not in cols]
        else:
            spec = {"format": "regex", "pattern": ""}
            cols = []
            notes.append("구분자나 key=value 형식이 아닙니다. 정규식에 (?P<src_ip>…) 같은 이름 붙은 그룹을 써 주세요.")
    mapping = {c: alias_for(c) for c in cols if alias_for(c)}
    spec["mapping"] = mapping
    # cells that look like k=v;k=v (NDR meta data): offer to expand them
    if spec.get("format") == "delimited":
        p = DefinedParser("suggest", 0, ParserSpec.model_validate({**spec, "detect": {}}))
        cells: dict[str, int] = {}
        for s in lines[:51]:  # the first line sets the header
            r = p._record(s)
            if isinstance(r, dict):
                for k, v in r.items():
                    if isinstance(v, str) and v.count("=") >= 2 and (";" in v or "&" in v):
                        cells[k] = cells.get(k, 0) + 1
        expand = [{"column": k, "pair_sep": ";", "kv_sep": "="} for k, n in cells.items() if n >= 5]
        if expand:
            spec["expand"] = expand
            notes.append(f"'{expand[0]['column']}' 칸 안의 key=value를 펼치도록 제안했습니다.")
    sensitive = [c for c in cols if re.search(r"(?i)cookie|passw|pwd|token|secret|주민|jumin|ssn", c)]
    if sensitive:
        spec["drop"] = sensitive
        notes.append(f"민감할 수 있는 열을 저장하지 않도록 제안했습니다: {', '.join(sensitive)}")
    return {"spec": spec, "columns": cols, "notes": notes}
