"""No archives, paths, commands, external engines, or executable extensions."""
from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from time import monotonic

from saw.detection.sigma_eval import apply_threshold, attack_tags, compile_rule, evaluate, validate_threshold, validate_with_pysigma
from saw.parsers.base import Failed, Parsed, RawLine
from saw.parsers.custom import CES_TARGETS, REGEX_TIMEOUT, DetectSpec, ExpandSpec, ParserSpec, DefinedParser
from saw.parsers.registry import to_ces

MAX_BYTES = 1024 * 1024
SCHEMA = "saw.content-package/1"
ENGINE = "saw-content-v1"
SOURCE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,46}$")
SIGMA_KEYS = ("title", "description", "data_source", "format", "logic", "threshold", "exceptions",
              "false_positive", "severity", "confidence", "attack")
MAX_TEST_SECONDS = 5.0


class TooLarge(ValueError):
    pass


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def payload_hash(document: dict) -> str:
    return digest({k: v for k, v in document.items() if k != "payload_sha256"})


def _keys(value, allowed, required=()):
    if not isinstance(value, dict) or set(value) - set(allowed) or set(required) - set(value):
        raise ValueError("지원하지 않는 필드 또는 필수 필드 누락입니다.")


def _string(value, maximum=256, empty=False):
    if not isinstance(value, str) or len(value) > maximum or (not empty and not value.strip()):
        raise ValueError("문자열 길이 또는 형식이 잘못되었습니다.")


def _tree(value, depth=0, budget=None):
    budget = budget if budget is not None else [0]
    budget[0] += 1
    if depth > 12 or budget[0] > 20000:
        raise ValueError("JSON 중첩 또는 항목 수가 한도를 넘습니다.")
    if isinstance(value, dict):
        if len(value) > 256:
            raise ValueError("JSON 객체가 너무 큽니다.")
        for key, child in value.items():
            _string(key, 128)
            _tree(child, depth + 1, budget)
    elif isinstance(value, list):
        if len(value) > 256:
            raise ValueError("JSON 배열이 너무 큽니다.")
        for child in value:
            _tree(child, depth + 1, budget)
    elif isinstance(value, str):
        _string(value, 65536, empty=True)
    elif isinstance(value, float) and not math.isfinite(value):
        raise ValueError("유한한 숫자만 허용합니다.")
    elif value is not None and type(value) not in (str, int, float, bool):
        raise ValueError("JSON 데이터만 허용합니다.")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("JSON 중복 키는 허용하지 않습니다.")
        result[key] = value
    return result


def read_json(text: str) -> dict:
    if not isinstance(text, str):
        raise ValueError("JSON 파일 내용을 입력하세요.")
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise TooLarge("콘텐츠 파일은 최대 1MiB입니다.")
    try:
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("유한한 숫자만 허용합니다.")))
        _tree(value)
    except (RecursionError, UnicodeError, json.JSONDecodeError):
        raise ValueError("올바른 UTF-8 JSON 파일이 아닙니다.") from None
    if not isinstance(value, dict):
        raise ValueError("JSON 객체가 필요합니다.")
    return value


def sigma_content(content: dict) -> dict:
    _keys(content, SIGMA_KEYS, ("title", "logic"))
    _string(content["title"], 256)
    _string(content["logic"], 65536)
    if content.get("format", "sigma") != "sigma":
        raise ValueError("이 버전은 지원되는 Sigma만 실행합니다.")
    rule = compile_rule(content["logic"])
    if set(rule.raw) - {"title", "id", "status", "description", "author", "date", "modified", "references", "logsource", "detection", "tags", "level", "falsepositives"}:
        raise ValueError("지원하지 않는 Sigma 문서 필드입니다.")
    errors = validate_with_pysigma(content["logic"])
    if errors:
        raise ValueError("Sigma 검증 실패: " + "; ".join(errors)[:500])
    threshold = validate_threshold(content.get("threshold") or {})
    if content.get("exceptions"):
        raise ValueError("묶음 v1의 별도 exceptions는 미지원입니다. Sigma 조건 안에 정상 제외 조건을 넣으세요.")
    if content.get("severity", "medium") not in {"critical", "high", "medium", "low", "info"} or content.get("confidence", "medium") not in {"low", "medium", "high"}:
        raise ValueError("잘못된 위험도 또는 신뢰도입니다.")
    tags = content.get("attack") or []
    if not isinstance(tags, list) or len(tags) > 32 or any(not isinstance(t, str) or not re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t) for t in tags):
        raise ValueError("지원하는 ATT&CK 태그만 입력하세요.")
    source = content.get("data_source", "web")
    if source not in rule.data_sources:
        raise ValueError("data_source가 Sigma logsource와 일치해야 합니다.")
    for key in ("description", "false_positive"):
        _string(content.get(key, ""), 4000, empty=True)
    return {"title": content["title"], "description": content.get("description", ""), "data_source": source,
            "format": "sigma", "logic": content["logic"], "threshold": threshold, "exceptions": [],
            "false_positive": content.get("false_positive", ""), "severity": content.get("severity", "medium"),
            "confidence": content.get("confidence", "medium"),
            "attack": sorted(set(tags) | {f"attack.{t.lower()}" for t in attack_tags(rule)})}


def parser_content(content: dict) -> dict:
    _keys(content, ("name", "spec"), ("name", "spec"))
    _string(content["name"], 128)
    spec = content["spec"]
    _keys(spec, ParserSpec.model_fields, ("format",))
    if "detect" in spec:
        _keys(spec["detect"], DetectSpec.model_fields)
    for item in spec.get("expand", []):
        _keys(item, ExpandSpec.model_fields, ("column",))
    parsed = ParserSpec.model_validate(spec, strict=True).model_dump()
    for key in ("mapping", "columns", "drop", "mask"):
        if len(parsed[key]) > 256:
            raise ValueError("파서 필드 한도를 넘습니다.")
    for key in parsed["mapping"]:
        _string(key, 128)
    return {"name": content["name"], "spec": parsed}


def normalized(entry: dict) -> dict:
    return sigma_content(entry["content"]) if entry["kind"] == "sigma" else parser_content(entry["content"])


def _validate(document: dict, *, sealed=True) -> dict:
    _keys(document, ("schema", "package_id", "revision", "requires", "payload_sha256", "entries"),
          ("schema", "package_id", "revision", "requires", "entries"))
    if document["schema"] != SCHEMA or document["requires"] != {"content_engine": ENGINE}:
        raise ValueError("지원하지 않는 콘텐츠 형식 또는 실행 계약입니다.")
    if not isinstance(document["package_id"], str) or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{1,63}", document["package_id"]):
        raise ValueError("package_id는 영문 소문자·숫자·점·밑줄·대시 2~64자입니다.")
    if type(document["revision"]) is not int or not 1 <= document["revision"] <= 2147483647:
        raise ValueError("revision은 양의 정수여야 합니다.")
    entries = document["entries"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 20:
        raise ValueError("콘텐츠 묶음은 1~20항목이어야 합니다.")
    seen = set()
    for entry in entries:
        _keys(entry, ("kind", "source_id", "source_version", "content", "fixtures"),
              ("kind", "source_id", "source_version", "content", "fixtures"))
        if entry["kind"] not in {"sigma", "parser"}:
            raise ValueError("지원하지 않는 콘텐츠 종류입니다. Sigma·선언형 파서만 허용합니다.")
        sid = entry["source_id"]
        if not isinstance(sid, str) or not SOURCE.fullmatch(sid) or (entry["kind"], sid) in seen:
            raise ValueError("잘못되거나 중복된 source_id입니다.")
        seen.add((entry["kind"], sid))
        if type(entry["source_version"]) is not int or not 1 <= entry["source_version"] <= 2147483647:
            raise ValueError("source_version은 양의 정수여야 합니다.")
        normalized(entry)
        fixtures = entry["fixtures"]
        if not isinstance(fixtures, list) or not 2 <= len(fixtures) <= 8:
            raise ValueError("각 항목에는 합성 양성·정상 예제 2~8개가 필요합니다.")
        expected = set()
        for fixture in fixtures:
            expected.add(fixture.get("expected") if isinstance(fixture, dict) else None)
            if entry["kind"] == "sigma":
                _keys(fixture, ("name", "expected", "events"), ("name", "expected", "events"))
                events = fixture["events"]
                if fixture["expected"] not in {"match", "no_match"} or not isinstance(events, list) or not 1 <= len(events) <= 20 or any(not isinstance(e, dict) for e in events):
                    raise ValueError("Sigma 합성 예제 형식이 잘못되었습니다.")
                for event in events:
                    if set(event) & {"investigation_id", "evidence_id", "raw_ref", "object_key", "raw_event", "source_file"}:
                        raise ValueError("합성 이벤트에 조사·원본 자료 참조를 넣을 수 없습니다.")
            else:
                _keys(fixture, ("name", "expected", "sample", "fields"), ("name", "expected", "sample"))
                _string(fixture["sample"], 8192)
                if len(fixture["sample"].splitlines()) > 20 or fixture["expected"] not in {"parsed", "no_match"}:
                    raise ValueError("파서 합성 예제 형식이 잘못되었습니다.")
                fields = fixture.get("fields", [])
                if fixture["expected"] == "parsed" and (not isinstance(fields, list) or not 1 <= len(fields) <= 20 or any(not isinstance(f, dict) or not f or set(f) - set(CES_TARGETS) for f in fields)):
                    raise ValueError("파서 양성 예제에 기대 CES 필드가 필요합니다.")
                if fixture["expected"] == "no_match" and fields:
                    raise ValueError("정상 제외 예제에는 해석 결과가 없어야 합니다.")
            _string(fixture["name"], 64)
        if not {"match" if entry["kind"] == "sigma" else "parsed", "no_match"} <= expected:
            raise ValueError("합성 양성 예제와 정상 제외 예제가 모두 필요합니다.")
    if len(canonical(document)) > MAX_BYTES:
        raise TooLarge("콘텐츠 파일은 최대 1MiB입니다.")
    if sealed and (not isinstance(document.get("payload_sha256"), str) or document["payload_sha256"] != payload_hash(document)):
        raise ValueError("SHA-256이 일치하지 않습니다. 원본 발행 파일을 다시 확인하세요.")
    return document


def validate(document: dict, *, sealed=True) -> dict:
    try:
        return _validate(document, sealed=sealed)
    except (TypeError, KeyError, AttributeError, RecursionError):
        raise ValueError("지원하는 콘텐츠 데이터 형식이 아닙니다.") from None


def seal(document: dict) -> dict:
    out = copy.deepcopy(document)
    out.pop("payload_sha256", None)
    validate(out, sealed=False)
    out["payload_sha256"] = payload_hash(out)
    validate(out)
    return out


def run_fixtures(document: dict) -> dict:
    validate(document)
    deadline = monotonic() + MAX_TEST_SECONDS
    rows = []
    for entry in document["entries"]:
        content = normalized(entry)
        for fixture in entry["fixtures"]:
            row = {"kind": entry["kind"], "source_id": entry["source_id"], "name": fixture["name"], "expected": fixture["expected"], "passed": False}
            try:
                if monotonic() >= deadline:
                    raise ValueError("전체 합성 시험 시간 한도 초과")
                if entry["kind"] == "sigma":
                    rule = compile_rule(content["logic"])
                    hits = []
                    for event in fixture["events"]:
                        if monotonic() >= deadline:
                            raise ValueError("전체 합성 시험 시간 한도 초과")
                        if event.get("data_source") in rule.data_sources and evaluate(rule, event):
                            hits.append(event)
                    hits = apply_threshold(hits, content["threshold"])
                    row.update(matched=len(hits), passed=bool(hits) == (fixture["expected"] == "match"))
                else:
                    parser = DefinedParser(entry["source_id"], entry["source_version"], ParserSpec.model_validate(content["spec"]))
                    lines = fixture["sample"].splitlines()
                    # The shared detector tolerates timeouts during ordinary ingest. Package tests must fail them.
                    if parser.line_rx:
                        for line in lines:
                            if monotonic() >= deadline:
                                raise ValueError("전체 합성 시험 시간 한도 초과")
                            parser.line_rx.search(line, timeout=REGEX_TIMEOUT)
                    score = parser.detect(lines)
                    parser.reset()
                    actual = []
                    for i, line in enumerate(lines, 1):
                        if monotonic() >= deadline:
                            raise ValueError("전체 합성 시험 시간 한도 초과")
                        raw = RawLine(line, i * 10000, i)
                        parsed = parser.parse_line(line)
                        if isinstance(parsed, Failed) and parsed.reason == "regex timeout":
                            raise ValueError("파서 정규식 시험 시간 초과")
                        if isinstance(parsed, Parsed):
                            actual.append(to_ces(parser, raw, parsed, investigation_id="synthetic", evidence_id=None,
                                                 file_id="synthetic", source_file="synthetic", object_key=None, assumed_tz="Asia/Seoul"))
                    if fixture["expected"] == "no_match":
                        passed = not actual and score < 0.8
                    else:
                        wanted = fixture["fields"]
                        passed = len(actual) == len(wanted) and all(all(a.get(k) == v for k, v in w.items()) for a, w in zip(actual, wanted))
                    row.update(parsed=len(actual), detect_score=score, passed=passed)
                if monotonic() >= deadline:
                    row["passed"] = False
                    raise ValueError("전체 합성 시험 시간 한도 초과")
            except (ValueError, TypeError, TimeoutError, KeyError, RecursionError):
                row["error"] = "예제 평가 실패 또는 시간 한도 초과"
            rows.append(row)
    return {"kind": "package_fixture", "engine": ENGINE, "digest": document["payload_sha256"],
            "passed": bool(rows) and all(r["passed"] for r in rows), "results": rows,
            "scope": "synthetic_only_not_historical_replay"}
