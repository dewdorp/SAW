"""Bounded, deterministic connection policies with explicit site assumptions."""
from __future__ import annotations

import ipaddress
import math
import re
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml

from saw.core.schemas.query import Filter
from saw.detectors.base import AttackMap, DetectorContext, FindingDraft, check, metric

PACK = Path(__file__).parent / "packs" / "ndr_policies.yaml"
KINDS = {"large_outbound", "unexpected_port", "foreign_destination", "off_hours_admin", "internal_admin"}
STAGES = {"INFRASTRUCTURE", "RECON", "DISCOVERY", "AUTHENTICATION", "EXPLOITATION", "DELIVERY",
          "DATA_ACCESS", "EXECUTION", "PERSISTENCE", "LATERAL", "OUTBOUND", "UNCLASSIFIED"}
# Assigned ISO 3166-1 alpha-2 codes. Unknown/vendor-specific codes need prior normalization.
# User-assigned ranges are not interchangeable: https://www.iso.org/glossary-for-iso-3166.html
COUNTRIES = frozenset((
    "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ "
    "CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR "
    "GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP "
    "KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT "
    "MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW "
    "SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ "
    "UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW"
).split())
EXAMPLE_BASELINE = "예시 기준입니다. 사용 전 승인된 서비스 목록과 기준일로 바꾸세요."
MISSING_LABELS = {"timestamp": "시각", "src_ip": "출발지 주소", "dst_ip": "목적지 주소",
                  "event_id": "근거 식별자", "dst_port": "목적지 포트", "dst_country": "목적지 국가",
                  "bytes_out": "출발지 송신량", "event": "연결 기록 형식"}


@lru_cache(maxsize=1)
def load() -> dict:
    config = yaml.safe_load(PACK.read_text(encoding="utf-8"))
    _validate(config)
    return config


def _positive(value, name, maximum):
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError(f"{name} must be an integer in 1..{maximum}")


def _fields(value, required, name, optional=()):
    if not isinstance(value, dict) or not set(required) <= value.keys() or value.keys() - set(required) - set(optional):
        raise ValueError(f"invalid or missing {name} fields")


def _list(value, name, maximum):
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError(f"{name} must be a list with at most {maximum} entries")


def _text(value, name, maximum, allow_empty=False):
    if not isinstance(value, str) or len(value) > maximum or (not allow_empty and not value.strip()):
        raise ValueError(f"{name} must be bounded text")


def _validate(config):
    _fields(config, ("version", "limits", "rules", "site"), "NDR policy")
    if type(config["version"]) is not int or config["version"] != 1:
        raise ValueError("unsupported NDR policy version")
    limits = config["limits"]
    caps = {"max_events": 1000000, "max_groups": 50000, "max_findings": 200, "max_samples": 50}
    _fields(limits, caps, "limits")
    for key, cap in caps.items():
        _positive(limits[key], key, cap)
    _list(config["rules"], "rules", 50)
    ids = set()
    fields = ("id", "kind", "enabled", "window_seconds", "min_connections", "severity",
              "title", "explain", "checks", "stage", "attack")
    for rule in config["rules"]:
        _fields(rule, fields, "rule", ("min_bytes", "examples", "benign"))
        rid, kind = rule["id"], rule["kind"]
        if (not isinstance(rid, str) or not re.fullmatch("[a-z][a-z0-9_]{0,63}", rid)
                or rid in ids or not isinstance(kind, str) or kind not in KINDS):
            raise ValueError("invalid or duplicate NDR rule id/kind")
        ids.add(rid)
        if type(rule["enabled"]) is not bool:
            raise ValueError("enabled must be boolean")
        _positive(rule["window_seconds"], "window_seconds", 86400)
        _positive(rule["min_connections"], "min_connections", 1000000)
        if type(rule["severity"]) not in (int, float) or not 0 < rule["severity"] <= 1:
            raise ValueError("severity must be a finite number in (0, 1]")
        for key, cap in (("title", 200), ("explain", 4000)):
            _text(rule[key], key, cap)
        if not isinstance(rule["stage"], str) or rule["stage"] not in STAGES:
            raise ValueError("invalid rule stage")
        _list(rule["checks"], "checks", 20)
        if not rule["checks"]:
            raise ValueError("checks must not be empty")
        for value in rule["checks"]:
            _text(value, "check", 1000)
        _list(rule["attack"], "attack", 20)
        if any(not isinstance(t, str) or not re.fullmatch(r"T[0-9]{4}(?:\.[0-9]{3})?", t) for t in rule["attack"]):
            raise ValueError("attack must contain technique identifiers")
        if kind == "large_outbound":
            _positive(rule.get("min_bytes"), "min_bytes", 10**16)
        elif "min_bytes" in rule:
            raise ValueError("min_bytes only applies to large_outbound")
        for key in ("examples", "benign"):
            if key in rule:
                _list(rule[key], key, 100)
    site = config["site"]
    _fields(site, ("internal_cidrs", "home_countries", "allowed_ports", "baseline_note", "admin_ports",
                   "timezone", "work_start_hour", "work_end_hour", "work_days"), "site")
    _list(site["internal_cidrs"], "internal_cidrs", 256)
    for cidr in site["internal_cidrs"]:
        _text(cidr, "internal_cidrs", 64)
        try:
            ipaddress.ip_network(cidr)
        except ValueError as exc:
            raise ValueError("invalid internal_cidrs") from exc
    for key in ("allowed_ports", "admin_ports"):
        _list(site[key], key, 65535)
        for port in site[key]:
            _positive(port, key, 65535)
    _list(site["home_countries"], "home_countries", len(COUNTRIES))
    if any(not isinstance(c, str) or c not in COUNTRIES for c in site["home_countries"]):
        raise ValueError("home_countries must use assigned uppercase country codes")
    _text(site["baseline_note"], "baseline_note", 1000, allow_empty=True)
    _text(site["timezone"], "timezone", 100)
    try:
        ZoneInfo(site["timezone"])
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError("invalid timezone") from exc
    if (type(site["work_start_hour"]) is not int or type(site["work_end_hour"]) is not int
            or not 0 <= site["work_start_hour"] < site["work_end_hour"] <= 24):
        raise ValueError("work hours must be an increasing same-day integer interval")
    _list(site["work_days"], "work_days", 7)
    if not site["work_days"] or any(type(x) is not int or x not in range(7) for x in site["work_days"]):
        raise ValueError("work_days must use 0 (Monday) to 6 (Sunday)")
    active = {r["kind"] for r in config["rules"] if r["enabled"]}
    if active and not site["internal_cidrs"]:
        raise ValueError("internal_cidrs must be configured")
    if "unexpected_port" in active and (not site["allowed_ports"] or not site["baseline_note"].strip()
                                       or site["baseline_note"].strip() == EXAMPLE_BASELINE):
        raise ValueError("port baseline must include approved ports and a reviewed baseline note")
    if "foreign_destination" in active and not site["home_countries"]:
        raise ValueError("home_countries must be configured")
    if active & {"off_hours_admin", "internal_admin"} and not site["admin_ports"]:
        raise ValueError("admin_ports must be configured")


def _time(value):
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt if dt.tzinfo is not None and math.isfinite(dt.timestamp()) else None
    except (ValueError, OverflowError, OSError):
        return None


def _ip(value):
    if not isinstance(value, str) or len(value) > 64 or "%" in value:
        return None
    try:
        ip = ipaddress.ip_address(value)
        return ip if not (ip.is_unspecified or ip.is_multicast or ip.is_loopback) else None
    except ValueError:
        return None


def _integer(value, minimum, maximum):
    # Normalized stores may retain decimal strings; never coerce booleans or fractions.
    if isinstance(value, str) and len(value) <= 17 and re.fullmatch("[0-9]+", value):
        value = int(value)
    return value if type(value) is int and minimum <= value <= maximum else None


def _country(event):
    ext = event.get("ext")
    ext = ext if isinstance(ext, dict) else {}
    values = [ext.get(source, {}).get("dst_country") for source in ("ndr", "zeek")
              if isinstance(ext.get(source, {}), dict)]
    values.append(event.get("dst_country"))
    for value in values:
        if isinstance(value, str) and len(value) <= 16:
            cc = value.strip().upper()
            if cc in COUNTRIES:
                return cc
    return None


def evaluate(events, config) -> list[FindingDraft]:
    """Evaluate only supplied normalized events; never run input code or fetch enrichment."""
    _validate(config)
    rules = [r for r in config["rules"] if r["enabled"]]
    if not rules:
        return []
    site, limits = config["site"], config["limits"]
    networks = [ipaddress.ip_network(c) for c in site["internal_cidrs"]]
    allowed_ports, admin_ports, home_countries = (set(site[k]) for k in ("allowed_ports", "admin_ports", "home_countries"))
    zone = ZoneInfo(site["timezone"]) if any(r["kind"] == "off_hours_admin" for r in rules) else None
    groups, missing = {}, {}
    seen, skipped = 0, 0
    partial = False

    def record_missing(fields):
        for field in fields:
            missing[field] = missing.get(field, 0) + 1

    def inside(ip):
        return any(ip.version == n.version and ip in n for n in networks)

    for event in events:
        # At most one lookahead event is read to distinguish an exact limit from truncation.
        if seen >= limits["max_events"]:
            partial = True
            break
        seen += 1
        if not isinstance(event, dict):
            skipped += 1
            record_missing({"event"})
            continue
        if event.get("data_source") != "zeek_conn":
            continue
        dt, src, dst = _time(event.get("timestamp")), _ip(event.get("src_ip")), _ip(event.get("dst_ip"))
        event_id = event.get("event_id")
        missing_fields = {k for k, value in (("timestamp", dt), ("src_ip", src), ("dst_ip", dst)) if value is None}
        if not isinstance(event_id, str) or not event_id.strip() or len(event_id) > 256:
            missing_fields.add("event_id")
        if missing_fields:
            skipped += 1
            record_missing(missing_fields)
            continue
        if not inside(src):
            continue
        dst_internal = inside(dst)
        port = _integer(event.get("dst_port"), 1, 65535)
        country = _country(event)
        up = _integer(event.get("bytes_out"), 0, 10**16)
        try:
            local = dt.astimezone(zone) if zone else None
        except (ValueError, OverflowError, OSError):
            local = None
            missing_fields.add("timestamp")
        off_hours = local is not None and (local.weekday() not in site["work_days"]
                                          or not site["work_start_hour"] <= local.hour < site["work_end_hour"])
        for rule in rules:
            kind = rule["kind"]
            required = None
            if kind == "large_outbound" and not dst_internal:
                required = "bytes_out" if up is None else None
                matches = up is not None
            elif kind == "foreign_destination" and not dst_internal:
                required = "dst_country" if country is None else None
                matches = country is not None and country not in home_countries
            elif kind == "unexpected_port":
                required = "dst_port" if port is None else None
                matches = port is not None and port not in allowed_ports
            elif (kind == "off_hours_admin" and off_hours) or (kind == "internal_admin" and dst_internal and src != dst):
                required = "dst_port" if port is None else None
                matches = port in admin_ports
            else:
                matches = False
            if required:
                missing_fields.add(required)
            if not matches:
                continue
            bucket = math.floor(dt.timestamp()) // rule["window_seconds"]
            key = (rule["id"], str(src), bucket)
            if key not in groups:
                if len(groups) >= limits["max_groups"]:
                    partial = True
                    break
                groups[key] = {"rule": rule, "src": str(src), "count": 0, "up": 0, "bytes_missing": False,
                               "samples": [], "dsts": set(), "first": dt, "last": dt}
            group = groups[key]
            group["count"] += 1
            group["up"] += up if up is not None else 0
            group["bytes_missing"] |= up is None
            group["first"], group["last"] = min(group["first"], dt), max(group["last"], dt)
            if len(group["samples"]) < limits["max_samples"]:
                group["samples"].append(event_id)
            if len(group["dsts"]) < 20:
                group["dsts"].add(str(dst))
        if missing_fields:
            skipped += 1
            record_missing(missing_fields)
        if partial:
            break
    out = []
    for (rid, src, bucket), group in groups.items():
        rule = group["rule"]
        if group["count"] < rule["min_connections"]:
            continue
        if rule["kind"] == "large_outbound" and group["up"] < rule["min_bytes"]:
            continue
        if len(out) >= limits["max_findings"]:
            partial = True
            break
        samples = group["samples"]
        baseline = (" 기준: " + site["baseline_note"]) if rule["kind"] == "unexpected_port" else ""
        out.append(FindingDraft(
            NdrPolicy.id, NdrPolicy.version, rule["title"], "ndr." + rid, rule["stage"],
            rule["severity"], "medium",
            [metric("connections", group["count"], label="조건에 맞는 연결"),
             metric("bytes_out", group["up"], unit="bytes", approx=group["bytes_missing"],
                    label="확인된 출발지 송신 바이트" if group["bytes_missing"] else "출발지 송신 바이트"),
             metric("window_seconds", rule["window_seconds"], unit="s", label="고정 시간 구간")],
            [check("설정 기준과 일치", True, group["count"], baseline),
             check("악성 행위 확정", None, "추가 확인 필요", "연결·국가·포트만으로 공격을 확정하지 않습니다.")],
            ["ip:" + src] + ["ip:" + ip for ip in sorted(group["dsts"])],
            {"filters": [Filter(field="data_source", value="zeek_conn").model_dump(),
                         Filter(field="event_id", op="in", value=samples).model_dump()],
             "sample_only": True, "entity_roles": {"source": [src], "destination": sorted(group["dsts"])},
             "time": {"start": group["first"].isoformat(), "end": group["last"].isoformat()}},
            group["first"].isoformat(), group["last"].isoformat(), f"ndr:{rid}:{src}:{bucket}",
            attack=[AttackMap(t, "low", "연결 기록 이외의 증거 확인 필요", condition_met=False) for t in rule["attack"]],
            attack_unmapped_reason=None if rule["attack"] else "국가 정보만으로 공격 기법을 추정하지 않음",
            success_signal=False,
            explanation=(rule["explain"] + baseline + f" 고정 {rule['window_seconds']}초 구간, 관측 {group['count']}건. "
                         f"근거 링크는 최대 {limits['max_samples']}개 일치 표본입니다.\n\n"
                         + "\n".join("- " + c for c in rule["checks"])),
            sample_event_ids=samples, total_events=group["count"]))
    if partial or skipped:
        # Coverage is itself a result and must fit inside the configured result cap.
        if len(out) >= limits["max_findings"]:
            out = out[:limits["max_findings"] - 1]
            partial = True
        detail = f"상한 도달={partial}, 필수 정보 부족={skipped}"
        for d in out:
            d.checks.append(check("입력 전체 검사", False, seen, detail))
            d.explanation += " 일부 범위만 검사했으며 전체 자료에서 이상이 없다고 판단할 수 없습니다."
        missing_text = ", ".join(MISSING_LABELS[k] for k in sorted(missing)) or "없음"
        out.append(FindingDraft(
            NdrPolicy.id, NdrPolicy.version, "연결 정책 분석 범위 확인 필요", "ndr.coverage", "DISCOVERY", 0.1, "low",
            [metric("examined", seen, label="읽은 연결"), metric("skipped", skipped, label="필수 정보 부족")]
            + [metric("missing_" + k, missing[k], label=MISSING_LABELS[k] + " 확인 불가") for k in sorted(missing)],
            [check("입력 전체 검사", False, seen, detail + ", 확인 불가: " + missing_text)],
            [], {"filters": [Filter(field="data_source", value="zeek_conn").model_dump()]},
            None, None, "ndr:coverage", success_signal=False, attack_unmapped_reason="분석 범위 안내",
            explanation=("일부 범위만 검사했습니다. 누락되거나 유효하지 않은 필수 정보: " + missing_text
                         + ". 처리 상한과 수집 필드를 확인하고 자료 범위를 나누어 다시 검사하세요.")))
    return out


def catalog() -> list[dict]:
    cfg = load()
    return [{k: v for k, v in r.items() if k not in ("examples", "benign")} | {"site": cfg["site"], "limits": cfg["limits"]}
            for r in cfg["rules"]]


class NdrPolicy:
    id, version, category, stage = "ndr.policy", "1.0.0", "ndr.policy", "DISCOVERY"
    data_sources = {"zeek_conn"}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        config = ctx.params.get("ndr_policy")
        if config is None:
            config = load()
        _validate(config)
        if not any(r["enabled"] for r in config["rules"]):
            return []
        events = ctx.events.iterate(ctx.investigation_id, [Filter(field="data_source", value="zeek_conn")],
                                    fields=["event_id", "data_source", "timestamp", "src_ip", "dst_ip", "dst_port",
                                            "bytes_out", "bytes_in", "ext", "dst_country"])
        return evaluate(events, config)
