"""Bounded format diagnostics; readiness is not a threat or truth verdict."""
from __future__ import annotations

from collections import Counter
from ipaddress import ip_address

from saw.core.schemas.query import Filter

# Korean and English exports of the same kinds share one readiness view.
PARSERS = {"ko_fw_csv": "fw", "ko_ndr_csv": "ndr", "en_fw_csv": "fw", "en_ndr_http_csv": "ndr"}
MAX_RECORDS = 100_000
MAX_DEVICES = 1000
FIELDS = ("timestamp", "source_ip", "destination_ip", "opaque_destination", "http_request",
          "http_response", "http_request_line", "http_request_summary", "session_id", "reported_alert", "verified_context", "verified_counters",
          "verified_time", "record_kind")


def _present(value):
    return value is not None and str(value).strip() not in {"", "-", "(empty)"}


def _ip(value):
    try:
        ip_address(str(value))
        return bool(value)
    except ValueError:
        return False


def inspect_events(events, *, max_records=MAX_RECORDS, cancelled=None):
    limit = max(1, min(MAX_RECORDS, int(max_records)))
    groups, checked, status = {}, 0, "complete"
    source = iter(events)
    try:
        for event in source:
            if cancelled and cancelled():
                status = "cancelled"
                break
            kind = PARSERS.get(event.get("parser"))
            if kind is None:
                continue
            if checked >= limit:
                status = "partial"
                break
            checked += 1
            group = groups.setdefault(kind, {"format": kind, "records": 0,
                "fields": Counter({key: 0 for key in FIELDS}), "devices": set(), "devices_limited": False})
            group["records"] += 1
            f = group["fields"]
            ext = (event.get("ext") or {}).get("security_csv") or {}
            device = ext.get("장비IP") or ext.get("_device_name") or ext.get("_device_ip")
            if isinstance(device, str) and _present(device):
                if len(group["devices"]) < MAX_DEVICES or device in group["devices"]:
                    group["devices"].add(device)
                else:
                    group["devices_limited"] = True
            f["timestamp"] += bool(event.get("timestamp"))
            f["source_ip"] += _ip(event.get("src_ip"))
            f["destination_ip"] += _ip(event.get("dst_ip"))
            f["opaque_destination"] += bool(event.get("dst_ip")) and not _ip(event.get("dst_ip"))
            request_observed = bool(event.get("method") and event.get("uri"))
            f["http_request"] += request_observed
            if request_observed:
                source_request = ext.get("요청헤더")
                if not _present(source_request) and _present(ext.get("path")):
                    f["http_request_summary"] += 1  # method and path columns; no HTTP version is recorded
                elif isinstance(source_request, str) and _present(source_request):
                    first = source_request.split("\n", 1)[0].removesuffix("\r").strip(" ")
                    key = "http_request_line" if first.rpartition(" ")[-1].startswith("HTTP/") else "http_request_summary"
                    f[key] += 1
            code = event.get("status_code")
            f["http_response"] += type(code) is int and 100 <= code <= 599
            f["session_id"] += _present(event.get("session_id"))
            f["reported_alert"] += _present(ext.get("공격명"))
            obs = (event.get("ext") or {}).get("observation") or {}
            if obs.get("producer") == "saw" and obs.get("version") == "connection-observation/1":
                f["verified_context"] += (obs.get("context") or {}).get("resolved") is True
                counters = obs.get("counters") or {}
                f["verified_counters"] += all((counters.get(key) or {}).get("state") == "observed"
                    for key in ("src_to_dst_bytes", "dst_to_src_bytes"))
                f["verified_time"] += (obs.get("time_profile") or {}).get("verified") is True
                f["record_kind"] += obs.get("record_kind") in {"session_start", "session_interim", "session_end"}
    finally:
        close = getattr(source, "close", None)
        if close:
            close()
    formats = []
    for group in sorted(groups.values(), key=lambda row: row["format"]):
        count, fields = group["records"], dict(group["fields"])
        limitations = ["no_ground_truth", "collection_scope_requires_confirmation"]
        for field, reason in (("verified_context", "unverified_context"),
                              ("verified_counters", "unverified_counter_semantics"),
                              ("verified_time", "unverified_time_semantics"),
                              ("record_kind", "missing_record_kind"),
                              ("session_id", "missing_session_id"),
                              ("timestamp", "missing_timestamp")):
            if fields[field] < count:
                limitations.append(reason)
        if fields["opaque_destination"]:
            limitations.append("opaque_destination")
        if fields["reported_alert"]:
            limitations.append("reported_alert_is_not_truth")
        if len(group["devices"]) > 1:
            limitations.append("multiple_source_devices")
        if group["format"] == "ndr" and fields["http_request"] < count:
            limitations.append("not_all_rows_are_http")
        formats.append({"format": group["format"], "records": count, "fields": fields,
                        "source_devices": len(group["devices"]),
                        "source_devices_limited": group["devices_limited"], "limitations": limitations})
    return {"schema": "csv-readiness/1", "status": status if checked or status != "complete" else "not_applicable",
            "counts": {"records": checked}, "formats": formats,
            "limits": {"max_records": limit, "coverage_complete": status == "complete",
                       "device_count_limit": MAX_DEVICES},
            "interpretation": "자료 준비도이며 탐지 실행·정오탐 정답·침해 여부 판정이 아닙니다."}


class CsvReadiness:
    id = "csv.readiness"
    version = "1.0.0"
    category = "quality.csv"
    stage = "observation"
    data_sources = frozenset({"connection", "web"})

    def run(self, ctx):
        filters = [Filter(field="parser", op="in", value=list(PARSERS))]
        events = ctx.events.iterate(ctx.investigation_id, filters, batch=500)
        result = inspect_events(events, cancelled=ctx.params.get("cancelled"))
        result["input_records"] = ctx.events.count(ctx.investigation_id, filters)
        ctx.params.setdefault("execution_reports", {})[self.id] = result
        return []
