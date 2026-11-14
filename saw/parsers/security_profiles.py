"""Input profiles for WAF, IPS, DDoS and application (authentication/business) exports.

These are *mappable profiles*, not vendor support: no vendor export was available, so each profile names the
columns SAW needs and keeps every other column as it is. A real export is connected by exporting (or renaming) to
these column names, or by an analyst-defined parser. Nothing here guesses a vendor's own semantics.

Every profile keeps the device's own values apart: the device's detection (alert name, rule id), the device's
action, the HTTP response and the business result are separate columns and never folded into one verdict.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

from saw.parsers.security_csv import _STATUS, _SecurityCsvParser, _http_target

_fallback_key = secrets.token_bytes(32)
_key_cache: dict[str, bytes] = {}


def _ref_key() -> bytes:
    """Per-installation key for linking references, derived from the existing read-cursor key (no new key file)."""
    try:
        from saw import container
        from saw.event_generations.reads import load_cursor_key

        data_dir = str(container.get().settings.data_dir)
        if data_dir not in _key_cache:
            _key_cache[data_dir] = hmac.new(load_cursor_key(data_dir), b"saw.link-ref/1", hashlib.sha256).digest()
        return _key_cache[data_dir]
    except Exception:  # noqa: BLE001 - outside a running application (tests, paste analysis) refs stay process-local
        return _fallback_key


def link_ref(kind: str, value: str) -> str:
    """A reference that links equal secrets (session ids, cookie values) without storing or showing the secret."""
    return hmac.new(_ref_key(), f"{kind}\x00{value}".encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()[:16]


def cookie_refs(cookie: str) -> list[str]:
    """`name=ref` per cookie: which cookie is the session identifier is knowledge an analyst confirms later."""
    out = {}
    for part in cookie.split(";"):
        name, sep, value = part.partition("=")
        name, value = name.strip(), value.strip()
        if name and sep and value and len(name) <= 128:
            out.setdefault(name, f"{name}={link_ref('session', value)}")
    return [out[name] for name in sorted(out)][:50]


def _clean(source: dict, name: str) -> str:
    value = (source.get(name) or "").strip()
    return "" if value == "-" else value


class _HttpAlertParser(_SecurityCsvParser):
    """Shared by the WAF and IPS profiles: an alert about one request or one connection."""
    data_source = "waf"
    event_type = "waf_alert"
    core_headers = frozenset({"event_time", "src_ip", "attack_name"})
    port_headers = frozenset({"src_port", "dest_port"})
    byte_headers: frozenset[str] = frozenset()
    ip_headers = frozenset({"src_ip", "dest_ip"})
    common_fields = {"event_time": "timestamp_raw", "src_ip": "src_ip", "src_port": "src_port", "dest_ip": "dst_ip",
                     "dest_port": "dst_port", "protocol": "protocol"}

    def _specific_fields(self, fields: dict, source: dict) -> None:
        fields.update(data_source=self.data_source, event_type=self.event_type)
        if _clean(source, "attack_name"):
            fields["alert_name"] = _clean(source, "attack_name")[:512]  # the device's own wording, verbatim
        method, path = _clean(source, "method").upper(), _clean(source, "path")
        if method or path:
            fields["uri"] = _http_target(path, _clean(source, "query"))
            if method:
                fields["method"] = method[:16]
        if _clean(source, "host"):
            fields["hostname"] = _clean(source, "host")
        match = _STATUS.fullmatch(_clean(source, "status")) if _clean(source, "status") else None
        if match:
            fields["status_code"] = int(match.group(1))
        raw = source.get("raw_data")
        if raw not in (None, "", "-"):
            # What the column holds (full request, part of it, a packet excerpt) is not known from the export.
            source["raw_data_state"] = "truncated" if _clean(source, "raw_truncated").lower() in {"1", "true", "y", "yes"} \
                else "as_exported"


class WafCsvProfileParser(_HttpAlertParser):
    """WAF alert export profile: detection, the WAF's own action and the request it was raised on."""
    id = "en_waf_csv"
    csv_format = "waf_alert"
    required_headers = frozenset(["event_time", "_device_name", "vendor", "product", "rule_id", "rule_version",
                                  "attack_name", "action", "src_ip", "src_port", "dest_ip", "dest_port", "host",
                                  "method", "path", "query", "status", "request_id", "raw_data"])


class IpsCsvProfileParser(_HttpAlertParser):
    """IPS alert export profile: a signature raised on a connection."""
    id = "en_ips_csv"
    data_source = "ips"
    event_type = "ips_alert"
    csv_format = "ips_alert"
    required_headers = frozenset(["event_time", "_device_name", "vendor", "product", "signature_id",
                                  "signature_version", "attack_name", "action", "src_ip", "src_port", "dest_ip",
                                  "dest_port", "protocol", "flow_id", "raw_data"])


class DdosCsvProfileParser(_SecurityCsvParser):
    """DDoS interval export profile: an aggregate over a service for a period, never one actor's behaviour."""
    id = "en_ddos_csv"
    data_source = "ddos"
    event_type = "ddos_interval"
    csv_format = "ddos_interval"
    required_headers = frozenset(["start_time", "end_time", "_device_name", "target_ip", "target_host", "vector",
                                  "metric", "unit", "value", "interval_seconds", "detection_state",
                                  "mitigation_state"])
    core_headers = frozenset({"start_time", "end_time", "vector"})
    port_headers: frozenset[str] = frozenset()
    byte_headers: frozenset[str] = frozenset()
    ip_headers = frozenset({"target_ip"})
    common_fields = {"start_time": "timestamp_raw", "target_ip": "dst_ip"}

    def _specific_fields(self, fields: dict, source: dict) -> None:
        fields.update(data_source="ddos", event_type="ddos_interval")
        if _clean(source, "target_host"):
            fields["hostname"] = _clean(source, "target_host")
        if _clean(source, "vector"):
            fields["alert_name"] = _clean(source, "vector")[:512]


class AppEventCsvProfileParser(_SecurityCsvParser):
    """Application event export profile (authentication result, business action result).

    This is where a business result comes from: an HTTP status alone never proves it. The session identifier is
    replaced by a linking reference before anything is stored.
    """
    id = "en_app_event_csv"
    data_source = "app"
    event_type = "app_event"
    csv_format = "app_event"
    required_headers = frozenset(["event_time", "service", "event", "result", "account", "session_id", "request_id",
                                  "target", "src_ip"])
    core_headers = frozenset({"event_time", "service", "event"})
    port_headers: frozenset[str] = frozenset()
    byte_headers: frozenset[str] = frozenset()
    ip_headers = frozenset({"src_ip"})
    common_fields = {"event_time": "timestamp_raw", "src_ip": "src_ip"}

    def parse_line(self, line: str):
        self._session = None
        result = super().parse_line(line)
        if self._session and getattr(result, "ext", None) is not None:
            # The stored line keeps the reference only; the original file keeps the identifier.
            result.raw = line.replace(self._session, "[가림]")
        return result

    def _specific_fields(self, fields: dict, source: dict) -> None:
        fields.update(data_source="app", event_type="app_event", hostname=_clean(source, "service") or None)
        if _clean(source, "account"):
            fields["user"] = _clean(source, "account")[:256]
        session = _clean(source, "session_id")
        if session:
            self._session = session
            source["session_ref"] = link_ref("session", session)
            source["session_id"] = "[원본 파일에만 보존]"
