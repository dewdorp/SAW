"""Synthetic Korean security-export contracts; no operational input is used."""
from __future__ import annotations

import csv
import io

import pytest

from saw.parsers.base import Failed, Parsed, Skip
from saw.parsers.registry import detect, get_parser, iter_lines, parse_text, sniff_encoding, to_ces

FW = ["탐지시간", "그룹명", "장비IP", "대응", "출발지IP", "출발지포트", "목적지IP", "목적지포트", "프로토콜", "TCP플래그", "세션시간", "송신바이트", "수신바이트", "총패킷수", "송신패킷수", "수신패킷수"]
NDR = ["탐지시간", "로그구분", "그룹명", "장비IP", "대응", "출발지IP", "출발지포트", "출발지국가", "목적지IP", "목적지포트", "프로토콜", "세션ID", "송신바이트", "수신바이트", "요청헤더", "호스트명", "응답값", "User-agent", "공격명"]


def row(**overrides):
    return {"탐지시간": "2026-10-25 12:00:01", "그룹명": "가상그룹", "장비IP": "192.0.2.10",
            "대응": "탐지", "출발지IP": "192.0.2.20", "출발지포트": "12345",
            "목적지IP": "opaque-destination", "목적지포트": "443", "프로토콜": "TCP",
            "TCP플래그": "S", "세션시간": "1234", "송신바이트": "12", "수신바이트": "34",
            "총패킷수": "9", "송신패킷수": "4", "수신패킷수": "5", "로그구분": "가상로그",
            "출발지국가": "ZZ", "세션ID": "synthetic-session", "요청헤더": "GET /sample?q=1 HTTP/1.1",
            "호스트명": "synthetic.invalid", "응답값": "200", "User-agent": "synthetic-client",
            "공격명": "synthetic attack label", **overrides}


def document(headers, *rows):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\r\n")
    writer.writerow(headers)
    for values in rows or (row(),):
        writer.writerow([values.get(name, "") for name in headers])
    return stream.getvalue()


def event(headers=NDR, **values):
    result = parse_text(document(headers, row(**values)))
    assert result["failed"] == 0
    assert len(result["events"]) == 1
    return result["events"][0]


@pytest.mark.parametrize(("headers", "parser_id", "kind"), [(FW, "ko_fw_csv", "fw"), (NDR, "ko_ndr_csv", "ndr")])
def test_exact_headers_select_security_adapter_and_preserve_originals(headers, parser_id, kind):
    result = parse_text(document(headers))
    assert result["parser"] == parser_id
    ev = result["events"][0]
    assert ev["product"] == "security_csv"
    assert ev["ext"]["security_csv"]["csv_format"] == kind
    assert ev["ext"]["security_csv"]["장비IP"] == "192.0.2.10"
    assert ev["src_ip"] == "192.0.2.20"
    assert ev["dst_ip"] == "opaque-destination"
    assert ev["dst_ip_scope"] == "invalid"
    assert "dst_geo_country" not in ev
    assert ev["timestamp"] == "2026-10-25T03:00:01.000Z"
    assert ev["bytes_out"] == 12
    assert ev["bytes_in"] == 34


@pytest.mark.parametrize(("headers", "parser_id"), [(FW, "ko_fw_csv"), (NDR, "ko_ndr_csv")])
def test_reordered_header_and_unknown_columns_preserve_values(headers, parser_id):
    headers = ["extra-field", *reversed(headers)]
    ev = event(headers, **{"extra-field": 'unknown,"quoted" value'})
    assert ev["parser"] == parser_id
    assert ev["ext"]["security_csv"]["extra-field"] == 'unknown,"quoted" value'


@pytest.mark.parametrize(("headers", "parser_id"), [(FW, "ko_fw_csv"), (NDR, "ko_ndr_csv")])
def test_missing_wrong_or_duplicate_required_header_never_claims_format(headers, parser_id):
    parser = get_parser(parser_id)
    for name in headers:
        for invalid in ([h for h in headers if h != name],
                        ["wrong-column" if h == name else h for h in headers],
                        [*headers, name]):
            text = document(invalid)
            assert parser.detect(text.splitlines()) == 0
            parser.reset()
            assert isinstance(parser.parse_line(text.splitlines()[0]), Failed)
            assert isinstance(parser.parse_line(text.splitlines()[1]), Failed)


@pytest.mark.parametrize("parser_id", ["ko_fw_csv", "ko_ndr_csv"])
def test_arbitrary_generic_csv_not_claimed(parser_id):
    assert get_parser(parser_id).detect(["timestamp,src_ip,dst_ip", "x,a,b"]) == 0


@pytest.mark.parametrize("headers", [FW, NDR])
@pytest.mark.parametrize("encoding", ["cp949", "utf-8-sig"])
def test_byte_references_include_quoted_multiline_records(headers, encoding):
    values = row(**{"extra-field": "가상 첫줄\n가상 둘째줄"})
    text = document([*headers, "extra-field"], values, row(**{"extra-field": "second"}))
    source = text.encode(encoding)
    parser_id = "ko_fw_csv" if headers == FW else "ko_ndr_csv"
    parser = get_parser(parser_id)
    encoding_detected = sniff_encoding(source)
    records = list(parser.parse(iter_lines([source[:27], source[27:100], source[100:]], encoding_detected)))
    events = [(rl, parsed) for rl, parsed in records if isinstance(parsed, Parsed)]
    assert len(events) == 2
    rl, parsed = events[0]
    expected_start = source.index(b"\n") + 1
    expected_end = source.index(b"\r\n", source.index("가상 둘째줄".encode(encoding_detected))) + 2
    assert rl.offset == expected_start
    assert rl.line_no == 2
    assert rl.length == expected_end - expected_start - 2
    assert source[rl.offset:rl.offset + rl.length].decode(encoding_detected).endswith('가상 둘째줄"')
    assert parsed.ext["extra-field"] == "가상 첫줄\n가상 둘째줄"
    ev = to_ces(parser, rl, parsed, investigation_id="synthetic", evidence_id=None,
                file_id="synthetic-file", source_file="synthetic.csv", object_key="synthetic-object", assumed_tz="Asia/Seoul")
    assert ev["raw_ref"] == {"offset": expected_start, "length": rl.length, "line_no": 2,
                             "object_key": "synthetic-object"}


def test_mixed_ndr_rows_only_valid_request_becomes_http():
    result = parse_text(document(NDR, row(), row(요청헤더="TLS application data", 응답값="200")))
    assert [(ev["data_source"], ev["event_type"]) for ev in result["events"]] == [
        ("web", "http_access"), ("connection", "conn")]
    http, connection = result["events"]
    assert http["method"] == "GET"
    assert http["uri"] == "/sample?q=1"
    assert http["status_code"] == 200
    assert http["session_id"] == connection["session_id"] == "synthetic-session"
    assert http["hostname"] == "synthetic.invalid"
    assert connection.get("method") is None
    assert connection.get("uri") is None
    assert connection.get("status_code") is None


@pytest.mark.parametrize("request_header", ["", "-", "GET /sample HTTP/1.1 trailing",
                                    "GET /bad path HTTP/1.1", "GET\t/sample\tHTTP/1.1",
                                    "garbage", "Host: synthetic.invalid", "GET relative HTTP/1.1",
                                    "GET /sample HTTP/no", "\x00GET /sample HTTP/1.1"])
def test_malformed_request_remains_connection(request_header):
    ev = event(요청헤더=request_header)
    assert (ev["data_source"], ev["event_type"]) == ("connection", "conn")
    assert ev.get("method") is None
    assert ev.get("uri") is None
    assert ev.get("status_code") is None
    assert ev["ext"]["security_csv"]["요청헤더"] == request_header


@pytest.mark.parametrize(("request_header", "method", "uri"), [
    ("POST /submit HTTP/1.0\r\nHost: synthetic.invalid", "POST", "/submit"),
    ("OPTIONS * HTTP/1.1", "OPTIONS", "*"),
    ("CONNECT synthetic.invalid:443 HTTP/1.1", "CONNECT", "synthetic.invalid:443"),
    ("GET https://synthetic.invalid/example HTTP/1.1", "GET", "https://synthetic.invalid/example"),
])
def test_valid_http_request_line_preserves_target(request_header, method, uri):
    ev = event(요청헤더=request_header)
    assert (ev["data_source"], ev["event_type"]) == ("web", "http_access")
    assert ev["method"] == method
    assert ev["uri"] == uri


@pytest.mark.parametrize(("response", "expected"), [("100", 100), ("599", 599), (" 204 ", 204),
    ("", None), ("-", None), ("99", None), ("600", None), ("0200", None), ("200 OK", None),
    ("HTTP/1.1 200", None), ("200.0", None), ("+200", None), ("２００", None)])
def test_http_status_is_strict_ascii_three_digit_range(response, expected):
    ev = event(응답값=response)
    assert ev.get("status_code") == expected
    assert ev["ext"]["security_csv"]["응답값"] == response


@pytest.mark.parametrize(("action", "expected"), [("차단", "blocked"), ("허용", "allowed"),
                                                ("탐지", None), ("detected", None), ("", None)])
def test_only_explicit_appliance_action_is_normalized(action, expected):
    ev = event(대응=action, 공격명="synthetic compromise label")
    assert ev.get("enforcement_action") == expected
    assert ev["ext"]["security_csv"]["대응"] == action
    assert ev["ext"]["security_csv"]["공격명"] == "synthetic compromise label"
    assert not ev.get("tags")
    assert not ev.get("ground_truth")


def test_firewall_preserves_unverified_duration_and_packet_semantics():
    ev = event(FW)
    assert (ev["data_source"], ev["event_type"]) == ("connection", "conn")
    for field in ("duration", "orig_pkts", "resp_pkts", "status_code", "method", "uri", "session_id"):
        assert ev.get(field) is None
    assert ev["ext"]["security_csv"]["세션시간"] == "1234"
    assert ev["ext"]["security_csv"]["총패킷수"] == "9"
    assert ev["ext"]["security_csv"]["송신패킷수"] == "4"


def test_security_adapters_do_not_override_approved_user_parser(monkeypatch):
    from saw.parsers import registry
    from saw.parsers.base import BaseParser

    class Approved(BaseParser):
        id = "u:synthetic@1"

        def detect(self, sample):
            return 0.995

    monkeypatch.setattr(registry, "_user_parsers", lambda: [Approved()])
    assert detect(document(NDR).splitlines()).parser_id == "u:synthetic@1"


def test_header_is_reset_between_files_and_invalid_rows_fail_closed():
    parser = get_parser("ko_ndr_csv")
    text = document(NDR)
    assert isinstance(parser.parse_line(text.splitlines()[0]), Skip)
    assert isinstance(parser.parse_line("a,b"), Failed)
    assert isinstance(parser.parse_line(text.splitlines()[1] + ",unexpected"), Failed)
    assert isinstance(list(parser.parse(iter_lines([text.encode()])))[1][1], Parsed)
    bad = document(FW).encode()
    assert all(not isinstance(result, Parsed) for _, result in parser.parse(iter_lines([bad])))


@pytest.mark.parametrize(("headers", "parser_id"), [(FW, "ko_fw_csv"), (NDR, "ko_ndr_csv")])
def test_case_variant_of_required_header_fails_closed_before_unique_names(headers, parser_id):
    for ambiguous in (["출발지ip", *headers], [*headers, "출발지ip"]):
        parser = get_parser(parser_id)
        text = document(ambiguous)
        assert parser.detect(text.splitlines()) == 0
        assert isinstance(parser.parse_line(text.splitlines()[0]), Failed)


def test_reserved_format_metadata_cannot_overwrite_original_extra_columns():
    ev = event([*NDR, "csv_format", "original_csv_format", "source_columns"],
               csv_format="source-format", original_csv_format="other-source", source_columns="source-value")
    ext = ev["ext"]["security_csv"]
    assert ext["csv_format"] == "ndr"
    assert ext["source_columns"]["csv_format"] == "source-format"
    assert ext["source_columns"]["original_csv_format"] == "other-source"
    assert ext["source_columns"]["source_columns"] == "source-value"


@pytest.mark.parametrize("request_header", [
    "  GET /padded?q=1 HTTP/1.1",
    "GET /padded?q=1 HTTP/1.1   ",
    "  GET /padded?q=1 HTTP/1.1  ",
    "  GET /padded?q=1 HTTP/1.1  \r\nHost: synthetic.invalid\r\n",
])
def test_export_padding_spaces_at_request_line_boundaries_preserve_original(request_header):
    parser = get_parser("ko_ndr_csv")
    text = document(NDR, row(요청헤더=request_header, 응답값=" 204 "))
    header, _, body = text.partition("\r\n")
    assert isinstance(parser.parse_line(header), Skip)
    parsed = parser.parse_line(body.removesuffix("\r\n"))
    assert isinstance(parsed, Parsed)
    assert (parsed.fields["data_source"], parsed.fields["event_type"]) == ("web", "http_access")
    assert parsed.fields["method"] == "GET"
    assert parsed.fields["uri"] == "/padded?q=1"
    assert parsed.fields["status_code"] == 204
    assert parsed.ext["요청헤더"] == request_header
    assert parsed.ext["응답값"] == " 204 "


@pytest.mark.parametrize("request_header", [
    " ", "   ", "\t ", "   \r\n", " \r\nGET /later HTTP/1.1",
    "  GET  /sample HTTP/1.1  ", "  GET /bad path HTTP/1.1  ",
    "  GET\t/sample\tHTTP/1.1  ", "\tGET /sample HTTP/1.1",
    "GET /sample HTTP/1.1\t", "  GET /sample HTTP/1.1\r  ",
])
def test_padding_does_not_invent_requests_or_collapse_internal_whitespace(request_header):
    parser = get_parser("ko_ndr_csv")
    text = document(NDR, row(요청헤더=request_header))
    header, _, body = text.partition("\r\n")
    assert isinstance(parser.parse_line(header), Skip)
    parsed = parser.parse_line(body.removesuffix("\r\n"))
    assert isinstance(parsed, Parsed)
    assert (parsed.fields["data_source"], parsed.fields["event_type"]) == ("connection", "conn")
    assert "method" not in parsed.fields
    assert "uri" not in parsed.fields
    assert "status_code" not in parsed.fields
    assert parsed.ext["요청헤더"] == request_header


@pytest.mark.parametrize("target", ["/sample", "*", "http://example.test", "https://example.test"])
def test_connect_rejects_non_authority_request_targets(target):
    ev = event(요청헤더=f"CONNECT {target} HTTP/1.1")
    assert (ev["data_source"], ev["event_type"]) == ("connection", "conn")
    assert ev.get("method") is None
    assert ev.get("uri") is None
    assert ev.get("status_code") is None


@pytest.mark.parametrize("target", ["synthetic.invalid:443", "192.0.2.1:8443", "[2001:db8::1]:443"])
def test_connect_accepts_authority_request_targets(target):
    ev = event(요청헤더=f"CONNECT {target} HTTP/1.1")
    assert (ev["data_source"], ev["event_type"]) == ("web", "http_access")
    assert ev["method"] == "CONNECT"
    assert ev["uri"] == target


@pytest.mark.parametrize(("headers", "parser_id", "kind"), [(FW, "ko_fw_csv", "fw"), (NDR, "ko_ndr_csv", "ndr")])
def test_largest_claimed_header_preserves_late_required_columns_and_marker(headers, parser_id, kind):
    extras = [f"extra-{index}" for index in range(199 - len(headers))]
    source = row(**dict.fromkeys(extras, "synthetic extra"))
    ev = event([*extras, *headers], **source)
    assert ev["parser"] == parser_id
    assert len(ev["ext"]["security_csv"]) == 200
    assert ev["ext"]["security_csv"]["csv_format"] == kind
    assert ev["ext"]["security_csv"]["장비IP"] == "192.0.2.10"
    assert ev["ext"]["security_csv"]["extra-0"] == "synthetic extra"


@pytest.mark.parametrize(("headers", "parser_id"), [(FW, "ko_fw_csv"), (NDR, "ko_ndr_csv")])
@pytest.mark.parametrize("width", [200, 220])
def test_excess_columns_fail_closed_before_registry_extension_truncation(headers, parser_id, width):
    extras = [f"extra-{index}" for index in range(width - len(headers))]
    text = document([*extras, *headers])
    parser = get_parser(parser_id)
    assert parser.detect(text.splitlines()) == 0
    assert isinstance(parser.parse_line(text.splitlines()[0]), Failed)
    assert isinstance(parser.parse_line(text.splitlines()[1]), Failed)


def test_largest_claimed_header_retains_reserved_metadata_collision_originals():
    extras = [f"extra-{index}" for index in range(199 - len(NDR) - 2)]
    headers = [*extras, "csv_format", "source_columns", *NDR]
    ev = event(headers, csv_format="source-format", source_columns="source-value")
    ext = ev["ext"]["security_csv"]
    assert len(ext) == 199
    assert ext["csv_format"] == "ndr"
    assert len(ext["source_columns"]) == 199
    assert ext["source_columns"]["csv_format"] == "source-format"
    assert ext["source_columns"]["source_columns"] == "source-value"
    assert ext["source_columns"]["장비IP"] == "192.0.2.10"


@pytest.mark.parametrize("method", ["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE"])
@pytest.mark.parametrize("padding", ["", "  "])
def test_recorded_origin_form_request_summary_routes_http_without_inventing_version(method, padding):
    request_header = f"{padding}{method} /summary?q=1{padding}"
    ev = event(요청헤더=request_header)
    assert (ev["data_source"], ev["event_type"]) == ("web", "http_access")
    assert ev["method"] == method
    assert ev["uri"] == "/summary?q=1"
    assert ev["status_code"] == 200
    assert ev["protocol"] == "TCP"
    assert "http_version" not in ev
    assert ev["ext"]["security_csv"]["요청헤더"] == request_header
    assert request_header in ev["raw_event"]


def test_recorded_request_summary_accepts_root_origin_target():
    ev = event(요청헤더="HEAD /")
    assert (ev["data_source"], ev["event_type"]) == ("web", "http_access")
    assert ev["method"] == "HEAD"
    assert ev["uri"] == "/"


@pytest.mark.parametrize("request_header", [
    "get /summary", "UNKNOWN /summary", "PROPFIND /summary", "/summary",
    "CONNECT synthetic.invalid:443", "CONNECT /summary", "OPTIONS *",
    "GET https://synthetic.invalid/summary", "GET relative",
    "GET  /summary", "GET\t/summary", "GET /bad path", "GET /bad\x00path",
    "GET /summary HTTP/no", "GET /summary HTTP/1.1 trailing", "GET /summary trailing",
    "GET /summary\t", "GET /summary#fragment", "GET /summary\rtrailing",
])
def test_invalid_or_unsupported_request_summary_remains_connection(request_header):
    # Exercise the CSV record directly: pasted text normalizes physical newline separators.
    parser = get_parser("ko_ndr_csv")
    text = document(NDR, row(요청헤더=request_header))
    header, _, body = text.partition("\r\n")
    assert isinstance(parser.parse_line(header), Skip)
    parsed = parser.parse_line(body.removesuffix("\r\n"))
    assert isinstance(parsed, Parsed)
    assert (parsed.fields["data_source"], parsed.fields["event_type"]) == ("connection", "conn")
    assert "method" not in parsed.fields
    assert "uri" not in parsed.fields
    assert "status_code" not in parsed.fields
    assert parsed.ext["요청헤더"] == request_header


@pytest.mark.parametrize(("headers", "parser_id"), [(FW, "ko_fw_csv"), (NDR, "ko_ndr_csv")])
@pytest.mark.parametrize(("destination", "scope"), [
    ("10.20.30.40", "internal"),
    ("8.8.8.8", "external"),
    ("fd12:3456:789a::40", "internal"),
    ("2606:4700:4700::1111", "external"),
])
def test_normal_destination_ips_preserve_address_scope_without_organizational_attribution(
        headers, parser_id, destination, scope):
    ev = event(headers, 목적지IP=destination)
    assert ev["parser"] == parser_id
    assert ev["dst_ip"] == destination
    assert ev["dst_port"] == 443
    assert ev["dst_ip_scope"] == scope
    assert ev["ext"]["security_csv"]["목적지IP"] == destination
    observation = ev["ext"]["observation"]
    assert observation["context"]["resolved"] is False
    assert observation["context"]["org_unit_id"] is None
    assert observation["context"]["device_id"] is None
    assert observation["context"]["network"] is None
    assert observation["profile_version"] is None
    assert "unresolved_context" in observation["quality"]
    device = ev["ext"]["device_observation"]
    assert device["dst_ip"] == destination
    assert device["verified"] is False
    assert device["observation_point"] is None
    assert device["mode"] == "unknown"


@pytest.mark.parametrize("combined_first", [False, True])
def test_reserved_source_columns_has_stable_object_shape_across_export_files(combined_first):
    only = document([*NDR, "source_columns"], row(source_columns="source-only"))
    combined = document([*NDR, "source_columns", "csv_format"],
                        row(source_columns="combined", csv_format="recorded-source-format"))
    texts = [combined, only] if combined_first else [only, combined]
    extensions = [parse_text(text)["events"][0]["ext"]["security_csv"] for text in texts]
    for ext, source_label in zip(extensions, ["combined", "source-only"] if combined_first else
                                ["source-only", "combined"], strict=True):
        assert isinstance(ext["source_columns"], dict)
        assert ext["source_columns"]["source_columns"] == source_label
        assert ext["csv_format"] == "ndr"


@pytest.mark.parametrize(("headers", "parser_id"), [(FW, "ko_fw_csv"), (NDR, "ko_ndr_csv")])
@pytest.mark.parametrize("extra_name", ["csv_format.x", "source_columns.x", "vendor.extra", "", "   "])
def test_dotted_or_blank_extra_headers_fail_closed_for_typed_namespace(headers, parser_id, extra_name):
    text = document([*headers, extra_name], row(**{extra_name: "synthetic original"}))
    parser = get_parser(parser_id)
    assert parser.detect(text.splitlines()) == 0
    assert isinstance(parser.parse_line(text.splitlines()[0]), Failed)
    assert isinstance(parser.parse_line(text.splitlines()[1]), Failed)


@pytest.mark.parametrize(("headers", "parser_id"), [(FW, "ko_fw_csv"), (NDR, "ko_ndr_csv")])
def test_safe_flat_extra_headers_preserve_original_values(headers, parser_id):
    values = {"ordinary_extra": "alpha", "ordinary-extra": "beta", "추가열": "가상 원본"}
    ev = event([*headers, *values], **values)
    assert ev["parser"] == parser_id
    for name, value in values.items():
        assert ev["ext"]["security_csv"][name] == value
    assert "가상 원본" in ev["raw_event"]
