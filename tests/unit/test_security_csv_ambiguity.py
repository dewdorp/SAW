"""Overlapping FW/NDR headers resolve by meaning; one bad row never stops the rows around it."""
from saw.parsers.registry import detect, parse_text
from tests.unit.test_security_csv import FW, NDR, document, row


def test_ndr_export_with_a_firewall_column_and_no_alert_column_stays_ndr():
    """PPA-01: NDR without 공격명 plus TCP플래그 tied with FW at 0.97 and registration order picked FW."""
    headers = [h for h in NDR if h != "공격명"] + ["TCP플래그"]
    text = document(headers, row(), row(세션ID="synthetic-session-2"))
    found = detect(text.splitlines())
    assert found.parser_id == "ko_ndr_csv", found.candidates
    scores = {c["parser_id"]: c["confidence"] for c in found.candidates}
    assert scores["ko_ndr_csv"] > scores.get("ko_fw_csv", 0) > scores.get("csv", 0)
    auto = parse_text(text)["events"][0]
    forced = parse_text(text, parser_id="ko_ndr_csv")["events"][0]
    for field in ("method", "uri", "status_code", "session_id"):
        assert auto.get(field) == forced.get(field) and auto.get(field) not in (None, ""), field
    # A plain firewall export is still a firewall export.
    assert detect(document(FW).splitlines()).parser_id == "ko_fw_csv"


def test_one_bad_row_is_isolated_and_the_rows_around_it_are_kept():
    """PPA-02: an impossible offset, date or port in one row must not stop the file."""
    for bad in (row(탐지시간="2026-10-25T12:00:01+25:00"), row(탐지시간="2026-02-30 12:00:01"),
                row(목적지포트="²"), row(탐지시간="2026-13-01 12:00:01")):
        out = parse_text(document(FW, row(), bad, row(출발지포트="23456")))
        assert len(out["events"]) + out["failed"] == 3, (bad, out["failure_samples"])
        assert len(out["events"]) >= 2
        kept = [e for e in out["events"] if e.get("src_port") == 23456]
        assert kept, "the row after the bad one must still be parsed"
        for e in out["events"]:
            # A month that does not exist is never moved to another month.
            assert not str(e.get("timestamp") or "").startswith("2026-01-01"), e.get("timestamp")


def test_a_bad_row_in_an_uploaded_file_keeps_the_job_and_the_good_rows(analyst):
    """PPA-02 through the real ingest path: the job completes, the good rows are stored, the bad one is named."""
    from tests.api.test_text_uploads import _process

    inv = analyst.post("/investigations", json={"title": "partial rows"}).json()
    data = document(FW, row(), row(탐지시간="2026-10-25T12:00:01+25:00"), row(출발지포트="23456")).encode("cp949")
    job = _process(analyst, inv["id"], "fw.csv", data)
    f = job["files"][0]
    assert f["parser_id"] == "ko_fw_csv" and f["events_parsed"] == 3, f
    events = analyst.post(f"/investigations/{inv['id']}/query/events", json={"filters": [], "limit": 10}).json()["events"]
    assert len(events) == 3 and sum(1 for e in events if not e.get("timestamp")) == 1
