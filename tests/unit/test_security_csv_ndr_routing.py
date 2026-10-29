"""The NDR adapter receives HTTP only when verified device semantics qualify it."""
import pytest

from saw.detectors.base import DetectorContext
from saw.detectors.device_observation import NdrObservation
from saw.devtools.security_csv_samples import ndr_csv
from saw.parsers.base import Parsed
from saw.parsers.registry import get_parser, iter_lines, to_ces
from saw.storage.eventstore import SQLiteEventStore
from tests.unit.test_device_observation import profile


@pytest.mark.parametrize("mode", ["ndr", "unverified", "waf"])
def test_http_rows_reach_configured_ndr_calculator_only_with_ndr_semantics(tmp_path, mode):
    context = profile("WAF" if mode == "waf" else "NDR", "http", capture_kind="mixed")
    context["profile"]["source_fields"].update(timestamp="탐지시간", record_kind="로그구분",
        session_id="session_id", http_status="status_code", uri="uri", user_agent="user_agent", action="대응")
    context["profile"]["record_kind_map"] = {"HTTP": "http", "경보": "alert"}
    context["profile"]["action_map"] = {"탐지": "detected"}
    if mode == "unverified":
        context["profile"]["device_semantics"]["verified"] = False
    parser = get_parser("ko_ndr_csv")
    events = [to_ces(parser, line, parsed, investigation_id="i", evidence_id="e", file_id="f",
              source_file="synthetic.csv", object_key=None, assumed_tz="UTC", context_snapshot=context)
              for line, parsed in parser.parse(iter_lines([ndr_csv()], encoding="cp949")) if isinstance(parsed, Parsed)]
    store = SQLiteEventStore(tmp_path/"events.sqlite")
    try:
        store.index(events)
        ctx = DetectorContext("i", store, data_sources={"web"})
        drafts = NdrObservation().run(ctx)
        report = ctx.params["execution_reports"]["ndr.observation"]
        assert report["counts"]["records"] == 47
        if mode == "ndr":
            assert report["counts"]["http_records"] == 47
            assert report["counts"]["eligible_records"] == 47
            assert any(draft.category == "device.ndr.http_characteristics" for draft in drafts)
        else:
            assert report["counts"]["eligible_records"] == 0
            assert drafts == []
    finally:
        store._conn().close()
