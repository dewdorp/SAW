from copy import deepcopy
import re

from saw.behavior.report import render_report


def result_dto():
    return {
        "id": "br-1", "version": 3, "job_id": "job-1", "created_at": "2026-10-16T00:00:00Z",
        "created_by": "analyst", "result_sha256": "a" * 64,
        "result": {
            "schema": "saw.behavior.result.v1",
            "scope": {"filters": [{"field": "data_source", "op": "is", "value": "waf"}],
                      "time": None, "ips": ["192.0.2.1"], "role": "src"},
            "methodology": {"version": "saw-web-behavior/1.0"},
            "profile": {"id": "theori-reference-v1", "label": "WhitepaperReference",
                        "thresholds": {"requests_10s": 30}},
            "source_manifest": {"files": [{"id": "f1", "sha256": "b" * 64}]},
            "observations": {
                "summary": {"count": 31, "first": "2026-10-16T00:00:00Z",
                            "last": "2026-10-16T00:00:09Z", "methods": {"GET": 31},
                            "services": ["app.test:443"], "status_codes": {"404": 17},
                            "actions": {"allowed": 31}, "unique_paths": 9, "user_agents": None},
                "quality": {"user_agent": {"present": 0, "not_collected": 31}},
                "metrics": [
                    {"id": "requests_10s", "label": "요청 수", "window_seconds": 10, "value": 31,
                     "data_state": "available", "result": "threshold_met",
                     "reference_threshold": 30, "applied_threshold": 30, "excluded_count": 0,
                     "eligible_count": 31, "partial_window": True, "evidence_ids": ["e1"],
                     "window": {"start": "2026-10-16T00:00:00Z",
                                "end_exclusive": "2026-10-16T00:00:10Z",
                                "src_ip": "192.0.2.1", "service": "app.test:443"}},
                    {"id": "ua_600s", "label": "UA 수", "window_seconds": 600, "value": None,
                     "data_state": "not_collected", "result": "unavailable", "window": None,
                     "reference_threshold": 2, "applied_threshold": 2, "evidence_ids": [],
                     "excluded_count": 0, "eligible_count": 0, "partial_window": True}],
                "timeline": {"interval_seconds": 10, "timezone": "UTC", "coverage_label": "수집 WAF 이벤트",
                             "buckets": [{"start": "2026-10-16T00:00:00Z",
                                          "end_exclusive": "2026-10-16T00:00:10Z",
                                          "count": 31, "status404": 17, "blocked": 0, "allowed": 31,
                                          "ua_values": None}], "annotations": []},
                "indicators": [{"id": "tool", "label": "<script>alert(1)</script>",
                                "state": "observed", "count": 1, "source": "user_agent",
                                "verification": "문자열 일치", "conditions": ["해당 필드 수집"],
                                "evidence_ids": ["e1"], "limits": ["도구 실행 여부는 확인하지 않음"]}],
                "followups": [{"id": "origin", "target": "웹 서버", "needed_data": ["처리 로그"],
                               "items": ["응답 이후 처리 결과 확인"], "conditions": ["허용 요청 관측"]}],
                "limits": ["수집 연속성 미확인"], "execution": {"scanned": 31, "processed": 31,
                    "truncated": False, "reason": None, "limits": {"max_events": 100000}}},
            "selected_evidence": [{"event_id": "e1", "sha256": "c" * 64, "raw_sha256": "d" * 64,
                                  "event": {"uri": "/?x=<img src=x onerror=alert(1)>",
                                            "secret_unlisted": "do-not-render"}}]}}


def test_report_uses_frozen_values_and_nine_sections_without_mutating_input():
    dto = result_dto()
    before = deepcopy(dto)
    html = render_report(dto)
    assert dto == before
    assert len(re.findall(r"<section\b", html)) == 9
    assert 'data-metric-id="requests_10s"' in html
    assert 'data-value="31"' in html
    assert 'data-count="31"' in html
    assert "WhitepaperReference" in html
    assert "2026-10-16T00:00:10Z" in html
    assert "미수집" in html and "부분 시간창" in html
    assert "A4" in html and "<svg" in html and "<figcaption>" in html
    assert "<script" not in html and "<link" not in html
    assert "https://" not in html and "http://" not in html.replace("http://www.w3.org/2000/svg", "")


def test_report_escapes_untrusted_values_and_keeps_analyst_interpretation_separate():
    dto = result_dto()
    html = render_report(dto, analyst_checks=[
        {"id": "c1", "state": "active", "note": "<b>승인된 점검</b>", "judgement": "normal",
         "author": "tester", "behavior": {"result_id": "br-1", "answer_status": "answered"}},
        {"id": "c2", "state": "cancelled", "note": "cancelled-note"},
    ])
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&lt;b&gt;승인된 점검&lt;/b&gt;" in html
    assert "분석가 해석" in html and "계산된 관측값" in html
    assert "cancelled-note" not in html and "do-not-render" not in html
    assert "<img" not in html
    assert "침해 확정" not in html


def test_report_marks_unavailable_and_truncation_explicitly():
    dto = result_dto()
    dto["result"]["observations"]["execution"].update(truncated=True, reason="max_events")
    html = render_report(dto)
    assert "제한으로 중단" in html and "max_events" in html
    unavailable = re.search(r'<tr data-metric-id="ua_600s".*?</tr>', html, re.S).group()
    assert 'data-value=""' in unavailable
    assert "미수집" in unavailable
    assert "<td>—</td>" in unavailable


def test_report_distinguishes_global_ua_peak_from_condition_qualifying_window():
    dto = result_dto()
    metric = dto["result"]["observations"]["metrics"][1]
    metric.update(value=5, data_state="available", result="threshold_met",
                  status404_in_window=0, required_status404=2,
                  qualifying_window={"start": "2026-10-16T02:00:00Z",
                                     "end_exclusive": "2026-10-16T02:10:00Z",
                                     "value": 2, "status404": 2, "evidence_ids": ["e1"]})
    html = render_report(dto)
    assert "동반 조건 충족 구간" in html
    assert "2026-10-16T02:00:00Z" in html
    assert 'data-value="5"' in html
    assert "UA 2 / 404 2" in html


def test_report_renders_readable_source_file_coverage():
    dto = result_dto()
    dto["result"]["source_manifest"] = {"evidence": [{"evidence_id": "src1", "files": [
        {"id": "f1", "display_name": "synthetic.log", "parser_id": "web", "parse_status": "done",
         "events_parsed": 31, "events_failed": 2, "timezone": None}
    ]}]}
    html = render_report(dto)
    assert "<td>synthetic.log</td>" in html
    assert "<td>web</td>" in html
    assert "미기록" in html


def test_report_renders_versioned_followup_contract_with_escaped_question():
    dto = result_dto()
    question = dto["result"]["observations"]["followups"][0]
    question.update(
        question_version="saw-web-behavior-questions/1.0",
        question="<script>질문</script>처리 결과가 확인되었는가?",
        allowed_actions=["보존된 로그 읽기 전용 대조"],
        resolution_criteria=["원본 처리 결과와 담당자 확인 일치"],
        if_unresolved="후속확인 상태 유지",
        forbidden_claims=["2xx만으로 실행 성공 단정 금지"],
    )
    before = deepcopy(dto)
    html = render_report(dto)
    assert dto == before
    for value in ("saw-web-behavior-questions/1.0", "&lt;script&gt;질문&lt;/script&gt;",
                  "보존된 로그 읽기 전용 대조", "원본 처리 결과와 담당자 확인 일치",
                  "후속확인 상태 유지", "2xx만으로 실행 성공 단정 금지"):
        assert value in html
    assert "<script>질문</script>" not in html
    assert len(re.findall(r"<section\b", html)) == 9


def test_report_marks_absent_followup_metadata_without_inventing_a_version():
    html = render_report(result_dto())
    assert "질문 버전" in html
    assert "이 저장 결과에는 미기록" in html
    assert "응답 이후 처리 결과 확인" in html
    assert "saw-web-behavior-questions/1.0" not in html
