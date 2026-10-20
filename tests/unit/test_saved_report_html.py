"""A no-match FW report still explains measured scope and missing semantics."""
from types import SimpleNamespace
from saw.reports.html import render


def test_fw_summary_and_counter_states_are_visible_without_findings():
    row = SimpleNamespace(version=1, content_sha256="a" * 64, content={
        "investigation": {"title": "<synthetic>", "org_unit": "A"},
        "analysis": {"version": 1, "status": "partial", "findings": [], "executions": [{
            "detector_id": "fw.observation", "detector_version": "1", "status": "partial",
            "input_count": 3, "match_count": 0, "detail": {
                "counts": {"records": 3, "sessions": 1, "new_connections": 1, "deny_attempts": 0,
                           "unresolved_records": 0, "omitted_sessions": 0, "omitted_candidates": 0},
                "sessions": [{"record_count": 3, "src_to_dst_bytes": 300, "dst_to_src_bytes": None,
                              "duration_seconds": 120, "action": "allowed", "event_refs": []}],
                "quality": {"counter_unknown": 1}, "limits": {"coverage_complete": True},
                "limitations": []}}],
        }, "checks": [], "limits": ["미확인"]})
    html = render(row)
    assert "원본 기록 3건" in html and "관측 세션 1개" in html
    assert "출발지 → 목적지" in html and "300" in html
    assert "미산출" in html and "일부만 완료" in html
    assert "&lt;synthetic&gt;" in html and "<synthetic>" not in html
    assert "원문 위치" in html


def test_scoped_candidates_include_reason_metrics_and_raw_refs():
    row = SimpleNamespace(version=1, content_sha256="a" * 64, content={
        "investigation": {"title": "Synthetic scoped", "org_unit": "A"},
        "analysis": {"version": 1, "status": "complete", "findings": [], "executions": [{
            "detector_id": "fw.observation", "detector_version": "1", "status": "complete",
            "input_count": 6, "match_count": 1, "detail": {
                "candidates": [{"kind": "scan", "metrics": {"distinct_destinations": 6},
                    "event_refs": [{"event_id": "evt-synthetic", "raw_ref": {"line": 12}}]}]}}]},
        "checks": [], "limits": ["<untrusted>"]})
    html = render(row)
    assert "복수 목적지·포트 탐색 가능성" in html
    assert "distinct_destinations" in html and "evt-synthetic" in html
    assert "저장된 후보 결과가 없습니다" not in html
    assert "&lt;untrusted&gt;" in html and "<untrusted>" not in html
