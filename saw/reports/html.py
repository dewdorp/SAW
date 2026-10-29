"""Escaped self-contained report: observations, evidence, then raw references."""
from html import escape

from saw.core.application.provenance import canonical

STATUS = {"complete": "완료", "partial": "일부만 완료", "failed": "실패",
          "insufficient_data": "자료 부족", "not_applicable": "적용 대상 아님", "limited": "범위 제한", "running": "실행 중",
          "cancelled": "취소"}
ACTIONS = {"allowed": "허용 기록", "blocked": "차단 기록", "reset": "연결 초기화 기록",
           "detected": "탐지 기록", "challenged": "추가 인증", "unknown": "의미 미확인", "conflicting": "상충"}
CSS = """body{margin:0;background:#f4f6f9;color:#18263b;font:15px/1.7 sans-serif}main{max-width:1100px;margin:auto;padding:36px}
h1{font-size:28px}h2{margin-top:30px}article,.card{background:white;padding:20px;border:1px solid #d6dfeb;border-radius:10px;margin:16px 0}
table{border-collapse:collapse;background:white;width:100%;font-size:13px}th,td{text-align:left;padding:10px;border:1px solid #d6dfeb}
th{background:#eaf0f7}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}small{color:#4b5c71}
@media print{body{background:white}main{padding:0}article,tr{break-inside:avoid}}"""


def _h(value):
    return escape(str(value), quote=True)


def _value(value):
    return "미산출" if value is None else _h(value)


def _firewall(detail):
    counts = detail.get("counts", {})
    summary = (f"원본 기록 {counts.get('records', 0)}건 · 관측 세션 {counts.get('sessions', 0)}개 · "
               f"시작 기록이 있는 새 접속 {counts.get('new_connections', 0)}개 · 차단 시도 {counts.get('deny_attempts', 0)}건")
    rows = []
    for session in detail.get("sessions", []):
        refs = canonical(session.get("event_refs", []))
        rows.append("<tr><td>" + _value(session.get("record_count")) + "</td><td>" +
            _value(session.get("src_to_dst_bytes")) + "</td><td>" +
            _value(session.get("dst_to_src_bytes")) + "</td><td>" +
            _value(session.get("duration_seconds")) + "</td><td>" +
            _h(ACTIONS.get(session.get("action"), "의미 미확인")) +
            "</td><td><details><summary>원문 위치</summary><pre>" + _h(refs) +
            "</pre></details></td></tr>")
    coverage = detail.get("limits", {}).get("coverage_complete")
    scope = "입력 검사 완료" if coverage is True else "입력 검사 범위가 제한되었거나 확인되지 않았습니다."
    return ('<section class="card"><h2>방화벽 관측 요약</h2><p>' + _h(summary) +
        '</p><p>' + _h(scope) + " · 관계사·장비를 해석하지 못한 기록 " +
        _h(counts.get("unresolved_records", 0)) + '건</p><p>표시에서 생략한 세션 ' +
        _h(counts.get("omitted_sessions", 0)) + "개 · 후보 " + _h(counts.get("omitted_candidates", 0)) +
        '개</p><p>허용 기록은 접속 성립이나 정상 판정의 증명이 아닙니다. 미산출은 0바이트와 다릅니다.</p>'
        '<table><thead><tr><th>기록 수</th><th>출발지 → 목적지 (바이트)</th><th>목적지 → 출발지 (바이트)</th>'
        '<th>지속 시간 (초)</th><th>장비 조치</th><th>근거</th></tr></thead><tbody>' +
        "".join(rows) + '</tbody></table><details><summary>자료 품질과 해석 제한</summary><pre>' +
        _h(canonical({"quality": detail.get("quality", {}), "limits": detail.get("limits", {})})) +
        '</pre></details></section>')


def render(row):
    data = row.content
    if data.get("schema_version") == "saw.report.v2":
        from saw.reports.projection_html import render as render_v2
        return render_v2(data)
    analysis = data["analysis"]
    items = "".join("<tr><td>" + _h(e["detector_id"]) + "</td><td>" + _h(e["detector_version"]) +
        "</td><td>" + _h(STATUS.get(e["status"], e["status"])) + "</td><td>" +
        _value(e["input_count"]) + "</td><td>" + _value(e["match_count"]) + "</td></tr>"
        for e in analysis["executions"])
    observations = "".join(_firewall(e["detail"]) for e in analysis["executions"]
                           if e["detector_id"] == "fw.observation" and e.get("detail", {}).get("counts") is not None)
    findings = "".join("<article><h3>" + _h(x["finding"]["title"]) + "</h3><p>" +
        _h(x["finding"]["explanation_md"]) + "</p><pre>" +
        _h(canonical(x["finding"]["metrics"])) + "</pre><details><summary>원문 위치와 조회 근거</summary><pre>" +
        _h(canonical(x["finding"]["evidence_refs"])) + "</pre></details></article>" for x in analysis["findings"])
    from saw.detectors.firewall_observation import LABELS
    has_fw_findings = any(x.get("finding", {}).get("detector", {}).get("id") == "fw.observation"
                          for x in analysis["findings"])
    if not has_fw_findings:
        findings += "".join("<article><h3>" + _h(LABELS.get(c["kind"], c["kind"])) +
            "</h3><p>관측된 후보입니다. 분석가의 확인이 필요합니다.</p><pre>" +
            _h(canonical(c.get("metrics", {}))) + "</pre><details><summary>원문 위치와 조회 근거</summary><pre>" +
            _h(canonical(c.get("event_refs", []))) + "</pre></details></article>"
            for e in analysis["executions"] if e["detector_id"] == "fw.observation"
            for c in e.get("detail", {}).get("candidates", []))
    records = "".join("<article><h3>" + _h(c.get("target_label") or "분석가 확인") +
        "</h3><p>" + _h(c.get("note", "")) + "</p><small>확인 기록 " + _h(c["id"]) +
        "</small></article>" for c in data.get("checks", []))
    return ('<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>SAW 저장 보고서</title><style>' + CSS + '</style></head><body><main><small>SAW · 불변 보고서</small><h1>' +
        _h(data["investigation"]["title"]) + '</h1><p>저장 보고서 v' + str(row.version) + ' · 분석 v' +
        str(analysis["version"]) + ' · ' + _h(STATUS.get(analysis["status"], analysis["status"])) +
        '</p><p>관계사: ' + _h(data["investigation"].get("org_unit") or "미지정") +
        '</p><section class="card"><h2>분석 범위와 실행 상태</h2><pre>' +
        _h(canonical(analysis.get("scope", {}))) +
        '</pre><table><thead><tr><th>탐지기</th><th>버전</th><th>상태</th><th>입력 기록</th><th>후보 결과</th></tr></thead><tbody>' +
        items + '</tbody></table></section>' + observations + '<h2>관측 후보와 근거</h2>' +
        (findings or '<p>저장된 후보 결과가 없습니다. 실행 상태와 자료 한계를 함께 확인하세요.</p>') +
        '<h2>저장 시점의 분석가 확인</h2>' + (records or '<p>아직 확인 기록이 없습니다.</p>') +
        '<h2>판단 한계</h2><ul>' + ''.join('<li>' + _h(v) + '</li>' for v in data["limits"]) +
        '</ul><small>내용 지문: ' + _h(row.content_sha256) + '</small></main></body></html>')


def csp():
    import base64
    import hashlib
    style_hash = base64.b64encode(hashlib.sha256(CSS.encode()).digest()).decode()
    from saw.reports.projection_html import CSS as v2_css
    v2_hash = base64.b64encode(hashlib.sha256(v2_css.encode()).digest()).decode()
    return "default-src 'none'; style-src 'sha256-" + style_hash + "' 'sha256-" + v2_hash + "'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
