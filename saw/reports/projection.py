"""Pure, bounded report read model. Frozen content is the only input."""
from __future__ import annotations

import json
import math
from collections import OrderedDict
from hashlib import sha256

MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
MAX_PROJECTED_ROWS = 100_000
MAX_DEPTH = 64
MAX_CHARTS = 64
SECTIONS = (("summary", "요약"), ("details", "상세"), ("followups", "확인 필요"),
            ("statistics", "통계"), ("timeline", "시간 추이"), ("evidence", "근거"),
            ("criteria", "적용 기준"), ("limits", "범위·한계"))
COLUMN_DEFS = (("investigation_id", "조사 ID"), ("analysis_run_id", "분석 버전 ID"),
    ("detector_id", "탐지기"), ("field", "항목 키"), ("label", "항목"), ("value", "값"), ("unit", "단위"),
    ("denominator", "분모"), ("start", "시작 UTC epoch 초"), ("end", "종료 UTC epoch 초"),
    ("statistic", "통계 종류"), ("context", "관측 문맥"))
LABELS = {"chart_omission": "차트 생략 사유", "status": "저장 상태", "scope": "저장 범위",
    "coverage_complete": "입력 검사 범위 완료 여부", "denominator": "분모", "value": "관측값",
    "question": "추가 확인 질문", "reason": "사유", "due_at": "기한", "owner": "담당",
    "revision_id": "정확 버전 ID", "payload_sha256": "내용 SHA-256", "record_count": "세션 원본 기록 수",
    "new_connection_observed": "시작 기록이 있는 새 접속", "established_connection": "접속 성립 확인",
    "action": "장비 조치", "time_start": "시작 시각", "time_end": "종료 시각","input_count": "검사 입력 기록", "match_count": "생성 Finding 수", "records": "원본 기록",
    "sessions": "관측 세션", "requests": "요청 수", "rule_hits": "룰 적중 기록", "alerts": "경보 기록",
    "src_to_dst_bytes": "출발지 → 목적지 바이트", "dst_to_src_bytes": "목적지 → 출발지 바이트",
    "duration_seconds": "지속 시간 (초)", "candidates": "계산 후보 수", "omitted_candidates": "표시 생략 후보",
    "omitted_sessions": "표시 생략 세션", "omitted_timeline": "표시 생략 시간 행"}
UNITS = {"src_to_dst_bytes": "bytes", "dst_to_src_bytes": "bytes", "bytes_in": "bytes", "bytes_out": "bytes",
    "requests": "requests", "rule_hits": "rule_hits", "alerts": "alerts", "sessions": "sessions",
    "records": "records", "eligible_records": "records", "input_count": "records", "match_count": "findings"}
RATE_FIELDS = {"value", "before", "after", "residual_observed_rate", "max_observed_rate", "previous_observed_mean"}
CHART_REASONS = {
    "saved_location_not_available": "저장된 관측 위치가 없어 비교 차트를 생략합니다.",
    "sampling_ratio_row_mapping_not_preserved": "행별 샘플링 비율이 결과에 보존되지 않아 비교 차트를 생략합니다.",
    "sampling_semantics_not_preserved": "샘플링 비율·버전의 검증된 의미가 보존되지 않아 비교 차트를 생략합니다.",
    "saved_location_or_sampling_conflict": "같은 장비·프로필의 저장 관측 위치 또는 샘플링이 상충하여 비교 차트를 생략합니다.",
    "comparison_context_not_preserved": "비교에 필요한 관계사·망·장비·프로필 문맥이 보존되지 않았습니다.",
    "numeric_time_or_measurement_unavailable": "시각 또는 관측값을 정확한 숫자로 표현할 수 없어 차트를 생략합니다.",
    "measurement_statistic_unavailable": "관측값의 건수·평균·최고값 의미가 확인되지 않아 차트를 생략합니다.",
    "measurement_interval_unavailable": "관측 구간의 시작·종료를 확인할 수 없어 차트를 생략합니다.",
    "chart_count_limit": "차트 표시 상한에 도달했습니다. 시간 행은 표에 보존됩니다.",
}
DETECTOR_LABELS = {"fw.observation": "FW", "waf.observation": "WAF", "ips.observation": "IPS",
                   "ddos.observation": "DDoS", "ndr.observation": "NDR"}
TIME_UNITS = {"requests", "alerts", "bps", "pps", "rps", "dns_records", "http_records", "tls_records"}


class ReportLimit(ValueError):
    """The bounded report cannot be represented without loss."""


class ReportCancelled(RuntimeError):
    """The caller cancelled before publication."""


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str,
                      allow_nan=False)


def digest(value):
    return sha256(canonical(value).encode("utf-8")).hexdigest()


def display(value):
    if value is None:
        return "미산출"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return canonical(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ReportLimit("report_nonfinite_number")
        if value.is_integer():
            value = int(value)
        elif len(str(value).replace(".", "").replace("-", "").replace("e", "").replace("+", "")) > 15:
            return str(value)
    if isinstance(value, int) and len(str(abs(value))) > 15:
        return str(value)
    return value if isinstance(value, (int, float, str)) else str(value)


def _escape(key):
    return str(key).replace("~", "~0").replace("/", "~1")


def _unit(field, parent):
    if field == "observed":
        return parent.get("unit") or ""
    if field.endswith(("_seconds", "_epoch")):
        return "seconds"
    if field.endswith("_bytes"):
        return "bytes"
    if field == "ratio" or field.endswith("_ratio"):
        return "ratio"
    if field in RATE_FIELDS:
        return parent.get("unit") or ""
    return UNITS.get(field, "")


def _frozen_location(analysis, context, *, ddos=False):
    matches = []
    for evidence in (analysis.get("input_manifest") or {}).get("evidence", []):
        snapshot = (evidence.get("source_context") or {}).get("snapshot") or {}
        observer = snapshot.get("observer") or {}
        if observer.get("device_id") == context[2] and observer.get("device_profile_version_id") == context[3]:
            matches.append(snapshot)
    if not matches:
        return None, "saved_location_not_available"
    values = set()
    for snapshot in matches:
        observer, profile = snapshot.get("observer") or {}, snapshot.get("profile") or {}
        point = observer.get("observation_point")
        if not point:
            return None, "saved_location_not_available"
        if ddos:
            semantics = profile.get("device_semantics") or {}
            if "sampling_ratio" in (profile.get("source_fields") or {}):
                return None, "sampling_ratio_row_mapping_not_preserved"
            ratio, version = semantics.get("sampling_ratio"), semantics.get("sampling_version")
            if (semantics.get("verified") is not True or isinstance(ratio, bool) or
                    not isinstance(ratio, (float, int)) or not 0 < ratio <= 1 or version in (None, "", "unknown")):
                return None, "sampling_semantics_not_preserved"
            values.add(canonical([point, ratio, version]))
        else:
            values.add(canonical([point]))
    if len(values) != 1:
        return None, "saved_location_or_sampling_conflict"
    return next(iter(values)), None


STATUS_LABELS = {"complete": "완료", "completed_match": "검사 완료·후보 있음",
    "completed_no_match": "검사 완료·후보 없음", "partial": "일부만 완료", "insufficient_data": "자료 부족",
    "not_applicable": "적용 대상 아님", "disabled": "사용 안 함", "failed": "실패",
    "cancelled": "취소", "running": "실행 중", "limited": "범위 제한"}
FOLLOWUP_LABELS = {"open": "확인 대기", "replied": "회신 접수·검증 전", "verified": "검증 기록 있음",
    "closed_with_limits": "한계를 남기고 종결", "cancelled": "취소"}
OUTCOME_LABELS = {"confirmed": "확인됨", "not_confirmed": "확인되지 않음",
                  "insufficient_data": "자료 부족 (정상 판정 아님)"}
OVERVIEW_LIMIT = 20


RISK_LABELS = {"critical": "매우 높음", "high": "높음", "medium": "중간", "low": "낮음",
               "info": "정보", "informational": "정보", "unknown": "미확인"}


def _execution_status(execution):
    outer = execution.get("status")
    inner = (execution.get("detail") or {}).get("status")
    # A completed inner calculation cannot erase an incomplete execution envelope.
    if outer and outer not in {"complete", "completed_match", "completed_no_match"}:
        return outer
    return inner or outer or ""


def _overview(items, content, version, limitations):
    kind = (content.get("scope") or {}).get("kind", "investigation")
    title = {"selected_followups": "선택한 후속 확인 보고서", "investigations": "선택한 조사 통합 보고서"}.get(kind, "조사 관측 보고서")
    lines = []

    def preview(value):
        value = str(display(value))
        return value if len(value) <= 300 else value[:300] + "… [요약 표시·원문은 전체 고정 투영에 보존]"

    def line(label, value, pointer):
        lines.append({"label": label, "value": preview(value), "source_pointer": pointer})

    line("읽는 순서", "관측 결과와 분석가 판단 → 근거 → 원문 위치입니다. 허용·응답·미탐지는 정상·침해 성공·무영향의 증명이 아닙니다.", "")
    line("저장 범위", f"명시적으로 선택한 조사 {len(items)}건 · 교차 장비 입력·고유 건수를 합산하지 않습니다.", "/scope" if version == "saw.report.v2" else "")
    line("보고서 저장 시각", content.get("created_at") or "미보존", "/created_at" if "created_at" in content else "")
    for index, item in enumerate(items):
        base = "/items/" + str(index) if version == "saw.report.v2" else ""
        inv, analysis = item.get("investigation") or {}, item.get("analysis") or {}
        line("조사·관계사", str(inv.get("title") or "제목 미보존") + " · " + str(inv.get("org_unit") or "관계사 미지정"), base + "/investigation")
        state = analysis.get("status", "")
        line("저장 분석", "분석 v" + str(analysis.get("version", "미보존")) + " · " + STATUS_LABELS.get(state, state or "상태 미보존"), base + "/analysis")
        executions = analysis.get("executions") or []
        order = {key: i for i, key in enumerate(DETECTOR_LABELS)}
        selected = sorted(((ei, execution) for ei, execution in enumerate(executions)
                           if execution.get("detector_id") in DETECTOR_LABELS),
                          key=lambda x: (order[x[1]["detector_id"]], x[0]))
        generic_states = OrderedDict()
        for execution in executions:
            if execution.get("detector_id") not in DETECTOR_LABELS:
                state = _execution_status(execution)
                generic_states[state] = generic_states.get(state, 0) + 1
        for ei, execution in selected:
            detail = execution.get("detail") or {}
            counts = detail.get("counts") or {}
            detector_id = execution.get("detector_id", "")
            label = DETECTOR_LABELS.get(detector_id, "추가 탐지")
            state = _execution_status(execution)
            parts = [STATUS_LABELS.get(state, state or "상태 미보존"),
                     "원본 기록 " + str(display(counts.get("records", execution.get("input_count"))))]
            for key, caption in (("sessions", "관측 세션"), ("requests", "요청"), ("rule_hits", "룰 적중 기록"),
                                 ("alerts", "경보"), ("candidates", "계산 후보"), ("omitted_candidates", "표시 생략 후보")):
                if key in counts:
                    parts.append(caption + " " + str(display(counts[key])))
            if "candidates" not in counts:
                parts.append("생성 Finding " + str(display(execution.get("match_count"))))
            line(label + " 관측", " · ".join(parts), base + "/analysis/executions/" + str(ei))
        for state, count in generic_states.items():
            line("기타 탐지 실행", STATUS_LABELS.get(state, state or "상태 미보존") + f" {count}개 실행"
                 + " · 각 실행 ID와 입력·결과 수치는 전체 고정 투영에 보존됩니다.", base + "/analysis/executions")
        findings = analysis.get("findings") or []
        line("저장 Finding", f"{len(findings)}건 · 관측 후보와 실제 영향 판단은 구분합니다.", base + "/analysis/findings")
        for fi, snapshot in enumerate(findings[:OVERVIEW_LIMIT]):
            finding = snapshot.get("finding") or {}
            risk = finding.get("risk_level")
            text = "위험 " + RISK_LABELS.get(risk, str(risk or "미보존")) + " · " + str(finding.get("title") or "제목 미보존")
            if finding.get("explanation_md"):
                text += " · " + str(finding["explanation_md"])
            line("관측·판단", text, base + "/analysis/findings/" + str(fi))
        checks, followups = item.get("checks") or [], item.get("followups") or []
        line("분석가 확인", f"저장된 확인 버전 {len(checks)}건", base + "/checks")
        for ci, entry in enumerate(checks[:OVERVIEW_LIMIT]):
            value = entry.get("payload", entry)
            judgement = value.get("judgement_ko") or value.get("judgement") or "판단 미기재"
            line("확인 기록", str(value.get("target_label") or "대상 미보존") + " · " + str(judgement)
                 + " · " + str(value.get("note") or ""), base + "/checks/" + str(ci))
        line("후속 확인", f"저장된 후속 확인 버전 {len(followups)}건 · 회신과 검증을 구분합니다.", base + "/followups")
        for fi, entry in enumerate(followups[:OVERVIEW_LIMIT]):
            value = entry.get("payload") or {}
            state = FOLLOWUP_LABELS.get(value.get("status"), str(value.get("status") or "상태 미보존"))
            verification = value.get("verification") or {}
            outcome = verification.get("outcome")
            text = state
            if outcome:
                text += " · 결과: " + OUTCOME_LABELS.get(outcome, str(outcome))
            owner = value.get("owner") or {}
            text += " · 담당 " + str(owner.get("department") or ("ID는 근거표 참조" if owner.get("user_id") or owner.get("org_unit_id") else "미지정"))
            text += " · 기한 " + str(value.get("due_at") or "미지정")
            text += " · 질문: " + str(value.get("question") or "미보존")
            line("확인 필요", text, base + "/followups/" + str(fi))
        for name, records in (("Finding", findings), ("분석가 확인", checks), ("후속 확인", followups)):
            if len(records) > OVERVIEW_LIMIT:
                line("요약 표시 한계", f"{name} {len(records)-OVERVIEW_LIMIT}건은 아래 전체 고정 투영에 보존됩니다.", base)
    for index, limit in enumerate((content.get("limits") or [])[:8]):
        line("범위·한계", limit, "/limits/" + str(index))
    if len(content.get("limits") or []) > 8:
        line("추가 한계", f"{len(content['limits'])-8}건은 전체 범위·한계 표에 보존됩니다.", "/limits")
    reasons = OrderedDict((item["reason"], item) for item in limitations)
    for item in list(reasons.values())[:8]:
        line("관측·차트 한계", item.get("message") or item["reason"], item["source_pointer"])
    if len(reasons) > 8:
        line("추가 관측 한계", f"{len(reasons)-8}개 사유는 전체 범위·한계 표에 보존됩니다.", "")
    return {"title": title, "lines": lines}


def project(content):
    """Return eight sections, stable source references and comparable observed chart groups."""
    try:
        encoded = canonical(content).encode("utf-8")
    except (ValueError, TypeError, RecursionError) as exc:
        raise ReportLimit("report_invalid_snapshot_json") from exc
    if len(encoded) > MAX_SNAPSHOT_BYTES:
        raise ReportLimit("report_snapshot_byte_limit")
    content_sha = sha256(encoded).hexdigest()
    del encoded
    version = content.get("schema_version")
    if version not in {"saw.report.v1", "saw.report.v2"}:
        raise ReportLimit("report_schema_unsupported")
    sections = [{"key": key, "title": title,
                 "columns": [{"key": key, "label": label, "kind": "value"} for key, label in COLUMN_DEFS],
                 "rows": []} for key, title in SECTIONS]
    by_key = {s["key"]: s for s in sections}
    limitations, chart_groups = [], OrderedDict()
    total = 0
    scope = content.get("scope") if version == "saw.report.v2" else {"kind": "legacy_investigation"}
    items = content.get("items", []) if version == "saw.report.v2" else [{
        key: content.get(key, [] if key in {"checks", "followups"} else {}) for key in
        ("investigation", "analysis", "checks", "followups")}]
    if not isinstance(items, list) or len(items) > 20:
        raise ReportLimit("report_investigation_limit")
    context = {"investigation_id": "", "analysis_run_id": "", "detector_id": ""}

    def add(section, pointer, field, value, *, row_type="field", unit="", denominator="", **extra):
        nonlocal total
        total += 1
        if total > MAX_PROJECTED_ROWS:
            raise ReportLimit("report_projection_row_limit")
        cells = {key: "" for key, _ in COLUMN_DEFS}
        cells.update(context)
        cells.update(field=str(field), label=LABELS.get(str(field), str(field)), value=display(value),
                     unit=unit, denominator=display(denominator))
        cells.update({key: display(v) for key, v in extra.items()})
        ref = "item:" + str(context["investigation_id"]) + "/run:" + str(context["analysis_run_id"]) + pointer
        row = {"row_ref": ref, "source_pointer": pointer, "row_type": row_type, "cells": cells}
        by_key[section]["rows"].append(row)
        return row

    def walk(section, value, pointer, *, field="", parent=None, row_type="field", depth=0):
        if depth > MAX_DEPTH:
            raise ReportLimit("report_nesting_limit")
        if isinstance(value, dict) and value:
            for key, val in value.items():
                walk(section, val, pointer + "/" + _escape(key), field=key, parent=value,
                     row_type=row_type, depth=depth+1)
        elif isinstance(value, list) and value:
            for index, val in enumerate(value):
                walk(section, val, pointer + "/" + str(index), field=field, parent=parent,
                     row_type=row_type, depth=depth+1)
        else:
            unit = _unit(str(field), parent or {})
            add(section, pointer, field, value, unit=unit, row_type=row_type,
                denominator=(parent or {}).get("denominator", ""))

    def omission(pointer, reason):
        message = CHART_REASONS.get(reason, reason)
        limitations.append({"source_pointer": pointer, "reason": reason, "message": message})
        row = add("limits", pointer, "chart_omission", message, row_type="limitation")
        row["row_ref"] += "/chart_omission"

    for index, item in enumerate(items):
        inv, analysis = item.get("investigation") or {}, item.get("analysis") or {}
        context.update(investigation_id=inv.get("id", ""), analysis_run_id=analysis.get("id", ""), detector_id="")
        base = "/items/" + str(index) if version == "saw.report.v2" else ""
        walk("summary", inv, base + "/investigation")
        walk("summary", {k: v for k, v in analysis.items() if k not in {"findings", "executions", "input_manifest"}},
             base + "/analysis")
        manifest = analysis.get("input_manifest") or {}
        for key, value in manifest.items():
            if key == "evidence":
                for ei, evidence in enumerate(value):
                    ptr = base + "/analysis/input_manifest/evidence/" + str(ei)
                    walk("evidence", {k: v for k, v in evidence.items() if k != "source_context"}, ptr)
                    if "source_context" in evidence:
                        walk("criteria", evidence["source_context"], ptr + "/source_context")
            else:
                walk("criteria", value, base + "/analysis/input_manifest/" + _escape(key), field=key)
        for key in ("checks", "followups"):
            for ri, record in enumerate(item.get(key) or []):
                walk("followups", record, base + "/" + key + "/" + str(ri), row_type=key[:-1])
        for fi, snapshot in enumerate(analysis.get("findings") or []):
            ptr = base + "/analysis/findings/" + str(fi)
            finding = snapshot.get("finding") or {}
            context["detector_id"] = (finding.get("detector") or {}).get("id", "")
            walk("evidence", {k: v for k, v in snapshot.items() if k != "finding"}, ptr, row_type="finding_snapshot")
            for key, value in finding.items():
                target = "statistics" if key == "metrics" else "evidence" if key == "evidence_refs" else "details"
                walk(target, value, ptr + "/finding/" + _escape(key), field=key, row_type="finding")
        for ei, execution in enumerate(analysis.get("executions") or []):
            ptr = base + "/analysis/executions/" + str(ei)
            context["detector_id"] = execution.get("detector_id", "")
            walk("summary", {k: v for k, v in execution.items() if k not in {"detail", "effective_config"}}, ptr, row_type="execution")
            walk("criteria", execution.get("effective_config", {}), ptr + "/effective_config", row_type="effective_config")
            detail = execution.get("detail") or {}
            for key, value in detail.items():
                if key in {"sessions", "candidates"}:
                    for ri, record in enumerate(value):
                        rp = ptr + "/detail/" + key + "/" + str(ri)
                        for name, part in record.items():
                            target = "evidence" if name == "event_refs" else "statistics" if name == "metrics" else "details"
                            walk(target, part, rp + "/" + _escape(name), field=name, row_type=key[:-1])
                elif key == "timeline":
                    for ti, point in enumerate(value):
                        tp = ptr + "/detail/timeline/" + str(ti)
                        raw_context = point.get("context")
                        series_context = {"scope": raw_context, **{k: v for k, v in point.items() if k not in {
                            "context", "start_epoch", "end_epoch", "unit", "statistic", "value", "denominator"}}}
                        row = add("timeline", tp, "value", point.get("value"), row_type="observed_bucket",
                            unit=point.get("unit", ""), denominator=point.get("denominator"),
                            start=point.get("start_epoch"), end=point.get("end_epoch"), statistic=point.get("statistic", ""),
                            context=canonical(series_context))
                        if (not isinstance(raw_context, list) or len(raw_context) < 5 or
                                not all(raw_context[i] for i in (0, 1, 2, 3))):
                            omission(tp, "comparison_context_not_preserved")
                            continue
                        location, reason = _frozen_location(analysis, raw_context, ddos=point.get("unit") in {"bps", "pps", "rps"})
                        if reason:
                            omission(tp, reason)
                            continue
                        start, val = point.get("start_epoch"), point.get("value")
                        if (isinstance(start, bool) or isinstance(val, bool) or
                                not isinstance(start, (int, float)) or not isinstance(val, (int, float)) or
                                not isinstance(display(val), (int, float)) or not isinstance(display(start), (int, float)) or
                                point.get("unit") not in TIME_UNITS):
                            omission(tp, "numeric_time_or_measurement_unavailable")
                            continue
                        rate = point.get("unit") in {"bps", "pps", "rps"}
                        if point.get("statistic") not in ({"mean", "peak"} if rate else {"count"}):
                            omission(tp, "measurement_statistic_unavailable")
                            continue
                        end = point.get("end_epoch")
                        if (end is not None and (isinstance(end, bool) or not isinstance(end, (int, float)) or end <= start)
                                or rate and end is None):
                            omission(tp, "measurement_interval_unavailable")
                            continue
                        interval = end - start if end is not None else None
                        group = canonical([context, series_context, point.get("unit"), point.get("statistic"), location, interval])
                        chart_groups.setdefault(group, []).append(row)
                else:
                    target = "statistics" if key in {"counts", "calculation_coverage"} else "limits" if key in {
                        "quality", "limits", "limitations", "status"} else "criteria"
                    walk(target, value, ptr + "/detail/" + _escape(key), field=key, row_type="execution_detail")
            if detail.get("sessions"):
                omission(ptr + "/detail/sessions", "세션 시각 미보존: 세션 발생 시계열을 만들지 않습니다.")
        context["detector_id"] = ""
    context.update(investigation_id="", analysis_run_id="", detector_id="")
    for key, value in content.items():
        if key in {"items", "investigation", "analysis", "checks", "followups"}:
            continue
        walk("limits" if key in {"limits", "schema_limits"} else "summary", value, "/" + _escape(key), field=key)
    if version == "saw.report.v1":
        row = add("limits", "", "legacy", "과거 Check·후속 확인의 정확 revision 및 보고서 생성 시각은 미보존입니다.")
        row["row_ref"] += "/legacy_revision_limit"

    charts, ordered = [], []
    accepted = set()
    for key, rows in chart_groups.items():
        rows.sort(key=lambda r: r["cells"]["start"])
        if len(charts) >= MAX_CHARTS:
            omission(rows[0]["source_pointer"], "chart_count_limit")
            continue
        refs = [r["row_ref"] for r in rows]
        first = rows[0]["cells"]
        charts.append({"id": "series-" + sha256(key.encode()).hexdigest()[:16], "row_refs": refs,
                       "unit": first["unit"], "statistic": first["statistic"],
                       "context": first["context"], "title": DETECTOR_LABELS.get(first["detector_id"], "장비") + " 관측 " + str(len(charts)+1) + " · " + first["unit"]})
        ordered.extend(rows)
        accepted.update(refs)
    ordered.extend(r for r in by_key["timeline"]["rows"] if r["row_ref"] not in accepted)
    by_key["timeline"]["rows"] = ordered
    return {"schema": "saw.report.projection.v1", "source_schema": version, "content_sha256": content_sha,
            "scope": scope, "sections": sections, "charts": charts, "limitations": limitations,
            "overview": _overview(items, content, version, limitations)}
