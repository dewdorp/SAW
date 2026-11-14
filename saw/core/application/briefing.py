"""Report-ready view of the analysis for people who do not read logs: one page per investigation (what happened,
impact, what was done, what is left, how far the result can be trusted) and a board over all investigations.

Everything is derived from what the analysis already recorded; nothing here is a new judgement. Text a person
wrote over a generated section is stored (models.Briefing) and wins over the generated text.
"""
from __future__ import annotations

import html
import ipaddress
import re
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from saw import container
from saw.core.application import audit
from saw.core.application.investigations import list_for, require
from saw.core.schemas.query import AggRequest
from saw.core.security.authz import Principal
from saw.detection.derived_access import (
    require_investigation_results,
)
from saw.storage.db import utcnow
from saw.storage.models import (
    AuditEvent,
    Briefing,
    Evidence,
    EvidenceFile,
    Finding,
    Investigation,
    InvestigationMember,
    Job,
    User,
)

KST = ZoneInfo("Asia/Seoul")
FIELDS = ("headline", "what", "impact", "done", "todo")  # the sections a person may rewrite
FIELD_MAX = 4000
RISK_ORDER = ["critical", "high", "medium", "low", "info"]
RISK_KO = {"critical": "매우 높음", "high": "높음", "medium": "보통", "low": "낮음", "info": "참고"}
STATUS_KO = {"open": "접수", "new": "접수", "in_progress": "분석 중", "pending_review": "검토 대기", "closed": "종결"}
VERDICT_KO = {"normal": "정상 업무로 확인", "attack_attempt": "공격 시도 확인(성공 미확인)",
              "compromise_confirmed": "침해·실제 영향 확인", "insufficient_evidence": "증거 부족 · 추가 확인 필요",
              "data_quality_limited": "데이터 품질로 판단 제한",
              "attack": "공격으로 판정", "false_positive": "오탐으로 판정", "unknown": "판단 보류"}
SOURCE_KO = {"web": "웹 서버·NDR 요청 기록", "waf": "웹 방화벽 기록", "zeek_conn": "네트워크 연결 기록", "zeek_dns": "DNS 조회 기록",
             "zeek_ssl": "암호화 통신(TLS) 기록", "zeek_http": "패킷 속 HTTP 기록", "zeek_files": "패킷 속 전송 파일",
             "suricata": "침입 탐지 경보", "pcap_auth": "패킷 속 로그인 기록", "pcap_arp": "ARP 기록", "ndr_http": "NDR 응답 기록",
             "ndr_meta": "NDR 기타 기록", "custom": "기타 로그"}
# detector category -> what it means in one plain phrase
CATEGORY_KO = {
    "web.api_enumeration": "고객 정보 등을 번호를 바꿔 가며 대량 조회", "web.credential_attack": "로그인 무차별 시도",
    "web.discovery": "웹 서버 경로 탐색(스캔)", "web.injection_like": "웹 공격 구문(주입 공격) 시도",
    "web.large_response": "평소보다 큰 응답(대량 반출 가능성)", "web.off_hours_sensitive": "업무 외 시간의 민감 경로 접근",
    "web.rare_path_access": "드문 관리·내보내기 경로 접근", "web.request_mutation_success": "요청 값 변조 후 성공 응답",
    "web.scripted_client": "자동화 도구로 보이는 접속", "web.sensitive_file_probe": "민감 파일 탐색",
    "net.dns_anomaly": "비정상 DNS 조회", "net.ids_alerts": "침입 탐지 경보", "net.large_outbound": "외부로 대량 전송",
    "net.long_conn": "장시간 유지된 외부 연결", "net.periodic": "주기적인 외부 통신(원격 조종 의심)", "net.scan": "내부·외부 포트 스캔",
    "net.tls_rarity": "드문 암호화 통신 지문", "net.unexpected_protocol": "예상 밖 통신 방식",
    "pcap.arp_spoof": "ARP 위장(통신 가로채기) 의심", "pcap.bruteforce": "로그인 무차별 시도", "pcap.cleartext_auth": "암호화되지 않은 로그인",
    "pcap.dga": "자동 생성 도메인 조회(악성코드 의심)", "pcap.direct_ip_http": "도메인 없이 IP로 직접 접속",
    "ioc.match": "알려진 악성 지표와 일치", "pcap.malware_delivery": "악성 파일 전달 의심", "pcap.tls_certificate": "의심스러운 인증서",
    "pcap.web_attack": "웹 공격 시도", "pcap.webshell": "웹셸(서버 원격 조종 파일) 업로드",
    "anomaly.entity": "다른 출발지와 다른 이례적 행동", "anomaly.rare": "드물게 나타난 값", "anomaly.relationship": "처음 보는 통신 관계",
    "anomaly.sequence": "이례적인 요청 순서", "anomaly.volume": "평소와 다른 요청량",
}
# what is usually checked next, for detections that carry no advice of their own (most specific prefix wins)
NEXT_KO = {
    "web.api_enumeration": ["조회된 번호 범위와 응답 내용을 확인해 실제 정보 유출 여부를 판단", "해당 출발지 차단 또는 요청 속도 제한 적용 검토"],
    "web.credential_attack": ["로그인에 성공한 계정이 있는지 확인하고, 있으면 비밀번호 변경·세션 종료", "반복 시도 출발지 차단 검토"],
    "web.injection_like": ["성공 응답을 받은 요청이 있는지 확인하고 대상 기능의 취약 여부를 개발 담당과 점검", "웹 방화벽 차단 규칙 적용 여부 확인"],
    "web.request_mutation_success": ["변조된 요청으로 다른 사용자의 정보가 조회·변경됐는지 확인", "해당 기능의 권한 검증을 개발 담당과 점검"],
    "web.sensitive_file_probe": ["성공 응답을 받은 민감 파일이 실제로 노출됐는지 확인하고 노출 시 제거·비밀값 교체"],
    "web.large_response": ["큰 응답으로 나간 자료의 종류와 대상자를 확인"],
    "web.": ["해당 출발지의 다른 요청과 성공 응답 여부를 확인", "필요하면 차단 정책 적용 검토"],
    "net.large_outbound": ["전송한 내부 시스템의 사용자·업무 목적을 확인", "전송된 자료의 종류 확인"],
    "net.periodic": ["해당 내부 시스템에서 통신을 일으킨 프로그램을 확인(악성코드 여부 점검)"],
    "net.": ["해당 내부 시스템의 통신 목적을 담당자에게 확인", "필요하면 목적지 차단 검토"],
    "anomaly.": ["평소와 다른 이유(업무 변경, 배치 작업 등)를 담당 부서에 확인"],
    "ioc.": ["일치한 지표와 통신한 내부 시스템을 점검", "해당 지표 차단 적용 여부 확인"],
}
# audit actions that mean "someone worked on the investigation" (reading it is not work)
WORK_ACTIONS = ("evidence.create", "evidence.upload", "evidence.processed", "evidence.parser_override", "job.start",
                "finding.feedback", "note.create", "story.edit", "investigation.create", "investigation.update",
                "investigation.member", "investigation.close", "hunt.create", "hunt.conclude", "hunt.finding",
                "connector.import", "case.item_add", "briefing.update")
STALE_DAYS = 7
_IPV4 = re.compile(r"(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}(?![\d.])")
_SUCCESS = re.compile(r"(?i)success|성공|afterwards|not refused|logged in")


# ---------------------------------------------------------------- small helpers
def hide(text: str | None, mask: bool) -> str:
    """Addresses keep their network part only: enough to recognise a range in a report, not a single machine."""
    return _IPV4.sub(r"\1.***", text or "") if mask else (text or "")


def _aware(dt: datetime | None) -> datetime | None:
    return None if dt is None else (dt if dt.tzinfo else dt.replace(tzinfo=UTC))


def kst(dt: datetime | str | None, fmt: str = "%Y-%m-%d %H:%M") -> str:
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
        except ValueError:
            return dt
    dt = _aware(dt)
    return dt.astimezone(KST).strftime(fmt) if dt else ""


def _period(a: datetime | None, z: datetime | None) -> str:
    """"10-03 17:38 ~ 17:52" (the date is repeated only when the end is on another day)."""
    start = kst(a, "%m-%d %H:%M")
    if not z or kst(z, "%m-%d %H:%M") == start:  # within the same minute: one time is enough
        return start
    return f"{start} ~ {kst(z, '%H:%M' if kst(a, '%m-%d') == kst(z, '%m-%d') else '%m-%d %H:%M')}"


def _fact(explanation: str) -> str:
    """The observation sentence of a finding (its text before the advice section)."""
    return " ".join((explanation or "").split("###", 1)[0].replace("`", "").split())


def _advice(explanation: str) -> list[str]:
    tail = (explanation or "").split("###", 1)
    return [ln.lstrip("- ").strip() for ln in tail[1].splitlines()[1:] if ln.strip().startswith("-")] if len(tail) > 1 else []


def _next(f: Finding) -> list[str]:
    own = _advice(f.explanation_md)
    if own:
        return own
    keys = sorted((k for k in NEXT_KO if f.category.startswith(k)), key=len, reverse=True)
    return NEXT_KO[keys[0]] if keys else []


_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                                                 "169.254.0.0/16", "100.64.0.0/10", "fc00::/7", "fe80::/10", "::1/128")]


def _is_internal(ip: str) -> bool:
    """Addresses of the organisation's own networks (not `is_private`, which also covers documentation ranges)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in _INTERNAL)


def _listed(ips: list[str], mask: bool, limit: int) -> str:
    """Addresses for a sentence: shortened when masking, without repeating what then looks the same."""
    shown = list(dict.fromkeys(hide(i, mask) for i in ips))
    return ", ".join(shown[:limit]) + (" 등" if len(shown) > limit else "")


def _succeeded(f: Finding) -> bool:
    return any(c.get("passed") is True and _SUCCESS.search(str(c.get("label") or "")) for c in f.checks or []) \
        or bool(_SUCCESS.search(f.title or ""))


def _names(s: Session, ids: list[str]) -> dict[str, str]:
    if not ids:
        return {}
    return {u.id: (u.display_name or u.username) for u in s.execute(select(User).where(User.id.in_(ids))).scalars()}


# ---------------------------------------------------------------- one investigation
def _caveats(inv: Investigation, files: list[EvidenceFile], active_jobs: int, unreviewed_high: int) -> list[str]:
    out = []
    if inv.status != "closed":
        out.append("아직 종결되지 않은 조사입니다. 이 보고는 판정 전의 중간 결과입니다.")
    if active_jobs:
        out.append(f"처리 중인 작업이 {active_jobs}건 있습니다. 끝나면 숫자와 탐지 결과가 달라질 수 있습니다.")
    leaves = [f for f in files if f.parse_status not in ("extracted",)]
    undone = [f for f in leaves if f.parse_status in ("pending", "parsing", "waiting_input")]
    failed = [f for f in leaves if f.parse_status == "failed"]
    partial = [f for f in leaves if f.parse_status == "degraded"]
    if undone:
        out.append(f"올린 자료 {len(undone)}개는 아직 분석에 포함되지 않았습니다(처리 전·처리 중·형식 선택 대기).")
    if failed:
        out.append(f"자료 {len(failed)}개는 읽지 못해 분석에서 빠졌습니다.")
    if partial:
        out.append(f"자료 {len(partial)}개는 일부만 분석했습니다(읽지 못한 줄이 많거나 파일이 끊겨 있음).")
    rejected = lines_failed = parsed = gaps = 0
    for f in leaves:
        parsed += f.events_parsed or 0
        lines_failed += f.events_failed or 0
        for x in f.error_samples or []:
            if isinstance(x, dict):
                rejected += int((x.get("coverage") or {}).get("rejected_events") or 0)
                gaps += int((x.get("pcap_summary") or {}).get("incomplete_flows") or 0)
    if rejected:
        out.append(f"기록 {rejected:,}건은 저장되지 않아 검색·탐지에서 빠졌습니다.")
    elif lines_failed and lines_failed / max(1, parsed + lines_failed) > 0.01:
        out.append(f"전체의 {lines_failed / (parsed + lines_failed):.1%}에 해당하는 줄은 형식이 맞지 않아 분석하지 못했습니다.")
    if gaps:
        out.append(f"패킷이 일부 빠진 통신이 {gaps:,}건 있습니다. 그 통신에 대한 해석은 불완전할 수 있습니다.")
    if unreviewed_high:
        out.append(f"높은 위험 탐지 {unreviewed_high}건은 분석가가 아직 확인하지 않았습니다(자동 탐지 결과).")
    return out


def _check_caveats(chk: dict, close_limits: str = "") -> list[str]:
    out = [f"종결할 때 남긴 범위 제한: {close_limits}"] if close_limits else []
    if chk["sample_only"]:
        out.append(f"확인 기록 {chk['sample_only']}건은 일부(표본)만 본 것입니다. 전체를 확인한 것이 아닙니다.")
    if chk["cited"]:
        out.append(f"확인 {chk['cited']}건은 다른 조사의 확인 결과를 참고한 것입니다(이 조사에서 직접 확인한 것이 아님).")
    if chk["source_changed"]:
        out.append(f"참고한 다른 조사의 확인 결과 {chk['source_changed']}건이 이후 바뀌었거나 철회되었습니다. 다시 확인이 필요합니다.")
    return out


def build(s: Session, inv: Investigation, mask: bool = True) -> dict[str, Any]:
    es = container.get().events
    files = s.execute(select(EvidenceFile).join(Evidence, Evidence.id == EvidenceFile.evidence_id)
                      .where(Evidence.investigation_id == inv.id)).scalars().all()
    parents = {f.parent_file_id for f in files if f.parent_file_id}
    leaves = [f for f in files if f.id not in parents]
    if s.info.get("principal") is not None:
        require_investigation_results(s, s.info["principal"], inv.id)
    findings = [f for f in s.execute(select(Finding).where(Finding.investigation_id == inv.id)
                                     .order_by(Finding.risk_score.desc())).scalars()
                if f.status not in ("false_positive", "duplicate")]
    counts = Counter(f.risk_level for f in findings)
    high = [f for f in findings if f.risk_level in ("critical", "high")]
    won = [f for f in high if _succeeded(f)]
    active_jobs = s.execute(select(func.count()).select_from(Job).where(
        Job.investigation_id == inv.id, Job.state.notin_(["COMPLETED", "FAILED", "CANCELLED"]))).scalar_one()
    members = [m.user_id for m in s.execute(select(InvestigationMember).where(
        InvestigationMember.investigation_id == inv.id)).scalars()]
    names = _names(s, list({inv.owner_id, *members}))
    events = es.count(inv.id)
    lo, hi = es.time_bounds(inv.id) if events else (None, None)
    sources = es.aggregate(inv.id, [], AggRequest(type="terms", field="data_source", size=20))["buckets"] if events else []
    risk = inv.risk_override or inv.risk_level
    detail = inv.close_detail or {}

    top = []
    for f in findings[:5]:
        when = _period(f.time_start, f.time_end)
        top.append({"id": f.id, "display_id": f.display_id, "risk_level": f.risk_level, "risk_ko": RISK_KO.get(f.risk_level, f.risk_level),
                    "what": CATEGORY_KO.get(f.category, f.title), "fact": hide(_fact(f.explanation_md), mask), "when": when,
                    "success": _succeeded(f), "reviewed": f.status != "new",
                    "attack": [f"{a.get('technique_id')} {a.get('name') or ''}".strip() for a in (f.attack or [])[:3]]})

    # ---- generated sections (plain sentences; a person may rewrite any of them)
    if inv.status == "closed":
        first = (inv.verdict_reason or "").strip().splitlines()[0] if (inv.verdict_reason or "").strip() else ""
        headline = f"{VERDICT_KO.get(inv.verdict or 'unknown', '판단 보류')}. {first}".strip()
    elif high:
        headline = f"분석 진행 중(판정 전). 높은 위험 탐지 {len(high)}건을 확인하고 있습니다."
    elif findings:
        headline = f"분석 진행 중(판정 전). 현재까지 높은 위험 탐지는 없고, 참고할 탐지가 {len(findings)}건 있습니다."
    elif events:
        headline = "분석 진행 중(판정 전). 현재까지 이상 징후가 탐지되지 않았습니다."
    else:
        headline = "분석할 자료가 아직 처리되지 않았습니다."
    what = [f"{t['when']} · {t['what']}: {t['fact']}" for t in top]
    ips = {e.split(":", 1)[1] for f in (high or findings[:5]) for e in (f.entities or []) if str(e).startswith("ip:")}
    inside, outside = sorted(i for i in ips if _is_internal(i)), sorted(i for i in ips if not _is_internal(i))
    impact = []
    if won:
        impact.append(f"공격이 성공한 정황이 있는 탐지가 {len(won)}건 있습니다: "
                      + ", ".join(dict.fromkeys(CATEGORY_KO.get(f.category, f.title) for f in won)) + ".")
    elif high:
        impact.append("높은 위험 탐지가 있으나, 공격이 성공했다는 정황은 자동 탐지 기준으로 확인되지 않았습니다.")
    elif findings or events:
        impact.append("현재까지 피해로 이어진 정황은 확인되지 않았습니다.")
    if inside:
        impact.append(f"관련된 내부 시스템 {len(inside)}대: {_listed(inside, mask, 6)}.")
    if outside:
        impact.append(f"관련된 외부 주소 {len(outside)}곳: {_listed(outside, mask, 4)}.")
    done = []
    if inv.status == "closed":
        if detail.get("response"):
            done.append(str(detail["response"]))
        done += [f"확인함: {c}" for c in detail.get("checks") or []]
    todo: list[str] = []
    if inv.status != "closed":
        for f in (high or findings)[:3]:
            for a in _next(f):
                if a not in todo and len(todo) < 6:
                    todo.append(a)
    elif detail.get("detection_idea"):
        todo.append(f"재발 탐지 방안 검토: {detail['detection_idea']}")
    from saw.core.application import checks as check_svc
    from saw.core.application import reviews as review_svc

    chk = check_svc.summary(s, inv.id)
    owed = review_svc.open_count(s, inv.id)
    auto = {"headline": hide(headline, mask), "what": hide("\n".join(what), mask), "impact": "\n".join(impact),
            "done": hide("\n".join(done), mask), "todo": "\n".join(todo)}
    saved = s.get(Briefing, inv.id)
    edited = {k: v for k, v in ((saved.fields or {}) if saved else {}).items() if k in FIELDS and str(v).strip()}
    return {
        "investigation": {"id": inv.id, "display_id": inv.display_id, "title": inv.title, "status": inv.status,
                          "status_ko": STATUS_KO.get(inv.status, inv.status), "verdict": inv.verdict,
                          "verdict_ko": VERDICT_KO.get(inv.verdict) if inv.verdict else None,
                          "risk_level": risk, "risk_ko": RISK_KO.get(risk, risk),
                          "owner": names.get(inv.owner_id, ""), "members": sorted(names[m] for m in members if m in names),
                          "created_at": inv.created_at, "closed_at": inv.closed_at},
        "facts": {"files": len(leaves), "bytes": sum(f.size or 0 for f in leaves), "events": events,
                  "time_range": [lo, hi], "time_range_kst": [kst(lo), kst(hi)],
                  "sources": [{"key": b["key"], "label": SOURCE_KO.get(str(b["key"]), str(b["key"])), "count": b["count"]} for b in sources],
                  "findings": {k: counts.get(k, 0) for k in RISK_ORDER}, "findings_total": len(findings),
                  "success_findings": len(won), "checks": chk},
        "top_findings": top,
        "check_line": _check_line(chk),
        "auto": auto, "edited": edited, "text": {k: edited.get(k) or auto[k] for k in FIELDS},
        "caveats": (_caveats(inv, leaves, active_jobs, sum(1 for f in high if f.status == "new")) + _check_caveats(chk, str(detail.get("limits") or "") if inv.status == "closed" else "")
                    + ([f"중요한 판단 {owed}건이 아직 동료 검토를 받지 않았습니다(공격 판정, 높은 위험 탐지를 정상·오탐으로 낮춘 경우)."]
                       if owed else [])),
        "reviews_open": owed,
        "edit": {"by": saved.updated_by_name, "at": saved.updated_at, "rev": saved.rev} if saved and edited else None,
        "masked": mask, "generated_at": utcnow(),
    }


def save(s: Session, p: Principal, inv_id: str, fields: dict[str, Any]) -> Briefing:
    """Store the sections a person rewrote. An empty section goes back to the generated text."""
    require(s, p, "investigation.write", inv_id)
    clean = {k: str(v).strip()[:FIELD_MAX] for k, v in (fields or {}).items() if k in FIELDS and str(v or "").strip()}
    b = s.get(Briefing, inv_id)
    if b is None:
        b = Briefing(investigation_id=inv_id, fields=clean, rev=1)
        s.add(b)
    else:
        b.fields, b.rev = clean, (b.rev or 1) + 1
    b.updated_by, b.updated_by_name, b.updated_at = p.user_id, p.username, utcnow()
    audit.record(s, "briefing.update", actor_id=p.user_id, actor_name=p.username, target_type="investigation",
                 target_id=inv_id, investigation_id=inv_id, detail={"sections": sorted(clean), "rev": b.rev})
    return b


# ---------------------------------------------------------------- printable page
def _lines(text: str) -> str:
    rows = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    if not rows:
        return "<p class='none'>기록된 내용이 없습니다.</p>"
    return "<ul>" + "".join(f"<li>{html.escape(r.lstrip('-• ').strip())}</li>" for r in rows) + "</ul>"


def _check_line(chk: dict) -> str:
    """"분석가가 직접 확인한 기록 5건 (정상 2, 악성 1, 판단 없음 2 · 표본 1)" - what a person verified, apart from detections."""
    obs = f" · 자동 관측 근거 {chk['observations']}건(직접 확인 제외)" if chk and chk.get("observations") else ""
    if not chk or not chk.get("direct"):
        return "분석가가 직접 확인해 남긴 기록: 없음" + obs
    from saw.core.application.checks import JUDGEMENTS

    parts = [f"{JUDGEMENTS[k]} {n}" for k, n in chk["by_judgement"].items() if k in JUDGEMENTS] + \
            ([f"판단 없음 {chk['by_judgement']['none']}"] if chk["by_judgement"].get("none") else [])
    extra = (f" · 표본 확인 {chk['sample_only']}" if chk["sample_only"] else "") + (f" · 다른 조사 참고 {chk['cited']}" if chk["cited"] else "")
    return f"분석가가 직접 확인해 남긴 기록 {chk['direct']}건 ({', '.join(parts)}{extra})" + obs


def render_html(b: dict[str, Any], author: str) -> str:
    """Self-contained page (no scripts, every value escaped) for printing or saving as PDF."""
    e = html.escape
    i, f, t = b["investigation"], b["facts"], b["text"]
    size = f["bytes"]
    size_txt = f"{size / 1024 ** 3:.1f}GB" if size >= 1024 ** 3 else f"{size / 1024 ** 2:.0f}MB" if size >= 1024 ** 2 else f"{size / 1024:.0f}KB"
    period = " ~ ".join(x for x in f["time_range_kst"] if x) or "—"
    chips = "".join(f"<span class='chip {k}'>{RISK_KO[k]} {f['findings'][k]}</span>" for k in RISK_ORDER if f["findings"][k])
    rows = "".join(
        f"<tr><td class='{e(x['risk_level'])}'>{e(x['risk_ko'])}</td><td>{e(x['when'])}</td><td><b>{e(x['what'])}</b><br>{e(x['fact'])}</td>"
        f"<td>{'있음' if x['success'] else '—'}</td><td>{'확인함' if x['reviewed'] else '확인 전'}</td></tr>" for x in b["top_findings"])
    caveats = "".join(f"<li>{e(c)}</li>" for c in b["caveats"])
    srcs = ", ".join(f"{e(x['label'])} {x['count']:,}건" for x in f["sources"]) or "—"
    people = ", ".join(dict.fromkeys([i["owner"], *i["members"]])) if i["owner"] or i["members"] else "—"
    return f"""<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>{e(i['display_id'])} 보고용 요약</title>
<style>
@page{{size:A4;margin:14mm}}
body{{font-family:'Malgun Gothic','Segoe UI',sans-serif;color:#1d2330;font-size:12.5px;line-height:1.55;margin:24px auto;max-width:820px}}
h1{{font-size:20px;margin:0 0 2px}} h2{{font-size:14px;margin:16px 0 4px;border-bottom:2px solid #1d2330;padding-bottom:3px}}
.meta{{color:#566;margin-bottom:10px}} .hl{{border:2px solid #1d2330;padding:10px 14px;font-size:15px;font-weight:700;margin:8px 0}}
.grid{{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0}} .box{{flex:1;min-width:120px;border:1px solid #ccd3dd;padding:6px 10px}}
.box b{{display:block;font-size:16px}} .box span{{color:#566;font-size:11px}}
table{{border-collapse:collapse;width:100%;margin:6px 0}} td,th{{border:1px solid #ccd3dd;padding:4px 7px;text-align:left;vertical-align:top}}
th{{background:#eef1f5}} ul{{margin:4px 0 4px 18px;padding:0}} .none{{color:#889}}
.chip{{display:inline-block;padding:1px 8px;margin-right:4px;border-radius:9px;border:1px solid #999;font-size:11px}}
.critical{{color:#b0003a;font-weight:700}} .high{{color:#c24a00;font-weight:700}} .medium{{color:#8a6d00}} .low{{color:#1565c0}}
.warn{{background:#fff7e0;border:1px solid #e0b84a;padding:6px 10px}} .foot{{margin-top:18px;color:#778;font-size:11px;border-top:1px solid #ccd3dd;padding-top:6px}}
@media print{{body{{margin:0}} h2{{break-after:avoid}} tr{{break-inside:avoid}}}}
</style></head><body>
<h1>보안 사건 분석 보고 (요약)</h1>
<div class="meta">{e(i['display_id'])} · {e(i['title'])}</div>
<div class="hl">{e(t['headline'])}</div>
<div class="grid">
<div class="box"><span>상태</span><b>{e(i['status_ko'])}</b></div>
<div class="box"><span>판정</span><b>{e(i['verdict_ko'] or '판정 전')}</b></div>
<div class="box"><span>위험도</span><b class="{e(i['risk_level'])}">{e(i['risk_ko'])}</b></div>
<div class="box"><span>담당</span><b style="font-size:13px">{e(people)}</b></div>
<div class="box"><span>접수 / 종결</span><b style="font-size:13px">{e(kst(i['created_at'], '%Y-%m-%d'))} / {e(kst(i['closed_at'], '%Y-%m-%d') or '진행 중')}</b></div>
</div>
<h2>1. 무슨 일이 있었나</h2>{_lines(t['what'])}
<h2>2. 영향</h2>{_lines(t['impact'])}
<h2>3. 조치한 내용</h2>{_lines(t['done'])}
<h2>4. 남은 일</h2>{_lines(t['todo'])}
<h2>5. 근거 (핵심 탐지 {len(b['top_findings'])}건 / 전체 {f['findings_total']}건)</h2>
<div>{chips or "<span class='none'>탐지 없음</span>"}</div>
{("<table><tr><th>위험도</th><th>시각(KST)</th><th>내용</th><th>성공 정황</th><th>분석가 확인</th></tr>" + rows + "</table>") if rows else ""}
<div>{e(_check_line(f['checks']))}</div>
<h2>6. 분석한 자료</h2>
<div>자료 {f['files']}개({e(size_txt)}), 기록 {f['events']:,}건, 기간 {e(period)} (한국 시간)</div>
<div>{srcs}</div>
{("<h2>7. 이 결과를 볼 때 유의할 점</h2><div class='warn'><ul>" + caveats + "</ul></div>") if caveats else ""}
<div class="foot">작성 {e(author)} · {e(kst(b['generated_at']))} (한국 시간) · SAW 분석 결과를 바탕으로 한 요약이며 최종 판단은 분석 담당자가 합니다.
{' · IP 주소 끝자리는 가려져 있습니다.' if b['masked'] else ''}{f" · 문구 수정: {e(b['edit']['by'])} ({e(kst(b['edit']['at']))})" if b.get('edit') else ''}</div>
</body></html>"""


# ---------------------------------------------------------------- board over all investigations the person may read
def board(s: Session, p: Principal, days: int = 30) -> dict[str, Any]:
    days = max(1, min(int(days), 365))
    now = utcnow()
    since = now - timedelta(days=days)
    invs = list_for(s, p, 1000)
    visible = []
    from saw.core.application.investigations import Forbidden, NotFound
    for inv in invs:
        try:
            require_investigation_results(s, p, inv.id)
        except (Forbidden, NotFound):
            continue
        visible.append(inv)
    invs = visible
    ids = [i.id for i in invs]
    names = _names(s, list({i.owner_id for i in invs}))
    highs: dict[str, int] = {}
    owed: dict[str, int] = {}
    helping: dict[str, int] = {}
    last: dict[str, datetime] = {}
    edited: set[str] = set()
    if ids:
        highs = dict(s.execute(select(Finding.investigation_id, func.count()).where(
            Finding.investigation_id.in_(ids), Finding.risk_level.in_(["critical", "high"]),
            Finding.status.notin_(["false_positive", "duplicate"])).group_by(Finding.investigation_id)).all())
        last = dict(s.execute(select(AuditEvent.investigation_id, func.max(AuditEvent.at)).where(
            AuditEvent.investigation_id.in_(ids), AuditEvent.action.in_(WORK_ACTIONS))
            .group_by(AuditEvent.investigation_id)).all())
        edited = set(s.execute(select(Briefing.investigation_id).where(Briefing.investigation_id.in_(ids))).scalars())
        from saw.core.application import reviews as review_svc
        from saw.core.application import teamwork
        from saw.storage.models import Review

        helping = teamwork.open_counts(s, ids)

        owed = {i: review_svc.open_count(s, i) for i in
                set(s.execute(select(Review.investigation_id).where(Review.investigation_id.in_(ids))).scalars())}
    rows = []
    for i in invs:
        risk = i.risk_override or i.risk_level
        created, closed = _aware(i.created_at), _aware(i.closed_at)
        active = _aware(last.get(i.id)) or created
        is_open = i.status != "closed"
        idle = (now - active).days if is_open and active else 0
        rows.append({
            "id": i.id, "display_id": i.display_id, "title": i.title, "status": i.status,
            "status_ko": STATUS_KO.get(i.status, i.status), "risk_level": risk, "risk_ko": RISK_KO.get(risk, risk),
            "verdict": i.verdict, "verdict_ko": VERDICT_KO.get(i.verdict) if i.verdict else None,
            "owner": names.get(i.owner_id, ""), "created_at": created, "closed_at": closed, "last_activity": active,
            "age_days": ((closed or now) - created).days if created else 0, "idle_days": idle,
            "high_findings": highs.get(i.id, 0), "stale": is_open and idle >= STALE_DAYS,
            "urgent": is_open and risk in ("critical", "high"), "has_briefing_edit": i.id in edited,
            "reviews_open": owed.get(i.id, 0), "support_open": helping.get(i.id, 0)})
    open_rows = [r for r in rows if r["status"] != "closed"]
    closed_in = [r for r in rows if r["closed_at"] and r["closed_at"] >= since]
    opened_in = [r for r in rows if r["created_at"] and r["created_at"] >= since]
    took = sorted(r["age_days"] for r in closed_in)
    owners: dict[str, dict] = {}
    for r in open_rows:
        o = owners.setdefault(r["owner"] or "(미지정)", {"owner": r["owner"] or "(미지정)", "open": 0, "urgent": 0, "stale": 0})
        o["open"] += 1
        o["urgent"] += int(r["urgent"])
        o["stale"] += int(r["stale"])
    weeks = []
    start = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    for k in range(min(12, max(1, (days + 6) // 7)) - 1, -1, -1):
        a, z = start - timedelta(weeks=k), start - timedelta(weeks=k - 1)
        weeks.append({"week": a.astimezone(KST).strftime("%m-%d"),
                      "opened": sum(1 for r in rows if r["created_at"] and a <= r["created_at"] < z),
                      "closed": sum(1 for r in rows if r["closed_at"] and a <= r["closed_at"] < z)})
    rank = {k: n for n, k in enumerate(RISK_ORDER)}
    rows.sort(key=lambda r: (r["status"] == "closed", rank.get(r["risk_level"], 9), -r["idle_days"],
                             -(r["created_at"].timestamp() if r["created_at"] else 0)))
    return {
        "days": days, "generated_at": now, "scope": "all" if any(str(r) in ("soc_manager", "admin") for r in p.roles) else "mine",
        "tiles": {"open": len(open_rows), "urgent": sum(1 for r in open_rows if r["urgent"]),
                  "stale": sum(1 for r in open_rows if r["stale"]), "opened": len(opened_in), "closed": len(closed_in),
                  "review_wait": sum(1 for r in rows if r["reviews_open"]),
                  "median_days_to_close": took[len(took) // 2] if took else None},
        "by_verdict": [{"key": k, "label": VERDICT_KO[k], "count": sum(1 for r in closed_in if (r["verdict"] or "unknown") == k)}
                       for k in VERDICT_KO],
        "by_risk_open": [{"key": k, "label": RISK_KO[k], "count": sum(1 for r in open_rows if r["risk_level"] == k)}
                         for k in RISK_ORDER],
        "by_owner": sorted(owners.values(), key=lambda o: (-o["urgent"], -o["open"])),
        "weeks": weeks, "stale_days": STALE_DAYS, "rows": rows,
    }
