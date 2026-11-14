"""The exception to "one analyst, one investigation": asking a colleague to answer one separate question, and the
five-point check shown before an investigation is closed.

Support is for a question that can be answered on its own, in parallel (e.g. "did the request succeed? - look at the
responses and packets"), not for more eyes on the same records. The owner stays the owner: a helper's answer is
attached to the investigation, and the conclusion remains the owner's - which is also why a helper cannot be the
reviewer of that conclusion.
"""
from __future__ import annotations
from saw.detection.derived_access import require_investigation_results

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from saw.core.application import audit
from saw.core.application.investigations import Forbidden, NotFound, require
from saw.core.domain.enums import Role
from saw.core.security.authz import Principal, is_lead
from saw.storage.db import utcnow
from saw.storage.models import Check, Finding, Investigation, InvestigationMember, Job, Support, User

STATUS_KO = {"requested": "요청됨", "working": "진행 중", "done": "완료", "declined": "맡을 수 없음", "cancelled": "취소"}
OPEN = ("requested", "working")


def to_dict(r: Support) -> dict[str, Any]:
    return {"id": r.id, "investigation_id": r.investigation_id, "question": r.question, "scope_note": r.scope_note,
            "helper_id": r.helper_id, "helper": r.helper_name, "status": r.status, "status_ko": STATUS_KO.get(r.status, r.status),
            "open": r.status in OPEN, "result_note": r.result_note, "remaining": r.remaining,
            "requested_by": r.requested_by_name, "requested_by_id": r.requested_by, "created_at": r.created_at,
            "updated_at": r.updated_at}


def is_helper(s: Session, inv_id: str, user_id: str) -> bool:
    return s.execute(select(Support.id).where(Support.investigation_id == inv_id, Support.helper_id == user_id,
                                              Support.status.in_(["requested", "working", "done"]))).first() is not None


def request(s: Session, p: Principal, inv_id: str, question: str, scope_note: str, helper_id: str) -> Support:
    inv = require(s, p, "investigation.write", inv_id)
    if inv.owner_id != p.user_id and not is_lead(p):
        raise ValueError("지원 요청은 조사 담당자나 관제 매니저만 할 수 있습니다")
    if len(question.strip()) < 5:
        raise ValueError("지원자가 따로 확인할 수 있는 질문을 한 줄로 적어 주세요")
    u = s.get(User, helper_id)
    if u is None or u.status != "active" or u.id == inv.owner_id or not {Role(r) for r in u.roles} & {Role.ANALYST, Role.SENIOR_ANALYST, Role.SOC_MANAGER, Role.ADMIN}:
        raise ValueError("지원자로 지정할 수 없는 사용자입니다")
    r = Support(investigation_id=inv_id, question=question.strip()[:500], scope_note=scope_note.strip()[:1000],
                helper_id=u.id, helper_name=u.display_name or u.username, requested_by=p.user_id, requested_by_name=p.username)
    s.add(r)
    m = s.get(InvestigationMember, (inv_id, u.id))  # a helper records what they checked: needs to write here
    if m is None:
        s.add(InvestigationMember(investigation_id=inv_id, user_id=u.id, access="editor"))
    elif m.access == "viewer":
        m.access = "editor"
    s.flush()
    audit.record(s, "support.request", actor_id=p.user_id, actor_name=p.username, target_type="support", target_id=r.id,
                 investigation_id=inv_id, detail={"helper": u.username})
    return r


def _get(s: Session, support_id: str) -> Support:
    r = s.get(Support, support_id)
    if r is None:
        raise NotFound("support request not found")
    return r


def update(s: Session, p: Principal, support_id: str, status: str, result_note: str = "", remaining: str = "") -> Support:
    """The helper reports: working / done (with what was found and what is still unknown) / cannot take it."""
    r = _get(s, support_id)
    require(s, p, "investigation.read", r.investigation_id)
    if r.helper_id != p.user_id:
        raise NotFound("support request not found")
    if r.status not in OPEN:
        raise ValueError("이미 끝났거나 취소된 요청입니다")
    if status not in ("working", "done", "declined"):
        raise ValueError("status must be working, done or declined")
    if status == "done" and len(result_note.strip()) < 5:
        raise ValueError("확인한 결과를 한 줄 적어 주세요(확인 기록은 조사 안에 따로 남기세요)")
    r.status, r.updated_at = status, utcnow()
    if status in ("done", "declined"):
        r.result_note, r.remaining = result_note.strip()[:2000], remaining.strip()[:1000]
    audit.record(s, "support.update", actor_id=p.user_id, actor_name=p.username, target_type="support", target_id=r.id,
                 investigation_id=r.investigation_id, detail={"status": status})
    return r


def cancel(s: Session, p: Principal, inv_id: str, support_id: str) -> Support:
    require(s, p, "investigation.write", inv_id)
    r = _get(s, support_id)
    if r.investigation_id != inv_id:
        raise NotFound("support request not found")
    if r.requested_by != p.user_id and not is_lead(p):
        raise ValueError("요청한 사람이나 관제 매니저만 취소할 수 있습니다")
    if r.status not in OPEN:
        raise ValueError("이미 끝난 요청입니다")
    r.status, r.updated_at = "cancelled", utcnow()
    audit.record(s, "support.cancel", actor_id=p.user_id, actor_name=p.username, target_type="support", target_id=r.id,
                 investigation_id=inv_id)
    return r


def list_for_investigation(s: Session, inv_id: str) -> list[dict[str, Any]]:
    return [to_dict(r) for r in s.execute(select(Support).where(Support.investigation_id == inv_id)
                                          .order_by(Support.created_at.desc())).scalars()]


def inbox(s: Session, p: Principal) -> list[dict[str, Any]]:
    rows = s.execute(select(Support).where(Support.helper_id == p.user_id, Support.status.in_(OPEN))
                     .order_by(Support.created_at)).scalars().all()
    out = []
    for r in rows:
        inv = s.get(Investigation, r.investigation_id)
        if inv is None or (inv.settings or {}).get("data_deletion"):
            continue
        try:
            inv = require(s, p, "investigation.read", r.investigation_id)
        except (Forbidden, NotFound):
            continue
        out.append(to_dict(r) | {"investigation": {"id": inv.id, "display_id": inv.display_id, "title": inv.title}})
    return out


def open_counts(s: Session, inv_ids: list[str]) -> dict[str, int]:
    if not inv_ids:
        return {}
    return dict(s.execute(select(Support.investigation_id, func.count()).where(
        Support.investigation_id.in_(inv_ids), Support.status.in_(OPEN)).group_by(Support.investigation_id)).all())


# ---------------------------------------------------------------- before closing: five points, no more
def _conflicts(checks: list[Check]) -> list[str]:
    """Targets where active records answer the same question with "normal" and "malicious"."""
    seen: dict[tuple[str, str], set[str]] = {}
    label: dict[str, str] = {}
    for c in checks:
        if c.kind != "direct" or c.judgement not in ("normal", "malicious"):
            continue
        label[c.target_key] = c.target_label
        for q in c.questions or []:
            seen.setdefault((c.target_key, q), set()).add(c.judgement)
    return sorted({label[k] for (k, _q), js in seen.items() if len(js) > 1})


def closing_check(s: Session, inv: Investigation) -> list[dict[str, Any]]:
    """What to look at before closing. Each point is "nothing to note" or lists what is open; none of them blocks
    the close - an investigation may be closed with limits, as long as the limits are said out loud."""
    from saw.core.application import briefing, reviews
    from saw.core.application import checks as check_svc

    require_investigation_results(s, s.info.get("principal"), inv.id)
    b = briefing.build(s, inv, mask=True)
    rows = check_svc.list_checks(s, inv.id)
    chk = b["facts"]["checks"]
    high = [f for f in s.execute(select(Finding).where(Finding.investigation_id == inv.id,
                                                       Finding.risk_level.in_(["critical", "high"]))).scalars()
            if f.status not in ("false_positive", "duplicate", "benign")]
    data_notes = [c for c in b["caveats"] if any(w in c for w in ("자료", "기록 ", "패킷", "줄은", "표본", "처리 중"))]
    scope = {"key": "scope", "title": "1. 조사 범위와 확인하지 못한 영역", "lines": data_notes}
    if not chk["direct"]:
        scope["lines"] = [*scope["lines"], "직접 확인해 남긴 기록이 없습니다(자동 탐지 결과만 있음)."]

    q_lines = []
    unseen = [f for f in high if f.status == "new"]
    if unseen:
        q_lines.append(f"높은 위험 탐지 {len(unseen)}건을 아직 평가하지 않았습니다: " + ", ".join(f.display_id for f in unseen[:6]))
    clash = _conflicts(rows)
    if clash:
        q_lines.append("같은 대상·같은 질문에 '정상'과 '악성' 확인이 함께 있습니다: " + ", ".join(clash[:4]))
    if chk["source_changed"]:
        q_lines.append(f"참고한 다른 조사의 확인 {chk['source_changed']}건이 바뀌었거나 철회되었습니다.")
    questions = {"key": "questions", "title": "2. 핵심 탐지 평가와 서로 다른 판단", "lines": q_lines}

    a_lines = []
    if high:
        by_q = chk["by_question"]
        if not by_q["success"]:
            a_lines.append("공격이 실제로 성공했는지 확인한 기록이 없습니다(시도와 성공은 다릅니다).")
        if not by_q["impact"]:
            a_lines.append("피해·유출 여부를 확인한 기록이 없습니다.")
    attack = {"key": "attack", "title": "3. 시도 · 성공 · 피해 구분", "lines": a_lines}

    t_lines = []
    jobs = s.execute(select(func.count()).select_from(Job).where(
        Job.investigation_id == inv.id, Job.state.notin_(["COMPLETED", "FAILED", "CANCELLED"]))).scalar_one()
    if jobs:
        t_lines.append(f"처리 중인 작업이 {jobs}건 있습니다.")
    helping = [r for r in list_for_investigation(s, inv.id) if r["open"]]
    if helping:
        t_lines.append(f"끝나지 않은 지원 요청 {len(helping)}건: " + ", ".join(f"{r['helper']}({r['status_ko']})" for r in helping[:4]))
    todo = {"key": "todo", "title": "4. 조치와 남은 일", "lines": t_lines,
            "hint": "종결할 때 '조치한 내용'과, 남은 일이 있으면 담당·기한을 적어 주세요."}

    r_lines = []
    owed = [r for r in reviews.list_for_investigation(s, inv.id) if r["open"]]
    if owed:
        r_lines.append(f"끝나지 않은 검토 {len(owed)}건: " + ", ".join(f"{r['subject_label'] or r['subject_ko']}({r['status_ko']})" for r in owed[:4]))
    review = {"key": "review", "title": "5. 검토와 보고 내용", "lines": r_lines,
              "hint": "공격으로 종결하면 결론이 검토 대상이 됩니다. 종결은 막지 않습니다."}
    out = [scope, questions, attack, todo, review]
    for x in out:
        x["ok"] = not x["lines"]
    return out
