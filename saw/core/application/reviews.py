"""Peer review of important conclusions (not of every record).

A review looks at one conclusion: does the evidence support it, and does it claim more than was checked? The reviewer
is someone other than the person who made the call and has to say how far they agree. An approval belongs to the
state it was given for: when the conclusion changes afterwards it reads "re-review needed" instead of staying valid.

Two situations create the need automatically, without blocking the work (urgent response must never wait for a
signature - but the open need stays visible in the investigation, on the board and in the report summary):
- a high or critical detection is rated normal / false positive,
- an investigation is closed as an attack (the conclusion goes into reports).
"""
from __future__ import annotations
from saw.detection.derived_access import source_ids, require_finding, visible_snapshot

import hashlib
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from saw.core.application import audit
from saw.core.application.investigations import Forbidden, NotFound, require
from saw.core.domain.enums import Role
from saw.core.security.authz import Principal
from saw.storage.db import utcnow
from saw.storage.models import Finding, Investigation, InvestigationMember, Review, User

SUBJECTS = {"finding": "탐지를 정상·오탐으로 낮춤", "conclusion": "조사 결론", "other": "기타 판단"}
OUTCOMES = {"approved": "근거가 결론을 지지함", "too_broad": "결론 범위가 너무 넓음", "insufficient": "자료 부족",
            "changes_requested": "보완 요청"}
STATUS_KO = {"needed": "검토자 지정 필요", "requested": "검토 대기", "withdrawn": "요청 취소", **OUTCOMES}
OPEN = ("needed", "requested")
REVIEWER_ROLES = {Role.ANALYST, Role.SENIOR_ANALYST, Role.SOC_MANAGER}
DOWNGRADE = ("benign", "false_positive")


def _digest(*parts: Any) -> str:
    return hashlib.sha256("\x1f".join(str(p or "") for p in parts).encode()).hexdigest()[:16]


def state_of(s: Session, r: Review) -> str:
    """Fingerprint of what the review is about, as it is now."""
    if r.subject_type == "finding":
        f = s.get(Finding, r.subject_id)
        return _digest("finding", f.status if f else "gone")
    if r.subject_type == "conclusion":
        inv = s.get(Investigation, r.investigation_id)
        return _digest("conclusion", inv.status, inv.verdict, inv.verdict_reason)
    return _digest("other", r.conclusion)


def _still_required(s: Session, r: Review) -> bool:
    """Does the subject, as it is now, still fall under a rule that asks for a review?"""
    if r.subject_type == "finding":
        f = s.get(Finding, r.subject_id)
        return bool(f and f.risk_level in ("critical", "high") and f.status in DOWNGRADE)
    if r.subject_type == "conclusion":
        inv = s.get(Investigation, r.investigation_id)
        return bool(inv and inv.status == "closed" and inv.verdict == "attack")
    return True



def _derived_visible(s, p, review):
    payload = list(review.evidence or [])
    if review.subject_type == "finding":
        finding = s.get(Finding, review.subject_id)
        if finding:
            payload.append(finding.evidence_refs or {})
    return visible_snapshot(s, p, payload)

def to_dict(s: Session, r: Review) -> dict[str, Any]:
    if not _derived_visible(s, s.info.get("principal"), r):
        raise Forbidden("derived_review_source")
    decided = r.status in OUTCOMES
    stale = decided and r.snapshot != state_of(s, r)
    if r.status in OPEN:
        is_open = (not r.required) or _still_required(s, r)   # the call was taken back: nothing is owed any more
    elif r.status == "approved":
        is_open = stale and _still_required(s, r)             # approved for an earlier state of the conclusion
    else:
        is_open = r.status in ("too_broad", "insufficient", "changes_requested")
    return {"id": r.id, "investigation_id": r.investigation_id, "subject_type": r.subject_type, "subject_id": r.subject_id,
            "subject_ko": SUBJECTS.get(r.subject_type, r.subject_type), "subject_label": r.subject_label,
            "conclusion": r.conclusion, "scope_note": r.scope_note, "limits": r.limits or [], "evidence": [x for x in r.evidence or [] if not isinstance(x, dict)],
            "required": r.required, "status": r.status, "status_ko": STATUS_KO.get(r.status, r.status),
            "stale": stale, "open": is_open,
            "requested_by": r.requested_by_name, "requested_by_id": r.requested_by, "reviewer": r.reviewer_name,
            "reviewer_id": r.reviewer_id, "outcome_note": r.outcome_note, "created_at": r.created_at,
            "decided_at": r.decided_at}


def reviewers(s: Session, p: Principal) -> list[dict[str, str]]:
    """People who may be asked: anyone who analyses, except the person asking."""
    out = []
    for u in s.execute(select(User).where(User.status == "active").order_by(User.username)).scalars():
        roles = {Role(r) for r in u.roles}
        if u.id != p.user_id and roles & REVIEWER_ROLES:
            out.append({"id": u.id, "name": u.display_name or u.username, "username": u.username,
                        "senior": bool(roles & {Role.SENIOR_ANALYST, Role.SOC_MANAGER})})
    return out


def _reviewer(s: Session, p: Principal, reviewer_id: str) -> User:
    u = s.get(User, reviewer_id)
    if u is None or u.status != "active" or not {Role(r) for r in u.roles} & REVIEWER_ROLES:
        raise ValueError("검토자로 지정할 수 없는 사용자입니다")
    if u.id == p.user_id:
        raise ValueError("자신에게 검토를 요청할 수 없습니다")
    return u


def _let_in(s: Session, inv_id: str, user_id: str) -> None:
    """A reviewer has to be able to open what they review: read access to this investigation only."""
    if s.get(InvestigationMember, (inv_id, user_id)) is None:
        s.add(InvestigationMember(investigation_id=inv_id, user_id=user_id, access="viewer"))


def _limits(s: Session, inv: Investigation) -> list[str]:
    """What is known to be missing, taken from the report summary, so the reviewer sees it without being told."""
    from saw.core.application import briefing

    try:
        return briefing.build(s, inv, mask=True)["caveats"][:8]
    except Exception:  # noqa: BLE001 - the request must not fail because the summary could not be built
        return []


def request(s: Session, p: Principal, inv_id: str, data: dict) -> Review:
    inv = require(s, p, "investigation.write", inv_id)
    st = str(data.get("subject_type") or "other")
    if st not in SUBJECTS:
        raise ValueError(f"subject_type must be one of {sorted(SUBJECTS)}")
    conclusion = str(data.get("conclusion") or "").strip()
    if not conclusion:
        raise ValueError("검토받을 결론을 한 줄로 적어 주세요")
    sid, label = str(data.get("subject_id") or ""), str(data.get("subject_label") or "")
    if st == "finding":
        f = s.get(Finding, sid)
        if f is None or f.investigation_id != inv_id:
            raise NotFound("finding not found")
        require_finding(s, p, f)
        label = label or f"{f.display_id} {f.title}"
    u = _reviewer(s, p, str(data.get("reviewer_id") or ""))
    if st == "conclusion":
        from saw.core.application import teamwork

        if teamwork.is_helper(s, inv_id, u.id):  # took part in the analysis: not an independent look at its conclusion
            raise ValueError("이 조사의 분석을 지원한 사람은 조사 결론의 검토자가 될 수 없습니다")
    limits = _limits(s, inv)
    # an open need for the same subject is filled in rather than duplicated
    r = s.execute(select(Review).where(Review.investigation_id == inv_id, Review.subject_type == st,
                                       Review.subject_id == sid, Review.status.in_(OPEN))).scalars().first()
    if r is None:
        r = Review(investigation_id=inv_id, subject_type=st, subject_id=sid, required=False,
                   requested_by=p.user_id, requested_by_name=p.username)
        s.add(r)
    r.subject_label, r.conclusion = label[:256], conclusion[:1000]
    r.scope_note = str(data.get("scope_note") or "").strip()[:1000]
    r.evidence = [str(x) for x in (data.get("evidence") or [])][:20]
    if st == "finding" and source_ids(f):
        r.evidence = [*r.evidence, {"_source_investigation_ids": sorted(source_ids(f))}]
    r.limits = limits
    r.requested_by, r.requested_by_name = p.user_id, p.username
    r.reviewer_id, r.reviewer_name, r.status = u.id, u.display_name or u.username, "requested"
    _let_in(s, inv_id, u.id)
    s.flush()
    r.snapshot = state_of(s, r)
    audit.record(s, "review.request", actor_id=p.user_id, actor_name=p.username, target_type="review", target_id=r.id,
                 investigation_id=inv_id, detail={"subject": st, "reviewer": u.username})
    return r


def need(s: Session, p: Principal, inv_id: str, subject_type: str, subject_id: str, label: str, conclusion: str) -> Review:
    """Record that a review is owed (no reviewer yet). Idempotent per subject; an earlier decision about a different
    state does not satisfy the new one."""
    r = s.execute(select(Review).where(Review.investigation_id == inv_id, Review.subject_type == subject_type,
                                       Review.subject_id == subject_id, Review.status.in_(OPEN))).scalars().first()
    if r is None:
        r = Review(investigation_id=inv_id, subject_type=subject_type, subject_id=subject_id, status="needed", required=True,
                   requested_by=p.user_id, requested_by_name=p.username)
        s.add(r)
    if subject_type == "finding":
        finding = s.get(Finding, subject_id)
        if finding:
            require_finding(s, p, finding)
            if source_ids(finding):
                r.evidence = [*(r.evidence or []), {"_source_investigation_ids": sorted(source_ids(finding))}]
    r.subject_label, r.conclusion, r.required = label[:256], conclusion[:1000], True
    s.flush()
    r.snapshot = state_of(s, r)
    return r


def on_finding_feedback(s: Session, p: Principal, f: Finding, verdict: str) -> Review | None:
    if f.risk_level in ("critical", "high") and verdict in DOWNGRADE:
        ko = {"benign": "정상", "false_positive": "오탐"}[verdict]
        return need(s, p, f.investigation_id, "finding", f.id, f"{f.display_id} {f.title}",
                    f"위험도 {f.risk_level} 탐지를 '{ko}'으로 평가함")
    return None


def on_close(s: Session, p: Principal, inv: Investigation) -> Review | None:
    if inv.verdict == "attack":
        first = (inv.verdict_reason or "").strip().splitlines()[0] if (inv.verdict_reason or "").strip() else ""
        return need(s, p, inv.id, "conclusion", "", inv.display_id, f"공격으로 판정: {first}"[:1000])
    return None


def _get(s: Session, review_id: str) -> Review:
    r = s.get(Review, review_id)
    if r is None:
        raise NotFound("review not found")
    return r


def decide(s: Session, p: Principal, review_id: str, outcome: str, note: str) -> Review:
    r = _get(s, review_id)
    require(s, p, "investigation.read", r.investigation_id)
    if r.reviewer_id != p.user_id:
        raise NotFound("review not found")  # only the person asked may answer
    if r.requested_by == p.user_id:
        raise ValueError("자신이 내린 판단을 스스로 검토할 수 없습니다")
    if r.status != "requested":
        raise ValueError("이미 처리되었거나 취소된 검토 요청입니다")
    if outcome not in OUTCOMES:
        raise ValueError(f"outcome must be one of {sorted(OUTCOMES)}")
    if len(note.strip()) < 5:
        raise ValueError("어떤 근거를 확인했고 어디까지 동의하는지 한 줄 적어 주세요")
    r.status, r.outcome_note, r.decided_at = outcome, note.strip()[:2000], utcnow()
    r.snapshot = state_of(s, r)  # the approval is for the conclusion as it stands now
    audit.record(s, "review.decide", actor_id=p.user_id, actor_name=p.username, target_type="review", target_id=r.id,
                 investigation_id=r.investigation_id, detail={"outcome": outcome, "subject": r.subject_type})
    return r


def withdraw(s: Session, p: Principal, inv_id: str, review_id: str) -> Review:
    require(s, p, "investigation.write", inv_id)
    r = _get(s, review_id)
    if r.investigation_id != inv_id:
        raise NotFound("review not found")
    if r.status not in OPEN:
        raise ValueError("이미 처리된 검토입니다")
    if r.required:  # a need created by the rules cannot be made to disappear: only the reviewer assignment is undone
        r.status, r.reviewer_id, r.reviewer_name = "needed", None, ""
    else:
        r.status = "withdrawn"
    audit.record(s, "review.withdraw", actor_id=p.user_id, actor_name=p.username, target_type="review", target_id=r.id,
                 investigation_id=inv_id, detail={"required": r.required})
    return r


def list_for_investigation(s: Session, inv_id: str) -> list[dict[str, Any]]:
    """Newest first. Only the latest review of a subject can be open: once the analyst asks again, earlier answers
    are history."""
    rows = s.execute(select(Review).where(Review.investigation_id == inv_id).order_by(Review.created_at.desc(), Review.id)).scalars()
    seen: set[tuple[str, str]] = set()
    out = []
    for r in rows:
        if not _derived_visible(s, s.info.get("principal"), r):
            continue
        d = to_dict(s, r)
        key = (r.subject_type, r.subject_id or r.id)
        d["latest"] = key not in seen
        if not d["latest"]:
            d["open"] = False
        seen.add(key)
        out.append(d)
    return out


def open_count(s: Session, inv_id: str) -> int:
    return sum(1 for r in list_for_investigation(s, inv_id) if r["open"])


def inbox(s: Session, p: Principal) -> dict[str, Any]:
    """Asked of me, and answers to what I asked that still need something from me."""
    mine = s.execute(select(Review).where(Review.reviewer_id == p.user_id, Review.status == "requested")
                     .order_by(Review.created_at)).scalars().all()
    back = s.execute(select(Review).where(Review.requested_by == p.user_id,
                                          Review.status.in_(["too_broad", "insufficient", "changes_requested", "needed"]))
                     .order_by(Review.created_at.desc()).limit(50)).scalars().all()
    invs = {i.id: i for i in s.execute(select(Investigation).where(
        Investigation.id.in_({r.investigation_id for r in [*mine, *back]}))).scalars()} if mine or back else {}

    def out(r: Review) -> dict[str, Any]:
        d = to_dict(s, r)
        i = invs.get(r.investigation_id)
        return d | {"investigation": {"id": r.investigation_id, "display_id": i.display_id if i else "", "title": i.title if i else ""}}

    usable = lambda r: r.investigation_id in invs and not (invs[r.investigation_id].settings or {}).get("data_deletion")
    return {"to_review": [out(r) for r in mine if usable(r) and _derived_visible(s, p, r)], "returned": [out(r) for r in back if usable(r) and _derived_visible(s, p, r)]}
