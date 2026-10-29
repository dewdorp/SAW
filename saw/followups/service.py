"""Versioned follow-up workflow, with explicit reply and verification actions."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime

from sqlalchemy import or_, select, update

from saw import container
from saw.core.application import audit
from saw.core.application.identity import principal_of
from saw.core.application.investigations import Forbidden, NotFound, access_of
from saw.core.application.provenance import canonical, digest
from saw.core.security.authz import can
from saw.detection.derived_access import source_ids
from saw.followups import schemas
from saw.followups.check_revisions import (
    Conflict,
    authorize,
    capture_check,
    check_revision_dict,
    collect_check_sources,
    get_check_revision,
)
from saw.followups.models import CheckRevision, FollowUp, FollowUpVersion
from saw.storage.db import utcnow
from saw.storage.models import Check, User

MAX_BYTES = 256 * 1024
TERMINAL = {"closed_with_limits", "cancelled"}
ACTIONS = ("edit", "reply", "verify", "close_with_limits", "cancel", "reopen")


def _get(s, inv_id, ident):
    row = s.get(FollowUp, ident)
    if row is None or row.investigation_id != inv_id:
        raise NotFound("follow-up not found")
    return row


def _version(s, row, version_id=None):
    value = s.get(FollowUpVersion, version_id or row.current_version_id)
    if value is None or value.followup_id != row.id:
        if version_id is None:
            raise Conflict("followup_current_version_corrupt")
        raise NotFound("follow-up version not found")
    if version_id is None and value.revision != row.current_revision:
        raise Conflict("followup_current_version_corrupt")
    if digest(value.payload) != value.payload_sha256:
        raise Conflict("followup_version_corrupt")
    if sorted(source_ids(value.payload)) != sorted(value.source_investigation_ids):
        raise Conflict("followup_version_source_corrupt")
    return value


def _owner(s, owner, sources):
    from saw.source_context.service import org_by_id
    if owner["org_unit_id"]:
        org_by_id(s, owner["org_unit_id"])
    if owner["user_id"]:
        user = s.get(User, owner["user_id"])
        if user is None or user.status != "active":
            raise ValueError("담당자를 찾을 수 없거나 비활성 계정입니다.")
        actor = principal_of(user)
        if any(not can(actor, "investigation.write", access_of(s, actor, iid)) for iid in sources):
            raise Forbidden("followup_owner_existing_source_write_access_required")
    return owner


def _log(s, p, row, version, action, reason):
    audit.record(s, "followup." + action, actor_id=p.user_id, actor_name=p.username,
                 target_type="followup", target_id=row.id, investigation_id=row.investigation_id,
                 detail={"version_id": version.id, "revision": version.revision,
                         "payload_sha256": version.payload_sha256, "reason": reason})


def _append(s, p, row, payload, action, sources, reason):
    payload["source_investigation_ids"] = sorted(sources)
    if len(canonical(payload).encode("utf-8")) > MAX_BYTES:
        raise ValueError("followup_version_too_large")
    version = FollowUpVersion(followup_id=row.id, revision=row.current_revision + 1,
        payload=payload, payload_sha256=digest(payload), source_investigation_ids=sorted(sources),
        created_by=p.user_id, action=action)
    s.add(version)
    s.flush()
    row.current_version_id, row.current_revision = version.id, version.revision
    _log(s, p, row, version, action, reason)
    return row


def create(s, p, inv_id, data):
    body = schemas.CreateIn.model_validate(data)
    check = s.get(Check, body.check_id)
    if check is None or check.investigation_id != inv_id:
        raise NotFound("check not found")
    sources = collect_check_sources(s, check)
    if body.check_revision_id:
        historical = s.get(CheckRevision, body.check_revision_id)
        if historical is None or historical.check_id != check.id:
            raise NotFound("selected check revision not found")
        sources |= set(historical.source_investigation_ids)
    authorize(s, p, sources, write_target=inv_id)
    s.refresh(check)
    if check.state != "active":
        raise Conflict("followup_active_check_required")
    if not collect_check_sources(s, check) <= sources:
        raise Conflict("followup_source_scope_changed")
    revision = (get_check_revision(s, p, inv_id, body.check_revision_id) if body.check_revision_id
                else capture_check(s, p, check, reason="followup_create"))
    if revision.payload["state"] != "active":
        raise Conflict("followup_active_check_revision_required")
    payload = body.model_dump(mode="json", exclude={"check_id", "check_revision_id", "origin_kind"})
    payload.update(schema="saw.followup.v1",
        check_ref={k: v for k, v in check_revision_dict(revision).items()
                   if k in {"check_id", "revision_id", "revision", "payload_sha256"}},
        status="open", reply=None, verification=None, disposition=None,
        origin={"kind": body.origin_kind, "check_id": check.id})
    sources |= set(revision.source_investigation_ids)
    _owner(s, payload["owner"], sources)
    row = FollowUp(investigation_id=inv_id, created_by=p.user_id)
    s.add(row)
    s.flush()
    return _append(s, p, row, payload, "create", sources, body.reason)


def _evidence(s, p, refs, *, target, sources, events=None):
    sources = set(sources) | {r["investigation_id"] for r in refs}
    authorize(s, p, sources, write_target=target)
    clean, seen = [], set()
    for item in refs:
        key = (item["investigation_id"], item["event_id"])
        if key in seen:
            continue
        event = container.get().events.get(*key)
        if event is None:
            raise NotFound("follow-up evidence not found")
        sources |= source_ids(event)
        clean.append({**item, "sha256": digest(event)})
        if events is not None:
            events.append({"investigation_id": item["investigation_id"], "timestamp": event.get("timestamp"),
                           "src_ip": event.get("src_ip"), "dst_ip": event.get("dst_ip"),
                           "dst_port": event.get("dst_port")})
        seen.add(key)
    authorize(s, p, sources, write_target=target)
    return clean, sources


def _scope_check(s, inv_id, payload, reply_scope, events):
    from saw.core.application.investigations import declared_period
    from saw.followups.scope import compare, requested_scope
    from saw.storage.models import Investigation

    inv = s.get(Investigation, inv_id)
    requested = requested_scope(payload, getattr(inv, "org_unit_id", None),
                                declared_period(inv) if inv is not None else (None, None))
    return compare(requested, reply_scope, events, inv_id)


def _reply_events(payload):
    return [{"investigation_id": item["investigation_id"], "event_id": item["event_id"]}
            for item in ((payload.get("reply") or {}).get("evidence") or [])]


def mutate(s, p, inv_id, ident, action, data):
    schema = schemas.PatchIn if action == "edit" else schemas.ReplyIn if action == "reply" else schemas.VerifyIn if action == "verify" else schemas.ActionIn
    body = schema.model_validate(data)
    row = _get(s, inv_id, ident)
    before = _version(s, row)
    sources = {inv_id, *before.source_investigation_ids}
    evidence = None
    scope_events: list[dict] = []
    if action in {"reply", "verify"}:
        evidence, sources = _evidence(s, p, [r.model_dump() for r in body.evidence], target=inv_id, sources=sources,
                                      events=scope_events)
    if action == "verify":
        # The reply's own evidence also counts when judging whether the reply covers the asked activity.
        _evidence(s, p, _reply_events(before.payload), target=inv_id, sources=sources, events=scope_events)
    authorize(s, p, sources, write_target=inv_id)
    s.execute(update(FollowUp).where(FollowUp.id == ident).values(id=ident)
              .execution_options(synchronize_session=False))
    s.refresh(row)
    if row.current_version_id != body.expected_version_id:
        raise Conflict("followup_version_conflict")
    before = _version(s, row)
    if not set(before.source_investigation_ids) <= sources:
        raise Conflict("followup_source_scope_changed")
    payload = deepcopy(before.payload)
    state = payload["status"]
    if action == "reopen":
        if state not in TERMINAL | {"verified"}:
            raise Conflict("followup_reopen_state_conflict")
        payload.update(status="replied" if payload["reply"] else "open", verification=None, disposition=None)
    elif state in TERMINAL:
        raise Conflict("followup_reopen_required")
    elif action == "edit":
        patch = body.patch.model_dump(mode="json", exclude_unset=True)
        if not patch:
            raise ValueError("followup_empty_patch")
        payload.update(patch)
        payload.update(status="replied" if payload["reply"] else "open", verification=None)
    elif action == "reply":
        reply_scope = body.scope.model_dump(mode="json") if body.scope else None
        payload.update(status="replied", verification=None,
                       reply={"note": body.note, "evidence": evidence, "received_by": p.user_id,
                              "received_at": utcnow().isoformat(), "scope": reply_scope,
                              "scope_check": _scope_check(s, inv_id, payload, reply_scope, scope_events)})
    elif action == "verify":
        if not payload["reply"] or not evidence:
            raise ValueError("회신과 검증 근거가 필요합니다.")
        check = _scope_check(s, inv_id, payload, payload["reply"].get("scope"), scope_events)
        outcome = body.outcome
        remaining: list[str] = []
        if outcome == "confirmed":
            if check["result"] in {"mismatch", "not_stated"}:
                raise ValueError("회신의 관계사·기간·대상이 확인 요청과 일치하지 않거나 적혀 있지 않아 '확인됨'으로 검증할 수 "
                                 f"없습니다: {check['summary']} 회신 범위를 보완받거나 '확인되지 않음'·'자료 부족'으로 기록하세요.")
            if check["result"] == "partial":
                # Only the covered part is explained; what the reply leaves out stays an open question.
                outcome, remaining = "partially_confirmed", list(check["uncovered"])
        payload.update(status="verified", verification={
            "outcome": outcome, "basis": body.basis, "evidence": evidence, "scope_check": check,
            "remaining_questions": remaining, "verified_by": p.user_id, "verified_at": utcnow().isoformat()})
    elif action in {"cancel", "close_with_limits"}:
        payload.update(status="cancelled" if action == "cancel" else "closed_with_limits",
                       disposition={"reason": body.reason, "by": p.user_id, "at": utcnow().isoformat()})
    else:
        raise ValueError("followup_action_invalid")
    _owner(s, payload["owner"], sources)
    # Recheck the final retained/new references after action replacement, using fresh reads.
    # The initial lookup can race with reprocessing; an old reply must not become verified.
    authorize(s, p, sources, write_target=inv_id)
    # The request read scope pins its first view; publication needs a new current view.
    with container.get().events.read_scope():
        _verify_evidence(payload, {})
    reason = payload["reason"] if action == "edit" else body.reason
    return _append(s, p, row, payload, action, sources, reason)


def _version_dict(version, *, full=True):
    value = {"id": version.id, "revision": version.revision, "payload_sha256": version.payload_sha256,
             "created_by": version.created_by, "created_at": version.created_at, "action": version.action}
    if full:
        value["payload"] = deepcopy(version.payload)
    return value


def to_dict(s, p, row, *, version_id=None):
    version = _version(s, row, version_id)
    actor = authorize(s, p, {row.investigation_id, *version.source_investigation_ids})
    if version_id:
        return {"id": row.id, "investigation_id": row.investigation_id, "version": _version_dict(version)}
    value = version.payload
    writable = can(actor, "investigation.write", access_of(s, actor, row.investigation_id))
    terminal = value["status"] in TERMINAL
    eligibility = {action: writable and (value["status"] in TERMINAL | {"verified"} if action == "reopen"
        else not terminal and (bool(value["reply"]) if action == "verify" else True)) for action in ACTIONS}
    eligibility["reasons"] = {action: [] if eligibility[action] else ["현재 권한 또는 상태에서 사용할 수 없습니다."] for action in ACTIONS}
    due = datetime.fromisoformat(value["due_at"]) if value["due_at"] else None
    overdue = bool(due and value["status"] in {"open", "replied"} and due < utcnow())
    return {"id": row.id, "investigation_id": row.investigation_id, "current": _version_dict(version),
            "eligibility": eligibility, "overdue": overdue}


def get(s, p, inv_id, ident, *, version_id=None):
    return to_dict(s, p, _get(s, inv_id, ident), version_id=version_id)


def list_for(s, p, inv_id, *, status=None, priority=None, owner_user_id=None, before=None, limit=50):
    authorize(s, p, {inv_id})
    limit = min(max(limit, 1), 100)
    q = select(FollowUp).where(FollowUp.investigation_id == inv_id).order_by(FollowUp.created_at.desc(), FollowUp.id.desc())
    if before:
        cursor = _get(s, inv_id, before)
        to_dict(s, p, cursor)
        q = q.where(or_(FollowUp.created_at < cursor.created_at,
                       (FollowUp.created_at == cursor.created_at) & (FollowUp.id < cursor.id)))
    out = []
    for row in s.scalars(q.execution_options(yield_per=100)):
        try:
            value = to_dict(s, p, row)
        except (Forbidden, NotFound):
            continue
        payload = value["current"]["payload"]
        if (status and payload["status"] != status) or (priority and payload["priority"] != priority):
            continue
        if owner_user_id and payload["owner"]["user_id"] != owner_user_id:
            continue
        out.append(value)
        if len(out) > limit:
            break
    return {"items": out[:limit], "next_cursor": out[limit - 1]["id"] if len(out) > limit else None}


def versions(s, p, inv_id, ident, *, before_revision=None, limit=50):
    row = _get(s, inv_id, ident)
    to_dict(s, p, row)
    q = select(FollowUpVersion).where(FollowUpVersion.followup_id == ident).order_by(FollowUpVersion.revision.desc())
    if before_revision is not None:
        q = q.where(FollowUpVersion.revision < before_revision)
    values = []
    for version in s.scalars(q.execution_options(yield_per=100)):
        try:
            to_dict(s, p, row, version_id=version.id)
        except (Forbidden, NotFound):
            continue
        values.append(_version_dict(version, full=False))
        if len(values) > limit:
            break
    return {"versions": values[:limit], "next_before_revision": values[limit - 1]["revision"] if len(values) > limit else None}


def choices(s, p, inv_id, *, followup_id=None, check_id=None, q=""):
    from saw.source_context.service import list_orgs
    sources = {inv_id}
    if followup_id:
        row = _get(s, inv_id, followup_id)
        sources |= set(_version(s, row).source_investigation_ids)
    if check_id:
        check = s.get(Check, check_id)
        if check is None or check.investigation_id != inv_id:
            raise NotFound("check not found")
        sources |= collect_check_sources(s, check)
    authorize(s, p, sources)
    users = []
    query = select(User).where(User.status == "active").order_by(User.username)
    if q:
        query = query.where(User.username.contains(q, autoescape=True))
    for user in s.scalars(query.execution_options(yield_per=100)):
        actor = principal_of(user)
        if all(can(actor, "investigation.write", access_of(s, actor, iid)) for iid in sources):
            users.append({"id": user.id, "label": user.username})
            if len(users) == 100:
                break
    return {"org_units": [{"id": org.id, "label": org.display_name} for org in list_orgs(s, p)],
            "users": users, "department_kind": "descriptive_text"}


def _selected(s, inv_id, version_ids):
    if version_ids is not None:
        ids = list(dict.fromkeys(version_ids))
        if len(ids) > 100:
            raise ValueError("followup_snapshot_limit")
        rows = list(s.execute(select(FollowUp, FollowUpVersion).join(FollowUpVersion,
            FollowUpVersion.followup_id == FollowUp.id).where(FollowUp.investigation_id == inv_id,
            FollowUpVersion.id.in_(ids))))
        if {v.id for _, v in rows} != set(ids):
            raise NotFound("selected follow-up version not found")
    else:
        rows = list(s.execute(select(FollowUp, FollowUpVersion).outerjoin(FollowUpVersion,
            FollowUp.current_version_id == FollowUpVersion.id).where(FollowUp.investigation_id == inv_id)
            .order_by(FollowUp.created_at, FollowUp.id).limit(101)))
        if len(rows) > 100:
            raise ValueError("followup_snapshot_limit")
        for row, version in rows:
            if version is None or version.followup_id != row.id or version.revision != row.current_revision:
                raise Conflict("followup_current_version_corrupt")
    return rows


def collect_followup_sources(s, inv_id, version_ids=None):
    """Internal preflight closure only; callers authorize before using snapshots."""
    sources = {inv_id}
    for row, version in _selected(s, inv_id, version_ids):
        _version(s, row, version.id)
        sources |= set(version.source_investigation_ids)
        check_ref = version.payload["check_ref"]
        check = s.get(CheckRevision, check_ref["revision_id"])
        if check is None or check.payload_sha256 != check_ref["payload_sha256"]:
            raise Conflict("followup_check_revision_changed")
        sources |= set(check.source_investigation_ids)
    return sources



def _period_widened(checked: dict, current: tuple) -> bool:
    """A request that inherited the investigation period no longer covers it after the period grew."""
    from saw.followups.scope import _time

    if not checked.get("inherited"):
        return False
    cs, ce, ns, ne = _time(checked.get("start")), _time(checked.get("end")), _time(current[0]), _time(current[1])
    if not (cs and ce and ns and ne):
        return bool(ns or ne) and not (cs and ce)
    return ns < cs or ne > ce


def benign_blockers(s, inv_id) -> list[dict]:
    """Follow-ups that keep a 'normal / false positive' conclusion from being recorded.

    Explicitly cancelled or 'closed with limits' requests do not block (the analyst decided knowingly).
    Unanswered, unverified, unconfirmed, partly confirmed or out-of-scope replies do.
    """
    from saw.core.application.investigations import declared_period
    from saw.storage.models import Investigation

    inv = s.get(Investigation, inv_id)
    period = declared_period(inv) if inv is not None else (None, None)
    out = []
    for row in s.scalars(select(FollowUp).where(FollowUp.investigation_id == inv_id)):
        version = s.get(FollowUpVersion, row.current_version_id) if row.current_version_id else None
        if version is None:
            continue
        payload = version.payload
        status, verification = payload.get("status"), payload.get("verification") or {}
        check = verification.get("scope_check") or {}
        reason = None
        if status == "open":
            reason = "회신을 기다리는 중입니다."
        elif status == "replied":
            reason = "회신은 받았지만 아직 검증하지 않았습니다."
        elif status == "verified" and verification.get("outcome") != "confirmed":
            reason = {"partially_confirmed": "회신이 일부만 설명합니다: " + "; ".join(verification.get("remaining_questions") or []),
                      "not_confirmed": "확인 결과 설명이 확인되지 않았습니다.",
                      "insufficient_data": "확인 자료가 부족합니다."}.get(verification.get("outcome"), "확인이 끝나지 않았습니다.")
        elif status == "verified" and check.get("result") not in (None, "matches", "no_request_scope"):
            reason = check.get("summary") or "회신 범위가 확인 대상과 일치하지 않습니다."
        elif status == "verified" and _period_widened(check.get("checked_period") or {}, period):
            checked = check["checked_period"]
            reason = (f"조사 기간이 바뀌어 이 확인 요청이 검증한 기간({checked.get('start')} ~ {checked.get('end')}) 밖의 "
                      "구간은 확인되지 않았습니다. 새 구간에 대해 다시 확인하세요.")
        if reason:
            out.append({"followup_id": row.id, "question": payload.get("question"), "status": status, "reason": reason})
    return out


def _verify_evidence(payload, cache):
    for field in ("reply", "verification"):
        for ref in (payload.get(field) or {}).get("evidence", []):
            key = (ref["investigation_id"], ref["event_id"])
            if key not in cache:
                event = container.get().events.get(*key)
                cache[key] = digest(event) if event is not None else None
            if cache[key] is None or cache[key] != ref.get("sha256"):
                raise Conflict("followup_evidence_changed")


def snapshot_followups(s, p, inv_id, *, version_ids=None):
    sources = collect_followup_sources(s, inv_id, version_ids)
    authorize(s, p, sources)
    out, checks, evidence_cache = [], {}, {}
    for row, version in _selected(s, inv_id, version_ids):
        _version(s, row, version.id)
        if not set(version.source_investigation_ids) <= sources:
            raise Conflict("followup_source_scope_changed")
        _verify_evidence(version.payload, evidence_cache)
        ref = version.payload["check_ref"]
        check = get_check_revision(s, p, inv_id, ref["revision_id"])
        if check.check_id != ref["check_id"] or check.payload_sha256 != ref["payload_sha256"]:
            raise Conflict("followup_check_revision_changed")
        checks[check.id] = check_revision_dict(check)
        out.append({"id": row.id, "revision_id": version.id, "revision": version.revision,
                    "payload_sha256": version.payload_sha256, "payload": deepcopy(version.payload)})
    return {"followups": out, "checks": list(checks.values()), "source_investigation_ids": sorted(sources), "limits": []}
