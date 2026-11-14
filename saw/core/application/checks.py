"""Confirmation records: what an analyst actually checked, and how results are reused across investigations.

Principles (from the 2026-10-10 design):
- Opening a record is not checking it; checking is not judging; a shared result is a reference, never a verdict.
- A check answers a question (was it an attack / did it succeed / was there damage / is it normal business), so
  "malicious request, success not checked" can be recorded as exactly that.
- A check on an address is not a check of every record of that address; a sample is not the whole.
- Nothing is edited in place: a change supersedes, a cancellation stays visible.
- A shared result shows the conditions it was made under next to the conditions of the investigation that reads it.
"""
from __future__ import annotations
from saw.detection.derived_access import require_snapshot

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.orm import Session

from saw import container
from saw.core.application import audit
from saw.core.application.investigations import NotFound, access_of, require
from saw.core.domain.enums import Role
from saw.core.schemas.query import AggRequest, Filter, TimeRange
from saw.core.security.authz import Principal, can
from saw.core.security.masking import mask_event, mask_text
from saw.storage.db import utcnow
from saw.storage.models import Check, Investigation

KST = ZoneInfo("Asia/Seoul")
QUESTIONS = {"nature": "요청 성격", "success": "성공 여부", "impact": "피해 여부", "business": "정상 업무 여부"}
JUDGEMENTS = {"normal": "정상", "suspicious": "의심", "malicious": "악성", "undetermined": "판단 불가"}
COVERAGE = {"one": "이 대상", "selected": "고른 기록", "sample": "표본", "all": "전체", "observation": "자동 관측 근거"}
TARGETS = ("event", "entity", "finding", "set")
ENTITY_TYPES = ("ip", "domain", "hash", "uri", "user", "session", "ja4", "ja3")
SHARE_STATUS = {"unreviewed": "미검토 참고", "reviewed": "검토됨", "recheck": "재확인 필요", "retracted": "철회"}
VALID_DAYS = {"normal": 90, "malicious": 180}  # a result is believed for a while, not for ever
DEFAULT_VALID_DAYS = 90
MAX_IDS = 200
# event field that carries each kind of entity (for the conditions a shared result was made under)
ENTITY_FIELDS = {"ip": ("src_ip", "dst_ip"), "domain": ("domain", "hostname"), "uri": ("uri_template", "url_path"),
                 "user": ("user",), "session": ("session_id",), "ja4": ("ja4",), "ja3": ("ja3",)}


class Conflict(ValueError):
    """The record was changed or cancelled by someone else since it was read."""


def set_key(query: dict) -> str:
    """Stable key of a search result: the same filters and time range give the same key."""
    return "set:" + hashlib.sha256(json.dumps(query or {}, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:24]


def _aware(dt: datetime | None) -> datetime | None:
    return None if dt is None else (dt if dt.tzinfo else dt.replace(tzinfo=UTC))


def _expired(c: Check, now: datetime | None = None) -> bool:
    v = _aware(c.valid_until)
    return bool(c.shared and v and v < (now or utcnow()))


def to_dict(c: Check, full: bool = True) -> dict[str, Any]:
    from sqlalchemy.orm import object_session
    session = object_session(c)
    if session is not None:
        require_snapshot(session, session.info.get("principal"), [c.scope, c.context])
    return _snapshot_payload(c, full)


def _snapshot_payload(c: Check, full: bool = True) -> dict[str, Any]:
    """Pure projection for an authorized serializer or private transition snapshot."""
    scope = c.scope or {}
    d = {
        "id": c.id, "investigation_id": c.investigation_id, "target_type": c.target_type, "target_key": c.target_key,
        "target_label": c.target_label, "questions": c.questions or [],
        "question_labels": [QUESTIONS[q] for q in c.questions or [] if q in QUESTIONS],
        "judgement": c.judgement, "judgement_ko": JUDGEMENTS.get(c.judgement) if c.judgement else None,
        "note": mask_text(c.note or "").text, "coverage": scope.get("coverage", "one"),
        "coverage_ko": COVERAGE.get(scope.get("coverage", "one"), ""), "checked": scope.get("checked"),
        "total": scope.get("total"), "kind": c.kind, "source_check_id": c.source_check_id, "source_state": c.source_state,
        "shared": c.shared, "share_status": c.share_status or None,
        "share_status_ko": SHARE_STATUS.get(c.share_status) if c.share_status else None,
        "valid_until": c.valid_until, "expired": _expired(c), "state": c.state, "state_note": c.state_note,
        "state_by": c.state_by, "supersedes_id": c.supersedes_id, "author_id": c.author_id, "author": c.author_name,
        "created_at": c.created_at, "time_start": c.time_start, "time_end": c.time_end,
        "guidance_status": scope.get("guidance", {}).get("answer_status"),
        "behavior_status": scope.get("behavior", {}).get("answer_status"),
    }
    if full:
        d |= {"share": {k: mask_text(str(v)).text for k, v in (c.share or {}).items()}, "evidence": c.evidence or [],
              "scope": {k: v for k, v in scope.items() if k != "event_ids"}, "context": c.context or {},
              "guidance": scope.get("guidance"), "capture": (c.context or {}).get("guidance"),
              "behavior": scope.get("behavior")}
    return d


# ---------------------------------------------------------------- conditions a result was made under
def _terms(es, inv_id: str, flt: list[Filter], field: str, time: TimeRange | None, size: int = 8) -> list[str]:
    try:
        return [str(b["key"]) for b in es.aggregate(inv_id, flt, AggRequest(type="terms", field=field, size=size), time)["buckets"]
                if b["key"] not in (None, "")]
    except Exception:  # noqa: BLE001 - a field the store cannot aggregate is simply "not known"
        return []


def context_of(inv_id: str, key: str, time: TimeRange | None = None) -> dict[str, Any]:
    """What the investigation shows about an entity: when it was active, whom it talked to, which paths and ports.
    Empty lists mean "not known here", which is different from "nothing"."""
    etype, _, value = key.partition(":")
    fields = ENTITY_FIELDS.get(etype)
    if not fields or not value:
        return {}
    es = container.get().events
    flt, n = [], 0
    for f in fields:
        flt = [Filter(field=f, value=value)]
        n = es.count(inv_id, flt, time)
        if n:
            break
    if not n:
        return {"events": 0}
    lo, hi = es.time_bounds(inv_id, flt)
    hours: list[int] = []
    try:
        a, z = (datetime.fromisoformat(x.replace("Z", "+00:00")).astimezone(KST) for x in (lo, hi))
        if z - a < timedelta(hours=23):
            h = a.hour
            while True:
                hours.append(h)
                if h == z.hour:
                    break
                h = (h + 1) % 24
    except (AttributeError, ValueError):
        pass
    role = flt[0].field
    peer = "dst_ip" if role == "src_ip" else "src_ip" if role == "dst_ip" else "dst_ip"
    return {"events": n, "role": role, "first": lo, "last": hi, "hours_kst": hours,  # [] = active around the clock/unknown
            "peers": _terms(es, inv_id, flt, peer, time), "ports": _terms(es, inv_id, flt, "dst_port", time),
            "paths": _terms(es, inv_id, flt, "url_path", time), "sources": _terms(es, inv_id, flt, "data_source", time)}


def _cmp_set(label: str, then: list, now: list) -> dict[str, Any]:
    if not then or not now:
        return {"label": label, "result": "unknown", "text": "비교할 정보 없음"}
    extra = [x for x in now if x not in then]
    if not extra:
        return {"label": label, "result": "match", "text": "확인 때와 같음"}
    return {"label": label, "result": "differ", "text": f"확인 때 없던 값 {len(extra)}개: " + ", ".join(map(str, extra[:3]))}


def compare(then: dict, now: dict) -> list[dict[str, Any]]:
    """Condition by condition: the same as when it was checked, different, or not comparable. "Not comparable" is
    never shown as a match."""
    if not then or not now or not now.get("events"):
        return [{"label": "조건", "result": "unknown", "text": "이 조사에서 비교할 기록이 없음"}]
    out = []
    th, nh = then.get("hours_kst") or [], now.get("hours_kst") or []
    if not th or not nh:
        out.append({"label": "시간대", "result": "unknown", "text": "비교할 정보 없음(하루 종일 활동했거나 알 수 없음)"})
    else:
        extra = sorted(h for h in nh if h not in th)
        out.append({"label": "시간대", "result": "differ" if extra else "match",
                    "text": (f"확인 때({th[0]}~{th[-1]}시) 밖의 시간: " + ", ".join(f"{h}시" for h in extra[:6])) if extra
                    else f"확인 때와 같은 시간대({th[0]}~{th[-1]}시)"})
    out.append(_cmp_set("상대 주소", then.get("peers") or [], now.get("peers") or []))
    out.append(_cmp_set("포트", then.get("ports") or [], now.get("ports") or []))
    out.append(_cmp_set("경로", then.get("paths") or [], now.get("paths") or []))
    return out


# ---------------------------------------------------------------- write
def _set_total(inv_id: str, query: dict) -> int | None:
    from saw import container

    try:
        filters = [Filter.model_validate(f) for f in (query or {}).get("filters") or []]
        time = TimeRange.model_validate(query["time"]) if (query or {}).get("time") else None
    except Exception:  # noqa: BLE001 - an unreadable stored query cannot be counted; the claim is then refused below
        return None
    return container.get().events.count(inv_id, filters, time)


def _existing(inv_id: str, ids: list[str]) -> int:
    from saw import container

    return container.get().events.count(inv_id, [Filter(field="event_id", op="in", value=sorted(set(ids)))], None)


ORIGIN_KEYS = {"kind", "bundle", "title", "description", "parameters", "preset", "scope", "completeness",
               "partial_reasons", "item", "questions"}
ITEM_KEYS = {"title", "observed", "basis", "records", "filters", "unknown", "normal_possibilities", "next_questions", "time", "evidence_time", "strength"}


def _origin(origin: Any, inv_id: str) -> dict:
    """Where a check came from: the question, its exact condition and run scope, and the whole item it records."""
    import json

    if not isinstance(origin, dict) or origin.get("kind") != "question":
        raise ValueError("확인 기록의 출처 형식이 올바르지 않습니다")
    clean = {k: v for k, v in origin.items() if k in ORIGIN_KEYS}
    clean["item"] = {k: v for k, v in (origin.get("item") or {}).items() if k in ITEM_KEYS}
    scope = clean.get("scope") or {}
    if scope.get("investigation_id") not in (None, inv_id):
        raise ValueError("다른 조사에서 계산한 질문 결과는 이 조사의 확인 기록으로 남길 수 없습니다")
    if len(json.dumps(clean, ensure_ascii=False, default=str)) > 32_000:
        raise ValueError("확인 기록의 출처 내용이 너무 깁니다")
    return clean


def _clean(data: dict, inv_id: str) -> dict[str, Any]:
    tt = str(data.get("target_type") or "")
    if tt not in TARGETS:
        raise ValueError(f"target_type must be one of {TARGETS}")
    scope_in = data.get("scope") or {}
    query = scope_in.get("query") or {}
    key = str(data.get("target_key") or "").strip()
    if tt == "set":
        key = set_key(query)
    if not key:
        raise ValueError("target_key is required")
    if tt == "entity" and key.partition(":")[0] not in ENTITY_TYPES:
        raise ValueError(f"entity key must start with one of {ENTITY_TYPES}")
    questions = [q for q in dict.fromkeys(data.get("questions") or []) if q in QUESTIONS]
    if not questions:
        raise ValueError("무엇을 확인했는지 하나 이상 고르세요")
    judgement = data.get("judgement") or None
    if judgement and judgement not in JUDGEMENTS:
        raise ValueError(f"judgement must be one of {sorted(JUDGEMENTS)}")
    note = str(data.get("note") or "").strip()[:2000]
    if judgement in ("normal", "malicious") and not note:
        raise ValueError("정상·악성으로 판단할 때는 근거를 한 줄 적어 주세요")
    coverage = scope_in.get("coverage") or ("one" if tt != "set" else "all")
    if coverage not in COVERAGE:
        raise ValueError(f"coverage must be one of {sorted(COVERAGE)}")
    ids = [str(x) for x in (scope_in.get("event_ids") or [])][:MAX_IDS]
    total, checked = scope_in.get("total"), scope_in.get("checked")
    loaded = scope_in.get("loaded")
    loaded = len(loaded) if isinstance(loaded, list) else loaded
    if tt == "set":
        # The server counts the search itself: a client cannot claim a larger or smaller result than it has.
        total = _set_total(inv_id, query)
        if ids and _existing(inv_id, ids) != len(set(ids)):
            raise ValueError("확인 기록의 대표 기록 중 이 조사에 없는 기록이 있습니다")
        if loaded is not None and total is not None and int(loaded) > total:
            raise ValueError("불러온 건수가 검색 결과 전체보다 많을 수 없습니다")
    if coverage == "observation":
        # Explicit, new coverage. Never infer this from old notes, a lack of judgement or checked=0.
        origin = scope_in.get("origin") or {}
        origin_scope = origin.get("scope") if isinstance(origin, dict) else None
        item = origin.get("item") if isinstance(origin, dict) else None
        if (tt != "set" or not isinstance(origin, dict) or origin.get("kind") != "question"
                or not isinstance(origin_scope, dict) or origin_scope.get("investigation_id") != inv_id or not isinstance(item, dict)
                or origin.get("bundle") not in {"web_attack", "transfer", "periodic", "spread"}
                or item.get("filters") != query.get("filters") or not query.get("filters")
                or (item.get("evidence_time") or origin_scope.get("time")) != query.get("time")
                or type(checked) is not int or checked != 0 or ids or loaded is not None or judgement or data.get("shared")
                or data.get("behavior") or data.get("guidance")):
            raise ValueError("자동 관측 근거에는 이 조사의 계산 조건만 남길 수 있습니다. 직접 확인이나 판단은 따로 기록하세요.")
        evidence = list(dict.fromkeys(str(x) for x in data.get("evidence") or []))
        if not evidence or len(evidence) > 20 or not total:
            raise ValueError("관측 근거를 다시 조회하세요. 현재 조건에 맞는 원문이 필요합니다.")
        filters = [Filter.model_validate(f) for f in query["filters"]]
        time = TimeRange.model_validate(query["time"]) if query.get("time") else None
        if container.get().events.count(inv_id, [*filters, Filter(field="event_id", op="in", value=evidence)], time) != len(evidence):
            raise ValueError("자동 관측의 대표 원문이 현재 조회 범위와 일치하지 않습니다. 다시 계산하세요.")
    if coverage == "sample":
        checked = int(checked or len(ids) or 0)
        if not total or not checked or checked >= int(total):
            raise ValueError("표본 확인은 본 건수가 전체보다 적어야 합니다(전체를 봤다면 '전체'를 고르세요)")
        if tt == "set" and checked > max(len(set(ids)), int(loaded or 0)):
            # Looked-at records are bounded by what was loaded on screen; the kept references are a part of those.
            raise ValueError(f"확인한 건수({checked})가 화면에 불러온 기록 수({int(loaded or len(set(ids)))})보다 많습니다. "
                             "불러온 기록 안에서만 표본으로 기록할 수 있습니다")
    if coverage == "all" and tt == "set" and total is not None:
        # Only records actually loaded can have been looked at: 20,000 shown of 100,000 is a sample, not "all".
        seen = loaded if loaded is not None else checked
        if seen is not None and int(seen) < int(total):
            raise ValueError("불러온 기록이 검색 결과 전체보다 적어 '전체 확인'으로 기록할 수 없습니다. '표본'으로 기록하세요")
        # Without a loaded count the record says nothing about how many rows were read (checked stays unknown).
        checked = total if seen is not None else None
    scope = {"coverage": coverage, "checked": int(checked) if checked is not None else (len(ids) or None),
             "total": int(total) if total is not None else None, "query": query, "event_ids": ids}
    if scope_in.get("origin"):
        scope["origin"] = _origin(scope_in["origin"], inv_id)
    if tt == "set":
        scope.update(loaded=int(loaded) if loaded is not None else None, kept_refs=len(ids))
    return {"target_type": tt, "target_key": key[:512], "target_label": str(data.get("target_label") or key)[:512],
            "scope": scope, "questions": questions, "judgement": judgement, "note": note,
            "evidence": [str(x) for x in (data.get("evidence") or [])][:20],
            "time_start": data.get("time_start"), "time_end": data.get("time_end")}


def _share_fields(c: Check, data: dict, inv_id: str) -> None:
    share = data.get("share") or {}
    if not data.get("shared"):
        c.shared, c.share, c.share_status, c.valid_until, c.context = False, {}, "", None, {}
        return
    if c.target_type != "entity":
        raise ValueError("다른 조사와 공유할 수 있는 것은 IP·도메인·해시 같은 대상에 대한 확인입니다")
    if c.kind == "cited":
        raise ValueError("다른 사람의 확인을 참고한 기록은 다시 공유할 수 없습니다(원래 확인을 보게 됩니다)")
    fact, confirmed = str(share.get("fact") or "").strip(), str(share.get("confirmed_scope") or "").strip()
    if not fact or not confirmed:
        raise ValueError("공유하려면 '확인한 사실'과 '확인한 범위'를 적어 주세요")
    c.shared = True
    c.share = {"fact": fact[:500], "confirmed_scope": confirmed[:500],
               "unconfirmed_scope": str(share.get("unconfirmed_scope") or "").strip()[:500]}
    c.share_status = "unreviewed"
    c.valid_until = utcnow() + timedelta(days=VALID_DAYS.get(c.judgement or "", DEFAULT_VALID_DAYS))
    time = TimeRange(start=c.time_start, end=c.time_end) if c.time_start or c.time_end else None
    c.context = context_of(inv_id, c.target_key, time)


def create(s: Session, p: Principal, inv_id: str, data: dict) -> Check:
    require(s, p, "investigation.write", inv_id)
    from saw.core.application.guidance import attach_capture, prepare_check
    if data.get("guidance"):
        data = prepare_check(data)
    from saw.behavior.service import prepare_check as prepare_behavior, attach_check as attach_behavior
    if data.get("behavior"):
        data = prepare_behavior(s, p, inv_id, data)
    c = Check(investigation_id=inv_id, author_id=p.user_id, author_name=p.username, **_clean(data, inv_id))
    _share_fields(c, data, inv_id)
    attach_capture(s, p, inv_id, c, data)
    attach_behavior(s, p, inv_id, c, data)
    s.add(c)
    s.flush()
    from saw.followups.check_revisions import _capture_transition
    _capture_transition(s, p, c, reason="create", new=True)
    audit.record(s, "check.create", actor_id=p.user_id, actor_name=p.username, target_type="check", target_id=c.id,
                 investigation_id=inv_id, detail={"target": c.target_type, "questions": c.questions,
                                                  "judgement": c.judgement, "coverage": c.scope["coverage"], "shared": c.shared})
    return c


def _get(s: Session, inv_id: str, check_id: str) -> Check:
    c = s.get(Check, check_id)
    if c is None or c.investigation_id != inv_id:
        raise NotFound("check not found")
    return c


def _flag_citations(s: Session, source: Check, state: str, p: Principal) -> int:
    """Investigations that relied on a shared result learn that it changed or was withdrawn."""
    rows = s.execute(select(Check).where(Check.source_check_id == source.id, Check.state == "active")).scalars().all()
    from saw.followups.check_revisions import _capture_transition
    for r in rows:
        _capture_transition(s, p, r, reason="before_source_change")
        r.source_state, r.updated_at = state, utcnow()
        _capture_transition(s, p, r, reason="source_change")
    return len(rows)


def change(s: Session, p: Principal, inv_id: str, check_id: str, data: dict) -> Check:
    """The author revises their own record: the old one stays as history. Others add their own record instead."""
    require(s, p, "investigation.write", inv_id)
    old = _get(s, inv_id, check_id)
    _require_cited_source(s, p, old)
    if old.author_id != p.user_id:
        raise ValueError("다른 사람의 확인 기록은 고칠 수 없습니다. 내 확인 기록을 따로 남기세요")
    if old.state != "active":
        raise Conflict("이 기록은 이미 변경되었거나 취소되었습니다. 최신 내용을 다시 불러오세요")
    from saw.core.application.guidance import attach_capture, prepare_check
    if data.get("guidance"):
        data = prepare_check(data)
    merged = {"target_type": old.target_type, "target_key": old.target_key, "target_label": old.target_label,
              "scope": old.scope, "questions": old.questions, "judgement": old.judgement, "note": old.note,
              "evidence": old.evidence, "time_start": old.time_start, "time_end": old.time_end,
              "shared": old.shared, "share": old.share, **data}
    from saw.behavior.service import prepare_check as prepare_behavior, attach_check as attach_behavior
    if data.get("behavior"):
        merged = prepare_behavior(s, p, inv_id, merged)
    new = Check(investigation_id=inv_id, author_id=p.user_id, author_name=p.username, kind=old.kind,
                source_check_id=old.source_check_id, supersedes_id=old.id, **_clean(merged, inv_id))
    _share_fields(new, merged, inv_id)
    attach_capture(s, p, inv_id, new, data, previous=old)
    attach_behavior(s, p, inv_id, new, merged if data.get("behavior") else data, previous=old)
    from saw.followups.check_revisions import _capture_transition
    _capture_transition(s, p, old, reason="before_change")
    old.state, old.state_by, old.updated_at = "superseded", p.username, utcnow()
    s.add(new)
    s.flush()
    _capture_transition(s, p, old, reason="superseded")
    _capture_transition(s, p, new, reason="change", new=True)
    affected = 0
    if old.shared:  # investigations that relied on the old record are told, and follow the new one if it is still shared
        for r in s.execute(select(Check).where(Check.source_check_id == old.id, Check.state == "active")).scalars():
            _capture_transition(s, p, r, reason="before_source_change")
            r.source_state, r.updated_at = ("changed" if new.shared else "retracted"), utcnow()
            if new.shared:
                r.source_check_id = new.id
            _capture_transition(s, p, r, reason="source_change")
            affected += 1
    audit.record(s, "check.change", actor_id=p.user_id, actor_name=p.username, target_type="check", target_id=new.id,
                 investigation_id=inv_id, detail={"supersedes": old.id, "judgement": new.judgement, "citations": affected})
    return new


def cancel(s: Session, p: Principal, inv_id: str, check_id: str, reason: str = "") -> Check:
    require(s, p, "investigation.write", inv_id)
    c = _get(s, inv_id, check_id)
    _require_cited_source(s, p, c)
    if c.author_id != p.user_id and not (p.roles & {Role.SOC_MANAGER, Role.ADMIN}):
        raise ValueError("확인 기록은 작성자(또는 관제 매니저)만 취소할 수 있습니다")
    if c.state != "active":
        raise Conflict("이 기록은 이미 변경되었거나 취소되었습니다")
    from saw.followups.check_revisions import _capture_transition
    _capture_transition(s, p, c, reason="before_cancel")
    c.state, c.state_by, c.state_note, c.updated_at = "cancelled", p.username, reason.strip()[:512], utcnow()
    affected = 0
    if c.shared:
        c.share_status = "retracted"
        affected = _flag_citations(s, c, "retracted", p)
    _capture_transition(s, p, c, reason="cancel")
    audit.record(s, "check.cancel", actor_id=p.user_id, actor_name=p.username, target_type="check", target_id=c.id,
                 investigation_id=inv_id, detail={"author": c.author_name, "citations": affected})
    return c


def _readable(s: Session, p: Principal, inv_id: str) -> bool:
    inv = s.get(Investigation, inv_id)
    return bool(inv is not None and not (inv.settings or {}).get("data_deletion")
                and can(p, "investigation.read", access_of(s, p, inv_id)))


def _source_checks(s: Session, c: Check) -> list[Check]:
    sources: list[Check] = []
    visited = {c.id}
    while c.kind == "cited":
        source = s.get(Check, c.source_check_id) if c.source_check_id else None
        if source is None or source.id in visited:
            raise NotFound("source check not found")
        visited.add(source.id)
        sources.append(source)
        c = source
    return sources


def _visible_check(s: Session, p: Principal, c: Check) -> bool:
    try:
        return all(_readable(s, p, row.investigation_id) for row in [c, *_source_checks(s, c)])
    except NotFound:
        return False


def _require_cited_source(s: Session, p: Principal, c: Check) -> None:
    for source in _source_checks(s, c):
        require(s, p, "investigation.read", source.investigation_id)


def source_investigation_ids(s: Session, p: Principal, inv_id: str) -> set[str]:
    """Validate active citation sources and return the complete investigation ledger for report/export checks."""
    require(s, p, "investigation.read", inv_id)
    ids = {inv_id}
    for c in s.execute(select(Check).where(Check.investigation_id == inv_id, Check.state == "active")).scalars():
        for source in _source_checks(s, c):
            require(s, p, "investigation.read", source.investigation_id)
            ids.add(source.investigation_id)
    return ids


# ---------------------------------------------------------------- read (own investigation)
def list_checks(s: Session, inv_id: str, target_key: str | None = None, history: bool = False, *, principal: Principal | None = None) -> list[Check]:
    q = select(Check).where(Check.investigation_id == inv_id).order_by(Check.created_at.desc()).limit(2000)
    if target_key:
        q = q.where(Check.target_key == target_key)
    if not history:
        q = q.where(Check.state == "active")
    return [c for c in s.execute(q).scalars() if (c.kind != "cited" if principal is None else _visible_check(s, principal, c))]


def _brief(c: Check) -> dict[str, Any]:
    return {"id": c.id, "questions": c.questions, "judgement": c.judgement, "author": c.author_name, "kind": c.kind,
            "coverage": (c.scope or {}).get("coverage", "one"), "shared": c.shared, "source_state": c.source_state,
            "guidance_status": (c.scope or {}).get("guidance", {}).get("answer_status")}


def lookup(s: Session, inv_id: str, event_ids: list[str], entity_keys: list[str], *, principal: Principal | None = None) -> dict[str, Any]:
    """Marks for the rows on screen. `events`: checks made on that very record. `entities`: checks on an address or
    name the record carries - shown as a reference to the parent, not as a judgement of the record."""
    want_e, want_k = set(event_ids), set(entity_keys)
    events: dict[str, list] = {}
    entities: dict[str, list] = {}
    for c in list_checks(s, inv_id, principal=principal):
        b = _brief(c)
        if c.target_type == "event" and c.target_key in want_e:
            events.setdefault(c.target_key, []).append(b)
        elif c.target_type == "entity" and c.target_key in want_k:
            entities.setdefault(c.target_key, []).append(b)
        for eid in (c.scope or {}).get("event_ids") or []:  # records the analyst named as looked at
            if eid in want_e and eid != c.target_key:
                events.setdefault(eid, []).append(b)
    return {"events": events, "entities": entities}


def marks(s: Session, inv_id: str, *, principal: Principal | None = None) -> dict[str, Any]:
    """Every mark of the investigation in one answer, so tables can decorate rows without asking per scroll."""
    events: dict[str, list] = {}
    entities: dict[str, list] = {}
    findings: dict[str, list] = {}
    for c in list_checks(s, inv_id, principal=principal):
        b = _brief(c)
        {"event": events, "entity": entities, "finding": findings}.get(c.target_type, {}).setdefault(c.target_key, []).append(b)
        for eid in (c.scope or {}).get("event_ids") or []:
            if not (c.target_type == "event" and eid == c.target_key):
                events.setdefault(eid, []).append(b)
    return {"events": events, "entities": entities, "findings": findings}


def summary(s: Session, inv_id: str, *, principal: Principal | None = None) -> dict[str, Any]:
    rows = list_checks(s, inv_id, principal=principal)
    direct = [c for c in rows if c.kind == "direct" and (c.scope or {}).get("coverage") != "observation"]
    observations = sum(1 for c in rows if c.kind == "direct" and (c.scope or {}).get("coverage") == "observation")
    by_j: dict[str, int] = {}
    for c in direct:
        by_j[c.judgement or "none"] = by_j.get(c.judgement or "none", 0) + 1
    return {"total": len(rows), "direct": len(direct), "cited": sum(1 for c in rows if c.kind == "cited"),
            "observations": observations,
            "by_judgement": by_j, "sample_only": sum(1 for c in direct if (c.scope or {}).get("coverage") == "sample"),
            "shared": sum(1 for c in direct if c.shared),
            "source_changed": sum(1 for c in rows if c.kind == "cited" and c.source_state),
            "by_question": {q: sum(1 for c in direct if q in (c.questions or [])) for q in QUESTIONS}}


# ---------------------------------------------------------------- team results (other investigations)
def team_for(s: Session, p: Principal, inv_id: str, keys: list[str]) -> list[dict[str, Any]]:
    """Shared results of other investigations about the same targets, each with how its conditions compare with
    this investigation. Every source investigation must be readable before any metadata is returned."""
    require(s, p, "investigation.read", inv_id)
    keys = [k for k in dict.fromkeys(keys) if k][:50]
    if not keys:
        return []
    rows = s.execute(select(Check).where(Check.shared.is_(True), Check.state == "active", Check.target_key.in_(keys),
                                         Check.investigation_id != inv_id, Check.share_status != "retracted")
                     .order_by(Check.created_at.desc()).limit(200)).scalars().all()
    rows = [r for r in rows if _visible_check(s, p, r)]
    if not rows:
        return []
    invs = {i.id: i for i in s.execute(select(Investigation).where(Investigation.id.in_({r.investigation_id for r in rows}))).scalars()}
    cites: dict[str, int] = {}
    for citation in s.execute(select(Check).where(Check.source_check_id.in_([r.id for r in rows]),
                                                  Check.state == "active")).scalars():
        if _visible_check(s, p, citation):
            cites[citation.source_check_id] = cites.get(citation.source_check_id, 0) + 1
    mine = {c.source_check_id for c in s.execute(select(Check).where(Check.investigation_id == inv_id, Check.state == "active",
                                                                     Check.kind == "cited")).scalars()}
    now_ctx: dict[str, dict] = {}
    out = []
    for r in rows:
        if r.target_key not in now_ctx:
            now_ctx[r.target_key] = context_of(inv_id, r.target_key)
        src = invs.get(r.investigation_id)
        d = to_dict(r)
        d.pop("scope", None)
        d |= {"source": {"display_id": src.display_id if src else "", "can_open": True,
                         "id": r.investigation_id,
                         "title": src.title if src else None},
              "comparison": compare(r.context or {}, now_ctx[r.target_key]), "citations": cites.get(r.id, 0),
              "cited_here": r.id in mine, "evidence_count": len(r.evidence or [])}
        d.pop("evidence", None)
        out.append(d)
    return out


def _shared(s: Session, p: Principal, check_id: str) -> Check:
    c = s.get(Check, check_id)
    if c is None or not c.shared or c.state != "active":
        raise NotFound("shared check not found")
    require(s, p, "investigation.read", c.investigation_id)
    _require_cited_source(s, p, c)
    return c


def evidence_view(s: Session, p: Principal, check_id: str, ip: str = "") -> dict[str, Any]:
    """Masked records referenced by a shared result, subject to its source investigation ACL."""
    if not can(p, "investigation.read"):
        raise NotFound("shared check not found")
    c = _shared(s, p, check_id)
    es = container.get().events
    events = []
    for eid in (c.evidence or [])[:20]:
        ev = es.get(c.investigation_id, eid)
        if ev:
            masked, _ = mask_event(ev)
            masked.pop("raw_event", None)  # fields are enough to compare; the line itself stays in its investigation
            events.append(masked)
    audit.record(s, "check.evidence_view", actor_id=p.user_id, actor_name=p.username, actor_ip=ip, target_type="check",
                 target_id=c.id, investigation_id=c.investigation_id, detail={"events": len(events)})
    return {"check": to_dict(c), "events": events}


def request_recheck(s: Session, p: Principal, check_id: str, note: str) -> Check:
    if not can(p, "investigation.write"):
        raise NotFound("shared check not found")
    c = _shared(s, p, check_id)
    if not note.strip():
        raise ValueError("왜 다시 확인이 필요한지 한 줄 적어 주세요")
    from saw.followups.check_revisions import _capture_transition
    _capture_transition(s, p, c, reason="before_recheck")
    c.share_status, c.state_note, c.state_by, c.updated_at = "recheck", note.strip()[:512], p.username, utcnow()
    _capture_transition(s, p, c, reason="recheck")
    audit.record(s, "check.recheck_request", actor_id=p.user_id, actor_name=p.username, target_type="check",
                 target_id=c.id, investigation_id=c.investigation_id, detail={"note": note.strip()[:200]})
    return c


def cite(s: Session, p: Principal, inv_id: str, source_id: str, note: str = "") -> Check:
    """Use another investigation's shared result as supporting evidence here. It is recorded as "relied on", not as
    something this analyst checked, and it never sets a judgement for this investigation."""
    require(s, p, "investigation.write", inv_id)
    src = _shared(s, p, source_id)
    if src.investigation_id == inv_id:
        raise ValueError("같은 조사의 확인 기록입니다")
    if _expired(src) or src.share_status in ("recheck", "retracted"):
        raise ValueError("유효 기간이 지났거나 재확인이 필요한 확인은 근거로 연결할 수 없습니다. 직접 확인해 주세요")
    dup = s.execute(select(Check).where(Check.investigation_id == inv_id, Check.source_check_id == src.id,
                                        Check.state == "active")).scalars().first()
    if dup:
        return dup
    c = Check(investigation_id=inv_id, author_id=p.user_id, author_name=p.username, target_type="entity",
              target_key=src.target_key, target_label=src.target_label, scope={"coverage": "one"},
              questions=list(src.questions or []), judgement=None, note=note.strip()[:2000], kind="cited",
              source_check_id=src.id)
    s.add(c)
    s.flush()
    from saw.followups.check_revisions import _capture_transition
    _capture_transition(s, p, c, reason="cite", new=True)
    audit.record(s, "check.cite", actor_id=p.user_id, actor_name=p.username, target_type="check", target_id=c.id,
                 investigation_id=inv_id, detail={"source": src.id, "source_investigation": src.investigation_id})
    return c


def inbox(s: Session, p: Principal) -> dict[str, Any]:
    """What needs this person's attention: their shared results someone asked to re-check, and results they relied on
    that have since changed or been withdrawn."""
    recheck = s.execute(select(Check).where(Check.author_id == p.user_id, Check.shared.is_(True), Check.state == "active",
                                            Check.share_status == "recheck")).scalars().all()
    changed = s.execute(select(Check).where(Check.author_id == p.user_id, Check.kind == "cited", Check.state == "active",
                                            Check.source_state != "")).scalars().all()
    return {"recheck": [to_dict(c, full=False) for c in recheck if _visible_check(s, p, c)],
            "source_changed": [to_dict(c, full=False) for c in changed if _visible_check(s, p, c)]}
