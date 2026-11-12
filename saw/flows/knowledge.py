"""Reusable analyst knowledge: what a request means, how a result is confirmed, how requests link, what a flow is.

Every change is a new version; nothing is overwritten. Stopping keeps the row and its history, restoring makes a
new version. Two active definitions of the same scope are a conflict: the second is refused unless the analyst
says so, and conflicting definitions are never applied silently (the engine reports them instead).
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import or_, select

from saw.core.application import audit
from saw.core.application.investigations import Forbidden, NotFound, require
from saw.core.security.authz import can
from saw.flows.engine import ROLES, Compiled, norm_host, split_uri
from saw.flows.models import FlowKnowledge, FlowKnowledgeVersion
from saw.storage.db import utcnow

Short = Annotated[str, Field(max_length=255)]
Text = Annotated[str, Field(max_length=4000)]
Host = Annotated[str, Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9._\-\[\]:]+$")]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Param(Strict):
    name: Annotated[str, Field(min_length=1, max_length=128)]
    value: Short = ""


class Outcome(Strict):
    """How a business result is confirmed. `http` reads this request's own fields, `app` an application record."""
    source: Literal["http", "app"] = "app"
    event: Short = ""
    field: Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z_][A-Za-z0-9_.\-]*$")]
    op: Literal["eq", "ne", "in", "contains", "prefix", "ge", "le"] = "eq"
    value: Short = ""
    result: Literal["success", "failure"]


class ActivityContent(Strict):
    host: Host
    method: Annotated[str, Field(max_length=16, pattern=r"^[A-Za-z]*$")] = ""
    path: Annotated[str, Field(min_length=1, max_length=900, pattern=r"^/")]
    match: Literal["exact", "prefix", "pattern"] = "exact"
    params: list[Param] = Field(default_factory=list, max_length=10)
    meaning: Annotated[str, Field(min_length=1, max_length=200)]
    role: Literal["auth_page", "auth_attempt", "lookup", "change", "logout", "other"] = "other"
    object_param: Annotated[str, Field(max_length=128)] = ""
    outcomes: list[Outcome] = Field(default_factory=list, max_length=10)
    note: Text = ""

    @model_validator(mode="after")
    def tidy(self):
        self.host, self.method = norm_host(self.host), self.method.upper()
        if self.match == "prefix" and self.path == "/":
            raise ValueError("서비스 전체('/'로 시작하는 모든 경로)에 한 가지 의미를 붙일 수 없습니다. 경로를 더 적어 주세요.")
        return self


class LinkContent(Strict):
    """Which fields link requests of one service. Unset means unconfirmed, and unconfirmed is never used to link."""
    host: Host
    session_cookie: Annotated[str, Field(max_length=128)] = ""
    request_id_confirmed: bool = False  # uuid is a request id shared with other sources (not a per-record id)
    note: Text = ""

    @model_validator(mode="after")
    def tidy(self):
        self.host = norm_host(self.host)
        return self


class FlowStep(Strict):
    activity: Annotated[str, Field(min_length=1, max_length=36)]
    state: Literal["", "success", "failure"] = ""
    optional: bool = False
    repeat: bool = False


class FlowContent(Strict):
    host: Host
    name: Annotated[str, Field(min_length=1, max_length=200)]
    steps: list[FlowStep] = Field(min_length=2, max_length=20)
    max_gap_seconds: Annotated[int, Field(ge=0, le=86400 * 30)] = 0
    classification: Literal["normal", "suspicious", "undetermined"] = "undetermined"
    exceptions: Text = ""
    note: Text = ""

    @model_validator(mode="after")
    def tidy(self):
        self.host = norm_host(self.host)
        return self


CONTENT = {"activity": ActivityContent, "link": LinkContent, "flow": FlowContent}
KIND_KO = {"activity": "업무 의미", "link": "연결 기준", "flow": "흐름"}


class Evidence(Strict):
    investigation_id: Annotated[str, Field(max_length=36)] = ""
    event_ids: list[Annotated[str, Field(max_length=64)]] = Field(default_factory=list, max_length=50)
    source: Annotated[str, Field(max_length=64)] = ""  # e.g. "event", "flow", "discovery", "memo", "casebook"


class KnowledgeIn(Strict):
    kind: Literal["activity", "link", "flow"]
    org_unit_id: Annotated[str, Field(max_length=36)] | None = None
    content: dict
    change_note: Text = ""
    evidence: Evidence = Field(default_factory=Evidence)
    allow_conflict: bool = False


class UpdateIn(Strict):
    content: dict
    change_note: Text = ""
    evidence: Evidence = Field(default_factory=Evidence)
    expected_version: int
    allow_conflict: bool = False


class StateIn(Strict):
    expected_version: int
    change_note: Text = ""


class Conflict(ValueError):
    """Another active definition covers the same scope."""

    def __init__(self, message: str, items: list[dict]):
        super().__init__(message)
        self.items = items


def scope_key(kind: str, org: str | None, content: dict) -> str:
    org = org or "*"
    if kind == "activity":
        params = "&".join(sorted(f"{p['name']}={p.get('value', '')}" for p in content.get("params") or []))
        return f"activity|{org}|{content['host']}|{content.get('method', '')}|{content.get('match', 'exact')}|{content['path']}|{params}"[:700]
    if kind == "link":
        return f"link|{org}|{content['host']}"
    return f"flow|{org}|{content['host']}|{content['name']}"[:700]


def _title(kind: str, c: dict) -> str:
    if kind == "activity":
        return f"{c['meaning']} — {(c.get('method') or '모든 메서드')} {c['path']}"[:256]
    if kind == "link":
        return ("세션 쿠키 " + c["session_cookie"] if c.get("session_cookie") else "세션 식별자 미확인")[:256]
    return c["name"][:256]


def _read(p):
    if not can(p, "knowledge.read"):
        raise Forbidden("knowledge.read")


def _write(p):
    if not can(p, "knowledge.write"):
        raise Forbidden("knowledge.write")


def _out(row: FlowKnowledge, *, conflicts: list[str] | None = None) -> dict:
    return {"id": row.id, "kind": row.kind, "kind_label": KIND_KO[row.kind], "org_unit_id": row.org_unit_id,
            "host": row.host, "title": row.title, "status": row.status, "version": row.current_version,
            "content": row.content, "updated_at": row.updated_at, "created_at": row.created_at,
            "conflicts_with": conflicts or []}


def _validate(s, kind: str, org: str | None, raw: dict) -> dict:
    content = CONTENT[kind].model_validate(raw).model_dump()
    if org:
        from saw.source_context.service import org_by_id

        org_by_id(s, org)
    if kind == "flow":
        for step in content["steps"]:
            target = s.get(FlowKnowledge, step["activity"])
            if target is None or target.kind != "activity" or target.host != content["host"]:
                raise ValueError("흐름의 단계는 같은 서비스에 등록된 업무 의미여야 합니다.")
    return content


def _same_scope(s, key: str, *, exclude: str | None = None) -> list[FlowKnowledge]:
    rows = s.scalars(select(FlowKnowledge).where(FlowKnowledge.scope_key == key, FlowKnowledge.status == "active"))
    return [r for r in rows if r.id != exclude]


def _guard_conflict(s, key: str, content: dict, allow: bool, exclude: str | None = None) -> None:
    others = _same_scope(s, key, exclude=exclude)
    different = [o for o in others if _core(o.kind, o.content) != _core(o.kind, content)]
    if others and not different:
        raise Conflict("같은 범위에 같은 내용이 이미 등록되어 있습니다. 기존 항목을 쓰세요.", [_out(o) for o in others])
    if different and not allow:
        raise Conflict("같은 범위에 다른 내용이 이미 등록되어 있습니다. 기존 항목을 고치거나, 둘 다 남기려면 '상충 상태로 저장'을 선택하세요. "
                       "상충하는 정의는 어느 쪽도 자동 적용되지 않습니다.", [_out(o) for o in different])


def _core(kind: str, c: dict):
    if kind == "activity":
        return (c.get("meaning"), c.get("role"))
    if kind == "link":
        return (c.get("session_cookie"), bool(c.get("request_id_confirmed")))
    return json.dumps(c.get("steps"), sort_keys=True)


def _version(s, row: FlowKnowledge, p, content: dict, note: str, evidence: dict, status: str = "active") -> None:
    row.current_version += 1
    row.content, row.status, row.title = content, status, _title(row.kind, content)
    row.updated_by, row.updated_at = p.user_id, utcnow()
    s.add(FlowKnowledgeVersion(knowledge_id=row.id, version=row.current_version, status=status, content=content,
                               change_note=note, evidence=evidence, changed_by=p.user_id, changed_by_name=p.username))


def create(s, p, body: KnowledgeIn | dict) -> dict:
    _write(p)
    body = KnowledgeIn.model_validate(body)
    content = _validate(s, body.kind, body.org_unit_id, body.content)
    key = scope_key(body.kind, body.org_unit_id, content)
    _guard_conflict(s, key, content, body.allow_conflict)
    if body.evidence.investigation_id:
        require(s, p, "investigation.read", body.evidence.investigation_id)
    row = FlowKnowledge(kind=body.kind, org_unit_id=body.org_unit_id or None, host=content["host"], scope_key=key,
                        created_by=p.user_id, updated_by=p.user_id, current_version=0)
    s.add(row)
    s.flush()
    _version(s, row, p, content, body.change_note, body.evidence.model_dump())
    s.flush()
    audit.record(s, "flow_knowledge.create", actor_id=p.user_id, actor_name=p.username, target_type="flow_knowledge",
                 target_id=row.id, detail={"kind": row.kind, "version": row.current_version})
    return _out(row, conflicts=[o.id for o in _same_scope(s, key, exclude=row.id)])


def _row(s, kid: str) -> FlowKnowledge:
    row = s.get(FlowKnowledge, kid)
    if row is None:
        raise NotFound("knowledge not found")
    return row


def _expect(row: FlowKnowledge, expected: int) -> None:
    if expected != row.current_version:
        raise Conflict(f"다른 사람이 먼저 수정했습니다(현재 v{row.current_version}). 다시 불러온 뒤 저장하세요.", [_out(row)])


def update(s, p, kid: str, body: UpdateIn | dict) -> dict:
    _write(p)
    body = UpdateIn.model_validate(body)
    row = _row(s, kid)
    _expect(row, body.expected_version)
    content = _validate(s, row.kind, row.org_unit_id, body.content)
    key = scope_key(row.kind, row.org_unit_id, content)
    if key != row.scope_key:
        _guard_conflict(s, key, content, body.allow_conflict, exclude=row.id)
    else:
        different = [o for o in _same_scope(s, key, exclude=row.id) if _core(o.kind, o.content) != _core(row.kind, content)]
        if different and not body.allow_conflict:
            raise Conflict("같은 범위의 다른 정의와 내용이 달라집니다. 상충 상태로 저장하려면 선택해 주세요.",
                           [_out(o) for o in different])
    row.scope_key, row.host = key, content["host"]
    _version(s, row, p, content, body.change_note, body.evidence.model_dump(), status=row.status)
    s.flush()
    audit.record(s, "flow_knowledge.update", actor_id=p.user_id, actor_name=p.username, target_type="flow_knowledge",
                 target_id=row.id, detail={"version": row.current_version})
    return _out(row)


def set_status(s, p, kid: str, body: StateIn | dict, status: str) -> dict:
    """Stop applying a definition, or restore it. Both are new versions; history and past runs are untouched."""
    _write(p)
    body = StateIn.model_validate(body)
    row = _row(s, kid)
    _expect(row, body.expected_version)
    if row.status == status:
        return _out(row)
    if status == "active":
        _guard_conflict(s, row.scope_key, row.content, True, exclude=row.id)
    if status == "stopped" and row.kind == "activity":
        used = [f for f in s.scalars(select(FlowKnowledge).where(FlowKnowledge.kind == "flow",
                                                                  FlowKnowledge.status == "active"))
                if any(st.get("activity") == row.id for st in f.content.get("steps") or [])]
        if used:
            raise ValueError("이 업무 의미를 단계로 쓰는 흐름이 있습니다: " + ", ".join(f.title for f in used[:5])
                             + ". 흐름을 먼저 중지하거나 고치세요.")
    _version(s, row, p, row.content, body.change_note, {}, status=status)
    s.flush()
    audit.record(s, f"flow_knowledge.{'restore' if status == 'active' else 'stop'}", actor_id=p.user_id,
                 actor_name=p.username, target_type="flow_knowledge", target_id=row.id,
                 detail={"version": row.current_version})
    return _out(row)


def restore_version(s, p, kid: str, version: int, body: StateIn | dict) -> dict:
    """Bring back an earlier version's content as a new version."""
    _write(p)
    body = StateIn.model_validate(body)
    row = _row(s, kid)
    _expect(row, body.expected_version)
    old = s.scalar(select(FlowKnowledgeVersion).where(FlowKnowledgeVersion.knowledge_id == kid,
                                                      FlowKnowledgeVersion.version == version))
    if old is None:
        raise NotFound("version not found")
    content = _validate(s, row.kind, row.org_unit_id, old.content)
    row.scope_key, row.host = scope_key(row.kind, row.org_unit_id, content), content["host"]
    _version(s, row, p, content, body.change_note or f"v{version} 내용으로 복원", {}, status="active")
    s.flush()
    audit.record(s, "flow_knowledge.restore_version", actor_id=p.user_id, actor_name=p.username,
                 target_type="flow_knowledge", target_id=row.id, detail={"from": version, "version": row.current_version})
    return _out(row)


def list_all(s, p, *, kind: str | None = None, org_unit_id: str | None = None, host: str | None = None,
             q: str = "", include_stopped: bool = True, limit: int = 500) -> list[dict]:
    _read(p)
    query = select(FlowKnowledge).order_by(FlowKnowledge.host, FlowKnowledge.kind, FlowKnowledge.title)
    if kind:
        query = query.where(FlowKnowledge.kind == kind)
    if org_unit_id:
        query = query.where(or_(FlowKnowledge.org_unit_id == org_unit_id, FlowKnowledge.org_unit_id.is_(None)))
    if host:
        query = query.where(FlowKnowledge.host == norm_host(host))
    if not include_stopped:
        query = query.where(FlowKnowledge.status == "active")
    rows = list(s.scalars(query.limit(min(max(limit, 1), 2000))))
    needle = q.strip().casefold()
    by_scope: dict[str, list[FlowKnowledge]] = {}
    for r in rows:
        if r.status == "active":
            by_scope.setdefault(r.scope_key, []).append(r)
    out = []
    for r in rows:
        if needle and needle not in f"{r.title} {r.host} {json.dumps(r.content, ensure_ascii=False)}".casefold():
            continue
        twins = [o.id for o in by_scope.get(r.scope_key, []) if o.id != r.id
                 and _core(o.kind, o.content) != _core(r.kind, r.content)] if r.status == "active" else []
        out.append(_out(r, conflicts=twins))
    return out


def get(s, p, kid: str) -> dict:
    _read(p)
    return _out(_row(s, kid))


def history(s, p, kid: str) -> list[dict]:
    _read(p)
    _row(s, kid)
    rows = s.scalars(select(FlowKnowledgeVersion).where(FlowKnowledgeVersion.knowledge_id == kid)
                     .order_by(FlowKnowledgeVersion.version.desc()))
    return [{"version": v.version, "status": v.status, "content": v.content, "change_note": v.change_note,
             "evidence": v.evidence, "changed_by": v.changed_by_name, "created_at": v.created_at} for v in rows]


def snapshot(s, org_unit_id: str | None, *, at: dict | None = None) -> list[dict]:
    """Active knowledge that applies to one affiliate: the common definitions plus that affiliate's own.

    `at` ({knowledge_id: version}) rebuilds the knowledge of an earlier run exactly, whatever changed since.
    """
    if at is not None:
        out = []
        for kid, version in at.items():
            v = s.scalar(select(FlowKnowledgeVersion).where(FlowKnowledgeVersion.knowledge_id == kid,
                                                            FlowKnowledgeVersion.version == version))
            row = s.get(FlowKnowledge, kid)
            if v is not None and row is not None:
                out.append({"id": kid, "version": version, "kind": row.kind, "org_unit_id": row.org_unit_id,
                            "title": row.title, "content": v.content})
        return out
    query = select(FlowKnowledge).where(FlowKnowledge.status == "active")
    query = query.where(or_(FlowKnowledge.org_unit_id == org_unit_id, FlowKnowledge.org_unit_id.is_(None))
                        if org_unit_id else FlowKnowledge.org_unit_id.is_(None))
    return [{"id": r.id, "version": r.current_version, "kind": r.kind, "org_unit_id": r.org_unit_id,
             "title": r.title, "content": r.content} for r in s.scalars(query.order_by(FlowKnowledge.id))]


def digest(items: list[dict]) -> str:
    return hashlib.sha256(json.dumps(sorted((i["id"], i["version"]) for i in items)).encode()).hexdigest()


# ---------------------------------------------------------------------------------------------------------------
# From an analyst's sentence to a draft (no model needed). The draft is only a proposal the analyst corrects.

_PATH = re.compile(r"(?<![A-Za-z0-9_.])(/[A-Za-z0-9_\-./{}*%~]+|[A-Za-z0-9_\-]+\.(?:html?|do|jsp|php|aspx?|action|json))(?![A-Za-z0-9_])")
_METHOD = re.compile(r"\b(GET|POST|PUT|DELETE|PATCH)\b", re.I)
_COOKIE = re.compile(r"([A-Za-z0-9_\-]{2,64})\s*(?:쿠키|cookie)", re.I)
_ROLE_WORDS = [
    ("logout", ("로그아웃", "logout", "세션 종료")),
    ("auth_attempt", ("인증 시도", "로그인 시도", "로그인 요청", "인증 요청", "인증 처리", "로그인 처리")),
    ("auth_page", ("인증 화면", "로그인 화면", "로그인 페이지", "인증 페이지")),
    ("lookup", ("조회", "열람", "검색", "다운로드", "내려받")),
    ("change", ("변경", "수정", "등록", "삭제", "이체", "송금")),
    ("auth_attempt", ("인증", "로그인", "auth", "login")),
]
_JUDGEMENT = [("normal", ("정상",)), ("suspicious", ("의심", "비정상", "이상", "공격")), ("undetermined", ("미확정", "확인 필요", "모름"))]


def extract(text: str, context: dict | None = None) -> dict:
    """Split a memo into reusable meaning (per path) and this incident's judgement. Deterministic; nothing is saved."""
    context = context or {}
    host = norm_host(context.get("host") or "")
    # A period ends a sentence only after Korean text or before a space: "auth.html" stays whole.
    sentences = [part.strip() for part in re.split(r"\n|;|。|(?<=[가-힣])\.(?=\s|$)|\.\s+|(?<=이고)\s+|(?<=이며)\s+", text)
                 if part.strip()]
    drafts, seen = [], set()
    for sentence in sentences:
        for match in _PATH.finditer(sentence):
            path = match.group(1)
            if not path.startswith("/"):
                path = "/" + path
            if path in seen:
                continue
            seen.add(path)
            role = next((r for r, words in _ROLE_WORDS if any(w in sentence.casefold() for w in words)), "other")
            meaning = _meaning_phrase(sentence, match.group(1)) or ROLES[role]
            method = _METHOD.search(sentence)
            drafts.append({"kind": "activity", "content": {
                "host": host, "method": method.group(1).upper() if method else "", "path": path, "match": "exact",
                "params": [], "meaning": meaning, "role": role, "object_param": "", "outcomes": [], "note": ""},
                "from_text": sentence, "needs_review": ["의미", "역할"] + ([] if host else ["서비스(host)"])})
    cookie = _COOKIE.search(text)
    if cookie and any(w in text for w in ("세션", "session")):
        drafts.append({"kind": "link", "content": {"host": host, "session_cookie": cookie.group(1),
                                                   "request_id_confirmed": False, "note": ""},
                       "from_text": cookie.group(0), "needs_review": ["세션 쿠키 이름"]})
    verdict = next((v for v, words in _JUDGEMENT if any(w in text for w in words)), None)
    judgement = {"verdict": verdict, "note": text.strip()[:2000],
                 "text": "이 판단은 이번 사건에만 남깁니다. 주소나 IP 전체를 계속 정상으로 처리하지 않습니다."} if verdict else None
    return {"drafts": drafts, "judgement": judgement,
            "note": "문장에서 뽑은 초안입니다. 틀린 항목만 고쳐 저장하세요. 저장 전에는 아무것도 적용되지 않습니다."}


def _meaning_phrase(sentence: str, token: str) -> str:
    """'auth.html은 인증 관련 기능이고' -> '인증 관련 기능'."""
    after = sentence.split(token, 1)[1] if token in sentence else ""
    m = re.match(r"\s*(?:은|는|이|가|=|:|->|→)?\s*([^,.]{2,60}?)(?:이고|이며|이다|입니다|임|이라|,|$)", after)
    phrase = (m.group(1).strip() if m else "").strip(" '\"")
    phrase = re.sub(r"^(?:이번 요청은|이 요청은)\s*", "", phrase)
    return phrase if 2 <= len(phrase) <= 60 and not any(w in phrase for w in ("정상", "의심")) else ""


def preview(s, p, inv_id: str, kind: str, raw: dict, *, limit: int = 20) -> dict:
    """Which records of this investigation the definition would apply to, before it is saved."""
    from saw import container
    from saw.core.schemas.query import Filter

    inv = require(s, p, "investigation.read", inv_id)
    content = CONTENT[kind].model_validate(raw).model_dump()
    if kind != "activity":
        return {"matches": None, "samples": [], "note": "연결 기준과 흐름은 저장 뒤 분석 결과에서 확인합니다."}
    one = Compiled([{"id": "preview", "version": 0, "kind": "activity", "org_unit_id": inv.org_unit_id,
                     "content": content}])
    es = container.get().events
    filters = [Filter(field="hostname", value=content["host"]), Filter(field="uri", op="exists")]
    total = es.count(inv_id, filters)
    matches, samples, read, others = 0, [], 0, {}
    for e in es.iterate(inv_id, filters, None, fields=["event_id", "timestamp", "method", "uri", "status_code", "src_ip"]):
        read += 1
        if read > 200_000:
            break
        path, params = split_uri(e.get("uri"))
        hit, _ = one.activity(content["host"], (e.get("method") or "").upper(), path, params)
        if hit:
            matches += 1
            if len(samples) < limit:
                samples.append({**e, "path": path})
        elif len(others) < 2000:
            others[(e.get("method"), path)] = others.get((e.get("method"), path), 0) + 1
    near = sorted(others.items(), key=lambda kv: -kv[1])[:5]
    return {"matches": matches, "examined": min(read, 200_000), "host_records": total, "partial": read > 200_000,
            "samples": samples,
            "not_matched_examples": [{"method": m, "path": path, "count": n} for (m, path), n in near],
            "note": "이 조사에서 같은 서비스의 요청 중 이 정의가 적용될 기록입니다."}
