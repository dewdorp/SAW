"""Saved conditions of investigation questions, with versions, a clear reach and edit conflicts.

Reach: "investigation" (this investigation), "affiliate" (every investigation of the same affiliate) or
"common" (a shared template, kept by senior roles). A preset only stores the condition; running it is the
same `question_bundles.run_one` as the unsaved preview, so a saved condition and its preview never differ.
A preset is a saved search, not an active detection policy.
"""
from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import or_, select

from saw.core.application import audit
from saw.core.application import question_bundles as qb
from saw.core.application.investigations import Forbidden, NotFound, require
from saw.core.security.authz import has_permission
from saw.question_presets.models import QuestionPreset, QuestionPresetVersion
from saw.storage.db import utcnow

SCOPES = {"investigation": "이번 조사", "affiliate": "같은 관계사의 조사", "common": "공통 템플릿"}


class Conflict(ValueError):
    pass


class PresetIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    bundle: Literal["spread", "web_attack", "transfer", "periodic"]
    scope_kind: Literal["investigation", "affiliate", "common"] = "investigation"
    name: Annotated[str, Field(min_length=1, max_length=128)]
    description: Annotated[str, Field(max_length=2000)] = ""
    parameters: dict[str, Any] = Field(default_factory=dict)
    change_note: Annotated[str, Field(max_length=2000)] = ""
    expected_version: int | None = None


def _scope_id(inv, kind: str) -> str | None:
    if kind == "investigation":
        return inv.id
    if kind == "affiliate":
        if not inv.org_unit_id:
            raise ValueError("관계사가 정해진 조사에서만 관계사 범위로 저장할 수 있습니다")
        return inv.org_unit_id
    return None


def _may_write(p, kind: str) -> None:
    # Investigation and affiliate presets follow the investigation's write right (checked by `require`);
    # a common template changes what every analyst starts from, so it is kept by senior roles.
    if kind == "common" and not has_permission(p, "signature.manage"):
        raise Forbidden("question_preset.common")


def _visible(inv):
    clauses = [(QuestionPreset.scope_kind == "investigation") & (QuestionPreset.scope_id == inv.id),
               QuestionPreset.scope_kind == "common"]
    if inv.org_unit_id:
        clauses.append((QuestionPreset.scope_kind == "affiliate") & (QuestionPreset.scope_id == inv.org_unit_id))
    return or_(*clauses)


def _version(s, row: QuestionPreset, number: int | None = None) -> QuestionPresetVersion:
    return s.scalar(select(QuestionPresetVersion).where(QuestionPresetVersion.preset_id == row.id,
                                                        QuestionPresetVersion.version == (number or row.current_version)))


def _view(s, row: QuestionPreset, number: int | None = None) -> dict:
    v = _version(s, row, number)
    if v is None:
        raise NotFound("preset version not found")
    return {"id": row.id, "bundle": row.bundle, "scope_kind": row.scope_kind, "scope_ko": SCOPES[row.scope_kind],
            "name": v.name, "description": v.description, "parameters": v.parameters,
            "condition": qb.describe(row.bundle, qb.validate(row.bundle, v.parameters)),
            "version": v.version, "current_version": row.current_version, "definition_version": v.definition_version,
            "change_note": v.change_note, "changed_by": v.changed_by, "changed_at": v.created_at.isoformat(),
            "created_by": row.created_by}


def list_for(s, p, inv_id: str, bundle: str | None = None) -> list[dict]:
    inv = require(s, p, "investigation.read", inv_id)
    q = select(QuestionPreset).where(_visible(inv))
    if bundle:
        q = q.where(QuestionPreset.bundle == bundle)
    rows = s.scalars(q.order_by(QuestionPreset.scope_kind, QuestionPreset.name)).all()
    return [_view(s, r) for r in rows]


def get(s, p, inv_id: str, preset_id: str, version: int | None = None) -> dict:
    inv = require(s, p, "investigation.read", inv_id)
    row = s.scalar(select(QuestionPreset).where(QuestionPreset.id == preset_id, _visible(inv)))
    if row is None:
        raise NotFound("preset not found")
    out = _view(s, row, version)
    out["versions"] = [{"version": v.version, "name": v.name, "change_note": v.change_note, "changed_by": v.changed_by,
                        "changed_at": v.created_at.isoformat(), "parameters": v.parameters}
                       for v in s.scalars(select(QuestionPresetVersion).where(QuestionPresetVersion.preset_id == row.id)
                                          .order_by(QuestionPresetVersion.version)).all()]
    return out


def diff(older: dict, newer: dict) -> list[dict]:
    """Changed conditions between two versions, by the definition's Korean labels."""
    keys = list(dict.fromkeys([*older, *newer]))
    return [{"name": k, "before": older.get(k), "after": newer.get(k)} for k in keys if older.get(k) != newer.get(k)]


def save(s, p, inv_id: str, body: PresetIn | dict, preset_id: str | None = None) -> dict:
    body = PresetIn.model_validate(body)
    inv = require(s, p, "investigation.write", inv_id)
    params = qb.validate(body.bundle, body.parameters)  # the same check the preview applies
    now = utcnow()
    if preset_id is None:
        _may_write(p, body.scope_kind)
        row = QuestionPreset(bundle=body.bundle, scope_kind=body.scope_kind, scope_id=_scope_id(inv, body.scope_kind),
                             name=body.name, current_version=0, created_by=p.user_id, updated_by=p.user_id)
        s.add(row)
        s.flush()
    else:
        row = s.scalar(select(QuestionPreset).where(QuestionPreset.id == preset_id, _visible(inv)).with_for_update())
        if row is None:
            raise NotFound("preset not found")
        _may_write(p, row.scope_kind)
        if body.bundle != row.bundle or body.scope_kind != row.scope_kind:
            raise ValueError("저장된 조건의 질문·적용 범위는 바꿀 수 없습니다. 복제해서 새로 저장하세요")
        if body.expected_version != row.current_version:
            raise Conflict("다른 사람이 먼저 이 조건을 수정했습니다. 최신 버전을 다시 불러온 뒤 저장하세요.")
    row.current_version += 1
    row.name, row.updated_by, row.updated_at = body.name, p.user_id, now
    s.add(QuestionPresetVersion(preset_id=row.id, version=row.current_version, name=body.name, description=body.description,
                                parameters=params, definition_version=qb.VERSION, change_note=body.change_note,
                                changed_by=p.user_id, created_at=now))
    s.flush()
    audit.record(s, "question_preset.save", actor_id=p.user_id, actor_name=p.username, target_type="question_preset",
                 target_id=row.id, investigation_id=inv_id,
                 detail={"bundle": row.bundle, "scope": row.scope_kind, "version": row.current_version})
    return _view(s, row)


def parameters_of(s, p, inv_id: str, preset_id: str, version: int | None = None) -> tuple[str, dict, dict]:
    """The stored condition to run: (bundle, parameters, reference to the exact preset version)."""
    view = get(s, p, inv_id, preset_id, version)
    return view["bundle"], view["parameters"], {"preset_id": view["id"], "version": view["version"], "name": view["name"],
                                               "scope_kind": view["scope_kind"]}
