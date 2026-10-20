"""Bounded, inspectable rule exports; never export investigation test samples."""
from __future__ import annotations

import json
from dataclasses import asdict

import yaml
from fastapi.encoders import jsonable_encoder
from sqlalchemy import select
from sqlalchemy.orm import Session

from saw.core.application.analysis import all_detectors
from saw.core.application.briefing import CATEGORY_KO
from saw.detection import service
from saw.detectors import ndr_policy, scenarios, signatures
from saw.storage.db import utcnow
from saw.storage.models import SignatureSetting

MAX_EXPORT_BYTES = 2 * 1024 * 1024
MAX_CUSTOM_RULES = 1000


def encode(document: dict, format: str) -> tuple[str, str]:
    data = jsonable_encoder(document)
    if format == "json":
        text, media = json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False) + "\n", "application/json"
    elif format == "yaml":
        text, media = yaml.safe_dump(data, allow_unicode=True, sort_keys=False), "application/yaml"
    else:
        raise ValueError("지원하는 내보내기 형식은 JSON/YAML입니다.")
    if len(text.encode("utf-8")) > MAX_EXPORT_BYTES:
        raise ValueError("내보내기 파일이 2MiB 한도를 넘습니다. 사용자 룰은 개별 파일로 내려받으세요.")
    return text, media


def signature_states(s: Session, p=None) -> dict:
    from saw.core.application.investigations import Forbidden, NotFound
    from saw.detection import governance as gov
    from saw.detection.policy_models import PolicyBinding
    states = {}
    for row in s.scalars(select(SignatureSetting)):
        states[row.sig_id] = {"enabled": row.enabled, "note": row.note, "updated_by": row.updated_by,
            "updated_at": row.updated_at, "effective_scope": {"kind": "group"},
            "provenance": "legacy_not_independently_approved"}
    bindings = s.scalars(select(PolicyBinding).where(PolicyBinding.detector_id.startswith("signature:"),
        PolicyBinding.scope_key == "group", PolicyBinding.active_version_id.is_not(None)))
    for binding in bindings:
        sid = binding.detector_id.split(":", 1)[1]
        try:
            if p is None:
                raise Forbidden("knowledge.read")
            effective = gov.resolve_effective(s, binding.detector_id, {"kind": "group"}, p=p)
            states[sid] = {**states.get(sid, {}), "enabled": effective["values"]["enabled"],
                "effective_scope": {"kind": "group"}, "provenance": "reviewed_active_policy",
                "policy_version_id": binding.active_version_id, "policy_sha256": effective["policy_sha256"]}
        except (Forbidden, NotFound, gov.Conflict):
            states[sid] = {"enabled": None, "effective_scope": {"kind": "group"}, "provenance": "unavailable"}
    return states


def shipped(s: Session, *, p=None) -> dict:
    settings = {x.sig_id: x for x in s.execute(select(SignatureSetting)).scalars()}
    states = signature_states(s, p)
    entries = []
    for rule in signatures.load_pack():
        state = settings.get(rule.id)
        entry = {key: getattr(rule, key) for key in (
            "id", "title", "group", "group_title", "stage", "severity", "confidence", "attack", "cve", "explain", "checks",
            "examples", "benign")}
        entry["matching"] = {"where": rule.where, "success": rule.success, "match": rule.needles,
            "all": rule.all_needles, "regex": rule.regex, "regex_not": rule.regex_not, "method": rule.methods,
            "raw": rule.raw, "raw_also": rule.raw_also}
        entry.update(enabled=state.enabled if state else True, note=state.note if state else "",
                     updated_by=state.updated_by if state else "", updated_at=state.updated_at if state else None)
        entry.update(states.get(rule.id, {"effective_scope": {"kind": "group"}, "provenance": "shipped_defaults"}))
        entries.append(entry)
    network = ndr_policy.load()
    return {"schema": "saw.detection-catalog.v1", "scope": "all_shipped_rules", "exported_at": utcnow(),
        "application": "inspection_only_no_automatic_import_or_approval",
        "matching_semantics": {"match": "any", "all": "all", "regex_not": "exclude",
            "normalization": "lowercase; URL decode up to twice unless raw; raw_also compares both forms",
            "http_2xx": "response condition only, not proof of compromise"},
        "signatures": entries, "scenarios": [asdict(x) for x in scenarios.load()],
        "network_rules": network["rules"], "network_site": network["site"], "network_limits": network["limits"],
        "network_pack_version": network["version"],
        "detectors": [{"id": d.id, "version": d.version, "title": CATEGORY_KO.get(d.category, d.category),
                       "stage": d.stage, "data_sources": sorted(d.data_sources), "implementation": "python",
                       "logic_included": False} for d in all_detectors() if d.id != "sig.match"],
        "limitations": ["코드 기반 탐지기의 구현 코드는 이 파일에 포함하지 않습니다.",
                        "규칙을 내보내도 승인·배포·탐지 상태는 바뀌지 않습니다.",
                        "전체 기본 목록입니다. 화면의 검색 필터는 내보내기에 적용하지 않습니다."]}


def custom(s: Session, *, p=None) -> dict:
    detections = s.scalars(select(service.Detection).order_by(service.Detection.display_id))
    rows = []
    for detection in detections:
        from saw.core.application.investigations import Forbidden, NotFound, require
        from saw.detection.derived_access import require_snapshot
        source = (detection.source or {}).get("investigation_id")
        try:
            require_snapshot(s, p, detection.source or {})
            if source:
                if p is None:
                    continue
                require(s, p, "investigation.read", source)
        except (Forbidden, NotFound):
            continue
        if len(rows) >= MAX_CUSTOM_RULES:
            raise ValueError("현재 룰 1000개 한도를 넘습니다. 룰별로 내려받으세요. 일부만 내보내지 않았습니다.")
        from saw.detection import governance
        vid = detection.draft_version_id or detection.approved_version_id or detection.active_version_id
        version = governance._version(s, "rule", detection, vid) if vid else service._latest(s, detection.id)
        rows.append({"id": detection.id, "display_id": detection.display_id, "status": detection.status,
            "version": version.version, "exported_version_id": version.id, "payload_sha256": version.payload_sha256,
            "pointers": {key: getattr(detection, key + "_version_id") for key in ("draft", "approved", "active")},
            "activation_revision": detection.activation_revision, **{key: getattr(version, key) for key in (
                "title", "description", "data_source", "format", "logic", "threshold", "exceptions", "false_positive",
                "severity", "confidence", "attack", "created_by", "reviewed_by")}})
    return {"schema": "saw.detection-rules.v1", "scope": "all_current_rule_versions", "exported_at": utcnow(),
            "rules": rows, "count": len(rows), "excluded": ["test_events", "test_runs", "source", "historical_versions"],
            "application": "inspection_only_no_automatic_import_or_approval"}
