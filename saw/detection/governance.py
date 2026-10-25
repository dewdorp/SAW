"""Exact-version governance. Approval never changes active runtime content."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from sqlalchemy import func, select

from saw.core.application import audit
from saw.core.application.identity import principal_of
from saw.core.application.investigations import Forbidden, NotFound, require
from saw.core.schemas.query import Filter
from saw.core.security.authz import can
from saw.detection.policy_models import Activation, Approval, PolicyBinding, PolicyVersion
from saw.storage.db import utcnow
from saw.storage.models import User

RULE_FIELDS = ("title", "description", "data_source", "format", "logic", "threshold",
               "exceptions", "false_positive", "severity", "confidence", "test_events", "attack")


class Conflict(ValueError):
    """A stale pointer or proof must be refreshed before another mutation."""


def digest(value):
    return sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                             allow_nan=False).encode("utf-8")).hexdigest()


def rule_payload(version):
    return {key: deepcopy(getattr(version, key)) for key in RULE_FIELDS}


def version_digest(version):
    return digest(rule_payload(version))


def _service():
    from saw.detection import service
    return service


def _spec(detector_id):
    from saw.detection.specs import get_spec
    return get_spec("sigma" if detector_id.startswith("sigma.approved:") else detector_id)


def spec_digest(spec):
    actual = digest({key: value for key, value in spec.items() if key != "sha256"})
    if spec.get("sha256") != actual:
        raise Conflict("분석기 사양 지문이 일치하지 않습니다.")
    return actual


def _values(spec, values):
    from saw.detection.specs import validate_values
    return validate_values(spec, values)


def _lock(s):
    _service()._lock_mutation(s)


def _actor(s, p, permission):
    user = s.get(User, p.user_id, populate_existing=True)
    if user is None or user.status != "active":
        raise Forbidden("현재 활성 사용자가 필요합니다.")
    actual = principal_of(user)
    if not can(actual, permission):
        raise Forbidden(permission)
    return actual


def _reason(data):
    reason = str(data.get("reason") or "").strip()
    if not reason or len(reason) > 2000:
        raise ValueError("1~2000자의 검토 사유가 필요합니다.")
    return reason


def _version(s, kind, owner, version_id):
    cls = _service().DetectionVersion if kind == "rule" else PolicyVersion
    row = s.get(cls, version_id) if version_id else None
    if row is None or getattr(row, "detection_id" if kind == "rule" else "binding_id") != owner.id:
        raise NotFound("해당 탐지의 버전을 찾지 못했습니다.")
    actual = version_digest(row) if kind == "rule" else digest(row.payload)
    if row.payload_sha256 != actual:
        raise Conflict("저장된 버전의 무결성이 일치하지 않습니다.")
    return row


def initialize_rule_version(s, d, version, p, parent=None):
    """Set immutable lineage before the new version is inserted."""
    version.author_id = p.user_id
    version.parent_version_id = parent.id if parent else None
    version.contributor_ids = sorted({d.created_by, p.user_id, *(parent.contributor_ids or [] if parent else [])})
    version.legacy_contributor_names = sorted(set(parent.legacy_contributor_names or [])) if parent else []
    version.contributor_resolution = parent.contributor_resolution if parent else "resolved"
    version.payload_sha256 = version_digest(version)
    return version


def _source_ids(s, kind, owner):
    if kind == "rule":
        from saw.detection.derived_access import source_ids
        ident = (owner.source or {}).get("investigation_id")
        return sorted(source_ids(owner.source or {}) | ({ident} if ident else set()))
    if owner.scope.get("kind") == "device":
        from saw.source_context.models import Device
        device = s.get(Device, owner.scope["device_id"])
        if device is None:
            raise NotFound("장비가 없습니다.")
        return [device.investigation_id]
    return []


def _read_sources(s, p, ids, *, write=False):
    for ident in sorted(set(ids)):
        require(s, p, "investigation.write" if write else "investigation.read", ident)


def contributors(version):
    return {"ids": sorted(set(version.contributor_ids or [])),
            "legacy_names": sorted(set(version.legacy_contributor_names or []))}


def _merge_contributors(*values):
    return {"ids": sorted({x for value in values for x in value.get("ids", [])}),
            "legacy_names": sorted({x for value in values for x in value.get("legacy_names", [])})}


def independent(s, p, people):
    if p.user_id in people["ids"] or p.username in people["legacy_names"]:
        raise Forbidden("모든 작성·수정·정답 기여자와 다른 검토자가 필요합니다.")
    for ident in people["ids"]:
        user = s.get(User, ident)
        if user is None or user.status != "active":
            raise Forbidden("기여자의 활성 상태를 확인하세요.")
    # Unresolved names must be resolved; never infer a stable identity from a renamed user.
    if people["legacy_names"]:
        raise Conflict("이전 기여자 식별자를 먼저 확인해야 합니다.")


def _scope(s, p, scope, *, write=False):
    from saw.source_context.models import Device, DeviceProfileVersion, OrgUnit
    if not isinstance(scope, dict) or scope.get("kind") not in {"group", "org", "device"}:
        raise ValueError("정책 범위는 group/org/device 중 하나여야 합니다.")
    kind = scope["kind"]
    allowed = {"kind"} | ({"org_unit_id"} if kind in {"org", "device"} else set()) | ({"device_id"} if kind == "device" else set())
    if set(scope) != allowed:
        raise ValueError("정책 범위의 식별자를 정확히 지정하세요.")
    if kind == "group":
        return {"kind": kind}, "group"
    org = s.get(OrgUnit, scope["org_unit_id"])
    if org is None or org.state != "active":
        raise ValueError("활성 관계사 식별자가 필요합니다.")
    if kind == "org":
        return dict(scope), "org:" + org.id
    device = s.get(Device, scope["device_id"])
    if device is None:
        raise NotFound("장비가 없습니다.")
    require(s, p, "investigation.write" if write else "investigation.read", device.investigation_id)
    return dict(scope), "device:" + org.id + ":" + device.id


def _layers(scope):
    result = [{"kind": "group"}]
    if scope["kind"] in {"org", "device"}:
        result.append({"kind": "org", "org_unit_id": scope["org_unit_id"]})
    if scope["kind"] == "device":
        result.append(scope)
    return result


def _key(scope):
    if scope["kind"] == "group":
        return "group"
    if scope["kind"] == "org":
        return "org:" + scope["org_unit_id"]
    return "device:" + scope["org_unit_id"] + ":" + scope["device_id"]



def _policy_binding(s, detector_id, scope):
    if scope["kind"] == "device" and s.scalar(select(PolicyBinding.id).where(
            PolicyBinding.detector_id == detector_id, PolicyBinding.scope_key == "device:" + scope["device_id"])):
        raise Conflict("legacy_device_policy_scope_requires_review: 이전 장비 정책 범위를 다시 검토하세요.")
    return s.scalar(select(PolicyBinding).where(PolicyBinding.detector_id == detector_id,
                                               PolicyBinding.scope_key == _key(scope)))


def resolve_effective(s, detector_id, scope, *, p, candidate=None):
    """Resolve exact active layer versions; a candidate substitutes only its own layer."""
    _actor(s, p, "knowledge.read")
    scope, _ = _scope(s, p, scope)
    if candidate is not None:
        candidate_binding = s.get(PolicyBinding, candidate.binding_id)
        if candidate_binding is None or candidate_binding.detector_id != detector_id or candidate_binding.scope != scope:
            raise Conflict("초안 정책과 선택한 관측 범위가 다릅니다.")
    spec = _spec(detector_id)
    spec_hash = spec_digest(spec)
    values = _values(spec, {})
    origins = {key: {"scope": "default", "provenance": "shipped_default"} for key in values}
    exclusions, layers, people, sources = [], [], {"ids": [], "legacy_names": []}, []
    # Keep pre-governance explicit disables effective until an approved layer overrides them.
    from saw.storage.models import SignatureSetting
    legacy = s.get(SignatureSetting, detector_id.removeprefix("signature:"))
    if legacy is not None and not legacy.enabled:
        values["enabled"] = False
        origins["enabled"] = {"scope": "legacy", "provenance": "legacy_not_recorded"}
    for layer_scope in _layers(scope):
        binding = _policy_binding(s, detector_id, layer_scope)
        if binding is None:
            continue
        _scope(s, p, binding.scope)
        if binding.scope != layer_scope:
            raise Conflict("저장된 정책과 선택한 관측 범위가 다릅니다.")
        vid = candidate.id if candidate is not None and candidate.binding_id == binding.id else binding.active_version_id
        layer = {"scope": deepcopy(binding.scope), "binding_id": binding.id, "revision": binding.activation_revision,
                 "active_version_id": binding.active_version_id, "approval_id": binding.active_approval_id}
        if not vid:
            # Draft-only bindings have no effect on runtime hashes or values.
            continue
        version = _version(s, "policy", binding, vid)
        if version.spec_sha256 != spec_hash:
            raise Conflict("정책이 시험된 분석기 사양과 현재 사양이 다릅니다.")
        if candidate is None or candidate.id != vid:
            approval = validate_approval(s, p, "policy", binding, version, binding.active_approval_id, fresh=False)
            people = _merge_contributors(people, {"ids": approval.contributor_ids})
            sources.extend(approval.source_investigation_ids)
        layer.update({"version_id": version.id, "payload_sha256": version.payload_sha256})
        if candidate is not None and candidate.id == vid:
            # The candidate payload is immutable. Its own mutable pointer is protected by CAS,
            # not hashed into the candidate proof; parent layers remain exactly pinned.
            layer.update(candidate_version_id=vid, revision=None, active_version_id=None, approval_id=None)
        layers.append(layer)
        values.update(version.payload["overrides"])
        values = _values(spec, values)
        origin = {"scope": binding.scope["kind"], "binding_id": binding.id,
                  "binding_revision": layer["revision"], "policy_version_id": version.id,
                  "payload_sha256": version.payload_sha256, "provenance": version.payload["provenance"]["kind"]}
        for key in version.payload["overrides"]:
            origins[key] = deepcopy(origin)
        if version.payload.get("exclusions_override") is not None:
            exclusions = deepcopy(version.payload["exclusions_override"])
            origins["exclusions"] = deepcopy(origin)
        people = _merge_contributors(people, contributors(version))
        sources.extend(_source_ids(s, "policy", binding))
    result = {"schema": "det-effective/1", "detector_id": detector_id, "values": values, "exclusions": exclusions,
              "per_value_source": origins, "layers": layers, "spec_sha256": spec_hash,
              "contributors": people, "source_investigation_ids": sorted(set(sources))}
    result["policy_sha256"] = digest(result)
    return result


def pin_rule(s, p, det_id, version_id, scope=None):
    d = s.get(_service().Detection, det_id)
    if d is None:
        raise NotFound("탐지 룰이 없습니다.")
    _actor(s, p, "knowledge.read")
    v = _version(s, "rule", d, version_id)
    if v.format != "sigma":
        raise ValueError("이 형식은 로컬 분석기 시험·적용을 지원하지 않습니다.")
    sources = _source_ids(s, "rule", d)
    _read_sources(s, p, sources)
    spec = _spec("sigma")
    policy = resolve_effective(s, "sigma.approved:" + d.id, scope or {"kind": "group"}, p=p)
    sources += policy["source_investigation_ids"]
    return {"schema": "det-runtime-pin/1", "subject": {"kind": "rule", "id": d.id, "version_id": v.id,
             "payload_sha256": v.payload_sha256},
            "context_scope": scope or {"kind": "group"},
            "rule": {"id": d.id, "display_id": d.display_id, "version_id": v.id, "version": v.version,
                     "payload_sha256": v.payload_sha256, "payload": rule_payload(v)},
            "spec": {"id": spec["id"], "version": spec["version"], "sha256": spec_digest(spec)},
            "engine": spec["engine"], "policy": policy,
            "contributors": _merge_contributors(contributors(v), policy["contributors"]),
            "source_investigation_ids": sorted(set(sources))}


def pin_policy(s, p, binding_id, version_id):
    binding = s.get(PolicyBinding, binding_id)
    if binding is None:
        raise NotFound("정책이 없습니다.")
    _scope(s, p, binding.scope)
    v = _version(s, "policy", binding, version_id)
    spec = _spec(binding.detector_id)
    effective = resolve_effective(s, binding.detector_id, binding.scope, p=p, candidate=v)
    rule = None
    if binding.detector_id.startswith("sigma.approved:"):
        det_id = binding.detector_id.split(":", 1)[1]
        det = s.get(_service().Detection, det_id)
        if det is None or not det.active_version_id:
            raise Conflict("정책 시험에 필요한 적용 중인 룰이 없습니다.")
        rv = _version(s, "rule", det, det.active_version_id)
        approval = validate_approval(s, p, "rule", det, rv, det.active_approval_id)
        source_ids = _source_ids(s, "rule", det) + approval.source_investigation_ids
        _read_sources(s, p, source_ids)
        rule = {"id": det.id, "display_id": det.display_id, "version_id": rv.id, "version": rv.version,
                "payload_sha256": rv.payload_sha256, "payload": rule_payload(rv)}
        effective["contributors"] = _merge_contributors(effective["contributors"], contributors(rv),
                                                        {"ids": approval.contributor_ids})
        effective["source_investigation_ids"] = sorted(set(effective["source_investigation_ids"] + source_ids))
        effective["policy_sha256"] = digest({key: value for key, value in effective.items() if key != "policy_sha256"})
    return {"schema": "det-runtime-pin/1", "subject": {"kind": "policy", "id": binding.id, "version_id": v.id,
            "payload_sha256": v.payload_sha256}, "context_scope": binding.scope, "rule": rule,
            "spec": {"id": spec["id"], "version": spec["version"], "sha256": spec_digest(spec)}, "engine": spec["engine"],
            "policy": effective, "contributors": _merge_contributors(contributors(v), effective["contributors"]),
            "source_investigation_ids": effective["source_investigation_ids"]}


def rule_policy_digest(pin):
    # Includes exact rule payload, threshold, exclusions, all layer identities and engine/spec.
    return digest(pin)


def _proof(s, p, kind, owner, version, request, *, read_inputs=True):
    pin = (pin_rule(s, p, owner.id, version.id, request.get("context_scope"))
           if kind == "rule" else pin_policy(s, p, owner.id, version.id))
    expected = rule_policy_digest(pin)
    if request.get("rule_policy_sha256") != expected:
        raise Conflict("시험 후 룰·정책 또는 상위 정책이 변경되었습니다.")
    from saw.detection.testing import verify_selected_proof
    proof = verify_selected_proof(s, p, test_run_id=request.get("test_run_id"), subject_kind=kind,
                                  subject_version_id=version.id, payload_sha256=version.payload_sha256,
                                  rule_policy_sha256=expected, _read_inputs=read_inputs)
    if request.get("expected_proof_sha256") != proof["proof_sha256"]:
        raise Conflict("검토한 시험 결과가 변경되었습니다.")
    return pin, proof


def _new_approval(s, p, kind, owner, version, proof, people, provenance="reviewed", *, reason=""):
    independent(s, p, people)
    ids = sorted(set(proof.get("source_investigation_ids", []) + _source_ids(s, kind, owner)))
    _read_sources(s, p, ids)
    row = Approval(subject_kind=kind, subject_id=owner.id, subject_version_id=version.id,
                   payload_sha256=version.payload_sha256, reviewer_id=p.user_id, reviewer_name=p.username,
                   proof=deepcopy(proof), proof_sha256=digest(proof), contributor_ids=people["ids"],
                   source_investigation_ids=ids, provenance=provenance)
    s.add(row)
    s.flush()
    owner.approved_version_id, owner.approved_approval_id = version.id, row.id
    if owner.draft_version_id == version.id:
        owner.draft_version_id = None
    if kind == "rule":
        version.status_at_version, version.reviewed_by = "approved", p.username
        owner.status = "draft" if owner.draft_version_id else "approved"
    audit.record(s, "detection.approve" if kind == "rule" else "detection.policy.approve", actor_id=p.user_id,
                 actor_name=p.username, target_type=kind, target_id=owner.id,
                 detail={"version_id": version.id, "approval_id": row.id, "proof_sha256": row.proof_sha256,
                         "reason": reason})
    return row


def _approve(s, p, kind, ident, request):
    # Native source reads occur before acquiring the transaction-wide mutation lock.
    p = _actor(s, p, "detection.approve")
    initial = s.get(_service().Detection if kind == "rule" else PolicyBinding, ident)
    if initial is None:
        raise NotFound("탐지가 없습니다.")
    initial_v = _version(s, kind, initial, request.get("version_id"))
    _, initial_proof = _proof(s, p, kind, initial, initial_v, request)
    _lock(s)
    p = _actor(s, p, "detection.approve")
    owner = s.get(_service().Detection if kind == "rule" else PolicyBinding, ident)
    if owner is None:
        raise NotFound("탐지가 없습니다.")
    reason = _reason(request)
    if kind == "policy":
        _scope(s, p, owner.scope, write=True)
    if request.get("expected_draft_version_id") != owner.draft_version_id or request.get("version_id") != owner.draft_version_id:
        raise Conflict("검토한 초안 버전이 변경되었습니다.")
    v = _version(s, kind, owner, request["version_id"])
    if request.get("payload_sha256") != v.payload_sha256:
        raise Conflict("검토한 본문의 지문이 다릅니다.")
    pin, proof = _proof(s, p, kind, owner, v, request, read_inputs=False)
    if proof["proof_sha256"] != initial_proof["proof_sha256"]:
        raise Conflict("시험 근거가 변경되었습니다.")
    reference = proof.get("reference") or {}
    if owner.active_version_id and reference.get("version_id") != owner.active_version_id:
        raise Conflict("현재 적용본과 비교한 시험이 필요합니다.")
    people = _merge_contributors(contributors(v), pin["contributors"], proof.get("contributors", {}))
    _new_approval(s, p, kind, owner, v, proof, people, reason=reason)
    return owner


def approve_rule(s, p, ident, request):
    return _approve(s, p, "rule", ident, request)


def approve_policy(s, p, ident, request):
    return _approve(s, p, "policy", ident, request)


def validate_approval(s, p, kind, owner, version, approval_id, *, fresh=False, read_inputs=True):
    row = s.get(Approval, approval_id) if approval_id else None
    if (row is None or (row.subject_kind, row.subject_id, row.subject_version_id, row.payload_sha256)
            != (kind, owner.id, version.id, version.payload_sha256) or digest(row.proof) != row.proof_sha256):
        raise Conflict("정확한 버전의 승인 근거가 필요합니다.")
    reviewer = s.get(User, row.reviewer_id)
    if reviewer is None or reviewer.status != "active" or not can(principal_of(reviewer), "detection.approve"):
        raise Forbidden("승인자의 현재 권한을 확인하세요.")
    independent(s, principal_of(reviewer), {"ids": row.contributor_ids, "legacy_names": version.legacy_contributor_names or []})
    _read_sources(s, p, row.source_investigation_ids)
    _read_sources(s, principal_of(reviewer), row.source_investigation_ids)
    if row.proof.get("method") == "package_fixture":
        from saw.content_packages.service import has_package_validation
        if kind != "rule" or not has_package_validation(s, owner.id, version.version):
            raise Conflict("반입 묶음의 시험 근거가 유효하지 않습니다.")
    elif row.proof.get("method") == "selected_truth_v1":
        if fresh:
            from saw.detection.testing import verify_selected_proof
            pin = (pin_rule(s, p, owner.id, version.id, row.proof.get("context_scope"))
                   if kind == "rule" else pin_policy(s, p, owner.id, version.id))
            proof = verify_selected_proof(s, p, test_run_id=row.proof["test_run_id"], subject_kind=kind,
                                          subject_version_id=version.id, payload_sha256=version.payload_sha256,
                                          rule_policy_sha256=rule_policy_digest(pin), _read_inputs=read_inputs)
            if proof["proof_sha256"] != row.proof["proof_sha256"]:
                raise Conflict("시험 근거가 변경되었습니다.")
    elif row.proof.get("method") == "legacy_admission":
        test = s.get(_service().TestRun, row.proof.get("historical_test_run_id"))
        if (test is None or test.detection_id != owner.id or test.version != version.version
                or not test.passed or test.result.get("execution") != "complete"
                or test.result.get("truncated") or test.result.get("evaluation_errors")
                or digest(test.result) != row.proof.get("result_sha256")):
            raise Conflict("이전 승인 시험의 근거가 유효하지 않습니다.")
    else:
        raise Conflict("지원하지 않는 승인 근거입니다.")
    return row


def _activate_record(s, p, kind, owner, version, approval, reason, action, *, snapshot=None):
    before = {"active_version_id": owner.active_version_id, "approval_id": owner.active_approval_id,
              "revision": owner.activation_revision}
    owner.activation_revision += 1
    owner.active_version_id = version.id if version else None
    owner.active_approval_id = approval.id if approval else None
    if kind == "rule":
        owner.updated_at = utcnow()
        owner.status = "draft" if owner.draft_version_id else ("approved" if version else "deprecated")
    row = Activation(subject_kind=kind, subject_id=owner.id, revision=owner.activation_revision,
                     from_version_id=before["active_version_id"], to_version_id=owner.active_version_id,
                     approval_id=owner.active_approval_id, action=action, actor_id=p.user_id, actor_name=p.username,
                     reason=reason, snapshot={"before": before, **(snapshot or {})})
    s.add(row)
    audit.record(s, "detection." + action, actor_id=p.user_id, actor_name=p.username, target_type=kind,
                 target_id=owner.id, detail={"version_id": owner.active_version_id, "revision": owner.activation_revision})
    return owner


def _activate(s, p, kind, ident, request, *, rollback=False):
    p = _actor(s, p, "detection.approve")
    initial = s.get(_service().Detection if kind == "rule" else PolicyBinding, ident)
    if initial is None:
        raise NotFound("탐지가 없습니다.")
    initial_v = _version(s, kind, initial, request.get("version_id"))
    initial_approval = validate_approval(s, p, kind, initial, initial_v, request.get("approval_id"), fresh=True)
    initial_proof_hash = initial_approval.proof_sha256
    _lock(s)
    p = _actor(s, p, "detection.approve")
    owner = s.get(_service().Detection if kind == "rule" else PolicyBinding, ident)
    if owner is None:
        raise NotFound("탐지가 없습니다.")
    reason = _reason(request)
    if kind == "policy":
        _scope(s, p, owner.scope, write=True)
    if ("expected_active_version_id" not in request or "expected_activation_revision" not in request
            or owner.active_version_id != request["expected_active_version_id"]
            or owner.activation_revision != request["expected_activation_revision"]):
        raise Conflict("적용 상태가 변경되었습니다. 다시 조회하세요.")
    v = _version(s, kind, owner, request.get("version_id"))
    approval = validate_approval(s, p, kind, owner, v, request.get("approval_id"), fresh=True, read_inputs=False)
    if approval.proof_sha256 != initial_proof_hash:
        raise Conflict("승인 근거가 변경되었습니다.")
    independent(s, p, {"ids": approval.contributor_ids, "legacy_names": v.legacy_contributor_names or []})
    if rollback and not s.scalar(select(Activation.id).where(Activation.subject_kind == kind,
                Activation.subject_id == owner.id, Activation.to_version_id == v.id, Activation.approval_id == approval.id).limit(1)):
        raise Conflict("이전에 적용한 승인본만 되돌릴 수 있습니다.")
    if not rollback and approval.proof.get("method") == "selected_truth_v1":
        reference = approval.proof.get("reference") or {}
        if reference.get("version_id") != owner.active_version_id:
            raise Conflict("시험 이후 적용본이 변경되었습니다. 현재 적용본과 다시 비교하세요.")
    if not rollback and (owner.approved_version_id != v.id or owner.approved_approval_id != approval.id):
        raise Conflict("현재 승인 포인터의 정확한 버전만 새로 적용할 수 있습니다.")
    return _activate_record(s, p, kind, owner, v, approval, reason, "rollback" if rollback else "activate")


def activate_rule(s, p, ident, request):
    return _activate(s, p, "rule", ident, request)


def rollback_rule(s, p, ident, request):
    return _activate(s, p, "rule", ident, request, rollback=True)


def activate_policy(s, p, ident, request):
    return _activate(s, p, "policy", ident, request)


def rollback_policy(s, p, ident, request):
    return _activate(s, p, "policy", ident, request, rollback=True)


def draft_policy(s, p, data):
    _lock(s)
    p = _actor(s, p, "detection.write")
    reason = _reason(data)
    scope, scope_key = _scope(s, p, data.get("scope"), write=True)
    detector_id = data["detector_id"]
    spec = _spec(detector_id)
    binding = _policy_binding(s, detector_id, scope)
    if binding is None:
        binding = PolicyBinding(detector_id=detector_id, scope_key=scope_key, scope=scope, created_by=p.user_id)
        s.add(binding)
        s.flush()
    if binding.scope != scope:
        raise Conflict("장비 정책은 최초 범위의 관계사 식별자를 유지해야 합니다.")
    if "expected_draft_version_id" not in data or data["expected_draft_version_id"] != binding.draft_version_id:
        raise Conflict("정책 초안이 변경되었습니다.")
    parent = _version(s, "policy", binding, data["base_version_id"]) if data.get("base_version_id") else None
    if parent is None and (binding.draft_version_id or binding.approved_version_id or binding.active_version_id):
        raise Conflict("수정할 정확한 기준 버전을 지정하세요.")
    inherited = deepcopy(parent.payload) if parent else {"overrides": {}, "exclusions_override": None}
    changes = data.get("changes") or {}
    overrides = inherited["overrides"]
    additions, removals = changes.get("set", {}), changes.get("inherit", [])
    if set(changes) - {"set", "inherit"} or not isinstance(additions, dict) or not isinstance(removals, list):
        raise ValueError("정책 값 변경 형식이 올바르지 않습니다.")
    if set(additions) & set(removals):
        raise ValueError("설정과 상속을 동시에 요청할 수 없습니다.")
    known = set(spec["defaults"])
    if (set(additions) | set(removals)) - known:
        raise ValueError("등록되지 않은 정책 값입니다.")
    for key in removals:
        overrides.pop(key, None)
    overrides.update(additions)
    _values(spec, overrides)
    exclusions = data.get("exclusions")
    if exclusions is not None:
        if exclusions.get("mode") == "inherit" and set(exclusions) == {"mode"}:
            inherited["exclusions_override"] = None
        elif exclusions.get("mode") == "set" and set(exclusions) == {"mode", "values"} and isinstance(exclusions["values"], list):
            if len(exclusions["values"]) > 32:
                raise ValueError("예외는 최대 32개입니다.")
            inherited["exclusions_override"] = [Filter(**v).model_dump(mode="json") for v in exclusions["values"]]
        else:
            raise ValueError("예외 변경 형식이 올바르지 않습니다.")
    payload = {"schema": "det-policy/1", "overrides": overrides, "exclusions_override": inherited["exclusions_override"],
               "provenance": {"kind": "reviewed_draft"}}
    number = (s.scalar(select(func.max(PolicyVersion.version)).where(PolicyVersion.binding_id == binding.id)) or 0) + 1
    people = _merge_contributors(contributors(parent) if parent else {}, {"ids": [binding.created_by, p.user_id]})
    v = PolicyVersion(binding_id=binding.id, version=number, parent_version_id=parent.id if parent else None,
                      spec_id=spec["id"], spec_version=str(spec["version"]), spec_sha256=spec_digest(spec), payload=payload,
                      payload_sha256=digest(payload), contributor_ids=people["ids"], legacy_contributor_names=people["legacy_names"],
                      created_by=p.user_id)
    s.add(v)
    s.flush()
    binding.draft_version_id = v.id
    audit.record(s, "detection.policy.draft", actor_id=p.user_id, actor_name=p.username, target_type="policy",
                 target_id=binding.id, detail={"version_id": v.id, "scope": scope, "reason": reason})
    return binding

def version_ref(version):
    return {"id": version.id, "version": version.version, "payload_sha256": version.payload_sha256} if version else None


def _public_approvals(s, p, kind, owner):
    result = []
    if p is None:
        return result
    for row in s.scalars(select(Approval).where(Approval.subject_kind == kind, Approval.subject_id == owner.id)
                         .order_by(Approval.reviewed_at)):
        try:
            _read_sources(s, p, row.source_investigation_ids)
        except (Forbidden, NotFound):
            continue
        result.append({"id": row.id, "version_id": row.subject_version_id, "payload_sha256": row.payload_sha256,
                       "reviewer": row.reviewer_name, "reviewed_at": row.reviewed_at, "provenance": row.provenance})
    return result


def pointers(s, kind, owner):
    cls = _service().DetectionVersion if kind == "rule" else PolicyVersion
    field = cls.detection_id if kind == "rule" else cls.binding_id
    latest = s.scalar(select(cls).where(field == owner.id).order_by(cls.version.desc()).limit(1))
    result = {name: version_ref(_version(s, kind, owner, getattr(owner, name + "_version_id")))
              if getattr(owner, name + "_version_id") else None for name in ("draft", "approved", "active")}
    result.update({"latest": version_ref(latest), "activation_revision": owner.activation_revision,
                   "active_approval_id": owner.active_approval_id, "approved_approval_id": owner.approved_approval_id})
    return result


def governance_dict(s, p, kind, owner):
    refs = pointers(s, kind, owner)
    approvals = _public_approvals(s, p, kind, owner)
    approved_ids = {a["id"] for a in approvals}
    targets = {}
    for entry in s.scalars(select(Activation).where(Activation.subject_kind == kind, Activation.subject_id == owner.id)):
        if entry.to_version_id and entry.approval_id in approved_ids:
            v = _version(s, kind, owner, entry.to_version_id)
            targets[(v.id, entry.approval_id)] = {**version_ref(v), "version_id": v.id, "approval_id": entry.approval_id}
    allowed = bool(p and can(p, "detection.approve"))
    reasons = {"approve": [], "activate": [], "rollback": []}
    for key in reasons:
        if not allowed:
            reasons[key].append("승인 권한이 필요합니다.")
    if not refs["draft"]:
        reasons["approve"].append("검토할 초안이 없습니다.")
    else:
        v = _version(s, kind, owner, refs["draft"]["id"])
        if p and (p.user_id in v.contributor_ids or p.username in v.legacy_contributor_names):
            reasons["approve"].append("작성·수정 기여자는 승인할 수 없습니다.")
    if not refs["approved"]:
        reasons["activate"].append("승인본이 없습니다.")
    elif allowed:
        try:
            version = _version(s, kind, owner, refs["approved"]["id"])
            approval = validate_approval(s, p, kind, owner, version, owner.approved_approval_id)
            independent(s, p, {"ids": approval.contributor_ids, "legacy_names": version.legacy_contributor_names})
        except (ValueError, Forbidden, NotFound) as exc:
            reasons["activate"].append(str(exc))
    eligible_targets = {}
    if allowed:
        for key, target in targets.items():
            try:
                version = _version(s, kind, owner, target["version_id"])
                approval = validate_approval(s, p, kind, owner, version, target["approval_id"])
                independent(s, p, {"ids": approval.contributor_ids, "legacy_names": version.legacy_contributor_names})
                eligible_targets[key] = target
            except (ValueError, Forbidden, NotFound):
                continue
    targets = eligible_targets
    if not targets:
        reasons["rollback"].append("현재 권한·기여자 분리 조건으로 복구할 수 있는 이전 승인본이 없습니다.")
    return {"pointers": refs, "approvals": approvals, "rollback_targets": list(targets.values()),
            "eligibility": {**{key: not value for key, value in reasons.items()}, "reasons": reasons}}


def exact_version_dict(s, p, det_id, version_id):
    d = s.get(_service().Detection, det_id)
    if d is None:
        raise NotFound("탐지 룰이 없습니다.")
    _actor(s, p, "knowledge.read")
    _read_sources(s, p, _source_ids(s, "rule", d))
    v = _version(s, "rule", d, version_id)
    return {"id": d.id, "display_id": d.display_id,
            "version": {**version_ref(v), **rule_payload(v), "contributors": contributors(v),
                        "created_by": v.created_by, "created_at": v.created_at, "status": v.status_at_version},
            "approvals": [a for a in _public_approvals(s, p, "rule", d) if a["version_id"] == v.id]}


def policy_to_dict(s, p, binding, *, full=True):
    _actor(s, p, "knowledge.read")
    _scope(s, p, binding.scope)
    result = {"id": binding.id, "detector_id": binding.detector_id, "scope": binding.scope,
              **governance_dict(s, p, "policy", binding)}
    def view(v):
        return {**version_ref(v), "payload": v.payload, "spec_id": v.spec_id, "spec_version": v.spec_version,
                "spec_sha256": v.spec_sha256, "contributors": contributors(v), "created_at": v.created_at}
    rows = list(s.scalars(select(PolicyVersion).where(PolicyVersion.binding_id == binding.id).order_by(PolicyVersion.version)))
    chosen = binding.draft_version_id or binding.approved_version_id or (rows[-1].id if rows else None)
    result["current"] = next((view(v) for v in rows if v.id == chosen), None)
    if full:
        result["versions"] = [view(v) for v in rows]
        from saw.detection.testing import serialized_test
        tests = s.scalars(select(_service().TestRun).where(_service().TestRun.detection_id == binding.id)
                          .order_by(_service().TestRun.ran_at.desc()))
        result["test_runs"] = [item for t in tests if (item := serialized_test(s, p, t)) is not None]
    return result


def list_policies(s, p, detector_id=None):
    _actor(s, p, "knowledge.read")
    query = select(PolicyBinding).order_by(PolicyBinding.detector_id, PolicyBinding.scope_key)
    if detector_id:
        query = query.where(PolicyBinding.detector_id == detector_id)
    result = []
    for binding in s.scalars(query):
        try:
            result.append(policy_to_dict(s, p, binding, full=False))
        except (Forbidden, NotFound):
            continue
    return result


def package_admit(s, d, version, author, reviewer, package, entry, *, reason):
    """Called only after the package engine reruns exact fixtures inside the serialized apply."""
    p = principal_of(reviewer)
    people = contributors(version)
    proof = {"method": "package_fixture", "status": "complete", "package_record_id": package.id,
             "package_sha256": package.digest, "source_id": entry["source_id"],
             "payload_sha256": version.payload_sha256, "engine": package.test_result["engine"],
             "source_investigation_ids": _source_ids(s, "rule", d)}
    approval = _new_approval(s, p, "rule", d, version, proof, people, provenance="package_fixture", reason=reason)
    _activate_record(s, p, "rule", d, version, approval, reason, "activate",
                     snapshot={"package_record_id": package.id, "package_sha256": package.digest})
    return approval


def package_restore(s, p, d, prior, reason, package_id):
    if prior and prior.get("active_version_id"):
        v = _version(s, "rule", d, prior["active_version_id"])
        approval = validate_approval(s, p, "rule", d, v, prior["active_approval_id"], fresh=False)
        independent(s, p, {"ids": approval.contributor_ids, "legacy_names": v.legacy_contributor_names})
    else:
        v, approval = None, None
    return _activate_record(s, p, "rule", d, v, approval, reason, "rollback",
                            snapshot={"package_record_id": package_id})


def runtime_candidates(s, p, investigation_id):
    """Keyset pages bound materialization; private inventory cannot consume the execution cap."""
    detection = _service().Detection
    source_inv = detection.source["investigation_id"].as_string()
    query = select(detection).where(
        detection.active_version_id.is_not(None),
        (source_inv.is_(None) | (source_inv == "") | (source_inv == investigation_id)))
    cursor = None
    while True:
        page = list(s.scalars((query.where(detection.id > cursor) if cursor is not None else query)
                             .order_by(detection.id).limit(51)))
        if not page:
            return
        cursor = page[-1].id
        for definition in page:
            try:
                _read_sources(s, p, _source_ids(s, "rule", definition))
            except (Forbidden, NotFound):
                continue
            yield definition
        if len(page) < 51:
            return


def pin_runtime(s, p, investigation_id, context_scopes=None):
    _actor(s, p, "analyze.run")
    require(s, p, "investigation.read", investigation_id)
    scopes = context_scopes or [{"kind": "group"}]
    if len(scopes) > 100:
        raise Conflict("runtime_context_limit: 최대 100개 맥락으로 분석 범위를 좁히세요.")
    scopes = list({digest(scope): scope for scope in scopes}.values())
    rules, reports = [], []
    admitted = 0
    for d in runtime_candidates(s, p, investigation_id):
        try:
            _read_sources(s, p, _source_ids(s, "rule", d))
            v = _version(s, "rule", d, d.active_version_id)
            approval = validate_approval(s, p, "rule", d, v, d.active_approval_id)
            scoped = [pin_rule(s, p, d.id, v.id, scope) for scope in scopes]
            if admitted == 50:
                reports.append({"detector_id": "sigma.approved", "status": "partial", "reason": "runtime_rule_limit"})
                break
            admitted += 1
            for pin in scoped:
                pin["source_investigation_ids"] = sorted(set(pin["source_investigation_ids"] + approval.source_investigation_ids))
                pin["contributors"] = _merge_contributors(pin["contributors"], {"ids": approval.contributor_ids})
                pin["approval_id"] = approval.id
                pin["activation_revision"] = d.activation_revision
                pin["validation_kind"] = approval.proof["method"]
                pin["rule_policy_sha256"] = rule_policy_digest(pin)
                rules.append(pin)
        except (Forbidden, NotFound):
            continue
        except (Conflict, ValueError):
            if admitted == 50:
                reports.append({"detector_id": "sigma.approved", "status": "partial", "reason": "runtime_rule_limit"})
                break
            admitted += 1
            reports.append({"detector_id": "sigma.approved:" + d.id, "status": "unsupported",
                            "reason": "active_approval_unavailable"})
    devices = []
    for detector_id in ("fw.observation", "waf.observation", "ips.observation", "ddos.observation", "ndr.observation"):
        for scope in scopes:
            effective = resolve_effective(s, detector_id, scope, p=p)
            devices.append({"detector_id": detector_id, "context_scope": scope, "policy": effective})
    from saw.detectors.signatures import by_id
    from saw.storage.models import SignatureSetting
    pack = by_id()
    pack_hash = digest([{"id": ident, "payload_sha256": _spec("signature:" + ident)["payload_sha256"]} for ident in sorted(pack)])
    target_ids = set(s.scalars(select(PolicyBinding.detector_id).where(
        PolicyBinding.detector_id.startswith("signature:"), PolicyBinding.active_version_id.is_not(None))))
    target_ids.update("signature:" + ident for ident in s.scalars(select(SignatureSetting.sig_id).where(SignatureSetting.enabled.is_(False)))
                      if ident in pack)
    signature_defaults = {"pack_sha256": pack_hash, "engine_version": "1.1.0", "enabled": True,
                          "available": True, "provenance": "pinned_shipped_pack", "count": len(pack)}
    signatures = []
    if len(target_ids) * len(scopes) > 500:
        # No override is silently omitted: the entire signature stage is unavailable.
        signature_defaults["available"] = False
        reports.append({"detector_id": "sig.match", "status": "partial", "reason": "runtime_signature_policy_limit"})
    else:
        for detector_id in sorted(target_ids):
            for scope in scopes:
                signatures.append({"detector_id": detector_id, "context_scope": scope,
                                   "policy": resolve_effective(s, detector_id, scope, p=p)})
    result = {"schema": "det-runtime-set/1", "rules": rules, "devices": devices,
              "signatures": signatures, "signature_defaults": signature_defaults, "execution_reports": reports}
    if len(json.dumps(result, ensure_ascii=False).encode()) > 4 * 1024 * 1024:
        raise Conflict("runtime_snapshot_limit: 분석 범위를 좁히세요.")
    result["sha256"] = digest(result)
    return result
