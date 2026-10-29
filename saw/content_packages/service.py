"""Atomic package staging, fixture validation, independent apply, and compensating rollback."""
from __future__ import annotations

import copy

from sqlalchemy import select

from saw.content_packages import format as fmt
from saw.content_packages.models import ContentBinding, ContentPackage, ContentValidation
from saw.core.application import audit
from saw.core.application.identity import principal_of
from saw.core.application.ids import next_display_id
from saw.core.application.investigations import Forbidden, NotFound
from saw.core.security.authz import Principal, can
from saw.detection import service as detection
from saw.detection import governance as gov
from saw.parsers import library
from saw.storage.db import utcnow
from saw.storage.models import User


class Conflict(ValueError):
    pass


def _current(s, principal: Principal) -> User:
    user = s.get(User, principal.user_id, populate_existing=True)
    if user is None or user.status != "active":
        raise Forbidden("현재 활성 사용자만 콘텐츠를 변경할 수 있습니다.")
    return user


def _permissions(user, document, review=False):
    p = principal_of(user)
    permissions = {"sigma": "detection.approve" if review else "detection.write",
                   "parser": "parser.approve" if review else "parser.manage"}
    for kind in {e["kind"] for e in document["entries"]}:
        if not can(p, permissions[kind]):
            raise Forbidden(permissions[kind])


def _locked(s):
    # Use the existing cross-process transaction lock. No filesystem state is changed.
    audit._head(s)
    s.expire_all()


def _get(s, ident):
    package = s.get(ContentPackage, ident)
    if package is None:
        raise NotFound("콘텐츠 묶음을 찾지 못했습니다.")
    return package


def _checked(package, expected):
    if expected != package.digest:
        raise Conflict("묶음 지문이 변경되었습니다. 다시 조회하세요.")
    fmt.validate(package.document)
    if package.document["payload_sha256"] != package.digest:
        raise Conflict("저장된 묶음 지문이 일치하지 않습니다.")


def _binding(binding):
    return {k: getattr(binding, k) for k in ("kind", "source_id", "target_id", "source_version", "max_source_version", "payload_digest")} if binding else None


def _sigma_payload(version):
    return {key: getattr(version, key) for key in fmt.SIGMA_KEYS}


def _snapshot(s, entry):
    kind, source_id = entry["kind"], entry["source_id"]
    binding = s.get(ContentBinding, (kind, source_id), populate_existing=True)
    live = None
    if kind == "sigma" and binding:
        d = s.get(detection.Detection, binding.target_id, populate_existing=True)
        if d is None:
            raise Conflict("현재 룰을 찾지 못했습니다.")
        v = gov._version(s, "rule", d, d.active_version_id) if d.active_version_id else None
        live = {"target_id": d.id, "current_version": v.version if v else None,
                "status": "approved" if v else "deprecated",
                "active_version_id": d.active_version_id, "active_approval_id": d.active_approval_id,
                "activation_revision": d.activation_revision, "payload_sha256": v.payload_sha256 if v else None,
                "payload": _sigma_payload(v) if v else None, "author": v.created_by if v else None,
                "reviewer": v.reviewed_by if v else None, "creator_id": d.created_by,
                "contributors": gov.contributors(v) if v else {"ids": [], "legacy_names": []},
                "version_status": v.status_at_version if v else None}
    elif kind == "parser":
        slug = binding.target_id if binding else source_id
        versions = s.scalars(select(library.ParserDefinition).where(library.ParserDefinition.slug == slug)
                            .order_by(library.ParserDefinition.version)).all()
        if versions and not binding:
            raise Conflict("같은 source_id의 기존 파서가 있습니다. 새로운 source_id를 사용하세요.")
        if binding:
            live = {"target_id": slug, "versions": [
                {"id": d.id, "version": d.version, "status": d.status, "name": d.name, "spec": d.spec,
                 "author_id": d.created_by, "reviewer_id": d.reviewed_by} for d in versions]}
    return {"kind": kind, "source_id": source_id, "binding": _binding(binding), "live": live}


def _baseline(s, document):
    return [_snapshot(s, e) for e in document["entries"]]


def _plan(s, document):
    snapshots = _baseline(s, document)
    rows = []
    for entry, snapshot in zip(document["entries"], snapshots):
        binding = snapshot["binding"]
        if binding and entry["source_version"] <= binding["max_source_version"]:
            raise Conflict("source_version은 현재 반입 버전보다 커야 합니다.")
        live = snapshot["live"]
        if binding and not binding["payload_digest"]:
            if entry["kind"] == "sigma":
                if live["active_version_id"] is not None:
                    raise Conflict("되돌린 룰이 수동 변경되었습니다. 기존 변경을 먼저 검토하세요.")
            elif any(v["status"] == "active" for v in live["versions"]):
                raise Conflict("되돌린 파서가 다시 활성화되었습니다. 기존 변경을 먼저 검토하세요.")
        if binding and binding["payload_digest"] and entry["kind"] == "sigma":
            if not live["active_version_id"]:
                raise Conflict("현재 룰이 승인 상태가 아닙니다. 변경을 먼저 정리하세요.")
            version = s.get(detection.DetectionVersion, live["active_version_id"])
            if fmt.digest(_sigma_payload(version)) != binding["payload_digest"] or not has_package_validation(s, binding["target_id"], version.version):
                raise Conflict("반입 후 룰이 변경되었습니다. 기존 변경을 먼저 검토하세요.")
        if binding and binding["payload_digest"] and entry["kind"] == "parser":
            active = [v for v in live["versions"] if v["status"] == "active"]
            if len(active) != 1 or fmt.digest({"name": active[0]["name"], "spec": active[0]["spec"]}) != binding["payload_digest"]:
                raise Conflict("반입 후 공용 파서가 변경되었거나 꺼져 있습니다.")
        rows.append({"kind": entry["kind"], "source_id": entry["source_id"], "source_version": entry["source_version"],
                     "action": "update" if binding else "add", "previous_source_version": binding["source_version"] if binding else None,
                     "before": live["payload"] if live and entry["kind"] == "sigma" else
                               next(({"name": v["name"], "spec": v["spec"]} for v in live["versions"] if v["status"] == "active"), None) if live else None,
                     "after": fmt.normalized(entry), "payload_digest": fmt.digest(fmt.normalized(entry))})
    return snapshots, rows


def verify(s, document):
    fmt.validate(document)
    _, changes = _plan(s, document)
    return {"digest": document["payload_sha256"], "package_id": document["package_id"], "revision": document["revision"],
            "integrity": "sha256_verified", "origin": "not_authenticated", "changes": changes,
            "limits": {"bytes": fmt.MAX_BYTES, "items": 20}, "runtime": fmt.ENGINE}


def _public_snapshot(snapshot):
    """Private parser drafts remain part of drift checks but never cross the package API."""
    result = copy.deepcopy(snapshot)
    live = result.get("live")
    if result.get("kind") == "parser" and live:
        live["versions"] = [v for v in live["versions"] if v["status"] != "draft"]
    return result


def _public_receipt(receipt):
    result = copy.deepcopy(receipt)
    for item in result.get("items", []):
        item["before"] = _public_snapshot(item["before"])
        item["after"] = _public_snapshot(item["after"])
    for item in result.get("rollback", {}).get("restored", []):
        item["state"] = _public_snapshot(item["state"])
    return result


def _rollback_blocked_reasons(package, p):
    reasons = []
    if not all(can(p, "detection.approve" if e["kind"] == "sigma" else "parser.approve") for e in package.document["entries"]):
        reasons.append("묶음의 룰·파서를 되돌릴 승인 권한이 필요합니다.")
    if package.status != "applied":
        reasons.append("적용된 묶음만 되돌릴 수 있습니다.")
    if package.receipt.get("applied_by_id") == p.user_id:
        reasons.append("적용한 사람과 다른 검토자가 되돌려야 합니다.")
    for item in package.receipt.get("items", []):
        before = item["before"]
        if item["kind"] == "sigma" and before["binding"] and before["binding"]["payload_digest"]:
            prior = before["live"]
            if p.user_id in prior.get("contributors", {}).get("ids", [prior["creator_id"]]) or p.username in prior.get("contributors", {}).get("legacy_names", [prior["author"]]):
                reasons.append("직전 룰 작성자 또는 최초 룰 작성자는 자기 룰의 복구를 승인할 수 없습니다. 적용자와 작성자를 제외한 검토자가 필요합니다.")
                break
    return reasons


def to_dict(package, p=None, *, full=True):
    result = {"id": package.id, "package_id": package.package_id, "revision": package.revision, "digest": package.digest,
              "status": package.status, "imported_by": package.imported_by_name, "created_at": package.created_at,
              "test_result": package.test_result, "receipt": _public_receipt(package.receipt),
              "integrity": "sha256_verified", "origin": "not_authenticated"}
    if full:
        result["document"] = package.document
        result["baseline"] = [_public_snapshot(row) for row in package.baseline]
    if p:
        permission = all(can(p, "detection.approve" if e["kind"] == "sigma" else "parser.approve") for e in package.document["entries"])
        result["can_apply"] = permission and package.imported_by != p.user_id and package.status == "staged" and bool(package.test_result.get("passed"))
        result["rollback_blocked_reasons"] = _rollback_blocked_reasons(package, p)
        result["can_rollback"] = not result["rollback_blocked_reasons"]
    return result


def list_packages(s, p):
    return [to_dict(d, p, full=False) for d in s.scalars(select(ContentPackage).order_by(ContentPackage.created_at.desc()).limit(100))]


def stage(s, p, document):
    fmt.validate(document)
    _locked(s)
    user = _current(s, p)
    _permissions(user, document)
    existing = s.scalar(select(ContentPackage).where(ContentPackage.package_id == document["package_id"],
                                                     ContentPackage.revision == document["revision"]))
    if existing:
        if existing.digest != document["payload_sha256"]:
            raise Conflict("같은 package_id·revision에 다른 파일이 있습니다.")
        return to_dict(existing, p)
    baseline, _ = _plan(s, document)
    package = ContentPackage(package_id=document["package_id"], revision=document["revision"], digest=document["payload_sha256"],
                             document=copy.deepcopy(document), imported_by=user.id, imported_by_name=user.username, baseline=baseline)
    s.add(package)
    s.flush()
    audit.record(s, "content_package.stage", actor_id=user.id, actor_name=user.username, target_type="content_package",
                 target_id=package.id, detail={"digest": package.digest, "items": len(document["entries"])})
    return to_dict(package, p)


def test_package(s, p, ident, expected):
    _locked(s)
    package = _get(s, ident)
    _checked(package, expected)
    user = _current(s, p)
    _permissions(user, package.document)
    if package.status != "staged":
        raise Conflict("적용 전 묶음만 시험할 수 있습니다.")
    result = fmt.run_fixtures(package.document)
    package.test_result = {**result, "tested_by": user.username, "tested_at": utcnow().isoformat()}
    audit.record(s, "content_package.test", actor_id=user.id, actor_name=user.username, target_type="content_package",
                 target_id=package.id, detail={"digest": package.digest, "kind": "package_fixture", "passed": result["passed"]})
    return to_dict(package, p)


def _add_validation(s, package, entry, d, v):
    s.add(ContentValidation(detection_id=d.id, version=v.version, package_record_id=package.id,
                            source_id=entry["source_id"], payload_digest=fmt.digest(_sigma_payload(v))))
    s.flush()


def _apply_item(s, package, entry, author, reviewer):
    content = fmt.normalized(entry)
    before = _snapshot(s, entry)
    binding = s.get(ContentBinding, (entry["kind"], entry["source_id"]))
    if entry["kind"] == "sigma":
        if binding:
            d = s.get(detection.Detection, binding.target_id)
            d.current_version += 1
        else:
            d = detection.Detection(display_id=next_display_id(s, "DET", daily=False, width=4),
                                    created_by=author.id, created_by_name=author.username, current_version=1,
                                    source={"content_source_id": entry["source_id"]})
            s.add(d)
            s.flush()
        # Authorship comes from the immutable staging actor. Review uses the actual current actor.
        if reviewer.id == d.created_by or reviewer.username == author.username:
            raise Forbidden("현재 룰 작성자는 자기 콘텐츠를 승인할 수 없습니다.")
        parent = s.get(detection.DetectionVersion, d.active_version_id) if d.active_version_id else None
        # An unrelated manual draft is not an ancestor of this package version and remains editable.
        v = gov.initialize_rule_version(s, d, detection._version_from(d.id, d.current_version, content, author.username),
                                        principal_of(author), parent)
        s.add(v)
        s.flush()
        _add_validation(s, package, entry, d, v)
        gov.package_admit(s, d, v, author, reviewer, package, entry, reason="Reviewed content package apply")
        target_id = d.id
    else:
        slug = entry["source_id"]
        versions = s.scalars(select(library.ParserDefinition).where(library.ParserDefinition.slug == slug)).all()
        for old in versions:
            if old.status == "active":
                old.status = "superseded"
        version = max((d.version for d in versions), default=0) + 1
        parser = library.ParserDefinition(slug=slug, name=content["name"], version=version, status="active",
                   spec=content["spec"], note=f"content package {package.package_id} revision {package.revision}",
                   created_by=author.id, created_by_name=author.username, reviewed_by=reviewer.id,
                   reviewed_by_name=reviewer.username, reviewed_at=utcnow(), review_note="승인된 콘텐츠 묶음 합성 예제 시험")
        s.add(parser)
        target_id = slug
    if binding is None:
        binding = ContentBinding(kind=entry["kind"], source_id=entry["source_id"], target_id=target_id)
        s.add(binding)
    binding.source_version, binding.payload_digest = entry["source_version"], fmt.digest(content)
    binding.max_source_version = max(binding.max_source_version or 0, entry["source_version"])
    s.flush()
    return {"kind": entry["kind"], "source_id": entry["source_id"], "target_id": target_id,
            "before": before, "after": _snapshot(s, entry)}


def apply_package(s, p, ident, expected, reason):
    if not reason.strip():
        raise ValueError("검토 사유가 필요합니다.")
    _locked(s)
    package = _get(s, ident)
    _checked(package, expected)
    reviewer = _current(s, p)
    _permissions(reviewer, package.document, review=True)
    if reviewer.id == package.imported_by:
        raise Forbidden("반입한 사람은 자기 묶음을 승인·적용할 수 없습니다.")
    if package.status == "applied":
        return to_dict(package, p)
    if package.status != "staged":
        raise Conflict("되돌린 묶음은 다시 적용하지 않습니다. 새 revision을 만드세요.")
    author = s.get(User, package.imported_by, populate_existing=True)
    if author is None or author.status != "active":
        raise Forbidden("반입한 사용자의 활성 상태를 확인하세요.")
    _permissions(author, package.document)
    previous = package.test_result
    if not previous.get("passed") or previous.get("digest") != package.digest or previous.get("engine") != fmt.ENGINE or previous.get("kind") != "package_fixture":
        raise ValueError("현재 지문의 합성 양성·정상 예제 시험 통과가 필요합니다.")
    # Revalidate the exact bytes at the authority boundary; a stale or altered test flag cannot activate content.
    checked = fmt.run_fixtures(package.document)
    if not checked["passed"]:
        raise ValueError("적용 직전 합성 예제 재검증이 실패했습니다.")
    if _baseline(s, package.document) != package.baseline:
        raise Conflict("반입 이후 현재 룰·파서가 변경되었습니다. 새 revision으로 다시 미리보기 하세요.")
    _plan(s, package.document)
    items = [_apply_item(s, package, entry, author, reviewer) for entry in package.document["entries"]]
    package.status = "applied"
    package.receipt = {"digest": package.digest, "applied_by_id": reviewer.id, "applied_by": reviewer.username,
                       "imported_by": author.username, "applied_at": utcnow().isoformat(), "reason": reason,
                       "validation_kind": "package_fixture", "items": items}
    audit.record(s, "content_package.apply", actor_id=reviewer.id, actor_name=reviewer.username, target_type="content_package",
                 target_id=package.id, detail={"digest": package.digest, "importer": author.id, "reason": reason,
                                             "targets": [i["target_id"] for i in items]})
    return to_dict(package, p)


def has_package_validation(s, det_id, version):
    proof = s.scalar(select(ContentValidation).where(ContentValidation.detection_id == det_id, ContentValidation.version == version))
    if proof is None or proof.kind != "package_fixture":
        return False
    package = s.get(ContentPackage, proof.package_record_id)
    v = s.scalar(select(detection.DetectionVersion).where(detection.DetectionVersion.detection_id == det_id,
                                                         detection.DetectionVersion.version == version))
    if package is None or v is None or package.status not in {"applied", "rolled_back"}:
        return False
    result = package.test_result or {}
    if not result.get("passed") or result.get("kind") != "package_fixture" or result.get("digest") != package.digest or result.get("engine") != fmt.ENGINE:
        return False
    try:
        if fmt.payload_hash(package.document) != package.digest or package.document.get("payload_sha256") != package.digest:
            return False
        entry = next(e for e in package.document["entries"] if e["kind"] == "sigma" and e["source_id"] == proof.source_id)
        return proof.payload_digest == fmt.digest(_sigma_payload(v)) == fmt.digest(fmt.normalized(entry))
    except (ValueError, TypeError, KeyError, StopIteration):
        return False



LEGACY_RECEIPT_ADAPTER = "package-receipt/0014-to-0017/1"


def _rollback_items(s, p, package):
    """Interpret old receipts without changing their stored snapshots or following live pointers."""
    from saw.detection.policy_models import Approval
    items = copy.deepcopy((package.receipt or {}).get("items", []))
    entries = package.document["entries"]
    if len(items) != len(entries):
        raise Conflict("legacy_receipt_requires_review: 적용 이력의 항목 수를 확인하세요.")
    for entry, item in zip(entries, items):
        if (entry["kind"], entry["source_id"]) != (item.get("kind"), item.get("source_id")):
            raise Conflict("legacy_receipt_requires_review: 적용 이력의 항목을 확인하세요.")
        if item["kind"] != "sigma":
            continue
        for side in ("before", "after"):
            snapshot = item[side]
            live, binding = snapshot.get("live"), snapshot.get("binding")
            if not live or "active_version_id" in live:
                continue
            try:
                d = s.get(detection.Detection, item["target_id"])
                version = s.scalar(select(detection.DetectionVersion).where(
                    detection.DetectionVersion.detection_id == item["target_id"],
                    detection.DetectionVersion.version == live["current_version"]))
                if (d is None or version is None or not binding or not binding["payload_digest"]
                        or live["status"] not in {"approved", "deployed"}
                        or live["version_status"] not in {"approved", "deployed"}
                        or live["current_version"] != live["latest_version"]
                        or live["target_id"] != d.id or binding["target_id"] != d.id
                        or live["author"] != version.created_by or live["reviewer"] != version.reviewed_by
                        or live["creator_id"] != d.created_by
                        or fmt.digest(live["payload"]) != binding["payload_digest"]
                        or fmt.digest(_sigma_payload(version)) != binding["payload_digest"]):
                    raise ValueError("legacy snapshot mismatch")
                # Historical approvals were admitted by migration only after real exact fixture replay.
                approvals = list(s.scalars(select(Approval).where(Approval.subject_kind == "rule",
                    Approval.subject_id == d.id, Approval.subject_version_id == version.id,
                    Approval.provenance == "legacy_admission")))
                approval = next((a for a in approvals if a.proof.get("method") == "package_fixture"
                                 and a.proof.get("legacy_receipt_adapter") == LEGACY_RECEIPT_ADAPTER), None)
                if approval is None:
                    raise ValueError("unproven historical approval")
                if side == "after" and (approval.proof.get("package_record_id") != package.id
                        or approval.proof.get("legacy_receipt_sha256") != gov.digest(package.receipt)):
                    raise ValueError("legacy receipt was changed")
                gov.validate_approval(s, p, "rule", d, version, approval.id)
                snapshot["live"] = {"target_id": d.id, "current_version": version.version,
                    "status": "approved", "active_version_id": version.id, "active_approval_id": approval.id,
                    # The migration's one current-head activation is fixed. Later cycles are drift.
                    "activation_revision": 1 if side == "after" else 0,
                    "payload_sha256": version.payload_sha256, "payload": _sigma_payload(version),
                    "author": version.created_by, "reviewer": version.reviewed_by, "creator_id": d.created_by,
                    "contributors": gov.contributors(version), "version_status": version.status_at_version}
            except (ValueError, TypeError, KeyError, Forbidden, NotFound) as exc:
                raise Conflict("legacy_receipt_requires_review: 이전 승인본과 시험·검토자 이력을 확인하세요.") from exc
    return items


def rollback_preview(s, p, ident):
    package = _get(s, ident)
    _checked(package, package.digest)
    if package.status != "applied":
        raise Conflict("적용된 묶음만 되돌릴 수 있습니다.")
    changed = []
    try:
        items = _rollback_items(s, p, package)
    except Conflict as exc:
        return {"digest": package.digest, "changes": [], "can_rollback": False,
                "rollback_blocked_reasons": [str(exc)]}
    for entry, item in zip(package.document["entries"], items):
        changed.append({"kind": entry["kind"], "source_id": entry["source_id"],
                        "action": "restore" if item["before"]["binding"] and item["before"]["binding"]["payload_digest"] else "disable",
                        "drift": _snapshot(s, entry) != item["after"]})
    reasons = _rollback_blocked_reasons(package, p)
    if any(c["drift"] for c in changed):
        reasons.append("적용 이후 콘텐츠가 변경되어 자동으로 되돌릴 수 없습니다.")
    return {"digest": package.digest, "changes": changed, "can_rollback": not reasons,
            "rollback_blocked_reasons": reasons}


def rollback_package(s, p, ident, expected, reason):
    if not reason.strip():
        raise ValueError("되돌리기 사유가 필요합니다.")
    _locked(s)
    package = _get(s, ident)
    _checked(package, expected)
    reviewer = _current(s, p)
    _permissions(reviewer, package.document, review=True)
    receipt = package.receipt or {}
    if reviewer.id == receipt.get("applied_by_id"):
        raise Forbidden("적용한 사람과 다른 검토자가 되돌려야 합니다.")
    if package.status == "rolled_back":
        return to_dict(package, p)
    if package.status != "applied":
        raise Conflict("적용된 묶음만 되돌릴 수 있습니다.")
    items = _rollback_items(s, p, package)
    for entry, item in zip(package.document["entries"], items):
        if _snapshot(s, entry) != item["after"]:
            raise Conflict("적용 이후 콘텐츠가 변경되어 자동으로 되돌릴 수 없습니다.")
    restored = []
    for entry, item in zip(package.document["entries"], items):
        before = item["before"]
        binding = s.get(ContentBinding, (entry["kind"], entry["source_id"]))
        if entry["kind"] == "sigma":
            d = s.get(detection.Detection, item["target_id"])
            prior = before["live"] if before["binding"] and before["binding"]["payload_digest"] else None
            gov.package_restore(s, principal_of(reviewer), d, prior, reason, package.id)
        else:
            rows = s.scalars(select(library.ParserDefinition).where(library.ParserDefinition.slug == item["target_id"])).all()
            for row in rows:
                if row.status == "active":
                    row.status = "superseded" if before["binding"] and before["binding"]["payload_digest"] else "disabled"
            if before["binding"] and before["binding"]["payload_digest"]:
                previous = [x for x in before["live"]["versions"] if x["status"] == "active"]
                if len(previous) != 1:
                    raise Conflict("직전 공용 파서를 확인하지 못했습니다.")
                chosen = previous[0]
                row = s.get(library.ParserDefinition, chosen["id"])
                if row is None or row.reviewed_by is None or row.reviewed_by == row.created_by or row.spec != chosen["spec"] or row.name != chosen["name"]:
                    raise Conflict("직전 승인 파서가 변경되었습니다.")
                row.status = "active"
        if before["binding"]:
            binding.source_version = before["binding"]["source_version"]
            binding.payload_digest = before["binding"]["payload_digest"]
        else:
            # Keep the source binding as a tombstone: later revisions cannot silently reuse an old applied source.
            binding.payload_digest = ""
        s.flush()
        restored.append({"kind": entry["kind"], "source_id": entry["source_id"], "state": _snapshot(s, entry)})
    package.status = "rolled_back"
    package.receipt = {**receipt, "rollback": {"by": reviewer.username, "by_id": reviewer.id, "at": utcnow().isoformat(),
                                             "reason": reason, "restored": restored}}
    audit.record(s, "content_package.rollback", actor_id=reviewer.id, actor_name=reviewer.username, target_type="content_package",
                 target_id=package.id, detail={"digest": package.digest, "reason": reason, "targets": [i["target_id"] for i in items]})
    return to_dict(package, p)
