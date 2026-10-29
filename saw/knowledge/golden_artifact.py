"""Deterministic bounded release archives, with private mapping kept outside the ZIP."""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path

from saw.knowledge.golden_conversion import conversion_record
from saw.knowledge.golden_projection import (
    MAX_BLOB,
    MAX_CASE,
    MAX_TOTAL,
    GoldenBuildFailure,
    IdentityMapper,
    canonical_bytes,
    check_cancel,
    digest,
    input_blob_graph,
)

MAX_FILES = 1024
_ALLOWED = re.compile(r"^(README\.md|FIELD-DICTIONARY\.md|METHODOLOGY\.md|DATASET\.json|LIMITS\.md|manifest\.json|"
                      r"(schema|evidence|answers)/[A-Za-z0-9_.-]+\.json|(input|answers|conversion)/[A-Za-z0-9_.-]+\.jsonl)$")
TRUTH = {"expected_match", "expected_no_match", "unlabeled"}
JUDGEMENTS = {"attack", "attempt", "approved_activity", "normal", "false_positive", "undetermined", "insufficient_data"}
NUMERIC_KEYS = {"value", "numerator", "denominator", "count", "matched_count", "sampled_count", "limit",
    "window_seconds", "threshold", "peak", "scanned", "processed", "deduplicated", "timestamp_ties",
    "missing_timestamp", "missing_src_ip", "missing_service", "field_denominator", "producer_observation_denominator",
    "unique_paths", "total", "duration_seconds", "src_to_dst_bytes", "dst_to_src_bytes"}
STATES = {"observed", "not_collected", "recorded_empty", "unknown_semantics", "invalid", "complete", "partial",
          "unavailable", "unknown", "insufficient_data", "not_applicable", "truncated"}
UNITS = {"count", "records", "sessions", "requests", "bytes", "packets", "seconds", "milliseconds", "ratio", "percent", "bps", "pps", "rps", ""}


def _time(value):
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
        if parsed.tzinfo is None:
            raise ValueError
        return parsed.isoformat()
    except (ValueError, TypeError):
        raise ValueError("golden_invalid_timestamp") from None


def _numeric(value):
    return value is None or type(value) in {int, float, bool}


def _metrics(rows, mapper, scope):
    out = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        safe = {k:v for k,v in row.items() if k in NUMERIC_KEYS and _numeric(v)}
        if row.get("id") is not None:
            safe["id"] = mapper.token("metric", row["id"], scope)
        if row.get("data_state", row.get("state")) in STATES:
            safe["data_state"] = row.get("data_state", row.get("state"))
        if row.get("unit") in UNITS:
            safe["unit"] = row["unit"]
        if safe:
            out.append(safe)
    return out


def _blob(blob, mapper, scope, resolve):
    schema = blob.get("schema")
    if schema in {"saw.golden.event.v1", "saw.golden.event.v2"}:
        result = {"schema": "saw.golden.event.v2", "event": mapper.event(blob["event"])}
        if blob.get("known_at"):
            result["known_at"] = _time(blob["known_at"])
        return result
    if schema not in {"saw.golden.observation.v1", "saw.golden.behavior-observation.v1"}:
        raise ValueError("golden_blob_schema_unsupported")
    result = {"schema": schema, "limits": ["unapproved_free_text_omitted", "source_metadata_kept_private"]}
    for key in ("captured_at", "known_at", "as_of"):
        if blob.get(key):
            result[key] = _time(blob[key])
    result["facts"] = _metrics(blob.get("facts", []), mapper, scope)
    observations = blob.get("observations", {})
    result["metrics"] = _metrics(observations.get("metrics", []) if isinstance(observations, dict) else [], mapper, scope)
    summary = observations.get("summary", {}) if isinstance(observations, dict) else {}
    result["summary"] = {k:v for k,v in summary.items() if k in NUMERIC_KEYS and _numeric(v)}
    result["queries"] = []
    for query in blob.get("queries", []):
        safe = {k:v for k,v in query.items() if k in NUMERIC_KEYS and _numeric(v)}
        if query.get("id") is not None:
            safe["id"] = mapper.token("query", query["id"], scope)
        if query.get("data_state") in STATES:
            safe["data_state"] = query["data_state"]
        if type(query.get("truncated")) is bool:
            safe["truncated"] = query["truncated"]
        if query.get("executed_at"):
            safe["executed_at"] = _time(query["executed_at"])
        result["queries"].append(safe)
    # Only known blob edges are exported; source manifests and raw query selectors stay private.
    refs = []
    for fact in blob.get("facts", []):
        for ref in fact.get("evidence_refs", []) if isinstance(fact, dict) else []:
            if isinstance(ref, str) and re.fullmatch("[a-f0-9]{64}", ref):
                refs.append(resolve(ref))
    if refs:
        result["evidence_refs"] = sorted(set(refs))
    return result


def _answers(value, mapper, case_id, inv_id, resolve, events, exported_event_ids):
    result = {"schema": "saw.golden.answers.v2", "limits": ["unapproved_free_text_omitted"]}
    detection = value.get("detection_truth", {})
    units = []
    for unit in detection.get("units", []):
        if unit.get("unit_kind") not in {"event", "window", "entity", "sequence"} or unit.get("detection_truth") not in TRUTH or unit.get("investigation_truth") not in JUDGEMENTS:
            raise ValueError("golden_answer_schema_invalid")
        event_ids = [mapper.require_event_id(ident, inv_id, exported_event_ids) for ident in unit.get("event_ids", [])]
        item = {"unit_id": mapper.token("unit", [unit.get("case_version_id"), unit.get("unit_id")], (case_id,)),
                "unit_kind": unit["unit_kind"], "detection_truth": unit["detection_truth"],
                "investigation_truth": unit["investigation_truth"],
                "event_ids": event_ids,
                "time": {k:_time(v) for k,v in (unit.get("time") or {}).items() if k in {"start", "end"}},
                "filters": mapper.filters(unit.get("filters", []), events),
                "limits": ["unapproved_free_text_omitted"]}
        units.append(item)
    result["detection_truth"] = {"status": "available" if units else "not_labeled", "units": units}
    investigation = value.get("investigation_truth", {})
    result["investigation_truth"] = {k:v for k,v in investigation.items()
        if k in {"behavior", "impact"} and v in JUDGEMENTS | {"unknown", "observed", "not_established"}}
    result["investigation_truth"]["evidence_refs"] = [
        resolve(v) for v in investigation.get("evidence_refs", []) if isinstance(v, str) and re.fullmatch("[a-f0-9]{64}", v)]
    result["investigation_truth"]["followups"] = []
    for record in investigation.get("followups", []):
        check_cancel(mapper._cancelled)
        if not isinstance(record, dict) or not isinstance(record.get("payload"), dict):
            result["investigation_truth"]["followups"].append({"state": "legacy_text_omitted"})
            continue
        payload = record["payload"]
        if digest(payload) != record.get("payload_sha256") or payload.get("status") not in {
                "open", "replied", "verified", "closed_with_limits", "cancelled"}:
            raise ValueError("golden_followup_record_invalid")
        item = {"followup_id": mapper.token("followup", record.get("followup_id"), (case_id,)),
            "version_id": mapper.token("followup_version", record.get("version_id"), (case_id,)),
            "revision": record.get("revision"), "status": payload["status"],
            "text_state": "unapproved_free_text_omitted"}
        if type(item["revision"]) is not int or item["revision"] < 1:
            raise ValueError("golden_followup_revision_invalid")
        if payload.get("priority") in {"low", "normal", "high", "urgent"}:
            item["priority"] = payload["priority"]
        if payload.get("due_at"):
            item["due_at"] = _time(payload["due_at"])
        for key, time_key in (("reply", "received_at"), ("verification", "verified_at")):
            block = payload.get(key)
            if block is None:
                item[key] = None
                continue
            if not isinstance(block, dict):
                raise ValueError("golden_followup_record_invalid")  # noqa: TRY004 - consistent public validation errors
            safe = {"evidence_state": "kept_private", "evidence_count": len(block.get("evidence", [])),
                    "text_state": "unapproved_free_text_omitted"}
            if block.get(time_key):
                safe[time_key] = _time(block[time_key])
            if key == "verification":
                if block.get("outcome") not in {"confirmed", "not_confirmed", "insufficient_data"}:
                    raise ValueError("golden_followup_outcome_invalid")
                safe["outcome"] = block["outcome"]
            item[key] = safe
        item["sha256"] = digest(item)
        result["investigation_truth"]["followups"].append(item)
    result["later_confirmed_facts"] = []
    for fact in value.get("later_confirmed_facts", []):
        refs = [resolve(v) for v in fact.get("evidence_refs", [])]
        if not refs or not fact.get("confirmed_at") or not fact.get("known_at"):
            raise ValueError("golden_later_fact_evidence_missing")
        result["later_confirmed_facts"].append({"text_state": "unapproved_free_text_omitted",
            "evidence_refs": refs, "confirmed_at": _time(fact["confirmed_at"]), "known_at": _time(fact["known_at"])})
    return result



def _legacy_answers(value, resolve):
    """Preserve approved v1 categorical answers and edges without resealing stored v1."""
    judgement = value.get("judgement") or {}
    behavior = judgement.get("behavior")
    if behavior not in JUDGEMENTS | {"unknown"}:
        raise ValueError("golden_legacy_judgement_unsupported")
    result = {"schema": "saw.golden.answers.v1",
        "judgement": {"behavior": behavior,
            "evidence_refs": [resolve(ref) for ref in judgement.get("evidence_refs", [])],
            "impact_state": "unapproved_free_text_omitted", "reason_state": "unapproved_free_text_omitted"},
        "required_facts_actions": [], "followups": [],
        "limits": ["unapproved_free_text_omitted", "original_source_metadata_kept_private"],
        "forbidden_claims_state": "unapproved_free_text_omitted",
        "no_followups_reason_state": "unapproved_free_text_omitted",
        "analyst_records_state": "unapproved_free_text_omitted"}
    for fact in value.get("required_facts_actions", []):
        if not isinstance(fact, dict):
            raise ValueError("golden_legacy_fact_unsupported")  # noqa: TRY004
        result["required_facts_actions"].append({"text_state": "unapproved_free_text_omitted",
            "evidence_refs": [resolve(ref) for ref in fact.get("evidence_refs", [])]})
    for follow in value.get("followups", []):
        item = {"text_state": "unapproved_free_text_omitted"}
        if isinstance(follow, dict):
            if follow.get("priority") in {"low", "normal", "high", "urgent"}:
                item["priority"] = follow["priority"]
            item["due_at"] = _time(follow.get("due_at"))
            for key in ("needed_data", "items"):
                values = follow.get(key, [])
                if not isinstance(values, list):
                    raise ValueError("golden_legacy_followup_unsupported")  # noqa: TRY004
                item[key + "_count"] = len(values)
        elif not isinstance(follow, str):
            raise ValueError("golden_legacy_followup_unsupported")  # noqa: TRY004
        result["followups"].append(item)
    return result

def build_release(inputs, path, *, cancelled):
    """Write a private atomic file; publication and authorization remain the caller's job."""
    check_cancel(cancelled)
    request, examples = inputs["request"], inputs["examples"]
    full = request["applicability_request"]["mode"] == "full_recalculation"
    holdout = request["split"] == "holdout"
    mapper = IdentityMapper(inputs["private_context"]["mapping_seed"], cancelled=cancelled)
    captures = inputs.get("captures", {})
    retained = sum(c.size_bytes for c in captures.values())
    if retained > MAX_TOTAL:
        raise ValueError("golden_total_capture_byte_limit")
    registration = []
    for ex in examples:
        check_cancel(cancelled)
        registration_blobs = input_blob_graph(ex["payload"]["input"], ex["blobs"]) if holdout else ex["blobs"]
        for blob in registration_blobs.values():
            if blob.get("schema") in {"saw.golden.event.v1", "saw.golden.event.v2"}:
                registration.append(blob["event"])
        if full:
            capture = captures.get(ex["version_id"])
            if capture is None or capture.status != "passed":
                raise GoldenBuildFailure(capture.reasons if capture is not None else ["complete_capture_missing"])
            for part in capture.original_parts:
                registration.extend(json.loads(line) for line in part.splitlines() if line)
    mapper.register_events(registration)
    del registration
    files, total, validations, cases = {}, 0, [], []

    def add(name, data, media="application/json"):
        nonlocal total
        check_cancel(cancelled)
        if not _ALLOWED.fullmatch(name) or name in files:
            raise ValueError("golden_archive_path_invalid")
        if len(files) + 1 > MAX_FILES or total + len(data) > MAX_TOTAL:
            raise ValueError("golden_archive_limit")
        data.decode("utf-8")
        files[name] = (data, media)
        total += len(data)

    add("README.md", b"# SAW Golden release\nFrozen observations with explicit scope and limitations. Pseudonymization does not grant redistribution rights.\n", "text/markdown")
    add("FIELD-DICTIONARY.md", b"# Fields\nrecord counts differ from session counts. Byte directions follow the producer observation. Unknown values remain null. Identifiers are release-scoped.\n", "text/markdown")
    add("METHODOLOGY.md", b"# Methodology\nSnapshot-only inputs. No model execution or tool trace is fabricated. Conversion target names do not assert model compatibility.\n", "text/markdown")
    add("LIMITS.md", b"# Limits\nUnapproved free text and original source metadata are omitted. Representative inputs support interpretation only. Whole-scope claims require separate server validation.\n", "text/markdown")
    identity_key = "example_id" if request["projection"] == "v1" else "case_id"
    add("schema/input.json", canonical_bytes({"$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object", "required": ["schema", identity_key, "retrieval", "evidence", "observations"],
        "properties": {identity_key: {"type": "string"}, "retrieval": {"const": "snapshot_only"},
            "evidence": {"type": "array"}, "observations": {"type": "array"}}}))
    for ex in examples:
        check_cancel(cancelled)
        case_id = mapper.token("case", ex["version_id"])
        payload, blobs = ex["payload"], ex["blobs"]
        selected = input_blob_graph(payload["input"], blobs)
        rewritten, busy, rewritten_values = {}, set(), {}
        def resolve(ident, rewritten=rewritten, busy=busy, blobs=blobs, case_id=case_id, rewritten_values=rewritten_values):
            if ident in rewritten:
                return rewritten[ident]
            if ident in busy or ident not in blobs:
                raise ValueError("golden_reference_invalid")
            busy.add(ident)
            value = _blob(blobs[ident], mapper, (case_id,), resolve)
            data = canonical_bytes(value, MAX_BLOB, cancelled=cancelled)
            transformed_sha = hashlib.sha256(data).hexdigest()
            rewritten[ident] = transformed_sha
            rewritten_values[transformed_sha] = value
            busy.remove(ident)
            filename = "evidence/" + transformed_sha + ".json"
            if filename not in files:
                add(filename, data)
            return transformed_sha
        for ident in selected:
            resolve(ident)
        inp = payload["input"]
        result_input = {"schema": "saw.golden.agent-input." + request["projection"],
            "case_id": case_id, "retrieval": "snapshot_only",
            "observations": [{"sha256": resolve(ident), "path": "evidence/" + resolve(ident) + ".json"}
                for ident in inp.get("observations", [])],
            "evidence": [{"sha256": resolve(ident), "path": "evidence/" + resolve(ident) + ".json"}
                for ident in inp.get("evidence", [])],
            "applicability": {"mode": "full_recalculation" if full else "interpretation_only"},
            "limits": ["unapproved_free_text_omitted", "original_source_metadata_kept_private"]}
        original_events = [blob["event"] for blob in blobs.values()
            if blob.get("schema") in {"saw.golden.event.v1", "saw.golden.event.v2"}]
        if request["projection"] == "v2":
            transformed_contexts = [value["event"].get("ext", {}).get("observation", {}).get("context", {})
                for value in rewritten_values.values() if "event" in value]
            result_input["context"] = {"identity_scope": "org_network",
                "org_units": sorted({c["org_unit_id"] for c in transformed_contexts if c.get("org_unit_id")}),
                "devices": sorted({c["device_id"] for c in transformed_contexts if c.get("device_id")}),
                "networks": sorted({c["network"] for c in transformed_contexts if c.get("network")}),
                "data_meanings": {"capture": "complete_scope" if full else "representative"}}
            versions = inp.get("versions", {})
            result_input["versions"] = {"normalization": versions.get("normalization")
                if versions.get("normalization") in {"saw.observation/1"} else None,
                "engines": [{"id": e["id"], "version": e["version"]} for e in versions.get("engines", [])
                    if e.get("id") in {"fw.observation", "waf.observation", "ips.observation", "ddos.observation", "ndr.observation"}
                    and e.get("version") in {"firewall-observation/1", "device-observation/1"}]}
            for key in ("analysis_run", "methodology", "rule_policy_refs", "parsers"):
                refs = versions.get(key)
                def opaque_ref(ref, key=key, case_id=case_id):
                    if not isinstance(ref, dict) or not ref.get("id"):
                        return None
                    safe = {"id": mapper.token("version", [key, ref["id"]], (case_id,))}
                    return {**safe, "sha256": digest(safe)}
                result_input["versions"][key] = [opaque_ref(r) for r in refs if opaque_ref(r)] if isinstance(refs, list) else opaque_ref(refs)
        if inp.get("cutoff"):
            result_input["cutoff"] = {k:_time(v) for k,v in inp["cutoff"].items() if k in {"as_of", "captured_at"}}
        if request["projection"] == "v1":
            result_input["example_id"] = result_input.pop("case_id")
            # The public projection has its own version; source revision history stays private.
            result_input["version"] = 1
            methodology = payload.get("methodology_version")
            result_input["methodology_version"] = methodology if methodology in {
                "soc-guidance/1.0", "saw.mixed-observations/1"} else None
            result_input["as_of"] = _time(inp.get("cutoff", {}).get("as_of", payload.get("as_of")))
            result_input["observations"] = [rewritten_values[resolve(ident)] for ident in inp.get("observations", [])]
            result_input["limits"].extend(["legacy_context_not_provided", "source_revision_history_kept_private"])
        exported_event_ids = {v["event"]["event_id"] for v in rewritten_values.values() if "event" in v}
        if full:
            from saw.knowledge.golden_capture import verify_complete_scope
            capture = captures[ex["version_id"]]
            parts, part = [], bytearray()
            for source in capture.original_parts:
                for line in source.splitlines():
                    check_cancel(cancelled)
                    if line:
                        encoded = canonical_bytes(mapper.event(json.loads(line)), MAX_BLOB) + b"\n"
                        if part and len(part) + len(encoded) > MAX_BLOB:
                            parts.append(bytes(part))
                            part.clear()
                        part.extend(encoded)
            if part:
                parts.append(bytes(part))
            exported_event_ids.update(json.loads(line)["event_id"] for part_bytes in parts for line in part_bytes.splitlines())
            if sum(map(len, parts)) > MAX_CASE:
                raise ValueError("golden_transformed_case_byte_limit")
            # Reverse maps are private process data, never capture claims from HTTP.
            capture.identity_mapper = mapper
            validation = verify_complete_scope(capture, capture.original_parts, parts, cancelled=cancelled)
            if validation["status"] != "passed":
                raise GoldenBuildFailure(validation["reasons"])
            validation["id"] = mapper.token("validation", ex["version_id"])
            validations.append(validation)
            from saw.knowledge.golden_capture import _policy
            policy = {k:v for k,v in _policy(capture.scope)["values"].items() if k != "enabled"}
            result_input["versions"]["normalization"] = capture.scope["analysis_run"]["input_manifest"]["normalization_version"]
            result_input["calculation"] = {"engine": {"id": "fw.observation", "version": "firewall-observation/1"},
                "policy": policy, "policy_sha256": digest(policy),
                "semantics": {"time_transform": "none", "window": "fixed_half_open_epoch_buckets"},
                "input_count": capture.native_count}
            result_input["parts"] = []
            for number, data in enumerate(parts):
                name = "input/" + case_id + "-part-" + str(number + 1).zfill(4) + ".jsonl"
                add(name, data, "application/x-ndjson")
                result_input["parts"].append({"path": name, "sha256": hashlib.sha256(data).hexdigest(),
                    "size_bytes": len(data), "records": len(data.splitlines())})
        input_bytes = canonical_bytes(result_input, MAX_CASE, cancelled=cancelled)
        add("input/" + case_id + ".jsonl", input_bytes + b"\n", "application/x-ndjson")
        input_hash = digest({"input": result_input, "blobs": rewritten_values})
        cases.append({"case_id": case_id, "input_sha256": input_hash})
        if not holdout:
            if ex["schema_version"] == "saw.golden.v1":
                answers = _legacy_answers(payload["answers"], resolve)
            elif ex["schema_version"] == "saw.golden.v2":
                answers = _answers(payload["answers"], mapper, case_id, payload.get("source_investigation_id") or
                    next(iter(ex.get("source_investigation_ids", [])), ""), resolve, original_events, exported_event_ids)
            else:
                raise ValueError("golden_answer_schema_unsupported")
            add("answers/" + case_id + ".json", canonical_bytes(answers, MAX_CASE))
            converted = conversion_record(inputs["profiles"]["model_conversion"]["implementation"], result_input, answers)
            if converted is not None:
                add("conversion/" + case_id + ".jsonl", canonical_bytes(converted, MAX_CASE) + b"\n", "application/x-ndjson")
    add("DATASET.json", canonical_bytes({"schema": "saw.golden.dataset." + request["projection"],
        "split": request["split"], "artifact_kind": request["artifact_kind"], "cases": cases,
        "projection": request["projection"], "pseudonymization": "scoped-identities/1",
        "conversion": inputs["profiles"]["model_conversion"]["implementation"],
        "applicability": {"mode": "full_recalculation" if full else "interpretation_only"}}))
    entries = [{"path": name, "media_type": media, "size_bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest()} for name, (data, media) in sorted(files.items())]
    manifest = {"schema": "saw.golden.manifest.v2", "files": entries, "uncompressed_bytes": total, "file_count": len(entries)}
    add("manifest.json", canonical_bytes(manifest))
    # Complete all fallible private outputs before replacing a previously built artifact.
    mapping = mapper.private_content()
    mapping_bytes = canonical_bytes(mapping, cancelled=cancelled)
    refs = [{"id": v["id"], "sha256": digest(v)} for v in validations]
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(prefix=".golden-", suffix=".tmp", dir=target.parent, delete=False) as stream:
            temporary = Path(stream.name)
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
            for name, (data, _) in sorted(files.items()):
                check_cancel(cancelled)
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = 0o100600 << 16
                info.compress_type = zipfile.ZIP_STORED
                with archive.open(info, "w") as destination:
                    for offset in range(0, len(data), 65536):
                        check_cancel(cancelled)
                        destination.write(data[offset:offset + 65536])
                if temporary.stat().st_size > MAX_TOTAL:
                    raise ValueError("golden_archive_byte_limit")
        if temporary.stat().st_size > MAX_TOTAL:
            raise ValueError("golden_archive_byte_limit")
        digest_file = hashlib.sha256()
        with temporary.open("rb") as stream:
            while chunk := stream.read(65536):
                check_cancel(cancelled)
                digest_file.update(chunk)
        check_cancel(cancelled)
        size = temporary.stat().st_size
        os.replace(temporary, target)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return {"manifest": manifest, "artifact_sha256": digest_file.hexdigest(), "size_bytes": size,
        "validation": {"passed": True, "checks": [{"code": "schema_references_leakage", "state": "passed",
                                                  "detail": "Validated allowlisted transformed graph."}]},
        "private_mapping": {"content": mapping, "sha256": hashlib.sha256(mapping_bytes).hexdigest(), "size_bytes": len(mapping_bytes)},
        "validations": validations, "applicability": {"mode": "full_recalculation" if full else "interpretation_only",
            "reasons": [] if full else ["representative_input"], "validations": refs}}
