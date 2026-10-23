"""Pure Golden release behavior, using synthetic observations and actual FW calculation."""
import hashlib
import importlib
import importlib.util
import json
import zipfile
from copy import deepcopy

import pytest


def module(name):
    name = "saw.knowledge." + name
    assert importlib.util.find_spec(name), name + " is not implemented"
    return importlib.import_module(name)

def raw(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()

def sha(value):
    return hashlib.sha256(raw(value)).hexdigest()

def profiles():
    return {
        "pseudonymization": {"id": "pseudo", "implementation": "scoped-identities/1", "payload": {
            "schema": "saw.pseudonymization-profile.v1", "version": 1, "identity_scope": "org_network",
            "identity_mapping": "scoped_injective/1", "time_transform": "none", "free_text": "drop_unapproved",
            "metadata": "allowlist_v2"}},
        "model_conversion": {"id": "native", "implementation": "golden-native/1", "payload": {
            "schema": "saw.model-conversion-profile.v1", "version": 1,
            "target": {"name": "golden-native", "version": "1"}, "field_mapping": "native-input-and-answers/1",
            "serialization_contract": "native-files/1", "validation_suite": "saw-release-reference-leakage/1"}}
    }

def sealed_profiles():
    values = profiles()
    for item in values.values():
        item["sha256"] = sha(item["payload"])
    return values

def event(eid="original-event-1", org="original-org", network="original-net", **updates):
    counters = {key: {"value": value, "state": "observed", "unit": "bytes", "counter_mode": "cumulative",
                      "raw_value": "SECRET RAW VALUE", "source_field": "SECRET COLUMN"}
                for key, value in (("src_to_dst_bytes", 300), ("dst_to_src_bytes", 1200))}
    value = {"event_id": eid, "investigation_id": "original-inv", "evidence_id": "original-evidence",
             "file_id": "original-file", "timestamp": "2026-10-20T00:00:00+00:00", "src_ip": "10.1.1.1",
             "dst_ip": "10.2.2.2", "src_port": 1000, "dst_port": 443, "protocol": "tcp",
             "data_source": "firewall", "product": "csv", "parser": "csv/1",
             "raw_ref": {"object_key": "SECRET OBJECT"}, "raw_event": "SECRET RAW EVENT",
             "ext": {"csv": {"inside_zone": "SECRET ZONE"}, "observation": {
                 "producer": "saw", "version": "connection-observation/1",
                 "context": {"org_unit_id": org, "network": network, "device_id": "original-fw",
                             "device_profile_version_id": "original-profile", "virtual_domain": "original-domain",
                             "resolved": True, "row_attribution": {"raw_value": "SECRET ATTRIBUTION"}},
                 "counters": counters, "session_id": "original-session", "record_kind": "session_end",
                 "action": "allowed", "timestamp": "2026-10-20T00:00:00+00:00",
                 "start_time": "2026-10-20T00:00:00+00:00", "duration_seconds": 1,
                 "time_profile": {"verified": True, "role": "occurred", "precision": "seconds", "basis": "SECRET BASIS"},
                 "timestamp_precision": "seconds", "quality": [], "collection": {"scope": "full"}}}}
    value.update(updates)
    return value

def example(split="train", eid="case-original", events=None):
    events = events or [event()]
    blobs = {sha({"schema": "saw.golden.event.v2", "event": e}):
             {"schema": "saw.golden.event.v2", "event": e} for e in events}
    inp = {"schema": "saw.golden.agent-input.v2", "observations": [], "evidence": list(blobs),
           "retrieval": "snapshot_only", "cutoff": {"as_of": "2026-10-21T00:00:00+00:00",
           "known_at_basis": "recorded_capture", "captured_at": "2026-10-21T00:00:00+00:00"},
           "applicability": {"mode": "interpretation_only", "reasons": ["representative_input"]}}
    answers = {"schema": "saw.golden.answers.v2", "detection_truth": {
        "status": "available", "case_versions": [], "units": [{
            "case_version_id": "original-truth", "unit_id": "window", "unit_kind": "window",
            "event_ids": [], "filters": [], "time": None, "detection_truth": "expected_match",
            "investigation_truth": "attack", "basis": "SECRET ANSWER"}]},
        "investigation_truth": {"reason": "SECRET ANSWER"}, "later_confirmed_facts": []}
    payload = {"input": inp, "answers": answers, "metadata": {"title": "SECRET ANSWER TITLE"},
               "manifest": [{"sha256": k, "size_bytes": len(raw(v)), "kind": "event"} for k, v in blobs.items()]}
    return {"version_id": eid, "content_sha256": sha(payload), "input_sha256": sha({"input": inp, "blobs": blobs}),
            "schema_version": "saw.golden.v2", "split": split, "payload": payload, "blobs": blobs,
            "source_investigation_ids": ["original-inv"], "contributor_ids": ["original-author"], "complete_scope": None}

def request(split="train", full=False):
    return {"schema_version": "saw.golden.release.v2", "projection": "v2", "split": split,
            "artifact_kind": "holdout_input" if split == "holdout" else split,
            "applicability_request": {"mode": "full_recalculation" if full else "interpretation_only"},
            "purpose": {"train": "external_training", "dev": "external_development", "holdout": "external_evaluation"}[split]}

def prepare(examples=None, split="train", full=False, selected_profiles=None):
    return module("golden_projection").prepare_release_inputs(request(split, full),
        examples or [example(split)], selected_profiles or sealed_profiles(),
        cancelled=lambda: False, private_context={"mapping_seed": "12" * 32,
        "release_id": "release-private", "created_at": "2026-10-22T00:00:00+00:00"})

def test_projection_preserves_semantics_and_drops_raw_free_text():
    projected = module("golden_projection").project_event_v2(event())
    text = raw(projected).decode()
    assert "SECRET RAW" not in text and "SECRET COLUMN" not in text and "SECRET ATTRIBUTION" not in text
    assert "SECRET BASIS" not in text and "raw_ref" not in projected
    assert projected["ext"]["observation"]["counters"]["src_to_dst_bytes"]["value"] == 300
    assert projected["ext"]["observation"]["context"]["network"] == "original-net"

@pytest.mark.parametrize("mutation", [
    lambda p: p.update(version=True), lambda p: p.update(expression="__import__('os')"),
    lambda p: p.update(time_transform="shift"), lambda p: p.update(identity_scope="global"),
])
def test_profile_rejects_executable_or_unsupported_variants(mutation):
    p = profiles()["pseudonymization"]["payload"]
    mutation(p)
    with pytest.raises(ValueError):
        module("golden_projection").validate_profile("pseudonymization", "scoped-identities/1", p)

def test_input_hash_is_answer_independent_and_requires_references():
    m = module("golden_projection")
    ex = example("holdout")
    before = m.input_graph_sha256(ex["payload"]["input"], ex["blobs"])
    ex["payload"]["answers"]["detection_truth"]["units"][0]["detection_truth"] = "expected_no_match"
    assert m.input_graph_sha256(ex["payload"]["input"], ex["blobs"]) == before == ex["input_sha256"]
    ex["blobs"].clear()
    with pytest.raises(ValueError, match="reference"):
        m.input_graph_sha256(ex["payload"]["input"], ex["blobs"])

def test_prepare_rejects_tampered_seal_and_missing_secret_seed():
    m = module("golden_projection")
    ex = example()
    ex["payload"]["answers"]["investigation_truth"]["reason"] = "tampered"
    with pytest.raises(ValueError, match="seal"):
        prepare([ex])
    with pytest.raises(ValueError, match="private_context"):
        m.prepare_release_inputs(request(), [example()], sealed_profiles(),
            cancelled=lambda: False, private_context={"release_id": "x"})

def test_holdout_zip_is_answer_free_and_deterministic(tmp_path):
    builder = module("golden_artifact")
    inputs = prepare(split="holdout")
    first = builder.build_release(inputs, tmp_path / "first.zip", cancelled=lambda: False)
    second = builder.build_release(inputs, tmp_path / "second.zip", cancelled=lambda: False)
    assert (tmp_path / "first.zip").read_bytes() == (tmp_path / "second.zip").read_bytes()
    assert first["artifact_sha256"] == second["artifact_sha256"]
    with zipfile.ZipFile(tmp_path / "first.zip") as archive:
        names = archive.namelist()
        assert names == sorted(names)
        assert {"README.md", "FIELD-DICTIONARY.md", "METHODOLOGY.md", "DATASET.json", "LIMITS.md", "manifest.json"} <= set(names)
        all_text = "\n".join(archive.read(n).decode() for n in names)
        ex = inputs["examples"][0]
        for forbidden in ("SECRET", "original-", "expected_match", "attack", ex["content_sha256"], "12" * 32):
            assert forbidden not in all_text
        assert not any("answer" in n.lower() for n in names)
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest == first["manifest"]
        assert {f["path"] for f in manifest["files"]} == set(names) - {"manifest.json"}
        assert manifest["file_count"] == len(names) - 1
        for entry in manifest["files"]:
            data = archive.read(entry["path"])
            assert entry["size_bytes"] == len(data)
            assert entry["sha256"] == hashlib.sha256(data).hexdigest()
        for info in archive.infolist():
            assert info.date_time == (1980, 1, 1, 0, 0, 0)
            assert not (info.external_attr >> 16) & 0o111
    assert "original-" in raw(first["private_mapping"]["content"]).decode()

@pytest.mark.parametrize("implementation,target,mapping", [
    ("input-output-jsonl/1", "input-output", "input-output/1"),
    ("messages-jsonl/1", "messages", "messages/1"),
])
def test_conversion_has_exact_roles_and_no_fake_tool_calls(tmp_path, implementation, target, mapping):
    p = sealed_profiles()
    item = p["model_conversion"]
    item.update(implementation=implementation)
    item["payload"].update(target={"name": target, "version": "1"},
        field_mapping=mapping, serialization_contract="jsonl-utf8/1")
    item["sha256"] = sha(item["payload"])
    inputs = prepare(selected_profiles=p)
    module("golden_artifact").build_release(inputs, tmp_path / "release.zip", cancelled=lambda: False)
    with zipfile.ZipFile(tmp_path / "release.zip") as archive:
        name = next(n for n in archive.namelist() if n.startswith("conversion/"))
        record = json.loads(archive.read(name))
    if target == "messages":
        assert set(record) == {"messages"}
        assert [m["role"] for m in record["messages"]] == ["system", "user", "assistant"]
        assert all(set(m) == {"role", "content"} for m in record["messages"])
    else:
        assert set(record) == {"input", "output"}
    with pytest.raises(ValueError, match="holdout"):
        prepare(split="holdout", selected_profiles=p)

def test_cancellation_preserves_existing_destination(tmp_path):
    target = tmp_path / "release.zip"
    target.write_bytes(b"existing artifact")
    with pytest.raises(Exception, match="cancel"):
        module("golden_artifact").build_release(prepare(), target, cancelled=lambda: True)
    assert target.read_bytes() == b"existing artifact"

def test_release_scoped_identities_do_not_merge_same_ip_across_networks(tmp_path):
    inputs = prepare([example(events=[event("e1"), event("e2", network="different-net")])])
    module("golden_artifact").build_release(inputs, tmp_path / "release.zip", cancelled=lambda: False)
    with zipfile.ZipFile(tmp_path / "release.zip") as archive:
        events = [json.loads(archive.read(n))["event"] for n in archive.namelist() if n.startswith("evidence/")]
    assert len(events) == 2
    assert events[0]["src_ip"] != events[1]["src_ip"]
    assert all(e["src_ip"] != "10.1.1.1" for e in events)

def test_evaluator_jsonl_is_separate_and_preserves_exact_answers():
    ex = example("holdout")
    result = module("golden_conversion").evaluator_jsonl([ex])
    row = json.loads(result)
    assert row["answers"] == ex["payload"]["answers"]
    assert row["example_id"] == ex["version_id"]

def complete_example(scope, events):
    ex = example(events=events)
    ex["source_investigation_ids"] = sorted({e["investigation_id"] for e in events})
    ex["payload"]["answers"]["detection_truth"]["units"] = deepcopy(scope["truth_units"])
    ex["payload"]["input"]["versions"] = {"analysis_run": {"id": scope["analysis_run"]["id"],
        "sha256": scope["analysis_run"]["input_sha256"]}, "normalization": "saw.observation/1",
        "engines": [{"id": "fw.observation", "version": "firewall-observation/1"}]}
    ex["content_sha256"] = sha(ex["payload"])
    ex["input_sha256"] = sha({"input": ex["payload"]["input"], "blobs": ex["blobs"]})
    scope["golden_ref"] = {"id": ex["version_id"], "content_sha256": ex["content_sha256"]}
    ex["complete_scope"] = scope
    return ex


def full_fixture(tmp_path, events=None, store=None):
    from saw.detection.specs import get_spec
    from saw.observation.firewall import DEFAULT_POLICY, analyze_firewall
    from saw.storage.eventstore import SQLiteEventStore
    events = deepcopy(events or [event()])
    investigation_id = "original-inv"
    if store is not None:
        from uuid import uuid4

        # Shared native indices survive SQL fixture resets, and their document
        # keys are event IDs alone. Isolate both IDs without deleting other cases.
        investigation_id = "fixture-" + uuid4().hex
        for row in events:
            row["investigation_id"] = investigation_id
            row["event_id"] = investigation_id + "-" + row["event_id"]
    store = store or SQLiteEventStore(tmp_path / "events.sqlite")
    assert store.index(events) == len(events)
    values = {"enabled": True, **DEFAULT_POLICY}
    policy = {"values": values, "exclusions": [], "layers": [], "spec_sha256": get_spec("fw.observation")["sha256"]}
    policy["policy_sha256"] = sha(policy)
    pinset = {"devices": [{"detector_id": "fw.observation", "context_scope": {
        "kind": "device", "org_unit_id": "original-org", "device_id": "original-fw"}, "policy": policy}]}
    pinset["sha256"] = sha(pinset)
    saved = analyze_firewall(events)
    scope = {"detector_id": "fw.observation", "filters": [], "org_unit_id": "original-org", "device_id": "original-fw"}
    manifest = {"data_epoch": 1, "normalization_version": "saw.observation/1", "runtime_pin": pinset}
    unit = {"case_version_id": "truth", "unit_id": "window", "unit_kind": "window", "filters": [],
            "event_ids": [], "time": None, "detection_truth": "expected_no_match",
            "investigation_truth": "normal", "basis": "Synthetic"}
    case = {"investigation_id": investigation_id, "filters": [], "time": None,
            "org_unit_id": "original-org", "device_id": "original-fw", "units": [{k:v for k,v in unit.items() if k != "case_version_id"}]}
    frozen = {"golden_ref": {"id": "case-original", "content_sha256": example()["content_sha256"]},
        "scope_sha256": sha(scope), "cutoff": "2026-10-21T00:00:00+00:00", "truth_units": [unit],
        "analysis_run": {"id": "run", "investigation_id": investigation_id, "status": "complete",
            "finished_at": "2026-10-20T01:00:00+00:00", "input_sha256": sha(manifest),
            "scope": scope, "input_manifest": manifest, "executions": [{"detector_id": "fw.observation",
            "detector_version": "firewall-observation/1", "status": "complete", "input_count": len(events),
            "detail": saved, "effective_config": {"pins": pinset["devices"], "values": DEFAULT_POLICY}}]},
        "truth_cases": [{"id": "truth", "sha256": sha(case), "payload": case,
            "input_sha256": sha(sorted(sha(e) for e in events)), "input_count": len(events),
            "source_manifest": {k:v for k,v in manifest.items() if k != "runtime_pin"}}]}
    state = {"source_manifest": {k:v for k,v in manifest.items() if k != "runtime_pin"},
        "source_epochs": {investigation_id: 1}, "processing_complete": True, "known_at": {
            "basis": "server_records", "acquired_at": ["2026-10-20T00:10:00+00:00"],
            "processed_at": ["2026-10-20T00:11:00+00:00"], "profile_available_at": ["2026-10-19T00:00:00+00:00"]}}
    complete_example(frozen, events)
    return store, frozen, state, events

def test_full_capture_runs_actual_original_and_transformed_fw(tmp_path):
    store, scope, state, events = full_fixture(tmp_path)
    capture = module("golden_capture").capture_complete_scope(store, scope, source_state=lambda: deepcopy(state), cancelled=lambda: False)
    assert capture.status == "passed" and capture.size_bytes > 0
    ex = complete_example(scope, events)
    inputs = prepare([ex], full=True)
    inputs["captures"][ex["version_id"]] = capture
    result = module("golden_artifact").build_release(inputs, tmp_path / "full.zip", cancelled=lambda: False)
    validation = result["validations"][0]
    assert validation["complete"] is True and validation["truth_preserved"] is True
    assert validation["input_count"] == validation["observed_count"] == 1

@pytest.mark.parametrize("bad", ["partial", "known_at", "epoch", "unsupported_unit", "saved_metrics"])
def test_full_capture_rejects_incomplete_or_changed_semantics(tmp_path, bad):
    store, scope, state, _ = full_fixture(tmp_path)
    if bad == "partial":
        scope["analysis_run"]["status"] = "partial"
    elif bad == "known_at":
        state["known_at"]["processed_at"] = ["2026-10-22T00:00:00+00:00"]
    elif bad == "unsupported_unit":
        scope["truth_units"][0]["unit_kind"] = "sequence"
    elif bad == "saved_metrics":
        scope["analysis_run"]["executions"][0]["detail"]["counts"]["sessions"] = 9
    calls = 0
    def source_state():
        nonlocal calls
        calls += 1
        if bad == "epoch" and calls > 1:
            state["source_epochs"]["original-inv"] = 2
        return deepcopy(state)
    capture = module("golden_capture").capture_complete_scope(store, scope, source_state=source_state, cancelled=lambda: False)
    if capture.status == "passed":
        ex = complete_example(scope, [event()])
        inputs = prepare([ex], full=True)
        inputs["captures"][ex["version_id"]] = capture
        with pytest.raises(ValueError):
            module("golden_artifact").build_release(inputs, tmp_path / "bad.zip", cancelled=lambda: False)
    else:
        assert capture.status in {"failed", "ineligible"} and capture.reasons

def test_parts_alone_cannot_attest_native_completeness():
    with pytest.raises(ValueError, match="capture"):
        module("golden_capture").verify_complete_scope({"complete": True}, [], [], cancelled=lambda: False)

def test_full_artifact_contains_reproducible_engine_policy_and_context(tmp_path):
    store, scope, state, events = full_fixture(tmp_path)
    ex = complete_example(scope, events)
    inputs = prepare([ex], full=True)
    inputs["captures"][ex["version_id"]] = module("golden_capture").capture_complete_scope(
        store, scope, source_state=lambda: deepcopy(state), cancelled=lambda: False)
    module("golden_artifact").build_release(inputs, tmp_path / "full.zip", cancelled=lambda: False)
    with zipfile.ZipFile(tmp_path / "full.zip") as archive:
        name = next(n for n in archive.namelist() if n.startswith("input/") and "-part-" not in n)
        value = json.loads(archive.read(name))
    assert value["calculation"]["engine"] == {"id": "fw.observation", "version": "firewall-observation/1"}
    assert value["calculation"]["policy"]["scan_window_seconds"] == 300
    assert value["context"]["identity_scope"] == "org_network"
    assert value["context"]["devices"] and value["versions"]["normalization"] == "saw.observation/1"

def test_train_preserves_rewritten_truth_selectors(tmp_path):
    ex = example()
    ex["payload"]["answers"]["detection_truth"]["units"][0]["filters"] = [{"field": "src_ip", "op": "is", "value": "10.1.1.1"}]
    ex["content_sha256"] = sha(ex["payload"])
    module("golden_artifact").build_release(prepare([ex]), tmp_path / "release.zip", cancelled=lambda: False)
    with zipfile.ZipFile(tmp_path / "release.zip") as archive:
        answer = json.loads(archive.read(next(n for n in archive.namelist() if n.startswith("answers/"))))
        ev = json.loads(archive.read(next(n for n in archive.namelist() if n.startswith("evidence/"))))["event"]
    selector = answer["detection_truth"]["units"][0]["filters"][0]
    assert selector == {"field": "src_ip", "op": "is", "value": ev["src_ip"]}

@pytest.mark.parametrize("key", ["protocol", "data_source", "status_code"])
def test_unrecognized_raw_strings_cannot_cross_event_projection(key):
    ev = event()
    ev[key] = "SECRET ARBITRARY CONTENT"
    projected = module("golden_projection").project_event_v2(ev)
    assert "SECRET ARBITRARY CONTENT" not in raw(projected).decode()

def test_prepare_stops_generator_at_aggregate_budget(monkeypatch):
    m = module("golden_projection")
    monkeypatch.setattr(m, "MAX_TOTAL", 7000)
    consumed = []
    def values():
        for index in range(10):
            consumed.append(index)
            yield example(eid="case-" + str(index))
    with pytest.raises(ValueError, match="byte_limit"):
        m.prepare_release_inputs(request(), values(), sealed_profiles(), cancelled=lambda: False,
            private_context={"mapping_seed": "12" * 32, "release_id": "r", "created_at": "2026-10-22T00:00:00+00:00"})
    assert len(consumed) < 10

def test_native_count_and_lookahead_never_accept_a_prefix(tmp_path):
    _store, scope, state, events = full_fixture(tmp_path)
    class Prefix:
        def count(self, *args, **kwargs):
            return 2
        def iterate(self, *args, **kwargs):
            yield events[0]
    cap = module("golden_capture").capture_complete_scope(Prefix(), scope, source_state=lambda: deepcopy(state), cancelled=lambda: False)
    assert cap.status == "ineligible" and "native_count_mismatch" in cap.reasons
    class Lookahead:
        def count(self, *args, **kwargs):
            return 10000
        def iterate(self, *args, **kwargs):
            for number in range(10001):
                ev = {"event_id": "event-" + str(number).zfill(5), "investigation_id": "original-inv",
                      "timestamp": "2026-10-20T00:00:00+00:00", "data_source": "firewall"}
                yield ev
    cap = module("golden_capture").capture_complete_scope(Lookahead(), scope, source_state=lambda: deepcopy(state), cancelled=lambda: False)
    assert cap.status == "ineligible" and "record_limit_lookahead" in cap.reasons

@pytest.mark.parametrize("mode", ["tied_session", "deny_allow", "nat_distinct", "nat_same"])
def test_same_timestamp_and_typed_nat_equivalence_survive_actual_engine(tmp_path, mode):
    left, right = event("a"), event("b")
    if mode == "tied_session":
        left["ext"]["observation"].update(record_kind="session_start", start_time=None)
        right["ext"]["observation"].update(record_kind="session_end", start_time=None)
    elif mode == "deny_allow":
        left["ext"]["observation"]["action"] = "blocked"
    elif mode == "nat_distinct":
        left["ext"]["csv"]["inside_zone"] = 1
        right["ext"]["csv"]["inside_zone"] = "1"
    store, scope, state, events = full_fixture(tmp_path, [left, right])
    capture = module("golden_capture").capture_complete_scope(store, scope, source_state=lambda: deepcopy(state), cancelled=lambda: False)
    ex = complete_example(scope, events)
    inputs = prepare([ex], full=True)
    inputs["captures"][ex["version_id"]] = capture
    result = module("golden_artifact").build_release(inputs, tmp_path / "full.zip", cancelled=lambda: False)
    assert result["validations"][0]["complete"] is True
    assert result["validations"][0]["input_count"] == 2

def test_full_rejects_changed_directional_bytes(tmp_path):
    store, scope, state, events = full_fixture(tmp_path)
    capture = module("golden_capture").capture_complete_scope(store, scope, source_state=lambda: deepcopy(state), cancelled=lambda: False)
    mapper = module("golden_projection").IdentityMapper("12" * 32)
    mapper.register_events(events)
    transformed = [mapper.event(e) for e in events]
    transformed[0]["ext"]["observation"]["counters"]["src_to_dst_bytes"]["value"] = 500
    capture.identity_mapper = mapper
    result = module("golden_capture").verify_complete_scope(capture, capture.original_parts,
        [b"".join(raw(e) + b"\n" for e in transformed)], cancelled=lambda: False)
    assert result["status"] == "failed" and not result.get("complete")

def test_nested_nat_semantics_are_explicitly_unsupported(tmp_path):
    ev = event()
    ev["ext"]["csv"]["inside_zone"] = {"nested": "unsupported"}
    with pytest.raises(ValueError, match="unsupported_nat"):
        module("golden_projection").project_event_v2(ev)

def test_full_capture_cannot_be_substituted_from_another_golden(tmp_path):
    _store, scope, _state, events = full_fixture(tmp_path)
    ex = example(events=events)
    ex["complete_scope"] = deepcopy(scope)
    ex["complete_scope"]["golden_ref"]["id"] = "different-golden"
    with pytest.raises(ValueError, match="scope.*golden|golden.*scope"):
        prepare([ex], full=True)

def test_answer_only_later_evidence_never_enters_holdout(tmp_path):
    ex = example()
    answer_blob = {"schema": "saw.golden.event.v2", "event": event("later-secret-event")}
    ident = sha(answer_blob)
    ex["blobs"][ident] = answer_blob
    ex["payload"]["manifest"].append({"sha256": ident, "size_bytes": len(raw(answer_blob)), "kind": "answer_evidence"})
    ex["payload"]["answers"]["later_confirmed_facts"] = [{
        "fact": "SECRET LATER FACT", "evidence_refs": [ident],
        "confirmed_at": "2026-10-22T00:00:00+00:00", "known_at": "2026-10-22T00:00:00+00:00"}]
    ex["content_sha256"] = sha(ex["payload"])
    m = module("golden_artifact")
    m.build_release(prepare([ex]), tmp_path / "train.zip", cancelled=lambda: False)
    with zipfile.ZipFile(tmp_path / "train.zip") as archive:
        answers = json.loads(archive.read(next(n for n in archive.namelist() if n.startswith("answers/"))))
        fact = answers["later_confirmed_facts"][0]
        assert fact["evidence_refs"] and fact["evidence_refs"][0] != ident
        assert "evidence/" + fact["evidence_refs"][0] + ".json" in archive.namelist()
        assert fact["known_at"] == "2026-10-22T00:00:00+00:00"
    ex["split"] = "holdout"
    m.build_release(prepare([ex], split="holdout"), tmp_path / "holdout.zip", cancelled=lambda: False)
    with zipfile.ZipFile(tmp_path / "holdout.zip") as archive:
        assert sum(n.startswith("evidence/") for n in archive.namelist()) == 1
        assert all(ident not in archive.read(n).decode() and "2026-10-22T00:00:00" not in archive.read(n).decode() for n in archive.namelist())

def test_input_graph_does_not_accept_later_known_event(tmp_path):
    ex = example()
    _old_ident, blob = next(iter(ex["blobs"].items()))
    blob["known_at"] = "2026-10-22T00:00:00+00:00"
    new_ident = sha(blob)
    ex["blobs"] = {new_ident: blob}
    ex["payload"]["input"]["evidence"] = [new_ident]
    ex["payload"]["manifest"] = [{"sha256": new_ident, "size_bytes": len(raw(blob)), "kind": "event"}]
    ex["input_sha256"] = sha({"input": ex["payload"]["input"], "blobs": ex["blobs"]})
    ex["content_sha256"] = sha(ex["payload"])
    with pytest.raises(ValueError, match="cutoff"):
        prepare([ex])

def test_holdout_bytes_do_not_depend_on_noninput_answer_blobs(tmp_path):
    ex = example("holdout")
    first = prepare([ex], split="holdout")
    answer_blob = {"schema": "saw.golden.event.v2", "event": event("000-before-input")}
    ident = sha(answer_blob)
    ex["blobs"][ident] = answer_blob
    ex["payload"]["manifest"].append({"sha256": ident, "size_bytes": len(raw(answer_blob)), "kind": "answer_evidence"})
    ex["payload"]["answers"]["investigation_truth"]["reason"] = "DIFFERENT ANSWER"
    ex["content_sha256"] = sha(ex["payload"])
    builder = module("golden_artifact")
    builder.build_release(first, tmp_path / "one.zip", cancelled=lambda: False)
    builder.build_release(prepare([ex], split="holdout"), tmp_path / "two.zip", cancelled=lambda: False)
    assert (tmp_path / "one.zip").read_bytes() == (tmp_path / "two.zip").read_bytes()

def test_legacy_projection_preserves_v1_input_contract(tmp_path):
    inputs = prepare()
    inputs["request"]["projection"] = "v1"
    module("golden_artifact").build_release(inputs, tmp_path / "v1.zip", cancelled=lambda: False)
    with zipfile.ZipFile(tmp_path / "v1.zip") as archive:
        value = json.loads(archive.read(next(n for n in archive.namelist() if n.startswith("input/"))))
    assert value["schema"] == "saw.golden.agent-input.v1"
    assert {"example_id", "version", "methodology_version", "as_of", "retrieval", "observations", "evidence"} <= set(value)
    assert "context" not in value and "versions" not in value

def test_real_archive_passes_independent_publication_verifier(tmp_path):
    from saw.knowledge.golden_archive import inspect_archive
    built = module("golden_artifact").build_release(prepare(split="holdout"), tmp_path / "holdout.zip", cancelled=lambda: False)
    with (tmp_path / "holdout.zip").open("rb") as stream:
        verified = inspect_archive(stream, expected_manifest=built["manifest"], holdout=True)
    assert len(verified["samples"]) <= 5
    assert sum(s["preview_bytes"] for s in verified["samples"]) <= 20 * 1024

def test_archive_inventory_budget_preserves_existing_file(tmp_path, monkeypatch):
    m = module("golden_artifact")
    monkeypatch.setattr(m, "MAX_FILES", 5)
    target = tmp_path / "existing.zip"
    target.write_bytes(b"old")
    with pytest.raises(ValueError, match="limit"):
        m.build_release(prepare(), target, cancelled=lambda: False)
    assert target.read_bytes() == b"old"

def test_private_mapping_failure_cannot_replace_existing_destination(tmp_path, monkeypatch):
    m = module("golden_artifact")
    class BadMapping(m.IdentityMapper):
        def private_content(self):
            raise ValueError("mapping_failure")
    monkeypatch.setattr(m, "IdentityMapper", BadMapping)
    target = tmp_path / "existing.zip"
    target.write_bytes(b"old")
    with pytest.raises(ValueError, match="mapping_failure"):
        m.build_release(prepare(), target, cancelled=lambda: False)
    assert target.read_bytes() == b"old"

def test_scope_source_state_exception_propagates(tmp_path):
    store, scope, _state, _events = full_fixture(tmp_path)
    def denied():
        raise PermissionError("source_acl_revoked")
    with pytest.raises(PermissionError, match="source_acl_revoked"):
        module("golden_capture").capture_complete_scope(store, scope, source_state=denied, cancelled=lambda: False)

def test_identity_registration_honors_cancellation():
    checks = 0
    def cancelled():
        nonlocal checks
        checks += 1
        return checks > 5
    m = module("golden_projection").IdentityMapper("1" * 64, cancelled=cancelled)
    with pytest.raises(Exception, match="cancel"):
        m.register_events([event(eid=str(i)) for i in range(50)])
    assert checks < 50

def test_reviewed_followup_status_survives_without_private_payload_text(tmp_path):
    ex = example()
    payload = {"status": "verified", "question": "SECRET QUESTION", "priority": "high",
        "owner": {"user_id": "PRIVATE OWNER"}, "due_at": "2026-10-23T00:00:00+00:00",
        "reply": {"note": "SECRET REPLY", "received_at": "2026-10-22T00:00:00+00:00",
                  "evidence": [{"event_id": "PRIVATE EVENT", "sha256": "a" * 64}]},
        "verification": {"outcome": "confirmed", "basis": "SECRET BASIS",
                         "verified_at": "2026-10-22T01:00:00+00:00", "verified_by": "PRIVATE REVIEWER", "evidence": []}}
    ex["payload"]["answers"]["investigation_truth"]["followups"] = [{
        "followup_id": "PRIVATE FU", "version_id": "PRIVATE VERSION", "revision": 3,
        "payload_sha256": sha(payload), "payload": payload}]
    ex["content_sha256"] = sha(ex["payload"])
    module("golden_artifact").build_release(prepare([ex]), tmp_path / "followup.zip", cancelled=lambda: False)
    with zipfile.ZipFile(tmp_path / "followup.zip") as archive:
        text = archive.read(next(n for n in archive.namelist() if n.startswith("answers/"))).decode()
    followup = json.loads(text)["investigation_truth"]["followups"][0]
    assert followup["status"] == "verified" and followup["revision"] == 3
    assert followup["reply"]["received_at"] == payload["reply"]["received_at"]
    assert followup["verification"]["outcome"] == "confirmed"
    assert followup["reply"]["evidence_state"] == "kept_private"
    assert "SECRET" not in text and "PRIVATE" not in text
    assert sha(payload) not in text

@pytest.mark.parametrize("selector", ["end", "is_not", "not_in"])
def test_complete_window_membership_matches_actual_p2_authority(app, tmp_path, selector):
    from time import monotonic

    from saw import container
    from saw.detection.testing import _members
    rows = [event("member-before", status_code=200), event("member-end", timestamp="2026-10-20T00:01:00+00:00")]
    store, scope, state, events = full_fixture(tmp_path, rows, container.get().events)
    unit = scope["truth_units"][0]
    unit["time"] = {"start": "2026-10-19T23:59:00+00:00", "end": "2026-10-20T00:01:00+00:00"}
    if selector != "end":
        unit["time"]["end"] = "2026-10-20T00:02:00+00:00"
        unit["filters"] = [{"field": "status_code", "op": selector, "value": 500 if selector == "is_not" else [500]}]
    case = scope["truth_cases"][0]
    case["payload"]["units"] = [{k:v for k,v in unit.items() if k != "case_version_id"}]
    case["sha256"] = sha(case["payload"])
    authoritative = _members(case["payload"], case["payload"]["units"], monotonic()+30)["window"]
    assert authoritative == {e["event_id"] for e in events}
    m = module("golden_capture")
    selected = {e["event_id"] for e in events if m._within(e, [case["payload"].get("time"), unit["time"]])
                and m._matches(e, unit["filters"])}
    assert selected == authoritative
    ex = complete_example(scope, events)
    capture = m.capture_complete_scope(store, scope, source_state=lambda: deepcopy(state), cancelled=lambda: False)
    assert capture.status == "passed", capture.reasons
    inputs = prepare([ex], full=True)
    inputs["captures"][ex["version_id"]] = capture
    result = module("golden_artifact").build_release(inputs, tmp_path / "native-window.zip", cancelled=lambda: False)
    check = next(c for c in result["validations"][0]["checks"] if c["code"] == "native_truth_membership")
    assert check["input_count"] == 2 and check["expected_sha256"] == check["actual_sha256"]


@pytest.mark.parametrize("second_event_id", ["original-event-1", "member-before"])
def test_full_fixture_isolates_cases_in_a_shared_event_store(tmp_path, second_event_id):
    from saw.storage.eventstore import SQLiteEventStore

    shared = SQLiteEventStore(tmp_path / "shared.sqlite")
    fixtures = [
        full_fixture(tmp_path / "first", [
            event("member-before", status_code=200),
            event("member-end", timestamp="2026-10-20T00:01:00+00:00"),
        ], shared),
        full_fixture(tmp_path / "second", [event(second_event_id)], shared),
    ]
    # Native indices outlive the per-test SQL database. Both snapshots must still
    # describe exactly their own events after the next fixture has been indexed.
    for index, (store, scope, state, events) in enumerate(fixtures):
        ex = complete_example(scope, events)
        capture = module("golden_capture").capture_complete_scope(
            store, scope, source_state=lambda: deepcopy(state), cancelled=lambda: False)
        assert capture.status == "passed", capture.reasons
        inputs = prepare([ex], full=True)
        inputs["captures"][ex["version_id"]] = capture
        result = module("golden_artifact").build_release(
            inputs, tmp_path / f"isolated-{index}.zip", cancelled=lambda: False)
        validation = result["validations"][0]
        assert validation["complete"] is True
        assert validation["input_count"] == validation["observed_count"] == len(events)
    assert fixtures[0][1]["analysis_run"]["investigation_id"] != fixtures[1][1]["analysis_run"]["investigation_id"]
    assert {e["event_id"] for e in fixtures[0][3]}.isdisjoint(e["event_id"] for e in fixtures[1][3])


def test_native_membership_disagreement_cannot_attest_complete(app, tmp_path, monkeypatch):
    from saw import container
    store, scope, state, events = full_fixture(tmp_path, store=container.get().events)
    ex = complete_example(scope, events)
    m = module("golden_capture")
    capture = m.capture_complete_scope(store, scope, source_state=lambda: deepcopy(state), cancelled=lambda: False)
    assert capture.status == "passed" and capture.native_count == len(events)
    inputs = prepare([ex], full=True)
    inputs["captures"][ex["version_id"]] = capture
    # Prove the unchanged engine/snapshot checks pass before injecting only the
    # local-vs-native membership disagreement this test is intended to reject.
    control = module("golden_artifact").build_release(inputs, tmp_path / "control.zip", cancelled=lambda: False)
    assert control["validations"][0]["complete"] is True
    monkeypatch.setattr(m, "_matches", lambda event, filters: False)
    with pytest.raises(ValueError, match="native_truth_membership_changed"):
        module("golden_artifact").build_release(inputs, tmp_path / "wrong.zip", cancelled=lambda: False)
    assert not (tmp_path / "wrong.zip").exists()


@pytest.mark.parametrize("kind", ["event", "sequence"])
def test_unexported_truth_event_reference_is_rejected(tmp_path, kind):
    ex = example()
    unit = ex["payload"]["answers"]["detection_truth"]["units"][0]
    unit.update(unit_kind=kind, event_ids=["unexported-event"])
    ex["content_sha256"] = sha(ex["payload"])
    target = tmp_path / "no-dangling.zip"
    with pytest.raises(ValueError, match="truth_event_reference_unavailable"):
        module("golden_artifact").build_release(prepare([ex]), target, cancelled=lambda: False)
    assert not target.exists()

def test_failure_reason_type_only_exposes_fixed_allowlisted_codes():
    from saw.knowledge.golden_jobs import public_stage
    from saw.storage.models import Job
    projection = module("golden_projection")
    failure = projection.GoldenBuildFailure(["unsupported_truth_unit", "PRIVATE source/path/secret",
        "unsupported_truth_unit"] * 100)
    assert failure.reasons == ("unsupported_truth_unit",)
    assert "PRIVATE" not in str(failure)
    job = Job(kind="golden_export", state="FAILED", stages={"golden_export": {
        "failure_reasons": ["PRIVATE source/path", "record_limit_exceeded"]}})
    assert public_stage(job)["failure_reasons"] == ["record_limit_exceeded"]
