from __future__ import annotations

import pytest

from saw.llm.providers import LLMRequest


def test_base_prompt_does_not_apply_chat_template():
    from saw.llm.cpu_provider import serialize_request
    prompt = serialize_request({"prompt_format": "base-completion-v1"}, LLMRequest("Rules", "Synthetic evidence"))
    assert "Completion:" in prompt
    assert "<|start_header_id|>" not in prompt
    assert "Synthetic evidence" in prompt


def test_instruct_uses_only_fixed_supported_serialization():
    from saw.llm.cpu_provider import serialize_request
    prompt = serialize_request({"prompt_format": "llama3-instruct-v1"}, LLMRequest("Rules", "Synthetic evidence"))
    assert prompt.endswith("<|start_header_id|>assistant<|end_header_id|>\n\n")
    assert prompt.count("<|start_header_id|>") == 3
    with pytest.raises(ValueError, match="cpu_prompt_special_token"):
        serialize_request({"prompt_format": "llama3-instruct-v1"}, LLMRequest("Rules", "<|eot_id|>"))


def test_cpu_rejects_unsupported_prompt_and_oversized_input():
    from saw.llm.cpu_provider import serialize_request
    with pytest.raises(ValueError, match="cpu_prompt_format"):
        serialize_request({"prompt_format": "arbitrary-template"}, LLMRequest("a", "b"))
    with pytest.raises(ValueError, match="cpu_prompt_limit"):
        serialize_request({"prompt_format": "base-completion-v1"}, LLMRequest("a", "b" * 17000))


def test_tokenizer_context_counts_real_ids_and_rejects_protocol_data():
    from saw.llm.cpu_provider import token_ids
    manifest = {"checkpoint_kind": "BASE"}
    assert token_ids(b"[128000, 12, 13]", manifest, 128256) == [128000, 12, 13]
    for invalid in [b"[12,13]", b"[128000,true]", b"[128000,128001]", b"[128000,-1]", b"{}"]:
        with pytest.raises(ValueError, match="cpu_tokenizer_output"):
            token_ids(invalid, manifest, 128256)

@pytest.mark.parametrize("value", [True, "32", None, -1, 0])
def test_invalid_output_budget_is_a_safe_error(value):
    from types import SimpleNamespace

    from saw.llm.cpu_provider import CPUProvider
    provider = CPUProvider(SimpleNamespace(), "test", "0" * 64)
    with pytest.raises(ValueError, match="cpu_output_budget"):
        provider._generate(LLMRequest("a", "b", max_tokens=value))


def test_json_mode_uses_fixed_native_schema_without_chat_mode():
    import json
    from saw.llm.cpu_provider import json_flags
    flags = json_flags(LLMRequest("rules", "synthetic", json_mode=True))
    assert flags[0] == "--json-schema"
    schema = json.loads(flags[1])
    assert schema["required"] == ["answer_md", "citations"]
    assert schema["additionalProperties"] is False
    assert json_flags(LLMRequest("rules", "synthetic", json_mode=False)) == []

@pytest.mark.parametrize("code", ["cpu_single_execution_busy", "cpu_execution_lock_failed"])
def test_machine_execution_lock_errors_are_safe_cpu_failures(monkeypatch, code):
    from contextlib import contextmanager
    from types import SimpleNamespace
    from saw.llm import cpu_provider

    @contextmanager
    def refused():
        raise ValueError(code)
        yield

    monkeypatch.setattr(cpu_provider, "single_execution", refused)
    provider = cpu_provider.CPUProvider(SimpleNamespace(), "test", "0" * 64)
    with pytest.raises(cpu_provider.CPUExecutionError) as caught:
        provider.generate(LLMRequest("rules", "synthetic"))
    assert str(caught.value) == code
    assert caught.value.actual_inference == "NOT_RUN"
    assert provider.last_receipt == {"actual_inference": "NOT_RUN", "error_code": code}


@pytest.mark.parametrize("status,returncode,expected", [
    ("TIMEOUT", 125, "cpu_wall_budget"),
    ("OUTPUT_LIMIT", 125, "cpu_output_limit"),
    ("CANCELLED", 125, "cpu_cancelled"),
    ("FAILED", 3221225477, "cpu_native_failed"),
    ("SUCCEEDED", 1, "cpu_native_failed"),
    ("SUCCEEDED", 0, None),
])
def test_native_failure_status_mapping_is_explicit(status, returncode, expected):
    from saw.llm.cpu_provider import native_failure_code
    assert native_failure_code({"status": status, "returncode": returncode}) == expected


def test_failure_diagnostics_accept_only_bounded_enums_and_numbers():
    from saw.llm.cpu_provider import CPUExecutionError
    error = CPUExecutionError("cpu_wall_budget", diagnostics={
        "native_status": "TIMEOUT", "native_returncode": 125, "native_elapsed_seconds": 299.5,
        "native_stage": "completion", "input_tokens": 440, "process_cpu_seconds": 991.5,
        "stdout": "private model output", "stderr": "private diagnostics", "prompt": "private prompt",
        "path": "private path", "unexpected": "private value"})
    assert error.diagnostics == {"native_status": "TIMEOUT", "native_returncode": 125,
        "native_elapsed_seconds": 299.5, "native_stage": "completion", "input_tokens": 440,
        "process_cpu_seconds": 991.5}
    invalid = CPUExecutionError("cpu_native_failed", diagnostics={
        "native_status": "private value", "native_stage": "private value", "native_returncode": True,
        "native_elapsed_seconds": float("nan"), "input_tokens": -1, "process_cpu_seconds": float("inf")})
    assert invalid.diagnostics == {}
    assert CPUExecutionError("cpu_native_failed", diagnostics={"process_cpu_seconds": 10**400}).diagnostics == {}


def test_native_timeout_keeps_sanitized_metadata_without_raw_output(tmp_path, monkeypatch):
    from contextlib import contextmanager, nullcontext
    from types import SimpleNamespace
    from saw.llm import cpu_provider

    manifest = {"prompt_format": "base-completion-v1", "checkpoint_kind": "BASE", "model_file": "model.gguf"}
    pack = {"_root": tmp_path / "pack", "_manifest": manifest, "_files": {},
            "_config": {"vocab_size": 128256}, "model_id": "test/synthetic"}
    spec = {"runtime_root": tmp_path / "engine", "manifest": tmp_path / "engine/manifest.json", "runtime_files": {}}
    monkeypatch.setattr(cpu_provider, "validate_pack", lambda *_: pack)
    monkeypatch.setattr(cpu_provider, "runtime_spec", lambda *_: spec)
    monkeypatch.setattr(cpu_provider, "_lock_directories", lambda *_: nullcontext())
    monkeypatch.setattr(cpu_provider, "_lock_artifacts", lambda *_: nullcontext())

    @contextmanager
    def sealed(*_):
        yield tmp_path / "engine", tmp_path / "cwd"

    monkeypatch.setattr(cpu_provider, "_sealed_runtime", sealed)
    def native(argv, **kwargs):
        completion = argv[0].endswith("llama-completion.exe")
        return {"token_appcontainer": True, "less_privileged_appcontainer": True,
            "network_capability_count": 0, "job_active_process_limit": 1, "job_kill_on_close": True,
            "status": "TIMEOUT" if completion else "SUCCEEDED", "returncode": 125 if completion else 0,
            "elapsed_seconds": 290.25 if completion else 1.25, "process_cpu_seconds": 1000 if completion else 0.1,
            "stdout": b"private incomplete output" if completion else b"[128000,12]", "stderr": b"private details"}

    monkeypatch.setattr(cpu_provider, "launch_appcontainer", native)
    provider = cpu_provider.CPUProvider(SimpleNamespace(llm_cpu_work_root=str(tmp_path / "work")), "synthetic", "0" * 64)
    with pytest.raises(cpu_provider.CPUExecutionError) as caught:
        provider._generate(LLMRequest("rules", "synthetic", max_tokens=8))
    assert str(caught.value) == "cpu_wall_budget"
    assert caught.value.diagnostics == {"native_status": "TIMEOUT", "native_returncode": 125,
        "native_elapsed_seconds": 290.25, "process_cpu_seconds": 1000, "input_tokens": 2,
        "native_stage": "completion"}
    assert provider.last_receipt["native_status"] == "TIMEOUT"
    assert "stdout" not in provider.last_receipt and "stderr" not in provider.last_receipt
