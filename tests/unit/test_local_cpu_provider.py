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
