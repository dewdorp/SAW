from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

import pytest


def gguf_fixture(**changes):
    def string(value):
        raw = value.encode()
        return struct.pack("<Q", len(raw)) + raw
    fields = {
        "general.architecture": (8, string("llama")),
        "general.file_type": (4, struct.pack("<I", 15)),
        "tokenizer.ggml.model": (8, string("gpt2")),
        "tokenizer.ggml.pre": (8, string("llama-bpe")),
        "tokenizer.ggml.bos_token_id": (4, struct.pack("<I", 128000)),
        "tokenizer.ggml.eos_token_id": (4, struct.pack("<I", 128001)),
        "tokenizer.ggml.add_bos_token": (7, b"\x01"),
    }
    special = {128000: "<|begin_of_text|>", 128001: "<|end_of_text|>",
               128006: "<|start_header_id|>", 128007: "<|end_header_id|>", 128009: "<|eot_id|>"}
    fields["tokenizer.ggml.tokens"] = (9, struct.pack("<IQ", 8, 128256)
        + b"".join(string(special.get(i, "x")) for i in range(128256)))
    fields.update(changes)
    raw = b"GGUF" + struct.pack("<IQQ", 3, 1, len(fields))
    for key, (kind, value) in fields.items():
        raw += string(key) + struct.pack("<I", kind) + value
    raw += string("synthetic.weight") + struct.pack("<IQIQ", 1, 1, 0, 0)
    return raw + bytes(32 - len(raw) % 32) + bytes(32)


def pack_fixture(root: Path, pack_id="synthetic-base", **changes):
    folder = root / pack_id
    folder.mkdir(parents=True, exist_ok=True)
    content = {
        "model.gguf": gguf_fixture(),
        "config.json": json.dumps({"architectures": ["LlamaForCausalLM"], "model_type": "llama",
                                   "bos_token_id": 128000, "eos_token_id": 128001, "vocab_size": 128256}).encode(),
        "tokenizer_config.json": json.dumps({"bos_token": "<|begin_of_text|>",
                                             "eos_token": "<|end_of_text|>"}).encode(),
        "LICENSE.txt": b"Synthetic fixture only; contains no real weights.",
    }
    manifest = {"schema": "saw.local-model-pack/1", "pack_id": pack_id, "model_id": "test/synthetic-llama",
                "revision": "1" * 40, "checkpoint_kind": "BASE", "prompt_format": "base-completion-v1",
                "quantization": "Q4_K_M", "model_file": "model.gguf", "config_file": "config.json",
                "tokenizer_file": "tokenizer_config.json", "license_files": ["LICENSE.txt"],
                "license_status": "PENDING_REVIEW", "synthetic_only": True,
                "runtime": {"version": "b11429", "commit": "d81235049384534c167caea52b85a694f6103d14"},
                "files": [{"path": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                          for name, raw in content.items()]}
    manifest.update(changes)
    for name, raw in content.items():
        (folder / name).write_bytes(raw)
    (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return folder, manifest


def configure(tmp_path):
    from saw import container
    settings = container.get().settings
    settings.__dict__["llm_models_root"] = str(tmp_path / "models")
    return settings


def test_only_admin_can_manage_model_packs(admin, analyst):
    assert analyst.get("/admin/local-models").status_code == 403
    response = admin.get("/admin/local-models")
    assert response.status_code == 200
    assert response.json()["active_pack_id"] is None
    assert response.json()["synthetic_only"] is True


def test_validate_records_integrity_without_claiming_inference(admin, tmp_path):
    settings = configure(tmp_path)
    pack_fixture(Path(settings.llm_models_root))
    response = admin.post("/admin/local-models/validate", json={"pack_id": "synthetic-base"})
    assert response.status_code == 200, response.text
    record = response.json()
    assert record["status"] == "FILES_VERIFIED"
    assert record["actual_inference"] == "NOT_RUN"
    assert record["synthetic_only"] is True
    assert len(record["manifest_sha256"]) == 64
    assert admin.get("/admin/local-models").json()["active_pack_id"] is None
    assert admin.get("/admin/audit?action=ai.model.validate").json()


@pytest.mark.parametrize("pack_id", ["../outside", "C:\\model", "a/b", "a:stream", "..", "UPPER"])
def test_pack_ids_are_not_paths(admin, pack_id):
    assert admin.post("/admin/local-models/validate", json={"pack_id": pack_id}).status_code in (400, 422)


@pytest.mark.parametrize("mutation", ["hash", "path", "base_template", "production", "identity"])
def test_model_pack_rejects_unsafe_or_mismatched_content(admin, tmp_path, mutation):
    settings = configure(tmp_path)
    folder, manifest = pack_fixture(Path(settings.llm_models_root))
    if mutation == "hash":
        (folder / "model.gguf").write_bytes(b"changed")
    elif mutation == "path":
        manifest["files"][0]["path"] = "../model.gguf"
    elif mutation == "base_template":
        manifest["prompt_format"] = "llama3-instruct-v1"
    elif mutation == "production":
        manifest["synthetic_only"] = False
    else:
        manifest["model_id"] = "fdtn-ai/Foundation-Sec-8B"
    (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert admin.post("/admin/local-models/validate", json={"pack_id": "synthetic-base"}).status_code == 400
    assert admin.get("/admin/local-models").json()["active_pack_id"] is None


def test_activate_requires_reason_and_csrf(admin):
    assert admin.post("/admin/local-models/activate", json={"pack_id": "x", "reason": " "}).status_code == 422
    response = admin.c.post("/api/v1/admin/local-models/deactivate", json={"reason": "synthetic cleanup"})
    assert response.status_code == 403


def test_native_failure_and_mutated_manifest_preserve_previous_selection(admin, tmp_path, monkeypatch):
    from saw.llm import model_packs
    settings = configure(tmp_path)
    folder, _ = pack_fixture(Path(settings.llm_models_root))
    assert admin.post("/admin/local-models/validate", json={"pack_id": folder.name}).status_code == 200
    monkeypatch.setattr(model_packs, "probe_pack", lambda *_: {"actual_inference": "EXECUTED"})
    response = admin.post("/admin/local-models/activate", json={"pack_id": folder.name, "reason": "synthetic smoke only"})
    assert response.status_code == 200, response.text
    assert response.json()["quality_adopted"] is False
    second, _ = pack_fixture(Path(settings.llm_models_root), "synthetic-second")
    assert admin.post("/admin/local-models/validate", json={"pack_id": second.name}).status_code == 200
    def failure(*_):
        raise ValueError("cpu_native_failed")
    monkeypatch.setattr(model_packs, "probe_pack", failure)
    assert admin.post("/admin/local-models/activate", json={"pack_id": second.name, "reason": "failure keeps previous"}).status_code == 400
    assert admin.get("/admin/local-models").json()["active_pack_id"] == folder.name
    (folder / "manifest.json").write_text("{}", encoding="utf-8")
    assert admin.post("/admin/local-models/activate", json={"pack_id": folder.name, "reason": "reject changed manifest"}).status_code == 400
    assert admin.get("/admin/local-models").json()["active_pack_id"] == folder.name
    assert admin.post("/admin/local-models/deactivate", json={"reason": "synthetic smoke complete"}).status_code == 200
    assert admin.get("/admin/local-models").json()["active_pack_id"] is None
    assert admin.get("/admin/audit?action=ai.model.activate").json()

@pytest.mark.parametrize("field,kind,value", [
    ("general.architecture", 8, struct.pack("<Q", 5) + b"qwen2"),
    ("general.file_type", 4, struct.pack("<I", 7)),
    ("tokenizer.ggml.eos_token_id", 4, struct.pack("<I", 128009)),
    ("tokenizer.chat_template", 8, struct.pack("<Q", 4) + b"chat"),
    ("tokenizer.ggml.tokens", 9, struct.pack("<IQ", 8, 2) + struct.pack("<Q", 1) + b"a" + struct.pack("<Q", 1) + b"b"),
])
def test_actual_gguf_metadata_must_match_declared_contract(admin, tmp_path, field, kind, value):
    settings = configure(tmp_path)
    folder, manifest = pack_fixture(Path(settings.llm_models_root))
    raw = gguf_fixture(**{field: (kind, value)})
    (folder / "model.gguf").write_bytes(raw)
    manifest["files"][0].update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert admin.post("/admin/local-models/validate", json={"pack_id": folder.name}).status_code == 400


def test_admin_role_revocation_during_probe_keeps_previous_selection(admin, tmp_path, monkeypatch):
    from sqlalchemy import select

    from saw.llm import model_packs
    from saw.storage.db import session_scope
    from saw.storage.models import User
    settings = configure(tmp_path)
    folder, _ = pack_fixture(Path(settings.llm_models_root))
    assert admin.post("/admin/local-models/validate", json={"pack_id": folder.name}).status_code == 200
    def probe(*_):
        with session_scope() as s:
            user = s.scalar(select(User).where(User.username == "admin1"))
            user.roles = ["analyst"]
        return {"actual_inference": "EXECUTED"}
    monkeypatch.setattr(model_packs, "probe_pack", probe)
    response = admin.post("/admin/local-models/activate", json={"pack_id": folder.name, "reason": "synthetic permission test"})
    assert response.status_code == 400
    assert response.json()["detail"] == "model_management_permission_changed"
    with session_scope() as s:
        assert model_packs.status(s)["active_pack_id"] is None


def test_concurrent_selection_change_rejects_stale_probe(admin, tmp_path, monkeypatch):
    from saw.llm import model_packs
    from saw.storage.db import session_scope
    settings = configure(tmp_path)
    folder, _ = pack_fixture(Path(settings.llm_models_root))
    assert admin.post("/admin/local-models/validate", json={"pack_id": folder.name}).status_code == 200
    def probe(*_):
        with session_scope() as s:
            s.add(model_packs.LocalModelSelection(id=1, pack_id=None, epoch=1))
        return {"actual_inference": "EXECUTED"}
    monkeypatch.setattr(model_packs, "probe_pack", probe)
    response = admin.post("/admin/local-models/activate", json={"pack_id": folder.name, "reason": "synthetic conflict test"})
    assert response.status_code == 400
    assert response.json()["detail"] == "model_selection_changed_retry"
    assert admin.get("/admin/local-models").json()["active_pack_id"] is None


def test_failed_success_audit_rolls_back_selection(admin, tmp_path, monkeypatch):
    from saw.llm import model_packs
    settings = configure(tmp_path)
    folder, _ = pack_fixture(Path(settings.llm_models_root))
    assert admin.post("/admin/local-models/validate", json={"pack_id": folder.name}).status_code == 200
    monkeypatch.setattr(model_packs, "probe_pack", lambda *_: {"actual_inference": "EXECUTED"})
    original = model_packs.audit.record
    def fail_success(s, action, **kwargs):
        if action == "ai.model.activate" and kwargs.get("outcome", "success") == "success":
            raise ValueError("model_audit_fixture_failure")
        return original(s, action, **kwargs)
    monkeypatch.setattr(model_packs.audit, "record", fail_success)
    response = admin.post("/admin/local-models/activate", json={"pack_id": folder.name, "reason": "synthetic atomic audit test"})
    assert response.status_code == 400
    assert admin.get("/admin/local-models").json()["active_pack_id"] is None
    assert admin.get("/admin/audit?action=ai.model.activate").json()[0]["outcome"] == "failure"


def test_active_registration_missing_does_not_fallback_to_template(admin):
    from saw.llm import model_packs
    from saw.storage.db import session_scope
    with session_scope() as s:
        s.add(model_packs.LocalModelSelection(id=1, pack_id="missing", epoch=3))
    with pytest.raises(ValueError, match="model_active_registration_missing"):
        model_packs.selected_provider()


def test_active_epoch_is_restored_from_database(admin, tmp_path, monkeypatch):
    from saw.llm import model_packs
    settings = configure(tmp_path)
    folder, _ = pack_fixture(Path(settings.llm_models_root))
    assert admin.post("/admin/local-models/validate", json={"pack_id": folder.name}).status_code == 200
    monkeypatch.setattr(model_packs, "probe_pack", lambda *_: {"actual_inference": "EXECUTED"})
    assert admin.post("/admin/local-models/activate", json={"pack_id": folder.name, "reason": "synthetic restart test"}).status_code == 200
    provider = model_packs.selected_provider(settings)
    assert provider.pack_id == folder.name and provider.selection_epoch == 1
    assert provider.model == "test/synthetic-llama"

@pytest.mark.parametrize("change", ["revoked", "expired", "mfa"])
def test_session_changed_during_probe_does_not_activate(admin, tmp_path, monkeypatch, change):
    from datetime import timedelta
    from sqlalchemy import select
    from saw.llm import model_packs
    from saw.storage.db import session_scope, utcnow
    from saw.storage.models import User, UserSession
    settings = configure(tmp_path)
    folder, _ = pack_fixture(Path(settings.llm_models_root))
    assert admin.post("/admin/local-models/validate", json={"pack_id": folder.name}).status_code == 200

    def probe(*_):
        with session_scope() as s:
            user = s.scalar(select(User).where(User.username == "admin1"))
            session = s.scalar(select(UserSession).where(UserSession.user_id == user.id))
            if change == "revoked":
                session.revoked_at = utcnow()
            elif change == "expired":
                session.expires_at = utcnow() - timedelta(seconds=1)
            else:
                session.mfa_passed = False
        return {"actual_inference": "EXECUTED"}

    monkeypatch.setattr(model_packs, "probe_pack", probe)
    response = admin.post("/admin/local-models/activate", json={"pack_id": folder.name, "reason": "synthetic session test"})
    assert response.status_code == 400
    assert response.json()["detail"] == "model_management_session_changed"
    with session_scope() as s:
        assert model_packs.status(s)["active_pack_id"] is None
