"""Offline model-pack registry; no downloads, arbitrary code, or production adoption."""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path, PurePosixPath

from sqlalchemy import JSON, DateTime, Integer, String, select, update
from sqlalchemy.orm import Mapped, Session, mapped_column

from saw import container
from saw.core.application import audit
from saw.llm.gguf_metadata import validate_metadata
from saw.storage.db import Base, session_scope, utcnow

MODEL_ID = "fdtn-ai/Foundation-Sec-8B"
MODEL_REVISION = "9e6bb1f70b402e55bbf68cfd7abf88458daf09b3"
MODEL_SHA256 = "98989f9e89414f8607fe76727b46852a3ec6f3d534fc6f6259a50b02bf14e681"
RUNTIME_VERSION = "b11429"
RUNTIME_COMMIT = "d81235049384534c167caea52b85a694f6103d14"
LIMITS = {"threads": 4, "context": 1024, "max_new_tokens": 128, "max_seconds": 300,
          "max_memory_bytes": 8 * 1024**3, "max_output_bytes": 1024**2}
PACK_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
SHA256 = re.compile(r"[a-f0-9]{64}\Z")


class LocalModelPack(Base):
    __tablename__ = "ai_local_model_pack"
    pack_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    manifest_sha256: Mapped[str] = mapped_column(String(64))
    summary: Mapped[dict] = mapped_column(JSON)
    validated_by: Mapped[str] = mapped_column(String(36))
    validated_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)


class LocalModelSelection(Base):
    __tablename__ = "ai_local_model_selection"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    pack_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    epoch: Mapped[int] = mapped_column(Integer, default=0)


def safe_path(value) -> Path:
    path = Path(value)
    if not path.is_absolute() or str(value).startswith("\\\\") or "\0" in str(value):
        raise ValueError("model_path_invalid")
    if ":" in str(path)[len(path.drive):]:
        raise ValueError("model_path_invalid")
    for candidate in (path, *path.parents):
        if candidate.is_symlink() or candidate.is_junction():
            raise ValueError("model_path_link_rejected")
        try:
            if getattr(candidate.lstat(), "st_file_attributes", 0) & 0x400:
                raise ValueError("model_path_reparse_rejected")
        except FileNotFoundError:
            pass
    return path.resolve()


def _pairs(items):
    out = {}
    for key, value in items:
        if key in out:
            raise ValueError("model_json_duplicate")
        out[key] = value
    return out


def read_json(path: Path, maximum=1024**2, *, with_pin=False):
    path = safe_path(path)
    if not path.is_file() or path.stat().st_size > maximum:
        raise ValueError("model_metadata_missing_or_large")
    try:
        raw = path.read_bytes()
        value = json.loads(raw, object_pairs_hook=_pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("model_metadata_invalid") from exc
    if not isinstance(value, dict):
        raise ValueError("model_metadata_invalid")
    return (value, hashlib.sha256(raw).hexdigest()) if with_pin else value


def relative_file(root: Path, name: str) -> Path:
    if (not isinstance(name, str) or not name or "\\" in name or ":" in name
            or PurePosixPath(name).is_absolute() or any(x in ("", ".", "..") for x in name.split("/"))):
        raise ValueError("model_relative_path_invalid")
    result = safe_path(root / name)
    if not result.is_relative_to(root) or not result.is_file():
        raise ValueError("model_file_missing")
    return result


def verify_file(path: Path, pin: str, size: int, check=lambda: None):
    if path.stat().st_size != size:
        raise ValueError("model_file_size_mismatch")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(8 * 1024**2):
            check()
            digest.update(block)
    if digest.hexdigest() != pin:
        raise ValueError("model_file_hash_mismatch")


def _inventory(root, entries, *, maximum, check=lambda: None):
    if not isinstance(entries, list) or not 1 <= len(entries) <= 200:
        raise ValueError("model_inventory_invalid")
    files = {}
    total = 0
    for item in entries:
        if not isinstance(item, dict) or set(item) != {"path", "bytes", "sha256"}:
            raise ValueError("model_inventory_invalid")
        name, size, pin = item["path"], item["bytes"], item["sha256"]
        if (type(size) is not int or not 0 < size <= maximum or not isinstance(pin, str)
                or not SHA256.fullmatch(pin) or not isinstance(name, str) or name in files):
            raise ValueError("model_inventory_invalid")
        total += size
        if total > maximum:
            raise ValueError("model_inventory_too_large")
        path = relative_file(root, name)
        verify_file(path, pin, size, check)
        files[name] = item
    return files


def validate_pack(pack_id: str, settings=None, expected_hash: str | None = None, check=lambda: None) -> dict:
    if not isinstance(pack_id, str) or not PACK_ID.fullmatch(pack_id):
        raise ValueError("model_pack_id_invalid")
    settings = settings or container.get().settings
    configured = settings.llm_models_root
    if not configured:
        raise ValueError("model_inbox_not_configured")
    root = safe_path(safe_path(configured) / pack_id)
    manifest_path = root / "manifest.json"
    manifest, pin = read_json(manifest_path, with_pin=True)
    if expected_hash and pin != expected_hash:
        raise ValueError("model_manifest_changed_revalidate_required")
    keys = {"schema", "pack_id", "model_id", "revision", "checkpoint_kind", "prompt_format", "quantization",
            "model_file", "config_file", "tokenizer_file", "license_files", "license_status", "synthetic_only",
            "runtime", "files"}
    if (set(manifest) != keys or manifest["schema"] != "saw.local-model-pack/1"
            or manifest["pack_id"] != pack_id or manifest["synthetic_only"] is not True
            or not isinstance(manifest["model_id"], str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", manifest["model_id"])
            or len(manifest["model_id"]) > 64
            or not isinstance(manifest["revision"], str) or not re.fullmatch("[a-f0-9]{40}", manifest["revision"])
            or manifest["runtime"] != {"version": RUNTIME_VERSION, "commit": RUNTIME_COMMIT}
            or manifest["license_status"] not in {"PENDING_REVIEW", "APPROVED_INTERNAL"}
            or manifest["quantization"] not in {"Q4_K_M", "Q5_K_M", "Q8_0"}):
        raise ValueError("model_manifest_contract")
    kind, fmt = manifest["checkpoint_kind"], manifest["prompt_format"]
    if (kind, fmt) not in {("BASE", "base-completion-v1"), ("INSTRUCT", "llama3-instruct-v1")}:
        raise ValueError("model_prompt_format_unsupported")
    files = _inventory(root, manifest["files"], maximum=20 * 1024**3, check=check)
    licenses = manifest["license_files"]
    if (not isinstance(licenses, list) or not 1 <= len(licenses) <= 10
            or any(not isinstance(name, str) or name not in files for name in licenses)):
        raise ValueError("model_license_evidence_required")
    required = [manifest[key] for key in ("model_file", "config_file", "tokenizer_file")]
    if any(not isinstance(name, str) or name not in files for name in required) or len(set(required)) != 3:
        raise ValueError("model_required_file_missing")
    allowed = {".gguf", ".json", ".md", ".txt"}
    if any(Path(name).suffix.lower() not in allowed and name.upper() not in {"LICENSE", "NOTICE"} for name in files):
        raise ValueError("model_executable_or_unknown_file_rejected")
    if any(name.endswith(".gguf") and name != manifest["model_file"] for name in files):
        raise ValueError("model_multiple_weights_not_supported")
    config = read_json(root / manifest["config_file"])
    tokenizer = read_json(root / manifest["tokenizer_file"])
    if (config.get("architectures") != ["LlamaForCausalLM"] or config.get("bos_token_id") != 128000
            or type(config.get("vocab_size")) is not int or not 128256 <= config["vocab_size"] <= 128512):
        raise ValueError("model_architecture_or_tokenizer_unsupported")
    eos = config.get("eos_token_id")
    if (kind == "BASE" and (eos != 128001 or tokenizer.get("chat_template"))) or (
            kind == "INSTRUCT" and (eos not in (128009, [128001, 128008, 128009]) or not tokenizer.get("chat_template"))):
        raise ValueError("model_checkpoint_template_mismatch")
    model_file = root / manifest["model_file"]
    validate_metadata(model_file, manifest, config, tokenizer)
    if manifest["model_id"] == MODEL_ID and (manifest["revision"] != MODEL_REVISION or kind != "BASE"
            or manifest["quantization"] != "Q4_K_M" or files[manifest["model_file"]]["sha256"] != MODEL_SHA256
            or config["vocab_size"] != 128384):
        raise ValueError("foundation_model_identity_mismatch")
    # Every on-disk extra is rejected, including a DLL added beside the model.
    actual = set()
    for folder, dirs, names in os.walk(root, followlinks=False):
        for name in [*dirs, *names]:
            safe_path(Path(folder) / name)
        actual.update((Path(folder) / name).relative_to(root).as_posix() for name in names)
    if actual != {*files, "manifest.json"}:
        raise ValueError("model_pack_unlisted_files")
    summary = {key: manifest[key] for key in ("pack_id", "model_id", "revision", "checkpoint_kind",
                                            "prompt_format", "quantization", "license_status", "synthetic_only")}
    return {**summary, "manifest_sha256": pin, "status": "FILES_VERIFIED", "actual_inference": "NOT_RUN",
            "detail": "파일 무결성 확인 · 실제 실행/한국어 품질/운영 채택은 별도",
            "_root": root, "_manifest": manifest, "_files": files, "_config": config}


def runtime_spec(settings=None, check=lambda: None):
    settings = settings or container.get().settings
    if not settings.llm_runtime_root or not SHA256.fullmatch(settings.llm_runtime_manifest_sha256):
        raise ValueError("cpu_runtime_not_configured")
    root = safe_path(settings.llm_runtime_root)
    path = root / "runtime-manifest.json"
    spec, pin = read_json(path, with_pin=True)
    if pin != settings.llm_runtime_manifest_sha256:
        raise ValueError("cpu_runtime_manifest_hash_mismatch")
    if (set(spec) != {"schema", "version", "commit", "files"} or spec["schema"] != "saw.local-cpu-runtime/1"
            or spec["version"] != RUNTIME_VERSION or spec["commit"] != RUNTIME_COMMIT):
        raise ValueError("cpu_runtime_contract")
    files = _inventory(root, spec["files"], maximum=512 * 1024**2, check=check)
    if not {"llama-completion.exe", "llama-tokenize.exe"} <= files.keys():
        raise ValueError("cpu_runtime_executable_missing")
    actual = set()
    for folder, dirs, names in os.walk(root, followlinks=False):
        for name in [*dirs, *names]:
            safe_path(Path(folder) / name)
        actual.update((Path(folder) / name).relative_to(root).as_posix() for name in names)
    if actual != {*files, "runtime-manifest.json"}:
        raise ValueError("cpu_runtime_unlisted_files")
    return {"runtime_root": root, "runtime_files": {name: item["sha256"] for name, item in files.items()},
            "entries": files, "manifest": path}


def _public(row: LocalModelPack):
    return {**row.summary, "manifest_sha256": row.manifest_sha256,
            "validated_at": row.validated_at.isoformat() if row.validated_at else None}


def status(s: Session):
    settings = container.get().settings
    selection = s.get(LocalModelSelection, 1)
    return {"active_pack_id": selection.pack_id if selection else None, "synthetic_only": True,
            "runtime": {"configured": bool(settings.llm_runtime_root and settings.llm_runtime_manifest_sha256),
                        "verified": False, "version": RUNTIME_VERSION,
                        "detail": "실행 직전 runtime 전체 hash 재검증"}, "limits": LIMITS,
            "models": [_public(row) for row in s.scalars(select(LocalModelPack).order_by(LocalModelPack.pack_id))]}


def register(s: Session, p, pack_id):
    result = validate_pack(pack_id)
    selection = s.get(LocalModelSelection, 1)
    previous = s.get(LocalModelPack, pack_id)
    if (previous and selection and selection.pack_id == pack_id
            and previous.manifest_sha256 != result["manifest_sha256"]):
        raise ValueError("active_model_changed_deactivate_before_revalidation")
    summary = {key: value for key, value in result.items() if not key.startswith("_")}
    row = previous or LocalModelPack(pack_id=pack_id)
    row.summary, row.manifest_sha256 = summary, result["manifest_sha256"]
    row.validated_by, row.validated_at = p.user_id, utcnow()
    s.add(row)
    audit.record(s, "ai.model.validate", actor_id=p.user_id, actor_name=p.username, target_type="local_model",
                 target_id=pack_id, detail={"manifest_sha256": row.manifest_sha256, "actual_inference": "NOT_RUN"})
    return _public(row)


def probe_pack(settings, pack_id, pin):
    from saw.llm.cpu_provider import CPUProvider
    from saw.llm.providers import LLMRequest
    response = CPUProvider(settings, pack_id, pin).generate(LLMRequest(
        "Write one short observation. Do not claim attack success.",
        "Synthetic fixture: a WAF blocked a request. Backend execution is unknown.", max_tokens=32))
    if not response.text.strip():
        raise ValueError("cpu_empty_probe_output")
    return {"actual_inference": "EXECUTED"}


def _selection(s):
    row = s.get(LocalModelSelection, 1)
    return (row.pack_id, row.epoch) if row else (None, 0)


def _replace_selection(s, pack_id, epoch):
    dialect = s.get_bind().dialect.name
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    else:
        from sqlalchemy.dialects.sqlite import insert
    s.execute(insert(LocalModelSelection).values(id=1, pack_id=None, epoch=0).on_conflict_do_nothing())
    changed = s.execute(update(LocalModelSelection).where(LocalModelSelection.id == 1,
                        LocalModelSelection.epoch == epoch).values(pack_id=pack_id, epoch=epoch + 1))
    if changed.rowcount != 1:
        raise ValueError("model_selection_changed_retry")


def activate(s: Session, p, pack_id, reason, *, session_id=None):
    row = s.get(LocalModelPack, pack_id)
    if row is None:
        raise ValueError("model_pack_not_validated")
    previous, epoch = _selection(s)
    settings = container.get().settings
    pin = row.manifest_sha256
    # Native work must not keep the request's SQLite read transaction open.
    s.commit()
    validate_pack(pack_id, settings, pin)
    result = probe_pack(settings, pack_id, pin)
    s.expire_all()
    from saw.core.application.identity import principal_of
    from saw.core.security.authz import has_permission
    from saw.storage.models import User, UserSession
    current_user = s.get(User, p.user_id)
    if current_user is None or current_user.status != "active" or not has_permission(principal_of(current_user), "ai.models.manage"):
        raise ValueError("model_management_permission_changed")
    if session_id:
        from datetime import UTC
        current_session = s.get(UserSession, session_id)
        if (current_session is None or current_session.user_id != p.user_id
                or current_session.revoked_at is not None or not current_session.mfa_passed
                or current_session.expires_at.replace(tzinfo=UTC) <= utcnow()):
            raise ValueError("model_management_session_changed")
    row = s.get(LocalModelPack, pack_id)
    if row is None or row.manifest_sha256 != pin:
        raise ValueError("model_registration_changed_retry")
    if result.get("actual_inference") != "EXECUTED":
        raise ValueError("cpu_probe_not_executed")
    _replace_selection(s, pack_id, epoch)
    row.summary = {**row.summary, "actual_inference": "EXECUTED"}
    audit.record(s, "ai.model.activate", actor_id=p.user_id, actor_name=p.username, target_type="local_model",
                 target_id=pack_id, detail={"manifest_sha256": row.manifest_sha256, "previous_pack_id": previous,
                                           "reason": reason, "synthetic_only": True, "quality_adopted": False})
    return {"active_pack_id": pack_id, "previous_pack_id": previous,
            "actual_inference": "EXECUTED", "quality_adopted": False}


def deactivate(s: Session, p, reason):
    previous, epoch = _selection(s)
    _replace_selection(s, None, epoch)
    audit.record(s, "ai.model.deactivate", actor_id=p.user_id, actor_name=p.username, target_type="local_model",
                 target_id=previous or "", detail={"reason": reason})
    return {"active_pack_id": None}


def selected_provider(settings=None):
    from saw.llm.cpu_provider import CPUProvider
    with session_scope() as s:
        selected = s.get(LocalModelSelection, 1)
        row = s.get(LocalModelPack, selected.pack_id) if selected and selected.pack_id else None
        if row is None:
            if selected and selected.pack_id:
                raise ValueError("model_active_registration_missing")
            return None
        provider = CPUProvider(settings or container.get().settings, row.pack_id, row.manifest_sha256, row.summary)
        provider.selection_epoch = selected.epoch
        return provider