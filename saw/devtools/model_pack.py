"""Build a separate offline model medium without executing model repository code."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

from saw.llm.model_packs import PACK_ID, RUNTIME_COMMIT, RUNTIME_VERSION, safe_path, validate_pack

MAX_BYTES = 20 * 1024**3


def _copy(source: Path, destination: Path, maximum: int) -> dict:
    source = safe_path(source)
    if not source.is_file() or not 0 < source.stat().st_size <= maximum:
        raise ValueError("model_source_missing_or_large")
    destination.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    copied = 0
    with source.open("rb") as reader, destination.open("xb") as writer:
        before = os.fstat(reader.fileno())
        while block := reader.read(8 * 1024**2):
            copied += len(block)
            if copied > maximum:
                raise ValueError("model_source_grew")
            digest.update(block)
            writer.write(block)
        writer.flush()
        os.fsync(writer.fileno())
        after = os.fstat(reader.fileno())
    current = safe_path(source).stat()
    fingerprint = lambda stat: (stat.st_ino, stat.st_size, stat.st_mtime_ns)
    if fingerprint(before) != fingerprint(after) or fingerprint(after) != fingerprint(current) or copied != before.st_size:
        raise ValueError("model_source_changed")
    return {"bytes": copied, "sha256": digest.hexdigest()}


def build_pack(*, inbox, pack_id: str, model_id: str, revision: str, kind: str,
               quantization: str, model, config, tokenizer, licenses: list) -> dict:
    """Publish only a complete validated pack; failed staging files are retained."""
    if not isinstance(pack_id, str) or not PACK_ID.fullmatch(pack_id):
        raise ValueError("model_pack_id_invalid")
    if kind not in {"BASE", "INSTRUCT"} or quantization not in {"Q4_K_M", "Q5_K_M", "Q8_0"}:
        raise ValueError("model_format_unsupported")
    if not isinstance(licenses, list) or not 1 <= len(licenses) <= 10:
        raise ValueError("model_license_evidence_required")
    sources = [("model.gguf", model, MAX_BYTES), ("config.json", config, 1024**2),
               ("tokenizer_config.json", tokenizer, 1024**2)]
    sources += [(f"licenses/{i:02d}.txt", path, 1024**2) for i, path in enumerate(licenses, 1)]
    # Check every caller-supplied path before creating anything in the inbox.
    for _, source, maximum in sources:
        path = safe_path(source)
        if not path.is_file() or not 0 < path.stat().st_size <= maximum:
            raise ValueError("model_source_missing_or_large")
    root = safe_path(inbox)
    root.mkdir(parents=True, exist_ok=True)
    destination = safe_path(root / pack_id)
    if destination.exists():
        raise ValueError("model_pack_exists")
    staging_root = root / (".stage-" + uuid.uuid4().hex)
    staging = staging_root / pack_id
    staging.mkdir(parents=True)
    entries = []
    total = 0
    for name, source, maximum in sources:
        entry = {"path": name, **_copy(Path(source), staging / name, maximum)}
        total += entry["bytes"]
        if total > MAX_BYTES:
            raise ValueError("model_inventory_too_large")
        entries.append(entry)
    manifest = {
        "schema": "saw.local-model-pack/1", "pack_id": pack_id, "model_id": model_id,
        "revision": revision, "checkpoint_kind": kind,
        "prompt_format": "base-completion-v1" if kind == "BASE" else "llama3-instruct-v1",
        "quantization": quantization, "model_file": "model.gguf", "config_file": "config.json",
        "tokenizer_file": "tokenizer_config.json", "license_files": [name for name, _, _ in sources[3:]],
        "license_status": "PENDING_REVIEW", "synthetic_only": True,
        "runtime": {"version": RUNTIME_VERSION, "commit": RUNTIME_COMMIT}, "files": entries,
    }
    (staging / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    result = validate_pack(pack_id, SimpleNamespace(llm_models_root=str(staging_root)))
    # Windows rename is atomic and fails when the destination already exists.
    # A staging directory is not a selectable pack and is never reused after failure.
    if destination.exists():
        raise ValueError("model_pack_exists")
    try:
        staging.rename(destination)
    except FileExistsError as exc:
        raise ValueError("model_pack_exists") from exc
    return {"pack_id": pack_id, "path": str(destination), "manifest_sha256": result["manifest_sha256"],
            "bytes": total, "status": "FILES_VERIFIED", "actual_inference": "NOT_RUN",
            "license_status": "PENDING_REVIEW", "synthetic_only": True}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="별도 반입할 모델 묶음을 만듭니다. 모델 코드는 실행하지 않습니다.")
    parser.add_argument("--inbox", required=True, type=Path, help="새 묶음을 저장할 절대 경로")
    parser.add_argument("--pack-id", required=True)
    parser.add_argument("--model-id", required=True, help="제작자/모델명")
    parser.add_argument("--revision", required=True, help="원본의 40자리 commit")
    parser.add_argument("--kind", required=True, choices=["BASE", "INSTRUCT"])
    parser.add_argument("--quantization", required=True, choices=["Q4_K_M", "Q5_K_M", "Q8_0"])
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--tokenizer", required=True, type=Path)
    parser.add_argument("--license", dest="licenses", required=True, action="append", type=Path)
    args = vars(parser.parse_args(argv))
    try:
        result = build_pack(**args)
    except (ValueError, OSError) as exc:
        # Never echo arbitrary file contents, source names, or platform error details.
        code = str(exc) if isinstance(exc, ValueError) and str(exc).startswith("model_") else "model_pack_io_error"
        print(json.dumps({"error": code, "published": False}), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
