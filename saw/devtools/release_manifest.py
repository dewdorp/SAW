"""Create and verify complete offline media without executing bundled code."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
from pathlib import Path

REQUIRED = {
    "native_manifest": "llm-runtime/runtime-manifest.json",
    "native_completion": "llm-runtime/llama-completion.exe",
    "native_tokenizer": "llm-runtime/llama-tokenize.exe",
    "native_license": "llm-runtime/licenses/LLAMA-MIT.txt",
    "native_exception": "llm-runtime/licenses/GCC-RUNTIME-EXCEPTION.txt",
    "installer": "install.ps1", "verifier": "verify-bundle.ps1",
    "python": "python/python-3.12.10-embed-amd64.zip",
    "postgresql": "postgresql/postgresql-16.15-1-windows-x64-binaries.zip",
    "opensearch": "opensearch/opensearch-2.19.6-windows-x64.zip",
    "nori": "opensearch/analysis-nori-2.19.6.zip", "winsw": "winsw/WinSW-x64.exe",
    "pip": "bootstrap/pip-25.1.1-py3-none-any.whl",
    "ui": "app/apps/web/dist/index.html", "requirements": "app/deploy/windows/requirements.txt",
}
DESKTOP_UPDATE_REQUIRED = {
    "desktop_launcher": "UPDATE-SAW.cmd",
    "desktop_ui": "update-ui.ps1",
    "desktop_ui_module": "update-ui.psm1",
    "desktop_worker": "update-worker.ps1",
    "desktop_app_launcher": "app/deploy/windows/UPDATE-SAW.cmd",
    "desktop_app_ui": "app/deploy/windows/update-ui.ps1",
    "desktop_app_ui_module": "app/deploy/windows/update-ui.psm1",
    "desktop_app_worker": "app/deploy/windows/update-worker.ps1",
    "desktop_controller": "app/saw/devtools/desktop_update.py",
}
EXCLUDED = {"release-manifest.json", "SHA256SUMS.txt"}
class BundleError(ValueError):
    """Media is incomplete, unsafe, or changed."""

def safe_relative(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or value.startswith("/"):
        raise BundleError("invalid manifest path")
    parts = value.split("/")
    for part in parts:
        if part in {"", ".", ".."} or any(ord(c) < 32 for c in part) or any(c in part for c in ':*?"<>|'):
            raise BundleError("unsafe manifest path")
        if part.endswith((".", " ")) or re.match(r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)", part, re.I):
            raise BundleError("aliased manifest path")
    return value

def public_path(value: str) -> None:
    parts = value.lower().split("/")
    if any(p in {".env", "var", "secrets", ".git", ".qa", "offline-bundle", "node_modules"} for p in parts):
        raise BundleError("private state forbidden in media")
    if Path(value).suffix.lower() in {".gguf", ".safetensors", ".pt", ".ckpt", ".db", ".sqlite"}:
        raise BundleError("weights or stores forbidden in media")

def digest(path: Path) -> str:
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()

def inventory(root: Path) -> list[dict]:
    root = Path(root).absolute()
    if not root.is_dir() or root.is_symlink() or any(getattr(p.lstat(), "st_file_attributes", 0) & 0x400 for p in (root, *root.parents)):
        raise BundleError("invalid media directory")
    rows = []
    seen = set()
    def enumeration_failed(_error):
        raise BundleError("Cannot enumerate every media directory; complete verification is required") from None

    for parent, dirs, files in os.walk(root, followlinks=False, onerror=enumeration_failed):
        for name in dirs + files:
            p = Path(parent) / name
            if p.is_symlink() or getattr(p.lstat(), "st_file_attributes", 0) & 0x400:
                raise BundleError("links or reparse points forbidden")
        for name in files:
            p = Path(parent) / name
            rel = safe_relative(p.relative_to(root).as_posix())
            if rel in EXCLUDED:
                continue
            public_path(rel)
            if rel.casefold() in seen:
                raise BundleError("duplicate case-insensitive path")
            seen.add(rel.casefold())
            rows.append({"path": rel, "bytes": p.stat().st_size, "sha256": digest(p)})
    return sorted(rows, key=lambda r: r["path"])

def _required(rows, metadata=None):
    found = {r["path"] for r in rows}
    required = dict(REQUIRED)
    if not set(required.values()) <= found:
        raise BundleError("required payload missing")
    metadata = {} if metadata is None else metadata
    if not isinstance(metadata, dict):
        raise BundleError("invalid release metadata")
    if "desktop_update_ui" in metadata:
        version = metadata["desktop_update_ui"]
        if type(version) is not int or version != 1:
            raise BundleError("unsupported desktop update contract")
        if not set(DESKTOP_UPDATE_REQUIRED.values()) <= found:
            raise BundleError("desktop update payload missing")
        required.update(DESKTOP_UPDATE_REQUIRED)
    return required

def seal(root: Path, metadata: dict) -> dict:
    root = Path(root)
    rows = inventory(root)
    required = _required(rows, metadata)
    doc = {"schema": "saw.offline-release/1", "model_weights_included": False,
           "required": required, "metadata": metadata, "files": rows}
    (root / "release-manifest.json").write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    sums = rows + [{"path": "release-manifest.json", "sha256": digest(root / "release-manifest.json")}]
    (root / "SHA256SUMS.txt").write_text("".join(f"{r['sha256']} *{r['path']}\n" for r in sums), encoding="ascii")
    return verify(root)

def verify(root: Path) -> dict:
    root = Path(root)
    try:
        doc = json.loads((root / "release-manifest.json").read_text(encoding="utf-8-sig"))
        if doc["schema"] != "saw.offline-release/1" or doc["model_weights_included"] is not False:
            raise BundleError("unsupported manifest")
        expected = doc["files"]
        if not isinstance(expected, list):
            raise BundleError("invalid files")
        seen = set()
        for r in expected:
            rel = safe_relative(r["path"])
            public_path(rel)
            if rel in EXCLUDED or rel.casefold() in seen or type(r["bytes"]) is not int or r["bytes"] < 0 or not re.fullmatch(r"[0-9a-f]{64}", r["sha256"]):
                raise BundleError("invalid file entry")
            seen.add(rel.casefold())
        _required(expected, doc.get("metadata"))
        actual = inventory(root)
        if actual != sorted(expected, key=lambda r: r["path"]):
            raise BundleError("media missing, changed, or contains unexpected files")
        return {"verified": True, "file_count": len(actual), "bytes": sum(r["bytes"] for r in actual),
                "manifest_sha256": digest(root / "release-manifest.json")}
    except (KeyError, TypeError, OSError, json.JSONDecodeError) as e:
        raise BundleError("invalid release media") from e

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["seal", "verify"])
    parser.add_argument("root", type=Path)
    parser.add_argument("--metadata", type=Path)
    args = parser.parse_args()
    md = json.loads(args.metadata.read_text(encoding="utf-8")) if args.metadata else {}
    print(json.dumps(seal(args.root, md) if args.action == "seal" else verify(args.root)))
if __name__ == "__main__":
    main()
