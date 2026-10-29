"""Validate the stored ZIP itself before publishing or showing a Golden artifact."""
from __future__ import annotations

import hashlib
import json
import re
import stat
import zipfile

MAX_BYTES = 20 * 1024 * 1024
MAX_FILES = 1024
MAX_MANIFEST_BYTES = 512 * 1024
SAFE_PATH = re.compile(r"(?:README\.md|FIELD-DICTIONARY\.md|METHODOLOGY\.md|DATASET\.json|LIMITS\.md|manifest\.json|(?:schema|evidence|answers)/[a-zA-Z0-9_.-]+\.json|(?:input|answers|conversion)/[a-zA-Z0-9_.-]+\.jsonl)\Z")
SHA = re.compile(r"[a-f0-9]{64}\Z")


def _unique_pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("golden_archive_duplicate_json_key")
        result[key] = value
    return result


def _check(cancelled):
    if cancelled():
        raise ValueError("golden_archive_cancelled")


def _read(z, info, cancelled):
    if info.file_size > MAX_BYTES:
        raise ValueError("golden_archive_size_limit")
    data = bytearray()
    with z.open(info) as stream:
        while block := stream.read(65536):
            _check(cancelled)
            data.extend(block)
            if len(data) > MAX_BYTES or len(data) > info.file_size:
                raise ValueError("golden_archive_size_limit")
    if len(data) != info.file_size:
        raise ValueError("golden_archive_size_mismatch")
    return bytes(data)


def inspect_archive(stream, *, expected_manifest=None, holdout=False, cancelled=lambda: False):
    """Return bounded escaped-by-consumer text, never an unverified archive URL."""
    _check(cancelled)
    stream.seek(0, 2)
    if stream.tell() > MAX_BYTES:
        raise ValueError("golden_archive_size_limit")
    stream.seek(0)
    try:
        with zipfile.ZipFile(stream) as z:
            entries = z.infolist()
            if not entries or len(entries) > MAX_FILES:
                raise ValueError("golden_archive_file_limit")
            if z.comment or sum(item.file_size for item in entries) > MAX_BYTES:
                raise ValueError("golden_archive_size_limit")
            names = [item.filename for item in entries]
            if len(set(names)) != len(names) or "manifest.json" not in names:
                raise ValueError("golden_archive_inventory_mismatch")
            for item in entries:
                _check(cancelled)
                mode = item.external_attr >> 16
                if (not SAFE_PATH.fullmatch(item.filename) or item.is_dir()
                        or item.flag_bits & 1 or item.comment
                        or stat.S_IFMT(mode) not in (0, stat.S_IFREG) or mode & 0o111):
                    raise ValueError("golden_archive_unsafe_entry")
                if holdout and item.filename.startswith(("answers/", "conversion/")):
                    raise ValueError("golden_archive_holdout_answers")
            info = z.getinfo("manifest.json")
            if info.file_size > MAX_MANIFEST_BYTES:
                raise ValueError("golden_archive_manifest_limit")
            manifest = json.loads(_read(z, info, cancelled).decode("utf-8"),
                                  object_pairs_hook=_unique_pairs)
            if not isinstance(manifest, dict) or manifest.get("schema") != "saw.golden.manifest.v2":
                raise ValueError("golden_archive_manifest_schema")
            files = manifest.get("files")
            if not isinstance(files, list) or len(files) != len(entries) - 1:
                raise ValueError("golden_archive_inventory_mismatch")
            listed = []
            for item in files:
                if (not isinstance(item, dict) or not isinstance(item.get("path"), str)
                        or type(item.get("size_bytes")) is not int or item["size_bytes"] < 0
                        or not isinstance(item.get("sha256"), str) or not SHA.fullmatch(item["sha256"])
                        or not isinstance(item.get("media_type"), str)):
                    raise ValueError("golden_archive_manifest_entry")
                listed.append(item["path"])
            if len(set(listed)) != len(listed) or set(listed) != set(names) - {"manifest.json"}:
                raise ValueError("golden_archive_inventory_mismatch")
            total = sum(item["size_bytes"] for item in files)
            if (type(manifest.get("file_count")) is not int or manifest["file_count"] != len(files)
                    or type(manifest.get("uncompressed_bytes")) is not int
                    or manifest["uncompressed_bytes"] != total):
                raise ValueError("golden_archive_inventory_mismatch")
            if expected_manifest is not None and manifest != expected_manifest:
                raise ValueError("golden_archive_manifest_changed")
            samples = []
            preview_bytes = 0
            ordered = sorted(files, key=lambda item: (
                0 if item["path"].startswith("input/") else
                1 if item["path"].startswith("evidence/") else 2, item["path"]))
            for item in ordered:
                _check(cancelled)
                data = _read(z, z.getinfo(item["path"]), cancelled)
                if len(data) != item["size_bytes"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
                    raise ValueError("golden_archive_digest_mismatch")
                data.decode("utf-8")
                if len(samples) < 5:
                    text = data[:4096].decode("utf-8", errors="ignore")
                    size = len(text.encode("utf-8"))
                    samples.append({"path": item["path"], "content_text": text,
                                    "bytes_total": len(data), "preview_bytes": size,
                                    "truncated": size < len(data)})
                    preview_bytes += size
            _check(cancelled)
            return {"manifest": manifest, "samples": samples,
                    "omitted": {"files": len(files)-len(samples), "bytes": total-preview_bytes},
                    "limits": ["bounded_plain_text_preview", "pseudonymization_is_not_anonymization"]}
    except (zipfile.BadZipFile, UnicodeError, json.JSONDecodeError, KeyError) as exc:
        raise ValueError("golden_archive_invalid") from exc
    finally:
        stream.seek(0)
