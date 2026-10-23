"""Actual ZIP bytes are verified before private Golden previews or downloads."""
import hashlib
import io
import json
import stat
import zipfile

import pytest


def archive(*, extra=None, bad_hash=False, path="input/example.jsonl", symlink=False):
    data = '{"schema":"synthetic-input","value":"가상 자료"}\n'.encode()
    files = [{"path": path, "size_bytes": len(data),
              "sha256": ("0"*64 if bad_hash else hashlib.sha256(data).hexdigest()),
              "media_type": "application/x-ndjson"}]
    manifest = {"schema": "saw.golden.manifest.v2", "files": files,
                "uncompressed_bytes": len(data), "file_count": 1}
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as z:
        info = zipfile.ZipInfo(path)
        info.external_attr = ((stat.S_IFLNK if symlink else stat.S_IFREG) | 0o600) << 16
        z.writestr(info, data)
        z.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False).encode())
        if extra:
            z.writestr(extra, b"unlisted")
    stream.seek(0)
    return stream, manifest


def test_archive_verification_returns_exact_manifest_and_bounded_plain_text():
    from saw.knowledge.golden_archive import inspect_archive
    stream, manifest = archive()
    result = inspect_archive(stream, expected_manifest=manifest, holdout=True)
    assert result["manifest"] == manifest
    assert result["samples"][0]["content_text"].endswith('가상 자료"}\n')
    assert result["samples"][0]["truncated"] is False
    assert result["omitted"] == {"files": 0, "bytes": 0}


@pytest.mark.parametrize("options", [
    {"bad_hash": True}, {"extra": "answers/secret.json"},
    {"path": "../escape.json"}, {"path": "input\\escape.jsonl"},
    {"symlink": True}, {"path": "answers/label.jsonl"},
])
def test_archive_rejects_digest_inventory_paths_links_and_holdout_answers(options):
    from saw.knowledge.golden_archive import inspect_archive
    stream, _ = archive(**options)
    with pytest.raises(ValueError):
        inspect_archive(stream, holdout=True)


def test_archive_preview_is_utf8_bounded_and_explicit_about_omissions():
    from saw.knowledge.golden_archive import inspect_archive
    stream = io.BytesIO()
    data = ("한"*2000).encode()
    manifest = {"schema":"saw.golden.manifest.v2","files":[],
                "uncompressed_bytes": len(data)*6, "file_count":6}
    with zipfile.ZipFile(stream,"w",zipfile.ZIP_DEFLATED) as z:
        for number in range(6):
            name = f"evidence/{number}.json"
            z.writestr(name,data)
            manifest["files"].append({"path":name,"size_bytes":len(data),
                "sha256":hashlib.sha256(data).hexdigest(),"media_type":"application/json"})
        z.writestr("manifest.json",json.dumps(manifest).encode())
    stream.seek(0)
    result = inspect_archive(stream)
    assert len(result["samples"]) == 5
    assert all(item["preview_bytes"] == 4095 and item["truncated"] for item in result["samples"])
    assert result["omitted"] == {"files":1,"bytes":15525}


def test_archive_rejects_cancelled_or_oversized_uncompressed_input():
    from saw.knowledge.golden_archive import inspect_archive
    stream, _ = archive()
    with pytest.raises(ValueError, match="cancelled"):
        inspect_archive(stream,cancelled=lambda:True)
    stream = io.BytesIO()
    with zipfile.ZipFile(stream,"w",zipfile.ZIP_DEFLATED) as z:
        z.writestr("input/bomb.jsonl",b"x"*(20*1024*1024+1))
        z.writestr("manifest.json",b"{}")
    stream.seek(0)
    with pytest.raises(ValueError, match="limit"):
        inspect_archive(stream)
