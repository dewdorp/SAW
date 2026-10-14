"""The offline install media rejects incomplete, changed and unsafe input."""
from __future__ import annotations
import json
import subprocess
from pathlib import Path
import pytest
from saw.devtools.release_manifest import BundleError, inventory, seal, verify
ROOT = Path(__file__).resolve().parents[2]
def minimal(root):
    from saw.devtools.release_manifest import REQUIRED
    root.mkdir()
    for rel in REQUIRED.values():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"synthetic")
    return root
def test_complete_media_is_sealed_and_unchanged(tmp_path):
    root = minimal(tmp_path / "bundle")
    seal(root, {"test": "synthetic"})
    assert verify(root)["file_count"] == len(inventory(root))
@pytest.mark.parametrize("case", ["missing", "changed", "extra", "required_removed"])
def test_media_closure_fails_closed(tmp_path, case):
    root = minimal(tmp_path / "bundle")
    seal(root, {})
    path = root / "app/apps/web/dist/index.html"
    if case == "missing": path.unlink()
    elif case == "changed": path.write_bytes(b"tampered")
    elif case == "extra": (root / "unexpected.dll").write_bytes(b"unexpected")
    else:
        doc = json.loads((root / "release-manifest.json").read_text())
        doc["files"] = [f for f in doc["files"] if f["path"] != "app/apps/web/dist/index.html"]
        path.unlink()
        (root / "release-manifest.json").write_text(json.dumps(doc))
    with pytest.raises(BundleError): verify(root)
@pytest.mark.parametrize("rel", ["../escape", "C:/outside", "a/../b", "a:stream", "a/CON.txt", "a/trailing.", "a//b"])
def test_manifest_path_cannot_escape_or_alias(tmp_path, rel):
    root = minimal(tmp_path / "bundle")
    seal(root, {})
    p = root / "release-manifest.json"
    doc = json.loads(p.read_text())
    doc["files"][0]["path"] = rel
    p.write_text(json.dumps(doc))
    with pytest.raises(BundleError): verify(root)
@pytest.mark.parametrize("rel", ["app/.env", "app/var/items.csv", "models/a.gguf", "app/secrets/test.txt", "model.safetensors"])
def test_private_state_and_weights_never_enter_inventory(tmp_path, rel):
    root = minimal(tmp_path / "bundle")
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"synthetic")
    with pytest.raises(BundleError): seal(root, {})
@pytest.mark.skipif(__import__("os").name != "nt", reason="PowerShell 5.1 verifier")
def test_powershell_verifier_agrees_without_python(tmp_path):
    root = minimal(tmp_path / "bundle")
    seal(root, {})
    cmd = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
           str(ROOT / "deploy/windows/verify-bundle.ps1"), "-BundleDir", str(root)]
    ok = subprocess.run(cmd, capture_output=True, timeout=30)
    assert ok.returncode == 0, (ok.stdout + ok.stderr).decode(errors="replace")
    (root / "app/apps/web/dist/index.html").write_bytes(b"tampered")
    bad = subprocess.run(cmd, capture_output=True, timeout=30)
    assert bad.returncode != 0
def test_installer_cannot_skip_manifest_and_cannot_download():
    text = (ROOT / "deploy/windows/install.ps1").read_text(encoding="utf-8-sig")
    assert "verify-bundle.ps1" in text
    assert "Invoke-WebRequest" not in text
    assert "python-3.12.10-embed-amd64.zip" in text
    assert "--no-index" in text
    assert "PostgresPort" in text and "OpenSearchTransportPort" in text


def test_public_guides_are_required_and_copied_with_start_here(tmp_path, monkeypatch):
    from saw.devtools import build_release
    source = tmp_path / "source"
    out = tmp_path / "media"
    for rel in build_release.PUBLIC_DOCS:
        path = source / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rel, encoding="utf-8")
    monkeypatch.setattr(build_release, "ROOT", source)
    build_release.copy_public_guides(out)
    assert (out / "START-HERE.md").read_text() == "docs/OFFLINE-RELEASE-2026-10-12.md"
    assert all((out / "app" / rel).is_file() for rel in build_release.PUBLIC_DOCS)
    (source / build_release.PUBLIC_DOCS[-1]).unlink()
    with pytest.raises(BundleError, match="public guide missing"):
        build_release.copy_public_guides(tmp_path / "incomplete")


def test_source_assembly_ships_guidance_rules_but_not_unlisted_data(tmp_path, monkeypatch):
    from saw.devtools import build_release
    source = tmp_path / "source"
    files = {
        "saw/core/application/guidance.py": "# synthetic module",
        "saw/core/application/guidance_rules.yaml": "version: test",
        "saw/content_packages/example.py": "# synthetic example",
        "saw/core/application/private.json": "synthetic private state",
        "saw/.env": "synthetic configuration",
        "saw/__pycache__/cache.py": "synthetic cache",
    }
    for rel, content in files.items():
        path = source / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    monkeypatch.setattr(build_release, "ROOT", source)
    out = tmp_path / "media"
    build_release.copy_app_sources(out)
    shipped = {p.relative_to(out / "app").as_posix() for p in (out / "app").rglob("*") if p.is_file()}
    assert shipped == set(list(files)[:3])
    assert (out / "app/saw/core/application/guidance_rules.yaml").read_text() == "version: test"
