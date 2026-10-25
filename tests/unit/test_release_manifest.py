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
    cmd = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "RemoteSigned", "-File",
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
    original_guide = ("# 합성 설치 안내\n\n원본 안내 본문을 보존합니다.\n"
                      "[전체 설치](INSTALL-WINDOWS.md)\n"
                      "[외부 문서](https://example.invalid/guide)\n"
                      "[현재 절](#확인)\n")
    (source / "docs/INSTALL-RECOVERY-2026-10-18.md").write_text(original_guide, encoding="utf-8")
    monkeypatch.setattr(build_release, "ROOT", source)
    build_release.copy_public_guides(out)
    updater_preface = ("# 기존 설치 업데이트\n\n"
                       "기존 계정과 자료를 유지하려면 UPDATE-SAW.cmd를 실행하고 "
                       "[9항목 점검·복구 안내](app/docs/UPDATER-STABILIZATION-GUIDE-20261019.html)를 확인하세요. "
                       "GitHub Source code ZIP은 설치 매체가 아닙니다.\n\n")
    rebased_guide = original_guide.replace("](INSTALL-WINDOWS.md)", "](app/docs/INSTALL-WINDOWS.md)")
    assert (out / "START-HERE.md").read_text(encoding="utf-8") == updater_preface + rebased_guide
    assert (out / "app/docs/INSTALL-RECOVERY-2026-10-18.md").read_text(encoding="utf-8") == original_guide
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


def test_current_offline_guides_are_included_for_installed_users(tmp_path):
    from saw.devtools import build_release
    build_release.copy_public_guides(tmp_path / "media")
    docs = tmp_path / "media/app/docs"
    for name in ("OFFLINE-RELEASE-2026-10-17.md", "OFFLINE-UPDATE-GUIDE.md",
                 "MODEL-8B-KOREAN-SECURITY-GUIDE.md", "STATISTICS-TEMPORAL-GUIDE.md",
                 "ASSISTANT-EVIDENCE-GUIDE.md", "ADMIN-RULES-ANALYTICS-GUIDE.md"):
        assert (docs / name).is_file(), name


def test_shipped_guides_keep_local_links_inside_complete_media(tmp_path):
    import re
    from saw.devtools import build_release
    root = tmp_path / "media"
    build_release.copy_app_sources(root)
    build_release.copy_windows_sources(root)
    build_release.copy_public_guides(root)
    for source in root.rglob("*.md"):
        for link in re.findall(r"\]\(([^)]+)\)", source.read_text(encoding="utf-8")):
            if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", link) or link.startswith("#"):
                continue
            relative = link.split("#")[0].split(' "')[0].strip("<>")
            target = (source.parent / relative).resolve()
            assert target.is_relative_to(root.resolve()), (source.name, relative)
            assert target.is_file(), (source.name, relative)

def test_inventory_directory_error_fails_closed_without_exposing_error_path(tmp_path, monkeypatch):
    from saw.devtools import release_manifest as manifest

    def inaccessible(path, *, followlinks=False, onerror=None):
        yield str(path), [], []
        if onerror is not None:
            onerror(PermissionError("synthetic confidential filename"))

    monkeypatch.setattr(manifest.os, "walk", inaccessible)
    with pytest.raises(BundleError, match="enumerat") as caught:
        inventory(tmp_path)
    assert "synthetic confidential filename" not in str(caught.value)


def _set_native_list_denial(path, denied):
    literal = "'" + str(path).replace("'", "''") + "'"
    operation = "AddAccessRule" if denied else "RemoveAccessRuleSpecific"
    script = f"""
$ErrorActionPreference='Stop'
$path={literal}
$acl=[IO.Directory]::GetAccessControl($path, [Security.AccessControl.AccessControlSections]::Access)
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'ListDirectory','None','None','Deny')
$acl.{operation}($rule)
[IO.Directory]::SetAccessControl($path,$acl)
"""
    result = subprocess.run(["powershell.exe", "-NoProfile", "-Command", script],
                            capture_output=True, timeout=30, check=False)
    assert result.returncode == 0, (result.stdout + result.stderr).decode(errors="replace")


@pytest.mark.skipif(__import__("os").name != "nt", reason="Windows directory-list denial")
@pytest.mark.parametrize("operation", ["inventory", "seal", "verify"])
def test_native_unlisted_inaccessible_payload_cannot_be_silently_omitted(tmp_path, operation):
    root = minimal(tmp_path / "bundle")
    seal(root, {"test": "synthetic"})
    manifest_before = (root / "release-manifest.json").read_bytes()
    sums_before = (root / "SHA256SUMS.txt").read_bytes()
    blocked = root / "optional-payload"
    blocked.mkdir()
    payload = blocked / "unlisted.dll"
    payload.write_bytes(b"synthetic unlisted payload")
    _set_native_list_denial(blocked, True)
    try:
        with pytest.raises(PermissionError):
            list(blocked.iterdir())
        # Deny only LIST on the directory; this is not a file-read or missing-required-file error.
        assert payload.read_bytes() == b"synthetic unlisted payload"
        with pytest.raises(BundleError, match="enumerat"):
            if operation == "inventory":
                inventory(root)
            elif operation == "seal":
                seal(root, {})
            else:
                verify(root)
        assert (root / "release-manifest.json").read_bytes() == manifest_before
        assert (root / "SHA256SUMS.txt").read_bytes() == sums_before
    finally:
        _set_native_list_denial(blocked, False)


# Literal fixture paths keep the new-media contract independent of implementation constants.
DESKTOP_UPDATE_PATHS = (
    "UPDATE-SAW.cmd", "update-ui.ps1", "update-ui.psm1", "update-worker.ps1",
    "app/deploy/windows/UPDATE-SAW.cmd", "app/deploy/windows/update-ui.ps1",
    "app/deploy/windows/update-ui.psm1", "app/deploy/windows/update-worker.ps1",
    "app/saw/devtools/desktop_update.py",
)

def desktop_media(root):
    minimal(root)
    for relative in DESKTOP_UPDATE_PATHS:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic desktop payload: " + relative, encoding="utf-8")
    return root

def run_powershell_verifier(root):
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "RemoteSigned", "-File",
         str(ROOT / "deploy/windows/verify-bundle.ps1"), "-BundleDir", str(root)],
        capture_output=True, timeout=30, check=False,
    )

@pytest.mark.parametrize("missing", DESKTOP_UPDATE_PATHS)
def test_desktop_contract_cannot_seal_missing_ui_or_controller(tmp_path, missing):
    root = desktop_media(tmp_path / "new")
    (root / missing).unlink()
    with pytest.raises(BundleError, match="desktop update"):
        seal(root, {"desktop_update_ui": 1})
    assert not (root / "release-manifest.json").exists()

def test_desktop_contract_records_required_payload_and_old_baseline_stays_usable(tmp_path):
    from saw.devtools import offline_update
    modern = desktop_media(tmp_path / "modern")
    seal(modern, {"desktop_update_ui": 1})
    document = json.loads((modern / "release-manifest.json").read_text(encoding="utf-8"))
    assert set(DESKTOP_UPDATE_PATHS) <= set(document["required"].values())
    original = minimal(tmp_path / "original")
    seal(original, {"source_commit": "synthetic legacy revision"})
    installed = tmp_path / "installed"
    installed.mkdir()
    baseline = offline_update._baseline(installed, original)
    assert baseline["metadata"] == {"source_commit": "synthetic legacy revision"}
    assert verify(original)["verified"] is True

@pytest.mark.parametrize("value", [0, 2, True, "1", 1.0, None])
def test_desktop_contract_rejects_unknown_or_ambiguous_versions(tmp_path, value):
    root = desktop_media(tmp_path / "new")
    with pytest.raises(BundleError, match="desktop update"):
        seal(root, {"desktop_update_ui": value})
    assert not (root / "release-manifest.json").exists()

@pytest.mark.parametrize("change", ["missing", "modified", "unlisted", "removed_from_manifest"])
@pytest.mark.parametrize("validator", ["python", "powershell"])
def test_desktop_payload_changes_are_refused_by_both_validators(tmp_path, change, validator):
    if validator == "powershell" and __import__("os").name != "nt":
        pytest.skip("PowerShell 5.1 media validator")
    root = desktop_media(tmp_path / "new")
    seal(root, {"desktop_update_ui": 1})
    target = root / "update-ui.psm1"
    if change == "missing":
        target.unlink()
    elif change == "modified":
        target.write_text("changed desktop code", encoding="utf-8")
    elif change == "unlisted":
        (root / "last-used-path.json").write_text("synthetic unwanted UI state", encoding="utf-8")
    else:
        target.unlink()
        path = root / "release-manifest.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["files"] = [row for row in document["files"] if row["path"] != "update-ui.psm1"]
        # Changing the manifest's advisory table must not bypass the verifier's known contract.
        document["required"] = {key: value for key, value in document["required"].items()
                                if value != "update-ui.psm1"}
        path.write_text(json.dumps(document), encoding="utf-8")
    if validator == "python":
        with pytest.raises(BundleError):
            verify(root)
    else:
        assert run_powershell_verifier(root).returncode != 0

@pytest.mark.skipif(__import__("os").name != "nt", reason="PowerShell 5.1 media validator")
@pytest.mark.parametrize("profile", ["legacy", "desktop", "unknown", "string_version"])
def test_desktop_and_legacy_media_validation_agrees_with_powershell(tmp_path, profile):
    root = desktop_media(tmp_path / "new") if profile != "legacy" else minimal(tmp_path / "old")
    seal(root, {} if profile == "legacy" else {"desktop_update_ui": 1})
    if profile in ("unknown", "string_version"):
        path = root / "release-manifest.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["metadata"]["desktop_update_ui"] = 2 if profile == "unknown" else "1"
        path.write_text(json.dumps(document), encoding="utf-8")
    result = run_powershell_verifier(root)
    assert (result.returncode == 0) is (profile in ("legacy", "desktop")), (result.stdout + result.stderr).decode(errors="replace")

def windows_source_fixture(source, module):
    names = set(module.WINDOWS_FILES) | set(DESKTOP_UPDATE_PATHS[:4])
    for name in names:
        path = source / "deploy/windows" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic Windows source: " + name, encoding="utf-8")

def test_desktop_windows_sources_ship_in_both_media_and_app_locations(tmp_path, monkeypatch):
    from saw.devtools import build_release
    source, out = tmp_path / "source", tmp_path / "out"
    windows_source_fixture(source, build_release)
    (source / "deploy/windows/unlisted-local.ps1").write_text("not approved for shipping", encoding="utf-8")
    monkeypatch.setattr(build_release, "ROOT", source)
    build_release.copy_windows_sources(out)
    for name in DESKTOP_UPDATE_PATHS[:4]:
        expected = ("synthetic Windows source: " + name).encode("utf-8")
        assert (out / name).read_bytes() == expected
        assert (out / "app/deploy/windows" / name).read_bytes() == expected
    assert not (out / "unlisted-local.ps1").exists()
    assert not (out / "app/deploy/windows/unlisted-local.ps1").exists()

@pytest.mark.parametrize("missing", DESKTOP_UPDATE_PATHS[:4])
def test_desktop_windows_source_omission_fails_build(tmp_path, monkeypatch, missing):
    from saw.devtools import build_release
    source = tmp_path / "source"
    windows_source_fixture(source, build_release)
    (source / "deploy/windows" / missing).unlink()
    monkeypatch.setattr(build_release, "ROOT", source)
    with pytest.raises(FileNotFoundError):
        build_release.copy_windows_sources(tmp_path / "out")

def test_desktop_operator_guide_is_copied_by_public_allowlist(tmp_path, monkeypatch):
    from saw.devtools import build_release
    source, out = tmp_path / "source", tmp_path / "out"
    required_guide = "docs/DOUBLE-CLICK-UPDATE-GUIDE.md"
    for relative in set(build_release.PUBLIC_DOCS) | {required_guide}:
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("public example: " + relative, encoding="utf-8")
    monkeypatch.setattr(build_release, "ROOT", source)
    build_release.copy_public_guides(out)
    assert (out / "app" / required_guide).read_text(encoding="utf-8") == "public example: " + required_guide


@pytest.mark.parametrize("version",[None,True,0,2,"1"])
def test_inspection_contract_rejects_invalid_version(version):
    from saw.devtools.release_manifest import _required, REQUIRED, INSPECTION_REQUIRED
    rows=[{"path":p} for p in {*REQUIRED.values(),*INSPECTION_REQUIRED.values()}]
    with pytest.raises(BundleError):
        _required(rows,{"updater_inspection":version})

def test_inspection_contract_requires_diagnostics_and_native_checker():
    from saw.devtools.release_manifest import _required, REQUIRED, INSPECTION_REQUIRED
    rows=[{"path":p} for p in REQUIRED.values()]
    with pytest.raises(BundleError):
        _required(rows,{"updater_inspection":1})
    rows.extend({"path":p} for p in INSPECTION_REQUIRED.values())
    assert set(INSPECTION_REQUIRED.values())<=set(_required(rows,{"updater_inspection":1}).values())

@pytest.mark.parametrize("missing", [None, "docs/samples/security-csv/ndr-normal.csv", "docs/images/security-csv-20261025/csv-readiness.png"])
def test_security_csv_public_media_copies_exact_bytes_and_rejects_missing_inputs(tmp_path, monkeypatch, missing):
    from saw.devtools import build_release
    public_csv = (
        "docs/RECURRING-SECURITY-CSV-GUIDE-20261025.md",
        *(f"docs/samples/security-csv/{name}.csv" for name in (
            "fw-mixed-devices", "ndr-potential-chain", "ndr-normal", "ndr-label-only", "ndr-missing-response")),
        *(f"docs/images/security-csv-20261025/{name}.png" for name in (
            "csv-upload", "csv-fw-complete", "csv-ndr-complete", "csv-readiness", "csv-ndr-fields", "csv-scenarios", "csv-old-run")),
    )
    source, out = tmp_path / "source", tmp_path / "out"
    for rel in set(build_release.PUBLIC_DOCS) | set(public_csv):
        path = source / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"public synthetic fixture\x00\xff\r\n" + rel.encode("utf-8"))
    unlisted = source / "docs/samples/security-csv/unapproved-original.csv"
    unlisted.write_bytes(b"synthetic private input must not ship")
    # This guide is decoded by the root entry-point generator.
    (source / "docs/INSTALL-RECOVERY-2026-10-18.md").write_text("# synthetic guide", encoding="utf-8")
    monkeypatch.setattr(build_release, "ROOT", source)
    if missing:
        (source / missing).unlink()
        with pytest.raises(BundleError, match="public guide missing"):
            build_release.copy_public_guides(out)
    else:
        build_release.copy_public_guides(out)
        for rel in public_csv:
            assert (out / "app" / rel).read_bytes() == (source / rel).read_bytes()
        assert not (out / "app/docs/samples/security-csv/unapproved-original.csv").exists()
