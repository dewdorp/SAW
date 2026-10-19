"""The real embedded runtime must resume safely without reusing unrelated Python."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "deploy/windows/install-python.ps1"
BUNDLE = Path(os.environ.get("SAW_INSTALL_TEST_BUNDLE", str(ROOT / ".release/model-free-20261017")))
pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell 5.1 runtime contract")


def literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def run_ps(tmp_path, body, timeout=240):
    assert HELPER.is_file(), "Resumable Python preparation is not implemented"
    script = tmp_path / "python-probe.ps1"
    script.write_text(
        "$ErrorActionPreference='Stop'\n"
        "$env:PSModulePath=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/Modules'\n"
        "[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)\n"
        ". " + literal(HELPER) + "\n" + body,
        encoding="utf-8-sig",
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "RemoteSigned", "-File", str(script)],
        capture_output=True, timeout=timeout,
    )
    assert result.returncode == 0, (result.stdout + result.stderr).decode("utf-8", "replace")
    return json.loads(result.stdout.decode("utf-8-sig"))


@pytest.fixture(scope="module")
def native_runtime(tmp_path_factory):
    if not (BUNDLE / "python/python-3.12.10-embed-amd64.zip").is_file():
        pytest.skip("Pinned offline media is unavailable; no runtime download is attempted")
    base = tmp_path_factory.mktemp("python-native")
    install = base / "SAW 공간"
    install.mkdir()
    result = run_ps(base, f"""
$env:PIP_CONFIG_FILE='synthetic-original'
$env:PIP_NO_INDEX='0'
$env:PIP_DISABLE_PIP_VERSION_CHECK='0'
$python=Ensure-SawPythonRuntime -BundleDir {literal(BUNDLE)} -InstallRoot {literal(install)}
@{{ python=$python; pip=$env:PIP_CONFIG_FILE; noIndex=$env:PIP_NO_INDEX;
   versionCheck=$env:PIP_DISABLE_PIP_VERSION_CHECK }} | ConvertTo-Json -Compress
""")
    return base, install, result


def full_snapshot(root):
    return {str(p.relative_to(root)): (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mtime_ns)
            for p in root.rglob("*") if p.is_file()}


def snapshot(root):
    """Preservation checks focus on startup files, ownership, and operator files."""
    relative = (
        "venv/.saw-python-runtime.json", "venv/pyvenv.cfg", "venv/Scripts/python.exe",
        "venv/Scripts/python312.dll", "venv/Scripts/python312.zip", "venv/Scripts/python312._pth",
        "venv/Scripts/notes.txt", "venv/operator-note.txt", "venv/interrupted.txt",
        "venv/Lib/site-packages/custom.pth", "venv/Lib/site-packages/sitecustomize.py",
        "app/sitecustomize.py", "saved-marker.json",
    )
    result = {}
    for name in relative:
        path = root / name
        if path.is_file():
            result[name] = (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns)
    for name in ("", "venv", "venv/Scripts", "venv/Lib/site-packages"):
        path = root / name
        if path.is_dir():
            result["entries:" + name] = tuple(sorted(child.name for child in path.iterdir()))
    return result


def clone_runtime(native_runtime, tmp_path):
    _, original, _ = native_runtime
    install = tmp_path / "SAW 한글"
    shutil.copytree(original, install)
    marker = install / "venv/.saw-python-runtime.json"
    content = json.loads(marker.read_text(encoding="utf-8-sig"))
    content["install_root"] = str(install.resolve())
    marker.write_text(json.dumps(content), encoding="utf-8")
    return install


def invoke(tmp_path, install, validate=False):
    switch = "-ValidateOnly" if validate else ""
    return run_ps(tmp_path, f"""
try {{
    $python=Ensure-SawPythonRuntime -BundleDir {literal(BUNDLE)} -InstallRoot {literal(install)} {switch}
    @{{ ok=$true; python=$python }} | ConvertTo-Json -Compress
}} catch {{
    @{{ ok=$false; error=$_.Exception.Message }} | ConvertTo-Json -Compress
}}
""")


def test_fresh_actual_embedded_runtime_and_repeated_reuse_preserve_all_bytes(native_runtime, tmp_path):
    _, install, result = native_runtime
    assert result["python"] == str(install / "venv/Scripts/python.exe")
    assert result["pip"] == "synthetic-original"
    assert result["noIndex"] == result["versionCheck"] == "0"
    executable = install / "venv/Scripts/python.exe"
    probe = subprocess.run([str(executable), "-S", "-c",
                            "import sys,struct,json;print(json.dumps([list(sys.version_info[:3]),struct.calcsize('P')*8]))"],
                           capture_output=True, check=True)
    assert json.loads(probe.stdout) == [[3, 12, 10], 64]
    before = full_snapshot(install)
    assert invoke(tmp_path, install)["ok"]
    assert invoke(tmp_path, install, validate=True)["ok"]
    assert full_snapshot(install) == before


@pytest.mark.parametrize("missing", ["Scripts/python312.dll", "Lib/site-packages/fastapi"])
def test_managed_missing_dll_or_dependency_is_retained_then_rebuilt(native_runtime, tmp_path, missing):
    install = clone_runtime(native_runtime, tmp_path)
    target = install / "venv" / missing
    target.rename(target.with_name(target.name + ".synthetic-interrupted"))
    note = install / "venv/operator-note.txt"
    note.write_text("keep this unknown file", encoding="utf-8")
    original_note = note.read_bytes()
    result = invoke(tmp_path, install)
    assert result["ok"], result
    retained = list(install.glob("venv.retained-*"))
    assert len(retained) == 1
    assert (retained[0] / "operator-note.txt").read_bytes() == original_note
    assert (retained[0] / missing).with_name(target.name + ".synthetic-interrupted").exists()
    assert not note.exists()
    assert target.exists()
    assert invoke(tmp_path, install, validate=True)["ok"]


def test_legacy_byte_identical_runtime_is_adopted_without_reinstall(native_runtime, tmp_path):
    install = clone_runtime(native_runtime, tmp_path)
    marker = install / "venv/.saw-python-runtime.json"
    marker.rename(install / "saved-marker.json")
    before = full_snapshot(install / "venv")
    assert invoke(tmp_path, install, validate=True)["ok"]
    assert not marker.exists(), "Read-only validation must not create an ownership marker"
    assert invoke(tmp_path, install)["ok"]
    after = full_snapshot(install / "venv")
    after.pop(".saw-python-runtime.json")
    assert after == before
    assert marker.exists()


@pytest.mark.parametrize("conflict", ["foreign_marker", "incompatible_exe", "developer_venv", "unapproved_pth"])
def test_incompatible_or_foreign_runtime_refuses_without_replacing_files(native_runtime, tmp_path, conflict):
    install = clone_runtime(native_runtime, tmp_path)
    venv = install / "venv"
    if conflict == "foreign_marker":
        marker = venv / ".saw-python-runtime.json"
        data = json.loads(marker.read_text(encoding="utf-8"))
        data["install_root"] = str(tmp_path / "another-installation")
        marker.write_text(json.dumps(data), encoding="utf-8")
    elif conflict == "incompatible_exe":
        with (venv / "Scripts/python.exe").open("ab") as stream:
            stream.write(b"synthetic altered interpreter")
    elif conflict == "developer_venv":
        (venv / "pyvenv.cfg").write_text("home = C:\\unrelated-python", encoding="utf-8")
    else:
        (venv / "Scripts/python312._pth").write_text(
            "python312.zip\n.\nC:\\unrelated-site-packages\nimport site\n", encoding="utf-8")
    before = snapshot(install)
    result = invoke(tmp_path, install)
    assert not result["ok"]
    assert snapshot(install) == before
    assert not list(install.glob("venv.retained-*"))


def test_unknown_partial_runtime_refuses_and_keeps_operator_files(tmp_path):
    install = tmp_path / "SAW"
    unknown = install / "venv/Scripts"
    unknown.mkdir(parents=True)
    (unknown / "notes.txt").write_text("not owned by installer", encoding="utf-8")
    before = snapshot(install)
    result = invoke(tmp_path, install)
    assert not result["ok"]
    assert snapshot(install) == before


def test_marker_written_before_extraction_recovers_missing_interpreter(native_runtime, tmp_path):
    install = clone_runtime(native_runtime, tmp_path)
    full = install / "venv"
    marker_bytes = (full / ".saw-python-runtime.json").read_bytes()
    full.rename(install / "complete-synthetic-runtime")
    full.mkdir()
    (full / ".saw-python-runtime.json").write_bytes(marker_bytes)
    (full / "interrupted.txt").write_text("retained", encoding="utf-8")
    result = invoke(tmp_path, install)
    assert result["ok"], result
    retained = list(install.glob("venv.retained-*"))
    assert len(retained) == 1
    assert (retained[0] / "interrupted.txt").read_text() == "retained"


def test_read_only_validation_rejects_partial_without_repair(native_runtime, tmp_path):
    install = clone_runtime(native_runtime, tmp_path)
    dll = install / "venv/Scripts/python312.dll"
    dll.rename(dll.with_name("python312.dll.synthetic-interrupted"))
    before = snapshot(install)
    assert not invoke(tmp_path, install, validate=True)["ok"]
    assert snapshot(install) == before


def test_reparse_runtime_is_rejected_without_following_target(tmp_path):
    install = tmp_path / "SAW"
    outside = tmp_path / "outside"
    install.mkdir()
    outside.mkdir()
    (outside / "note.txt").write_text("keep", encoding="utf-8")
    result = run_ps(tmp_path, f"""
$null=New-Item -ItemType Junction -Path {literal(install / 'venv')} -Target {literal(outside)}
try {{
    $null=Ensure-SawPythonRuntime -BundleDir {literal(BUNDLE)} -InstallRoot {literal(install)}
    @{{ rejected=$false }} | ConvertTo-Json -Compress
}} catch {{
    @{{ rejected=$true }} | ConvertTo-Json -Compress
}}
""")
    assert result["rejected"]
    assert (outside / "note.txt").read_text() == "keep"
    assert len(list(outside.iterdir())) == 1


@pytest.mark.parametrize("interrupted", ["binary", "official_pth"])
def test_interrupted_extraction_prefix_is_recovered_only_for_preparing_marker(native_runtime, tmp_path, interrupted):
    install = clone_runtime(native_runtime, tmp_path)
    marker = install / "venv/.saw-python-runtime.json"
    data = json.loads(marker.read_text(encoding="utf-8"))
    data["state"] = "preparing"
    marker.write_text(json.dumps(data), encoding="utf-8")
    filename = "python312.dll" if interrupted == "binary" else "python312._pth"
    target = install / "venv/Scripts" / filename
    if interrupted == "binary":
        partial = target.read_bytes()[:4096]
    else:
        with zipfile.ZipFile(BUNDLE / "python/python-3.12.10-embed-amd64.zip") as archive:
            partial = archive.read("python312._pth")
    target.write_bytes(partial)
    result = invoke(tmp_path, install)
    assert result["ok"], result
    retained = list(install.glob("venv.retained-*"))
    assert len(retained) == 1
    assert (retained[0] / "Scripts" / filename).read_bytes() == partial
    assert target.read_bytes() != partial


@pytest.mark.parametrize("startup", ["custom.pth", "sitecustomize.py"])
def test_unapproved_startup_code_is_neither_executed_nor_silently_reused(native_runtime, tmp_path, startup):
    install = clone_runtime(native_runtime, tmp_path)
    sentinel = tmp_path / "should-not-execute.txt"
    hook = install / "venv/Lib/site-packages" / startup
    hook.write_text("import pathlib; pathlib.Path(" + repr(str(sentinel)) + ").write_text('unsafe')\n",
                    encoding="utf-8")
    before = snapshot(install)
    result = invoke(tmp_path, install)
    assert not result["ok"]
    assert not sentinel.exists()
    assert snapshot(install) == before


def test_application_sitecustomize_is_refused_before_native_execution(native_runtime, tmp_path):
    install = clone_runtime(native_runtime, tmp_path)
    app = install / "app"
    app.mkdir()
    sentinel = tmp_path / "app-hook-executed.txt"
    hook = app / "sitecustomize.py"
    hook.write_text("from pathlib import Path\nPath(" + repr(str(sentinel)) + ").write_text('unsafe')\n",
                    encoding="utf-8")
    before = snapshot(install)
    result = invoke(tmp_path, install)
    assert (result["ok"], sentinel.exists()) == (False, False)
    assert snapshot(install) == before


def test_running_native_interpreter_prevents_incomplete_runtime_replacement(native_runtime, tmp_path):
    install = clone_runtime(native_runtime, tmp_path)
    interpreter = install / "venv/Scripts/python.exe"
    process = subprocess.Popen(
        [str(interpreter), "-B", "-c", "import time; print('ready',flush=True); time.sleep(600)"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW,
    )
    try:
        assert process.stdout.readline().strip() == b"ready"
        package = install / "venv/Lib/site-packages/fastapi"
        package.rename(package.with_name("fastapi.synthetic-missing"))
        before = snapshot(install)
        result = invoke(tmp_path, install)
        assert not result["ok"], result
        assert "running" in result["error"].lower() or "active" in result["error"].lower()
        assert snapshot(install) == before
    finally:
        process.terminate()
        process.wait(timeout=15)
        process.stdout.close()


@pytest.mark.parametrize("conflict", ["unknown_python_process", "running_service"])
def test_uncertain_process_or_running_service_blocks_repair_without_changes(native_runtime, tmp_path, conflict):
    install = clone_runtime(native_runtime, tmp_path)
    package = install / "venv/Lib/site-packages/fastapi"
    package.rename(package.with_name("fastapi.synthetic-missing"))
    before = snapshot(install)
    body = f"""
function Get-CimInstance {{
    param($ClassName, $Property, $ErrorAction)
    if ($ClassName -eq 'Win32_Process' -and {literal(conflict)} -eq 'unknown_python_process') {{
        [pscustomobject]@{{ Name='python.exe'; ProcessId=876543; ExecutablePath=$null }}
    }}
    if ($ClassName -eq 'Win32_Service' -and {literal(conflict)} -eq 'running_service') {{
        [pscustomobject]@{{ Name='saw'; State='Running'; PathName={literal(str(install / 'service/saw-service.exe'))} }}
    }}
}}
try {{
    $null=Ensure-SawPythonRuntime -BundleDir {literal(BUNDLE)} -InstallRoot {literal(install)}
    @{{ ok=$true }} | ConvertTo-Json -Compress
}} catch {{
    @{{ ok=$false; error=$_.Exception.Message }} | ConvertTo-Json -Compress
}}
"""
    result = run_ps(tmp_path, body)
    assert not result["ok"]
    assert snapshot(install) == before
