"""Native PowerShell bootstrap verifies media and isolates private worker state."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import zipfile

import pytest

from saw.devtools.release_manifest import DESKTOP_UPDATE_REQUIRED, REQUIRED, seal

ROOT = Path(__file__).resolve().parents[2]
WORKER = ROOT / "deploy/windows/update-worker.ps1"
EMBEDDED = ROOT / ".qa/packaging/inputs/python/python-3.12.10-embed-amd64.zip"
pytestmark = pytest.mark.skipif(os.name != "nt", reason="Native Windows PowerShell worker")


def literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def powershell(script):
    script = "$env:PSModulePath=Join-Path $PSHOME 'Modules';$ProgressPreference='SilentlyContinue';\n" + script
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand",
         base64.b64encode(script.encode("utf-16-le")).decode("ascii")],
        capture_output=True, timeout=30, check=False,
    )


def private_directory(path):
    path.mkdir(parents=True)
    result = powershell(f"""
$ErrorActionPreference='Stop'
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$acl=New-Object Security.AccessControl.DirectorySecurity
$acl.SetOwner($sid)
$acl.SetAccessRuleProtection($true,$false)
foreach($id in @($sid,(New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))) {{
 $rule=New-Object Security.AccessControl.FileSystemAccessRule($id,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
 $acl.AddAccessRule($rule)
}}
Set-Acl -LiteralPath {literal(path)} -AclObject $acl
""")
    assert result.returncode == 0, (result.stdout + result.stderr).decode(errors="replace")


CONTROLLER = r"""
import json, os, pathlib, sys
args = sys.argv[1:]
def value(flag):
    return args[args.index(flag)+1] if flag in args else None
state = pathlib.Path(value('--state-dir'))
call = {'args': args, 'cwd': os.getcwd(), 'saw_environment': [k for k in os.environ if k.upper().startswith('SAW_')],
        'isolated': sys.flags.isolated, 'no_bytecode': sys.dont_write_bytecode}
(state/'controller-call.json').write_text(json.dumps(call),encoding='utf-8')
mode = MODE
action = args[0]
result = {'schema':'saw.desktop-update/1','action':action,'phase':'ready' if action=='inspect' else 'completed',
          'status':'ready' if action=='inspect' else 'completed','code':'ready','message':'합성 준비 완료',
          'install_root':value('--install-root'),'requires_admin':False,'needs_acceptance':False}
if mode == 'wrong_identity': result['install_root'] = 'C:/unrelated-synthetic-install'
if mode == 'failed':
    result.update(status='failed', phase='failed', code='synthetic_controller_failure',message='합성 실패')
if mode != 'missing_state':
    (state/'state.json').write_text(json.dumps(result),encoding='utf-8')
print('SYNTHETIC_PRIVATE_OUTPUT_MUST_NOT_ESCAPE')
print('SYNTHETIC_PRIVATE_STDERR_MUST_NOT_ESCAPE',file=sys.stderr)
raise SystemExit(9 if mode=='failed' else 0)
"""


def media(root, *, real_runtime=False, mode="ready"):
    root.mkdir()
    for relative in set(REQUIRED.values()) | set(DESKTOP_UPDATE_REQUIRED.values()):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"synthetic unused payload")
    shutil.copyfile(ROOT / "deploy/windows/verify-bundle.ps1", root / "verify-bundle.ps1")
    if real_runtime:
        if not EMBEDDED.is_file():
            pytest.skip("Pinned public embedded Python is absent")
        shutil.copyfile(EMBEDDED, root / "python/python-3.12.10-embed-amd64.zip")
    (root / "app/saw/devtools/desktop_update.py").write_text(
        CONTROLLER.replace("MODE", repr(mode)), encoding="utf-8")
    seal(root, {"desktop_update_ui": 1})
    return root


@pytest.fixture
def paths(tmp_path):
    install = tmp_path / "설치 & example"
    install.mkdir()
    state = tmp_path / "private state"
    private_directory(state)
    return {"install": install, "state": state, "media": tmp_path / "매체 & example",
            "recovery": tmp_path / "new recovery", "baseline": tmp_path / "old media"}


def invoke(paths, *, action="inspect", extra=()):
    command = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
               "-File", str(WORKER), "-Action", action, "-InstallRoot", str(paths["install"]),
               "-BundleDir", str(paths["media"]), "-StateDir", str(paths["state"])]
    environment = dict(os.environ, SAW_SYNTHETIC_PRIVATE_TOKEN="SYNTHETIC_ENV_SECRET_MUST_NOT_ESCAPE")
    result = subprocess.run(command + list(extra), capture_output=True, timeout=90,
                            cwd=ROOT, env=environment, check=False)
    output = (result.stdout + result.stderr).decode(errors="replace")
    assert "SYNTHETIC_PRIVATE_OUTPUT" not in output
    assert "SYNTHETIC_PRIVATE_STDERR" not in output
    assert "SYNTHETIC_ENV_SECRET" not in output
    return result


def state_value(paths):
    return json.loads((paths["state"] / "state.json").read_text(encoding="utf-8-sig"))


def test_worker_missing_media_reports_safe_failure_without_extracting(paths):
    paths["media"].mkdir()
    result = invoke(paths)
    assert result.returncode != 0
    value = state_value(paths)
    assert value["schema"] == "saw.desktop-update/1"
    assert value["action"] == "inspect"
    assert value["install_root"] == str(paths["install"])
    assert value["status"] == "failed"
    assert value["code"] == "media_verification_failed"
    assert not (paths["state"] / "runtime").exists()


def test_worker_tampered_media_never_extracts_or_executes_controller(paths):
    media(paths["media"])
    (paths["media"] / "app/saw/devtools/desktop_update.py").write_text(
        "raise RuntimeError('SYNTHETIC_PRIVATE_OUTPUT')", encoding="utf-8")
    result = invoke(paths)
    assert result.returncode != 0
    assert state_value(paths)["code"] == "media_verification_failed"
    assert not (paths["state"] / "runtime").exists()
    assert not (paths["state"] / "controller-call.json").exists()


@pytest.mark.parametrize("case", ["unprotected", "foreign_allow", "not_empty"])
def test_worker_refuses_unsafe_or_reused_state_without_modifying_it(paths, case):
    media(paths["media"])
    if case == "not_empty":
        (paths["state"] / "preserved.txt").write_text("private previous operation", encoding="utf-8")
    else:
        edit = "$acl.SetAccessRuleProtection($false,$true)" if case == "unprotected" else """
$id=New-Object Security.Principal.SecurityIdentifier('S-1-1-0')
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($id,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')))
"""
        result = powershell(f"$ErrorActionPreference='Stop';$p={literal(paths['state'])};$acl=[IO.Directory]::GetAccessControl($p,[Security.AccessControl.AccessControlSections]::Access);{edit};[IO.Directory]::SetAccessControl($p,$acl)")
        assert result.returncode == 0, (result.stdout + result.stderr).decode(errors="replace")
    before = {p.name: p.read_bytes() for p in paths["state"].iterdir() if p.is_file()}
    result = invoke(paths)
    assert result.returncode != 0
    assert {p.name: p.read_bytes() for p in paths["state"].iterdir() if p.is_file()} == before
    assert not (paths["state"] / "runtime").exists()


@pytest.mark.parametrize("container", ["install", "media", "recovery", "baseline"])
def test_worker_refuses_state_nested_in_other_operation_paths(paths, container):
    media(paths["media"])
    if container in ("recovery", "baseline"):
        paths[container].mkdir()
    nested = paths[container] / "nested-private-state"
    private_directory(nested)
    paths["state"] = nested
    extra = []
    if container == "recovery":
        extra = ["-RecoveryPoint", str(paths["recovery"])]
    elif container == "baseline":
        extra = ["-BaselineBundleDir", str(paths["baseline"])]
    result = invoke(paths, extra=extra)
    assert result.returncode != 0
    assert not list(nested.iterdir())


def test_worker_refuses_state_directory_junction(paths, tmp_path):
    media(paths["media"])
    target = paths["state"]
    link = tmp_path / "state-junction"
    result = powershell(f"New-Item -ItemType Junction -Path {literal(link)} -Target {literal(target)} | Out-Null")
    assert result.returncode == 0, (result.stdout + result.stderr).decode(errors="replace")
    paths["state"] = link
    result = invoke(paths)
    assert result.returncode != 0
    assert not list(target.iterdir())


@pytest.mark.parametrize("action,extra", [
    ("apply", ()),
    ("restore", ("-MaintenanceConfirmed",)),
])
def test_worker_missing_acknowledgement_never_bootstraps_runtime(paths, action, extra):
    media(paths["media"])
    result = invoke(paths, action=action, extra=("-RecoveryPoint", str(paths["recovery"]), *extra))
    assert result.returncode != 0
    assert state_value(paths)["code"] == "confirmation_required"
    assert not (paths["state"] / "runtime").exists()


def test_worker_validated_python_gets_exact_arguments_and_clean_environment(paths):
    media(paths["media"], real_runtime=True)
    paths["baseline"].mkdir()
    extra = ("-BaselineBundleDir", str(paths["baseline"]), "-RecoveryPoint", str(paths["recovery"]),
             "-MaintenanceConfirmed", "-ConfirmPointInTimeRecovery")
    result = invoke(paths, action="apply", extra=extra)
    assert result.returncode == 0, (result.stdout + result.stderr).decode(errors="replace")
    call = json.loads((paths["state"] / "controller-call.json").read_text(encoding="utf-8"))
    assert call == {
        "args": ["apply", "--install-root", str(paths["install"]), "--bundle-dir", str(paths["media"]),
                 "--state-dir", str(paths["state"]), "--baseline-bundle-dir", str(paths["baseline"]),
                 "--recovery-point", str(paths["recovery"]), "--maintenance-confirmed",
                 "--confirm-point-in-time-recovery"],
        "cwd": str(paths["state"]),
        "saw_environment": [], "isolated": 1, "no_bytecode": True,
    }
    assert state_value(paths)["status"] == "completed"


@pytest.mark.parametrize("mode", ["failed", "missing_state", "wrong_identity"])
def test_worker_never_reports_success_for_failed_or_mismatched_controller(paths, mode):
    media(paths["media"], real_runtime=True, mode=mode)
    result = invoke(paths)
    assert result.returncode != 0
    value = state_value(paths)
    assert value["status"] == "failed"
    assert value["action"] == "inspect"
    assert value["install_root"] == str(paths["install"])
    assert value["code"] in {"controller_failed", "invalid_controller_result", "synthetic_controller_failure"}


def test_worker_archive_cannot_escape_private_runtime(paths):
    media(paths["media"])
    archive = paths["media"] / "python/python-3.12.10-embed-amd64.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("../escaped.txt", "synthetic traversal")
        z.writestr("python.exe", "synthetic invalid executable")
    seal(paths["media"], {"desktop_update_ui": 1})
    result = invoke(paths)
    assert result.returncode != 0
    assert state_value(paths)["code"] == "runtime_bootstrap_failed"
    assert not (paths["state"] / "escaped.txt").exists()
