"""Native private-state handoff; no SAW installation, services, or update actions.

Run this file twice on Windows PowerShell 5.1, using the existing test Python:

* In a normal shell, set SAW_TEST_STATE_TOKEN_OWNER=current-user (the default).
* In an independently opened elevated shell whose token default owner is the
  Administrators group, set SAW_TEST_STATE_TOKEN_OWNER=administrators.

The selected gate fails if its token precondition is absent. These tests never
elevate, change the token or machine policy, or download an embedded runtime.
Only selected production PowerShell function definitions are evaluated. The
Python child loads the actual controller but never calls run or any lifecycle
method. All files belong to an otherwise empty pytest temporary installation.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
WORKER = ROOT / "deploy/windows/update-worker.ps1"
UI_MODULE = ROOT / "deploy/windows/update-ui.psm1"
CONTROLLER = ROOT / "saw/devtools/desktop_update.py"
POWERSHELL = (Path(os.environ.get("SystemRoot", r"C:\Windows"))
              / "System32/WindowsPowerShell/v1.0/powershell.exe")
pytestmark = pytest.mark.skipif(os.name != "nt", reason="Native Windows PowerShell 5.1 state handoff")


def ps_literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def powershell_json(source):
    preamble = r"""
$ErrorActionPreference='Stop'
$env:PSModulePath=Join-Path $PSHOME 'Modules'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
"""
    result = subprocess.run(
        [str(POWERSHELL), "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand",
         base64.b64encode((preamble + source).encode("utf-16-le")).decode("ascii")],
        capture_output=True, timeout=60, check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    return json.loads(result.stdout.decode("utf-8-sig"))


PS_FUNCTION_LOADER = r"""
function Get-ProductionFunctionSource([string]$SourcePath,[string]$Name) {
    $tokens=$null; $parseErrors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($SourcePath,[ref]$tokens,[ref]$parseErrors)
    if($parseErrors.Count){throw 'Production PowerShell source did not parse'}
    $definitions=@($ast.FindAll({param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $Name
    },$false))
    if($definitions.Count -ne 1){throw ('Expected one production function: '+$Name)}
    return $definitions[0].Extent.Text
}
function Get-PrivateStateMetadata([string]$Path) {
    $current=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $sections=[Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Access
    if([IO.Directory]::Exists($Path)){$acl=[IO.Directory]::GetAccessControl($Path,$sections)}
    else{$acl=[IO.File]::GetAccessControl($Path,$sections)}
    $trusted=@($current,'S-1-5-18')
    $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    $allowed=@($rules | Where-Object {$_.AccessControlType -eq 'Allow'})
    $foreign=@($allowed | Where-Object {$_.IdentityReference.Value -notin $trusted})
    $full=[Security.AccessControl.FileSystemRights]::FullControl
    $fullPrincipals=@{}
    foreach($rule in $allowed){
        if(($rule.FileSystemRights -band $full) -eq $full){
            $fullPrincipals[$rule.IdentityReference.Value]=$true
        }
    }
    $item=Get-Item -LiteralPath $Path -Force
    return [pscustomobject]@{
        owner_is_current=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq $current
        dacl_protected=$acl.AreAccessRulesProtected
        foreign_allow_count=$foreign.Count
        full_control_principal_count=$fullPrincipals.Count
        allow_count=$allowed.Count
        deny_count=@($rules | Where-Object {$_.AccessControlType -eq 'Deny'}).Count
        reparse=[bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint)
    }
}
"""


def production_functions(*, include_ui=False):
    source = PS_FUNCTION_LOADER
    names = ["New-PrivateWorkerFile", "Write-WorkerState", "Read-ControllerState"]
    for name in names:
        source += ("\n. ([scriptblock]::Create((Get-ProductionFunctionSource "
                   + ps_literal(WORKER) + " " + ps_literal(name) + ")))\n")
    if include_ui:
        for name in ("Get-SawUpdateLocalPath", "Test-SawUpdatePathsSeparate", "New-SawUpdateStateDirectory"):
            source += ("\n. ([scriptblock]::Create((Get-ProductionFunctionSource "
                       + ps_literal(UI_MODULE) + " " + ps_literal(name) + ")))\n")
    return source


@pytest.fixture(scope="module")
def token_gate():
    if not POWERSHELL.is_file():
        pytest.skip("Windows PowerShell 5.1 executable is absent")
    expected = os.environ.get("SAW_TEST_STATE_TOKEN_OWNER", "current-user")
    assert expected in {"current-user", "administrators"}, "Unknown SAW_TEST_STATE_TOKEN_OWNER gate"
    identity = powershell_json(r"""
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]::new($identity)
[pscustomobject]@{
    owner_is_user=$identity.Owner.Value -eq $identity.User.Value
    owner_is_administrators=$identity.Owner.Value -eq 'S-1-5-32-544'
    elevated=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    ps_major=$PSVersionTable.PSVersion.Major
    ps_minor=$PSVersionTable.PSVersion.Minor
} | ConvertTo-Json -Compress
""")
    assert (identity["ps_major"], identity["ps_minor"]) == (5, 1)
    if expected == "current-user":
        assert identity["owner_is_user"] and not identity["elevated"], (
            "The current-user gate requires a normal, non-elevated token with its user as default owner"
        )
    else:
        assert identity["owner_is_administrators"] and identity["elevated"], (
            "The administrators gate requires an externally supplied elevated token with Administrators owner"
        )
    return expected


PYTHON_HANDOFF = r"""
import json, os, pathlib, runpy, sys

source, state_path, root_path, bundle_path, mode = sys.argv[1:]
module = runpy.run_path(source, run_name='_saw_private_state_handoff')
state, root, bundle = map(pathlib.Path, (state_path, root_path, bundle_path))
backend = module['backend']
current = module['_current_sid']()
trusted = {current, 'S-1-5-18'}
full_control = 0x1F01FF
reports = []

def validate(label):
    # This is the real controller boundary that rejected the bootstrap file.
    checked = module['_state_directory'](state, (root, bundle))
    assert checked == state
    path = checked / 'state.json'
    owner, entries = backend._access_metadata(path)
    allowed = [entry for entry in entries if entry[0] == 0]
    full_principals = {sid for kind, flags, rights, sid in allowed
                       if rights & full_control == full_control}
    reports.append({
        'label': label,
        'owner_is_current': owner == current,
        'dacl_protected': backend._acl(path).startswith('D:P'),
        'foreign_allow_count': sum(sid not in trusted for kind, flags, rights, sid in allowed),
        'full_control_principal_count': len(full_principals),
        'allow_count': len(allowed),
        'deny_count': sum(kind == 1 for kind, flags, rights, sid in entries),
        'reparse': bool(getattr(path.lstat(), 'st_file_attributes', 0) & 0x400),
        'links': path.stat().st_nlink,
        'code': json.loads(path.read_text(encoding='utf-8'))['code'],
    })

validate('received')
if mode == 'write':
    writer = module['State'](state, 'inspect', root, None)
    writer.write('validate')
    validate('python_working')
    writer.write('ready', 'ready', 'ready')
    validate('python_ready')
else:
    assert mode == 'validate'
print(json.dumps({'reports': reports, 'isolated': sys.flags.isolated,
                  'no_bytecode': sys.dont_write_bytecode}, ensure_ascii=True))
"""


def python_handoff(state, root, bundle, *, mode="write"):
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", PYTHON_HANDOFF,
         str(CONTROLLER), str(state), str(root), str(bundle), mode],
        capture_output=True, timeout=120, check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    output = json.loads(result.stdout.decode("utf-8"))
    assert output["isolated"] == 1 and output["no_bytecode"] is True
    for report in output["reports"]:
        assert_private_metadata(report)
        assert report["links"] == 1
    return output["reports"]


def assert_private_metadata(report):
    assert report["owner_is_current"] is True
    assert report["dacl_protected"] is True
    assert report["foreign_allow_count"] == 0
    assert report["full_control_principal_count"] == 2
    assert report["allow_count"] == 2
    assert report["deny_count"] == 0
    assert report["reparse"] is False


def test_private_state_survives_powershell_python_handoff(tmp_path, token_gate, record_property):
    record_property("state_token_owner_gate", token_gate)
    root, bundle = tmp_path / "synthetic-install", tmp_path / "synthetic-media"
    root.mkdir()
    bundle.mkdir()
    bindings = ("\n$Action='inspect'; $RecoveryPoint=''\n$InstallRoot=" + ps_literal(root)
                + "\n$BundleDir=" + ps_literal(bundle) + "\n")
    bootstrap = powershell_json(production_functions(include_ui=True) + bindings + "\n" + r"""
$StateDir=New-SawUpdateStateDirectory -BasePath BASE_PATH -ExcludedPaths @($InstallRoot,$BundleDir)
$directory=Get-PrivateStateMetadata $StateDir
$lock=New-PrivateWorkerFile (Join-Path $StateDir 'worker.lock') $true
$lockReadable=$lock.CanRead
$lock.Dispose()
$lockMetadata=Get-PrivateStateMetadata (Join-Path $StateDir 'worker.lock')
Write-WorkerState 'working' 'verify_media' 'Synthetic initial state'
$created=Get-PrivateStateMetadata (Join-Path $StateDir 'state.json')
Write-WorkerState 'working' 'prepare_runtime' 'Synthetic replacement state'
$replaced=Get-PrivateStateMetadata (Join-Path $StateDir 'state.json')
[pscustomobject]@{state_dir=$StateDir;directory=$directory;created=$created;replaced=$replaced;lock=$lockMetadata;lock_readable=$lockReadable} |
    ConvertTo-Json -Depth 6 -Compress
""".replace("BASE_PATH", ps_literal(tmp_path)))
    assert bootstrap["lock_readable"] is True
    for name in ("directory", "created", "replaced", "lock"):
        assert_private_metadata(bootstrap[name])
    state = Path(bootstrap["state_dir"])
    assert state.parent == tmp_path
    reports = python_handoff(state, root, bundle)
    assert [(row["label"], row["code"]) for row in reports] == [
        ("received", "prepare_runtime"), ("python_working", "working"), ("python_ready", "ready"),
    ]

    # The actual worker reader accepts Python's result. Its fallback writer then
    # replaces that Python-owned file, exercising the reverse handoff as well.
    completed = powershell_json(production_functions() + bindings
                                + "\n$StateDir=" + ps_literal(state) + "\n" + r"""
$ready=Read-ControllerState
$readyMetadata=Get-PrivateStateMetadata (Join-Path $StateDir 'state.json')
Write-WorkerState 'failed' 'synthetic_controller_failure' 'Synthetic failure state'
$failed=Read-ControllerState
$failedMetadata=Get-PrivateStateMetadata (Join-Path $StateDir 'state.json')
[pscustomobject]@{
    ready_status=$ready.status;ready_code=$ready.code;ready_metadata=$readyMetadata
    failed_status=$failed.status;failed_code=$failed.code;failed_metadata=$failedMetadata
} | ConvertTo-Json -Depth 6 -Compress
""")
    assert (completed["ready_status"], completed["ready_code"]) == ("ready", "ready")
    assert (completed["failed_status"], completed["failed_code"]) == (
        "failed", "synthetic_controller_failure",
    )
    assert_private_metadata(completed["ready_metadata"])
    assert_private_metadata(completed["failed_metadata"])
    final = python_handoff(state, root, bundle, mode="validate")
    assert len(final) == 1 and final[0]["code"] == "synthetic_controller_failure"
    assert {path.name for path in state.iterdir()} == {"state.json", "worker.lock"}
    assert list(root.iterdir()) == [] and list(bundle.iterdir()) == []
