"""Native PowerShell installation journal and path-selection contracts."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import pytest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "deploy/windows/install-state.ps1"
pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell 5.1 installer")

def lit(value):
    return "'" + str(value).replace("'", "''") + "'"

def run(tmp_path, body):
    script = tmp_path / "state-probe.ps1"
    script.write_text("$ErrorActionPreference='Stop'\n"
        "$env:PSModulePath=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/Modules'\n"
        "[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)\n"
        + ". " + lit(ROOT / "deploy/windows/install-paths.ps1") + "\n"
        + ". " + lit(HELPER) + "\n" + body, encoding="utf-8-sig")
    p = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "RemoteSigned", "-File", str(script)],
                       capture_output=True, timeout=120)
    assert p.returncode == 0, (p.stdout + p.stderr).decode("utf-8", "replace")
    return json.loads(p.stdout.decode("utf-8-sig"))

def fixture(tmp_path):
    media = tmp_path / "media"
    media.mkdir()
    (media / "release-manifest.json").write_text('{"schema":"saw.offline-release/1","files":[]}', encoding="utf-8")
    return media, tmp_path / "관제 설치"

def test_interrupted_install_resumes_at_same_root_without_erasing_files(tmp_path):
    media, root = fixture(tmp_path)
    result = run(tmp_path, f"""
$c=Enter-SawInstall -InstallRoot {lit(root)} -BundleDir {lit(media)} -Options @{{ noAdmin=$true; port=8443 }}
Set-SawInstallStage $c 'Python'
Set-SawInstallStage $c 'PostgreSQL'
[IO.File]::WriteAllText((Join-Path $c.Root 'preserved.txt'),'synthetic')
Exit-SawInstall $c
$d=Enter-SawInstall -InstallRoot {lit(root)} -BundleDir {lit(media)} -Options @{{ noAdmin=$true; port=8443 }}
try {{ @{{ mode=$d.Mode; prior=$d.State.previous_status; stage=$d.State.stage;
 done=@($d.State.completed); preserved=[IO.File]::ReadAllText((Join-Path $d.Root 'preserved.txt')) }} | ConvertTo-Json -Compress }}
finally {{ Exit-SawInstall $d }}
""")
    assert result == {"mode": "resume", "prior": "running", "stage": "PostgreSQL",
                      "done": ["Python"], "preserved": "synthetic"}

@pytest.mark.parametrize("conflict", ["options", "media"])
def test_conflicts_do_not_change_journal_or_user_files(tmp_path, conflict):
    media, root = fixture(tmp_path)
    extra = "$options.port=8444" if conflict == "options" else f"[IO.File]::AppendAllText({lit(media / 'release-manifest.json')},' ')"
    result = run(tmp_path, f"""
$options=@{{noAdmin=$true;port=8443}}
$c=Enter-SawInstall -InstallRoot {lit(root)} -BundleDir {lit(media)} -Options $options
Exit-SawInstall $c
$before=[IO.File]::ReadAllText((Join-Path {lit(root)} '.saw-install-state.json'))
{extra}
$blocked=$false
try {{ $d=Enter-SawInstall -InstallRoot {lit(root)} -BundleDir {lit(media)} -Options $options; Exit-SawInstall $d }}
catch {{ $blocked=$true }}
@{{blocked=$blocked;unchanged=($before -ceq [IO.File]::ReadAllText((Join-Path {lit(root)} '.saw-install-state.json')))}}|ConvertTo-Json -Compress
""")
    assert result == {"blocked": True, "unchanged": True}

def test_second_install_is_blocked_and_lock_recovers_after_exit(tmp_path):
    media, root = fixture(tmp_path)
    result = run(tmp_path, f"""
$c=Enter-SawInstall -InstallRoot {lit(root)} -BundleDir {lit(media)} -Options @{{noAdmin=$true}}
$blocked=$false
try {{ $d=Enter-SawInstall -InstallRoot {lit(root)} -BundleDir {lit(media)} -Options @{{noAdmin=$true}} }}
catch {{ $blocked=$true }}
Exit-SawInstall $c
$d=Enter-SawInstall -InstallRoot {lit(root)} -BundleDir {lit(media)} -Options @{{noAdmin=$true}}
Exit-SawInstall $d
@{{blocked=$blocked;released=$true}}|ConvertTo-Json -Compress
""")
    assert result == {"blocked": True, "released": True}

def test_failure_records_component_and_code_without_copying_error_or_secrets(tmp_path):
    media, root = fixture(tmp_path)
    result = run(tmp_path, f"""
$c=Enter-SawInstall -InstallRoot {lit(root)} -BundleDir {lit(media)} -Options @{{noAdmin=$true}}
Set-SawInstallStage $c 'PostgreSQL'
Set-SawInstallFailed $c 23
Exit-SawInstall $c
Get-Content -LiteralPath (Join-Path {lit(root)} '.saw-install-state.json') -Raw
""")
    assert result["status"] == "failed"
    assert result["stage"] == "PostgreSQL" and result["exit_code"] == 23
    assert "error" not in result

def test_unknown_nonempty_directory_stays_unchanged(tmp_path):
    media, root = fixture(tmp_path)
    root.mkdir()
    (root / "user.txt").write_text("do not overwrite")
    result = run(tmp_path, f"""
$blocked=$false
try {{ $c=Enter-SawInstall -InstallRoot {lit(root)} -BundleDir {lit(media)} -Options @{{noAdmin=$true}}; Exit-SawInstall $c }}
catch {{ $blocked=$true }}
@{{blocked=$blocked;files=@(Get-ChildItem -LiteralPath {lit(root)} -Force).Count}}|ConvertTo-Json -Compress
""")
    assert result == {"blocked": True, "files": 1}

def test_path_preview_uses_selected_volume_and_lists_all_storage(tmp_path):
    media, root = fixture(tmp_path)
    result = run(tmp_path, f"""
Get-SawInstallLayout -InstallRoot {lit(root)} | ConvertTo-Json -Compress
""")
    assert result["root"] == str(root)
    assert all(str(value).startswith(str(root)) for key, value in result.items() if key != "volume")
    assert result["database"].endswith(r"data\postgresql")
    assert result["indices"].endswith(r"data\opensearch")
    assert result["evidence"].endswith(r"data\objects")

def test_resume_does_not_mark_previously_failed_stage_as_completed(tmp_path):
    media, root = fixture(tmp_path)
    result = run(tmp_path, f"""
$c=Enter-SawInstall -InstallRoot {lit(root)} -BundleDir {lit(media)} -Options @{{noAdmin=$true}}
Set-SawInstallStage $c 'Python'
Set-SawInstallStage $c 'PostgreSQL'
Set-SawInstallFailed $c 1
Exit-SawInstall $c
$d=Enter-SawInstall -InstallRoot {lit(root)} -BundleDir {lit(media)} -Options @{{noAdmin=$true}}
Set-SawInstallStage $d 'Python'
try {{ @{{done=@($d.State.completed)}} | ConvertTo-Json -Compress }}
finally {{ Exit-SawInstall $d }}
""")
    assert result["done"] == ["Python"]

def test_completed_install_twice_is_readonly_even_from_newer_media(tmp_path):
    media, root = fixture(tmp_path)
    result = run(tmp_path, f"""
$c=Enter-SawInstall -InstallRoot {lit(root)} -BundleDir {lit(media)} -Options @{{noAdmin=$true}}
Set-SawInstallStage $c 'Health'
Complete-SawInstall $c
Exit-SawInstall $c
$state=Join-Path {lit(root)} '.saw-install-state.json'
$before=[IO.File]::ReadAllText($state)
$time=(Get-Item -LiteralPath $state).LastWriteTimeUtc
[IO.File]::AppendAllText({lit(media / 'release-manifest.json')},' ')
$modes=@()
1..2 | ForEach-Object {{
 $d=Enter-SawInstall -InstallRoot {lit(root)} -BundleDir {lit(media)} -Options @{{noAdmin=$true}}
 $modes+=@($d.Mode)
 Exit-SawInstall $d
}}
@{{modes=$modes;unchanged=($before -ceq [IO.File]::ReadAllText($state));mtime=($time -eq (Get-Item -LiteralPath $state).LastWriteTimeUtc)}}|ConvertTo-Json -Compress
""")
    assert result == {"modes": ["verify", "verify"], "unchanged": True, "mtime": True}

def test_manifest_paths_cannot_read_outside_installation(tmp_path):
    media, root = fixture(tmp_path)
    (media / "bad.json").write_text(json.dumps({"schema": "saw.offline-release/1", "files": [
        {"path": "app/../../private.txt", "sha256": "0"*64, "bytes": 1}]}), encoding="utf-8")
    result = run(tmp_path, f"""
$blocked=$false
try {{ $null=Read-SawInstallManifest {lit(media / 'bad.json')} }} catch {{ $blocked=$true }}
@{{blocked=$blocked}}|ConvertTo-Json -Compress
""")
    assert result == {"blocked": True}

@pytest.mark.parametrize("name", ["SAW.", "SAW ", "NUL", "COM1"])
def test_aliased_install_names_are_rejected_before_mutation(tmp_path,name):
    result=run(tmp_path,f"""
$blocked=$false
try {{ $null=Get-SawInstallLayout -InstallRoot {lit(tmp_path/name)} }} catch {{ $blocked=$true }}
@{{blocked=$blocked}} | ConvertTo-Json -Compress
""")
    assert result == {"blocked": True}


@pytest.mark.parametrize("runtime", ["complete", "missing", "modified"])
def test_completed_install_checks_postgresql_runtime_without_repair(tmp_path, runtime):
    media, root = fixture(tmp_path)
    # The native fixture only emits a version or canned verifier result. It never
    # connects to a database, creates a service, or writes outside this temp root.
    result = run(tmp_path, f"""
$root={lit(root)}; $media={lit(media)}; $stage=Join-Path {lit(tmp_path)} 'stage'
$probe=Join-Path {lit(tmp_path)} 'native-probe.exe'
Add-Type -TypeDefinition @'
using System;
public static class Probe {{
 public static int Main(string[] args) {{
  if(Array.IndexOf(args,"--version")>=0) Console.WriteLine("postgres (PostgreSQL) 16.15");
  if(Array.IndexOf(args,"--root")>=0) Console.WriteLine("{{\\"ok\\":true,\\"ready\\":false,\\"checks\\":{{}}}}");
  return 0;
 }}
}}
'@ -OutputAssembly $probe -OutputType ConsoleApplication
$null=New-Item -ItemType Directory -Force (Join-Path $stage 'pgsql\\bin'),(Join-Path $root 'pgsql\\bin'),(Join-Path $root 'venv\\Scripts'),(Join-Path $media 'postgresql'),(Join-Path $media 'app\\deploy\\windows')
[IO.File]::WriteAllText((Join-Path $media 'app\\deploy\\windows\\setup-opensearch.ps1'),'# synthetic external boundary')
$required=@('postgres.exe','initdb.exe','pg_ctl.exe','pg_controldata.exe','pg_isready.exe','psql.exe')
foreach($name in $required) {{
 Copy-Item -LiteralPath $probe -Destination (Join-Path $stage ('pgsql\\bin\\'+$name))
 Copy-Item -LiteralPath $probe -Destination (Join-Path $root ('pgsql\\bin\\'+$name))
}}
Copy-Item -LiteralPath $probe -Destination (Join-Path $root 'venv\\Scripts\\python.exe')
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($stage,(Join-Path $media 'postgresql\\postgresql-16.15-synthetic-windows-x64-binaries.zip'))
foreach($rel in @('tls\\saw.crt','tls\\saw.key','secrets\\postgres-superuser.pw','secrets\\postgres-saw.pw','data\\postgresql\\PG_VERSION','data\\postgresql\\global\\pg_control','data\\postgresql\\postgresql.conf','data\\postgresql\\pg_hba.conf','opensearch-2.19.6\\config\\opensearch.yml','opensearch-2.19.6\\jdk\\bin\\java.exe','opensearch-2.19.6\\jdk\\bin\\server\\jvm.dll')) {{
 $path=Join-Path $root $rel
 $null=New-Item -ItemType Directory -Force (Split-Path $path)
 [IO.File]::WriteAllText($path,'synthetic')
}}
if({lit(runtime)} -eq 'missing') {{ [IO.File]::Delete((Join-Path $root 'pgsql\\bin\\postgres.exe')) }}
if({lit(runtime)} -eq 'modified') {{ [IO.File]::AppendAllText((Join-Path $root 'pgsql\\bin\\postgres.exe'),'changed') }}
function Read-SawInstallManifest {{ return [pscustomobject]@{{metadata=@{{application_schema='0014'}};files=@()}} }}
function Assert-SawApplicationFiles {{}}
function Ensure-SawPythonRuntime {{ return (Join-Path $root 'venv\\Scripts\\python.exe') }}
function Assert-SawInstalledConfiguration {{}}
function Get-CimInstance {{}}
function Snapshot {{
 @((Get-ChildItem -LiteralPath $root -File -Recurse | Sort-Object FullName | ForEach-Object {{
  $_.FullName+'='+(Get-FileHash -LiteralPath $_.FullName).Hash+'='+$_.LastWriteTimeUtc.Ticks
 }})) -join '|'
}}
$before=Snapshot
$context=[pscustomobject]@{{Root=$root;State=$null}}
$options=@{{noAdmin=$true;noServices=$false;heapGB=1;hostName='localhost';port=8443;postgresPort=5432;opensearchPort=9200;opensearchTransportPort=9300}}
$rejected=$false; $errorText=''
try {{ Assert-SawCompletedInstall $context $media $options 6>$null }} catch {{ $rejected=$true; $errorText=$_.Exception.Message }}
@{{rejected=$rejected;unchanged=($before -ceq (Snapshot));error=$errorText}}|ConvertTo-Json -Compress
""")
    assert result["rejected"] == (runtime != "complete"), result
    assert result["unchanged"], result

def test_korean_install_messages_keep_utf8_bom_for_powershell_51():
    for relative in ("deploy/windows/install-state.ps1", "deploy/windows/install.ps1"):
        data = (ROOT / relative).read_bytes()
        assert data.startswith(b"\xef\xbb\xbf"), relative
        assert "검증" in data.decode("utf-8-sig")

@pytest.mark.parametrize("case,relative,accepted", [
    ("present", "data/postgresql/base/16385/pg_internal.init", True),
    ("item", "data/postgresql/base/16385/pg_internal.init", True),
    ("acl", "data/postgresql/base/16385/pg_internal.init", True),
    ("item", "data/postgresql/global/pg_internal.init.1234", True),
    ("item", "data/postgresql/global/pg_control", False),
    ("item", "data/postgresql/postgresql.conf", False),
    ("item", "app/pg_internal.init", False),
    ("item", "secrets/pg_internal.init", False),
    ("item", "data/opensearch/pg_internal.init", False),
    ("parent_replace", "data/postgresql/base/16385/pg_internal.init", False),
    ("parent_missing", "data/postgresql/base/16385/pg_internal.init", False),
    ("parent_acl_denied", "data/postgresql/base/16385/pg_internal.init", False),
    ("parent_reparse", "data/postgresql/base/16385/pg_internal.init", False),
    ("item_denied", "data/postgresql/base/16385/pg_internal.init", False),
    ("acl_denied", "data/postgresql/base/16385/pg_internal.init", False),
    ("enumeration", "data/postgresql/base/16385/pg_internal.init", False),
    ("directory", "data/postgresql/base/16385/pg_internal.init", False),
    ("queued_reparse", "data/postgresql/base/16385/pg_internal.init", False),
])
def test_private_install_only_allows_vanished_postgresql_relcache(tmp_path, case, relative, accepted):
    media, root = fixture(tmp_path)
    target = root / relative
    result = run(tmp_path, rf"""
$root=Initialize-SawInstallRoot -InstallRoot {lit(root)} -BundleDir {lit(media)} -NoAdmin
$script:target={lit(target)}; $script:case={lit(case)}; $script:changed=$false
$parent=Split-Path $script:target
$null=New-Item -ItemType Directory -Force $parent
$sentinel=Join-Path $root 'untouched.txt'
[IO.File]::WriteAllText($sentinel,'unchanged')
$before=(Microsoft.PowerShell.Management\Get-Item -LiteralPath $sentinel).LastWriteTimeUtc.Ticks
if($script:case -eq 'directory') {{ $null=New-Item -ItemType Directory $script:target }}
elseif($script:case -eq 'queued_reparse') {{
 $junctionTarget=Join-Path {lit(tmp_path)} 'junction-target'
 $null=New-Item -ItemType Directory $junctionTarget
 $null=New-Item -ItemType Junction -Path $script:target -Target $junctionTarget
}} else {{ [IO.File]::WriteAllText($script:target,'synthetic relcache') }}
function Remove-SyntheticLeaf {{
 if($script:case -in @('directory','queued_reparse')) {{ [IO.Directory]::Delete($script:target) }}
 else {{ [IO.File]::Delete($script:target) }}
 $script:changed=$true
}}
function Get-Item {{
 [CmdletBinding()] param([string]$LiteralPath,[switch]$Force)
 if($LiteralPath -eq $script:target -and -not $script:changed -and $script:case -notin @('present','acl','acl_denied','enumeration')) {{
  Remove-SyntheticLeaf
  if($script:case -in @('parent_replace','parent_reparse','parent_missing')) {{
   $parentPath=Split-Path $script:target
   $retained=$parentPath+'.retained'
   [IO.Directory]::Move($parentPath,$retained)
   if($script:case -eq 'parent_reparse') {{ $null=New-Item -ItemType Junction -Path $parentPath -Target $retained }}
   elseif($script:case -ne 'parent_missing') {{ $null=New-Item -ItemType Directory $parentPath }}
  }}
  if($script:case -eq 'item_denied') {{ throw (New-Object UnauthorizedAccessException 'synthetic item access denied') }}
 }}
 Microsoft.PowerShell.Management\Get-Item @PSBoundParameters
}}
function Get-Acl {{
 [CmdletBinding()] param([string]$LiteralPath)
 if($script:case -eq 'parent_acl_denied' -and $script:changed -and $LiteralPath -eq (Split-Path $script:target)) {{ throw (New-Object UnauthorizedAccessException 'synthetic parent ACL denied') }}
 if($LiteralPath -eq $script:target -and -not $script:changed -and $script:case -in @('acl','acl_denied')) {{
  Remove-SyntheticLeaf
  if($script:case -eq 'acl_denied') {{ throw (New-Object UnauthorizedAccessException 'synthetic ACL access denied') }}
 }}
 Microsoft.PowerShell.Security\Get-Acl @PSBoundParameters
}}
function Get-ChildItem {{
 [CmdletBinding()] param([string]$LiteralPath,[switch]$Force)
 if($script:case -eq 'enumeration' -and $LiteralPath -eq (Split-Path $script:target)) {{ throw (New-Object UnauthorizedAccessException 'synthetic enumeration denied') }}
 Microsoft.PowerShell.Management\Get-ChildItem @PSBoundParameters
}}
$accepted=$false; $failure=''
try {{ Assert-SawPrivateInstall $root; $accepted=$true }} catch {{ $failure=$_.Exception.Message }}
@{{accepted=$accepted; failure=$failure; changed=$script:changed;
 unchanged=([IO.File]::ReadAllText($sentinel) -ceq 'unchanged' -and (Microsoft.PowerShell.Management\Get-Item -LiteralPath $sentinel).LastWriteTimeUtc.Ticks -eq $before)}} | ConvertTo-Json -Compress
""")
    assert result["accepted"] == accepted, result
    assert result["unchanged"], result