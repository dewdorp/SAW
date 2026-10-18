"""Exercise actual PS5.1 updater boundaries without touching installations."""
from __future__ import annotations
import base64
import json
import os
import subprocess
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "deploy/windows/update-ui.psm1"
PS = Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell 5.1 UI contract")
def literal(value):
    return "'" + str(value).replace("'", "''") + "'"
def ps(source):
    code = "$env:PSModulePath=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/Modules'; $ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); Import-Module " + literal(MODULE) + " -Force; " + source
    proc = subprocess.run([str(PS), "-NoProfile", "-STA", "-ExecutionPolicy", "Bypass", "-EncodedCommand", base64.b64encode(code.encode("utf-16-le")).decode("ascii")], capture_output=True, timeout=45)
    assert proc.returncode == 0, proc.stderr.decode("utf-8", errors="replace")[-3000:]
    return json.loads(proc.stdout.decode("utf-8-sig").strip())

@pytest.mark.parametrize("action,maintenance,recovery,expected", [
    ("inspect", False, False, True), ("apply", False, False, False), ("apply", True, False, True),
    ("restore", True, False, False), ("restore", False, True, False), ("restore", True, True, True), ("start", False, False, True)])
def test_destructive_actions_require_operator_acknowledgement(tmp_path, action, maintenance, recovery, expected):
    output = ps(f"$errorText=Test-SawUpdateAction -Action {action} -InstallRoot {literal(tmp_path / 'installed')} -RecoveryPoint {literal(tmp_path / 'recovery')} -Maintenance:{'$'}{str(maintenance).lower()} -RecoveryAcknowledged:{'$'}{str(recovery).lower()}; @{{allowed=([string]::IsNullOrEmpty($errorText))}} | ConvertTo-Json -Compress")
    assert output["allowed"] is expected

def state_result(tmp_path, update=None, exit_code=0, raw=None):
    installed = tmp_path / "installed"
    state = {"schema": "saw.desktop-update/1", "action": "apply", "status": "completed", "phase": "complete", "install_root": str(installed), "message": "완료"}
    state.update(update or {})
    path = tmp_path / "state.json"
    path.write_text(json.dumps(state, ensure_ascii=False) if raw is None else raw, encoding="utf-8")
    return ps(f"Get-SawUpdateResult -StatePath {literal(path)} -Action apply -InstallRoot {literal(installed)} -ExitCode {exit_code} | ConvertTo-Json -Compress")
def test_correct_completed_result_is_accepted(tmp_path):
    assert state_result(tmp_path)["accepted"] is True
@pytest.mark.parametrize("update,exit_code", [({"status":"working"},0), ({"status":"ready"},0), ({"status":"failed"},0), ({"action":"restore"},0), ({"schema":"unexpected"},0), ({"install_root":"C:/different-installation"},0), ({},7)])
def test_exit_zero_alone_or_foreign_results_are_not_success(tmp_path, update, exit_code):
    assert state_result(tmp_path, update, exit_code)["accepted"] is False
@pytest.mark.parametrize("raw", ["{", "[]", " " * 70000], ids=["broken", "array", "oversized"])
def test_malformed_or_oversized_state_is_rejected(tmp_path, raw):
    assert state_result(tmp_path, raw=raw)["accepted"] is False
def test_missing_result_is_rejected(tmp_path):
    value = ps(f"Get-SawUpdateResult -StatePath {literal(tmp_path / 'missing.json')} -Action inspect -InstallRoot {literal(tmp_path / 'installed')} -ExitCode 0 | ConvertTo-Json -Compress")
    assert value["accepted"] is False

def test_worker_arguments_roundtrip_without_shell_evaluation(tmp_path):
    marker = tmp_path / "captured.json"
    worker = tmp_path / "작업 & '(literal).ps1"
    worker.write_text("param($Action,$InstallRoot,$BundleDir,$StateDir,$BaselineBundleDir,$RecoveryPoint,[switch]$MaintenanceConfirmed,[switch]$ConfirmPointInTimeRecovery)\n$PSBoundParameters | ConvertTo-Json -Compress | Set-Content -Encoding UTF8 -LiteralPath " + literal(marker), encoding="utf-8-sig")
    install = str(tmp_path / "설치 ' & $()")
    result = ps(f"$si=New-SawWorkerStartInfo -WorkerPath {literal(worker)} -Action apply -InstallRoot {literal(install)} -BundleDir {literal(tmp_path)} -StateDir {literal(tmp_path)} -RecoveryPoint {literal(tmp_path / '복구')} -MaintenanceConfirmed; $proc=[Diagnostics.Process]::Start($si); $proc.WaitForExit(); @{{exit=$proc.ExitCode;hidden=$si.CreateNoWindow;shell=$si.UseShellExecute}} | ConvertTo-Json -Compress")
    assert result == {"exit":0,"hidden":True,"shell":False}
    captured=json.loads(marker.read_text(encoding="utf-8-sig"))
    assert captured["InstallRoot"] == install
    assert captured["MaintenanceConfirmed"]["IsPresent"] is True
def test_private_state_directory_has_no_foreign_allow_principal(tmp_path):
    result=ps(f"$path=New-SawUpdateStateDirectory -BasePath {literal(tmp_path)}; $acl=Get-Acl -LiteralPath $path; $sids=@($acl.Access | ForEach-Object {{$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value}}); @{{path=$path;protected=$acl.AreAccessRulesProtected;sids=$sids;current=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value}} | ConvertTo-Json -Compress")
    assert result["protected"] is True
    assert set(result["sids"]) <= {result["current"],"S-1-5-18"}
    assert Path(result["path"]).is_dir()
def test_actual_winforms_has_update_restore_and_distinct_acknowledgements(tmp_path):
    result=ps(f"$view=New-SawUpdateWindow -BundleDir {literal(tmp_path)}; $view.Form.CreateControl(); @{{update=$view.Context.ApplyButton.Text;restore=$view.Context.RestoreButton.Text;maintenance=$view.Context.Maintenance.Checked;pointInTime=$view.Context.RecoveryAck.Checked;install=$view.Context.InstallRoot.Text}} | ConvertTo-Json -Compress; $view.Form.Dispose()")
    assert result["update"] == "업데이트 시작"
    assert result["restore"] == "이전 상태로 복구"
    assert result["maintenance"] is False
    assert result["pointInTime"] is False
    assert result["install"] == "C:\\SAW"


@pytest.mark.parametrize("path", ["relative", "C:SAW", "\\\\server\\share", "C:\\"])
def test_action_refuses_nonlocal_or_ambiguous_install_path(tmp_path, path):
    result = ps(f"$value=Test-SawUpdateAction -Action inspect -InstallRoot {literal(path)}; @{{allowed=([string]::IsNullOrEmpty($value))}} | ConvertTo-Json -Compress")
    assert result["allowed"] is False

def test_state_directory_is_empty_owned_and_separate(tmp_path):
    result = ps(f"$path=New-SawUpdateStateDirectory -BasePath {literal(tmp_path)}; $acl=Get-Acl -LiteralPath $path; @{{empty=(@(Get-ChildItem -LiteralPath $path -Force).Count -eq 0);owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;current=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value}} | ConvertTo-Json -Compress")
    assert result["empty"] and result["owner"] == result["current"]
    result = ps(f"$rejected=$false; try {{New-SawUpdateStateDirectory -BasePath {literal(tmp_path)} -ExcludedPaths @({literal(tmp_path)}) | Out-Null}} catch {{$rejected=$true}}; @{{rejected=$rejected}} | ConvertTo-Json -Compress")
    assert result["rejected"] is True

def test_winforms_event_gating_and_busy_close_preserve_worker(tmp_path):
    result = ps(f"""
$view=New-SawUpdateWindow -BundleDir {literal(tmp_path)}
$ctx=$view.Context
$view.Form.StartPosition='Manual'; $view.Form.Location=[Drawing.Point]::new(-3000,-3000)
$view.Form.Show(); [Windows.Forms.Application]::DoEvents()
$initial=(-not $ctx.ApplyButton.Enabled -and -not $ctx.RestoreButton.Enabled)
$ctx.Maintenance.Checked=$true
$maintenance=($ctx.ApplyButton.Enabled -and -not $ctx.RestoreButton.Enabled)
$ctx.RecoveryAck.Checked=$true
$ack=$ctx.RestoreButton.Enabled
Set-SawUpdateUiBusy $ctx $true
$disabled=(-not $ctx.InstallRoot.Enabled -and -not $ctx.ApplyButton.Enabled -and -not $ctx.InspectButton.Enabled)
$view.Form.Close()
$closeBlocked=(-not $view.Form.IsDisposed -and $view.Form.Visible)
Set-SawUpdateUiBusy $ctx $false
$view.Form.Close();$view.Form.Dispose()
@{{initial=$initial;maintenance=$maintenance;ack=$ack;disabled=$disabled;closeBlocked=$closeBlocked}} | ConvertTo-Json -Compress
""")
    assert all(result.values()), result

@pytest.mark.parametrize("status,code,write_result,accepted", [
    ("completed", 0, True, True), ("failed", 0, True, False),
    ("completed", 9, True, False), ("working", 0, True, False),
    ("completed", 0, False, False),
], ids=["success", "failed-state", "nonzero-exit", "unfinished-state", "missing-result"])
def test_actual_worker_completion_requires_matching_final_state(tmp_path, status, code, write_result, accepted):
    install=tmp_path/"installed"
    state={"schema":"saw.desktop-update/1","action":"apply","status":status,"phase":"complete","install_root":str(install)}
    encoded=base64.b64encode(json.dumps(state).encode()).decode()
    worker=tmp_path/"worker.ps1"
    write=("[IO.File]::WriteAllBytes((Join-Path $StateDir 'state.json'),[Convert]::FromBase64String('"+encoded+"'))") if write_result else ""
    worker.write_text("param($Action,$InstallRoot,$BundleDir,$StateDir)\nStart-Sleep -Milliseconds 250\n"+write+f"\nexit {code}\n",encoding="utf-8-sig")
    result=ps(f"""
$si=New-SawWorkerStartInfo -WorkerPath {literal(worker)} -Action apply -InstallRoot {literal(install)} -BundleDir {literal(tmp_path)} -StateDir {literal(tmp_path)}
$process=[Diagnostics.Process]::Start($si)
$before=Get-SawUpdateCompletion -Process $process -StatePath {literal(tmp_path/"state.json")} -Action apply -InstallRoot {literal(install)}
$process.WaitForExit()
$after=Get-SawUpdateCompletion -Process $process -StatePath {literal(tmp_path/"state.json")} -Action apply -InstallRoot {literal(install)}
@{{initialFinished=$before.finished;finished=$after.finished;accepted=$after.result.accepted}} | ConvertTo-Json -Compress
$process.Dispose()
""")
    assert result == {"initialFinished":False,"finished":True,"accepted":accepted}

@pytest.mark.parametrize("mode,requires", [("noadmin",True),("noadmin",False),("service",False),("",True)])
def test_elevation_is_unavailable_without_inspected_service_requirement(tmp_path, mode, requires):
    result=ps(f"$refused=$false;try{{New-SawElevatedUiStartInfo -Mode {literal(mode)} -RequiresAdmin:{'$'}{str(requires).lower()} -UiPath {literal(tmp_path/'ui.ps1')} | Out-Null}}catch{{$refused=$true}};@{{refused=$refused}} | ConvertTo-Json -Compress")
    assert result["refused"]

def test_admin_required_inspection_is_not_reported_as_full_acceptance(tmp_path):
    root=tmp_path/"installed"
    path=tmp_path/"state.json"
    path.write_text(json.dumps({"schema":"saw.desktop-update/1","action":"inspect","status":"ready","phase":"inspect","install_root":str(root),"mode":"service","requires_admin":True,"code":"administrator_required","message":"do not print arbitrary message"}),encoding="utf-8")
    result=ps(f"Get-SawUpdateResult -StatePath {literal(path)} -Action inspect -InstallRoot {literal(root)} -ExitCode 0 | Select-Object accepted,message,requires_admin,mode | ConvertTo-Json -Compress")
    assert result["accepted"] and result["requires_admin"] and result["mode"]=="service"
    assert "아직 끝나지 않았습니다" in result["message"]
    assert "arbitrary" not in result["message"]

@pytest.mark.parametrize("value", [{"mode":"unknown"},{"requires_admin":"false"},{"requires_admin":True,"mode":"noadmin"},{"phase":"bad\nphase"},{"schema":["saw.desktop-update/1"]}])
def test_malformed_security_relevant_state_fields_are_rejected(tmp_path,value):
    assert not state_result(tmp_path,value)["accepted"]


@pytest.mark.parametrize("value,allowed", [
    ("https://localhost:58449/",True),("https://127.0.0.1:8443/",True),
    ("http://localhost:8443/",False),("https://foreign.invalid/",False),
    ("file:///C:/Windows/",False),("https://user:password@localhost/",False),
    ("https://localhost/path",False),("https://localhost/?next=other",False),
    ("https://localhost/#fragment",False),("https://localhost/\n",False),
])
def test_browser_target_is_strict_local_https_without_credentials(tmp_path,value,allowed):
    result=ps(f"$url=Get-SawUpdateAppUrl {literal(value)};@{{allowed=(-not [string]::IsNullOrEmpty($url))}} | ConvertTo-Json -Compress")
    assert result["allowed"] is allowed

def test_retained_installation_must_be_matching_sibling(tmp_path):
    (tmp_path/".saw-k-123456abcdef").mkdir()
    (tmp_path/"foreign").mkdir()
    result=ps(f"$good=Get-SawRetainedInstallationPath -Value {literal(tmp_path/'.saw-k-123456abcdef')} -InstallRoot {literal(tmp_path/'installed')};$bad=Get-SawRetainedInstallationPath -Value {literal(tmp_path/'foreign')} -InstallRoot {literal(tmp_path/'installed')};@{{good=([bool]$good);bad=([bool]$bad)}} | ConvertTo-Json -Compress")
    assert result == {"good":True,"bad":False}

def test_record_folder_open_is_limited_to_ui_created_private_directory(tmp_path):
    result=ps(f"""
$path=New-SawUpdateStateDirectory -BasePath {literal(tmp_path)}
$owned=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$ctx=[pscustomobject]@{{StateDir=$path;OwnedStateDirs=$owned}}
$rejected=$false;try{{New-SawRecordStartInfo $ctx | Out-Null}}catch{{$rejected=$true}}
$null=$owned.Add($path)
$si=New-SawRecordStartInfo $ctx
@{{rejected=$rejected;explorer=($si.FileName -eq (Join-Path $env:SystemRoot 'explorer.exe'));argument=$si.Arguments}} | ConvertTo-Json -Compress
""")
    assert result["rejected"] and result["explorer"]
    assert result["argument"].startswith('"') and result["argument"].endswith('"')


def test_folder_labels_fit_their_visible_native_row(tmp_path):
    result=ps(f"""
$view=New-SawUpdateWindow -BundleDir {literal(tmp_path)}
$view.Form.StartPosition='Manual';$view.Form.Location=[Drawing.Point]::new(-3000,-3000);$view.Form.Show();[Windows.Forms.Application]::DoEvents()
$rows=@($view.Form.Controls[0].Controls | Where-Object {{$_.GetType().Name -eq 'TableLayoutPanel'}})
$visible=@($rows | Where-Object {{$_.Controls[0].Height -gt 0 -and $_.Controls[0].Height -le $_.Height}})
@{{rows=$rows.Count;visibleLabels=$visible.Count}} | ConvertTo-Json -Compress
$view.Form.Close();$view.Form.Dispose()
""")
    assert result == {"rows":4,"visibleLabels":4}


def test_failure_with_success_code_cannot_show_success_message(tmp_path):
    result=state_result(tmp_path,{"status":"failed","code":"completed"})
    assert not result["accepted"]
    assert "기동 확인이 끝났습니다" not in result["message"]
    assert "완료하지 못했습니다" in result["message"]

def test_completed_mutation_with_admin_requirement_is_not_success(tmp_path):
    result=state_result(tmp_path,{"mode":"service","requires_admin":True})
    assert not result["accepted"]


def test_native_compact_form_keeps_actions_and_status_visible(tmp_path):
    result=ps(f"""
$view=New-SawUpdateWindow -BundleDir {literal(tmp_path)}
$view.Form.StartPosition='Manual';$view.Form.Location=[Drawing.Point]::new(-3000,-3000)
$view.Form.Size=[Drawing.Size]::new(950,680)
$view.Form.Show();[Windows.Forms.Application]::DoEvents()
$controls=@($view.Context.InspectButton,$view.Context.ApplyButton,$view.Context.RestoreButton,$view.Context.StartButton,$view.Context.OpenButton,$view.Context.RecordsButton,$view.Context.Status)
$inside=@($controls | Where-Object {{
    $r=$view.Form.RectangleToClient($_.RectangleToScreen($_.ClientRectangle))
    $r.Left -ge 0 -and $r.Top -ge 0 -and $r.Right -le $view.Form.ClientSize.Width -and $r.Bottom -le $view.Form.ClientSize.Height
}})
@{{width=$view.Form.Width;height=$view.Form.Height;inside=$inside.Count;count=$controls.Count;statusHeight=$view.Context.Status.Height}} | ConvertTo-Json -Compress
$view.Form.Close();$view.Form.Dispose()
""")
    assert result["width"] == 950 and result["height"] == 680
    assert result["inside"] == result["count"] and result["statusHeight"] >= 40
