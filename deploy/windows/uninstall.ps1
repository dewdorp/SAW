# Remove SAW services and firewall rule. Data, backups and secrets are KEPT unless -RemoveData is given.
#   powershell -ExecutionPolicy Bypass -File C:\SAW\app\deploy\windows\uninstall.ps1 [-RemoveData]
[CmdletBinding()]
#   user-mode install (-NoAdmin, no admin rights needed): uninstall.ps1 -InstallRoot "$env:LOCALAPPDATA\SAW"
param([string]$InstallRoot = "C:\SAW", [switch]$RemoveData)
$ErrorActionPreference = "Continue"
$ctl = Join-Path $InstallRoot "saw-ctl.ps1"
if (Test-Path $ctl) {  # user-mode install: stop the user processes and remove the shortcuts
    & powershell -NoProfile -ExecutionPolicy Bypass -File $ctl stop
    Remove-Item -Recurse -Force (Join-Path ([Environment]::GetFolderPath("Programs")) "SAW") -ErrorAction SilentlyContinue
    Remove-Item -Force (Join-Path ([Environment]::GetFolderPath("Startup")) "SAW start.lnk") -ErrorAction SilentlyContinue
}
$svcExe = Join-Path $InstallRoot "service\saw-service.exe"
if (Test-Path $svcExe) { & $svcExe stop; & $svcExe uninstall }
$os = Get-ChildItem $InstallRoot -Directory -Filter "opensearch-*" | Select-Object -First 1
if ($os -and (Get-Service saw-opensearch -ErrorAction SilentlyContinue)) {
    Stop-Service saw-opensearch -ErrorAction SilentlyContinue
    & (Join-Path $os.FullName "bin\opensearch-service.bat") remove saw-opensearch
}
if (Get-Service saw-postgresql -ErrorAction SilentlyContinue) {
    Stop-Service saw-postgresql -ErrorAction SilentlyContinue
    & (Join-Path $InstallRoot "pgsql\bin\pg_ctl.exe") unregister -N saw-postgresql
}
if (Get-NetFirewallRule -DisplayName "SAW HTTPS" -ErrorAction SilentlyContinue) {  # none in user mode
    Get-NetFirewallRule -DisplayName "SAW HTTPS" | Remove-NetFirewallRule
}
if ($RemoveData) {
    $answer = Read-Host "Type DELETE to permanently remove $InstallRoot including all evidence, indices and backups"
    if ($answer -eq "DELETE") { Remove-Item -Recurse -Force $InstallRoot; Write-Host "Removed $InstallRoot" }
    else { Write-Host "Data kept." }
} else {
    Write-Host "Services removed. Data kept in $InstallRoot (re-run install.ps1 to restore services)."
}
