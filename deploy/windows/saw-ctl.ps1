# SAW start / stop / status without Windows services (installed with install.ps1 -NoAdmin). PowerShell 5.1.
# Everything runs as the current user, bound to 127.0.0.1 only. No administrator rights are needed.
#   powershell -ExecutionPolicy Bypass -File "%LOCALAPPDATA%\SAW\saw-ctl.ps1" start
[CmdletBinding()]
param(
    [Parameter(Position = 0)][ValidateSet("start", "stop", "restart", "status")][string]$Action = "status",
    [string]$InstallRoot = ""
)
$ErrorActionPreference = "Stop"
if (-not $InstallRoot) { $InstallRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }  # empty in PS 5.1 param defaults
$cfg = Get-Content (Join-Path $InstallRoot "saw-ctl.json") -Raw | ConvertFrom-Json
$run = Join-Path $InstallRoot "run"
$logs = Join-Path $InstallRoot "logs"
New-Item -ItemType Directory -Force $run, (Join-Path $logs "saw"), (Join-Path $logs "postgresql") | Out-Null
$pgCtl = Join-Path $InstallRoot "pgsql\bin\pg_ctl.exe"
$pgData = Join-Path $InstallRoot "data\postgresql"
$osHome = (Get-ChildItem $InstallRoot -Directory -Filter "opensearch-*" | Select-Object -First 1).FullName
$vpy = Join-Path $InstallRoot "venv\Scripts\python.exe"
# Limit this process's PATH to bundled runtimes and Windows; do not change machine settings.
$env:PATH = (Join-Path $osHome 'jdk\bin') + ';' + (Split-Path $vpy) + ';' + (Join-Path $env:SystemRoot 'System32') + ';' + $env:SystemRoot
Get-ChildItem Env:SAW_* | ForEach-Object { Remove-Item -LiteralPath ('Env:' + $_.Name) }
$sawUrl = "https://localhost:$($cfg.port)/api/v1/health"
$osUrl = "http://127.0.0.1:$($cfg.opensearchPort)/_cluster/health"

function Get-Tracked([string]$name) {
    $f = Join-Path $run "$name.pid"
    if (-not (Test-Path $f)) { return $null }
    $p = Get-Process -Id ([int](Get-Content $f -Raw)) -ErrorAction SilentlyContinue
    if (-not $p) { Remove-Item $f -Force }
    return $p
}
function Stop-Tracked([string]$name) {
    $p = Get-Tracked $name
    if ($p) { & taskkill.exe /PID $p.Id /T /F | Out-Null; Remove-Item (Join-Path $run "$name.pid") -Force }
}
function Test-Up([string]$url) {
    $uri = [Uri]$url
    $kind = if ($uri.AbsolutePath -eq '/api/v1/health') { 'api' } else { 'opensearch' }
    $args_ = @('-m', 'saw.devtools.runtime_health', '--kind', $kind, '--port', $uri.Port)
    if ($kind -eq 'api') { $args_ += @('--ca', (Join-Path $InstallRoot 'tls\saw.crt')) }
    try { & $vpy @args_ *> $null; return ($LASTEXITCODE -eq 0) } catch { return $false }
}
function Wait-Up([string]$url, [string]$what, [int]$seconds) {
    for ($i = 0; $i -lt $seconds; $i += 2) { if (Test-Up $url) { return } ; Start-Sleep -Seconds 2 }
    throw "$what did not start within $seconds s; see $logs"
}
function Test-Pg { & $pgCtl status -D $pgData *> $null; return ($LASTEXITCODE -eq 0) }
# Long-running children are started through the shell (no inherited handles): a pipe handle inherited by
# postgres/java/python would keep the caller waiting for as long as they run.
function Start-Detached([string]$exe, [string]$argLine, [string]$dir) {
    $sp = @{ FilePath = $exe; WorkingDirectory = $dir; WindowStyle = "Hidden"; PassThru = $true }
    if ($argLine) { $sp.ArgumentList = $argLine }  # Start-Process rejects an empty argument list
    $p = Start-Process @sp
    $null = $p.Handle  # PS 5.1: keep the handle so ExitCode is available after exit
    return $p
}

function Start-All {
    if (-not (Test-Pg)) {
        Write-Host "PostgreSQL 시작 ..."
        $p = Start-Detached $pgCtl ('start -w -t 120 -D "{0}" -l "{1}"' -f $pgData, (Join-Path $logs "postgresql\postgresql.log")) $InstallRoot
        $p.WaitForExit()  # pg_ctl itself exits once the server accepts connections
        if ($p.ExitCode -ne 0) { throw "PostgreSQL did not start; see $logs\postgresql" }
    }
    if (-not (Test-Up $osUrl)) {
        Write-Host "OpenSearch 시작 ... (저사양 PC에서는 1~2분 걸릴 수 있습니다)"
        $env:OPENSEARCH_JAVA_HOME = Join-Path $osHome "jdk"  # the bundled JDK, never a JAVA_HOME found on the PC
        $p = Start-Detached (Join-Path $osHome "bin\opensearch.bat") "" $osHome
        Set-Content (Join-Path $run "opensearch.pid") $p.Id
        Wait-Up $osUrl "OpenSearch" 240
    }
    if (-not (Get-Tracked "saw") -or -not (Test-Up $sawUrl)) {
        Stop-Tracked "saw"
        Write-Host "SAW 시작 ..."
        $tls = Join-Path $InstallRoot "tls"
        # cmd does the log redirection so PowerShell never hands its own handles to the server process
        $cmdLine = ('/d /c ""{0}" -m saw.cli serve --host 127.0.0.1 --port {1} --cert "{2}" --key "{3}" >> "{4}" 2>&1"' -f
                    $vpy, $cfg.port, (Join-Path $tls "saw.crt"), (Join-Path $tls "saw.key"), (Join-Path $logs "saw\saw.log"))
        $p = Start-Detached (Join-Path $env:SystemRoot "System32\cmd.exe") $cmdLine (Join-Path $InstallRoot "app")
        Set-Content (Join-Path $run "saw.pid") $p.Id
        Wait-Up $sawUrl "SAW" 180
    }
    Write-Host "SAW 실행 중: https://localhost:$($cfg.port)/" -ForegroundColor Green
}

function Stop-All {
    Write-Host "SAW 종료 ..."
    Stop-Tracked "saw"
    # Flush accepted writes before stopping the process tree. Failed flush leaves the store running.
    if ((Get-Tracked "opensearch") -or (Test-Up $osUrl)) {
        if (-not (Test-Up $osUrl)) { throw 'OpenSearch is unhealthy; storage was left running.' }
        try { & $vpy -m saw.devtools.runtime_health --kind flush --port $cfg.opensearchPort *> $null }
        catch { throw 'OpenSearch flush failed; storage was left running.' }
        if ($LASTEXITCODE -ne 0) { throw 'OpenSearch flush failed; storage was left running.' }
    }
    Stop-Tracked "opensearch"
    if (Test-Pg) { & $pgCtl stop -D $pgData -m fast -w | Out-Null }
    Write-Host "종료했습니다. (원본 증거와 분석 결과는 그대로 보관됩니다)"
}

function Show-Status {
    "PostgreSQL : $(if (Test-Pg) { '실행 중' } else { '중지' })"
    "OpenSearch : $(if (Test-Up $osUrl) { '실행 중' } else { '중지' })"
    "SAW        : $(if (Test-Up $sawUrl) { "실행 중  https://localhost:$($cfg.port)/" } else { '중지' })"
}

switch ($Action) {
    "start" { Start-All }
    "stop" { Stop-All }
    "restart" { Stop-All; Start-All }
    "status" { Show-Status }
}
