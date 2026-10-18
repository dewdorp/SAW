# SAW offline installer for Windows 10/Server (target: Windows 10 Enterprise LTSC 2019 x64; target validation pending). ADR-0016.
# Run from the bundle root in an elevated PowerShell:
#   powershell -ExecutionPolicy Bypass -File .\install.ps1 -HostName saw.corp.local -AllowFrom 10.20.0.0/16
# Single analyst PC (browser on the same machine, nothing exposed to the network):
#   powershell -ExecutionPolicy Bypass -File .\install.ps1 -LocalOnly
# Analyst PC WITHOUT administrator rights (normal PowerShell; no services, installs under %LOCALAPPDATA%\SAW,
# started/stopped with saw-ctl.ps1 or the Start-menu shortcuts):
#   powershell -ExecutionPolicy Bypass -File .\install.ps1 -NoAdmin [-AutoStartAtLogon]
# New installation / safe resume / read-only completed-install verification. Use update.ps1 for version upgrades.
[CmdletBinding()]
param(
    [string]$BundleDir = "",                        # default: the folder containing this script
    [string]$InstallRoot = "C:\SAW",
    [switch]$ChooseInstallLocation,
    [string]$BaselineBundleDir = "",
    [string]$HostName = $env:COMPUTERNAME,         # name analysts type in the browser (certificate SAN)
    [string[]]$ExtraNames = @(),                    # more SANs: FQDN, IP address
    [int]$Port = 443,
    [string[]]$AllowFrom = @(),                     # firewall: analyst subnets/IPs; empty = no rule created
    [string]$CertFile = "",                         # organisation-issued certificate (PEM); empty = self-signed
    [string]$KeyFile = "",
    [int]$OpenSearchHeapGB = 1,
    [string]$PgSharedBuffers = "256MB",
    [string]$PythonExe = "",                        # use an existing Python 3.12 x64 instead of the bundled installer
    [switch]$LocalOnly,                             # analyst PC: bind 127.0.0.1, no firewall rule, memory sized for a desktop
    [switch]$NoAdmin,                               # analyst PC without admin rights: user processes, no services (implies -LocalOnly)
    [switch]$AutoStartAtLogon,                      # with -NoAdmin: start SAW when the user logs on (Startup folder shortcut)
    [int]$PostgresPort = 5432,
    [int]$OpenSearchPort = 9200,
    [int]$OpenSearchTransportPort = 9300,
    [switch]$SkipShortcuts,
    [switch]$NoServices,                            # developer dry run (no services or firewall; root remains private)
    [switch]$DevNoAcl
)
$ErrorActionPreference = "Stop"
$env:PSModulePath = (Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\Modules") + ";" + $env:PSModulePath
Get-ChildItem Env:SAW_* | ForEach-Object { Remove-Item -LiteralPath ("Env:" + $_.Name) }
if (-not $BundleDir) { $BundleDir = Split-Path -Parent $MyInvocation.MyCommand.Path }  # $PSScriptRoot is empty in PS 5.1 param defaults
if ($NoAdmin) {
    $LocalOnly = $true
    if (-not $PSBoundParameters.ContainsKey("InstallRoot")) { $InstallRoot = Join-Path $env:LOCALAPPDATA "SAW" }
    if (-not $PSBoundParameters.ContainsKey("Port")) { $Port = 8443 }
}
if ($ChooseInstallLocation) {
    Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -ne $null } |
        Select-Object Name, @{Name='여유 공간(GB)';Expression={[math]::Round($_.Free/1GB,1)}} | Format-Table | Out-Host
    $choice=Read-Host "설치 폴더를 입력하세요 (예: D:\SAW, Enter=$InstallRoot)"
    if ($choice) { $InstallRoot=$choice }
}
if ($InstallRoot -notmatch '^[A-Za-z]:\\') { throw 'Choose an absolute local path such as D:\SAW' }
# The install folder ends up inside configuration files, command lines and URLs. Spaces, "&" and non-English names
# are handled; the characters below would change the meaning of those files, so they are refused up front.
if ($InstallRoot -match '[%"''`;^!#$]') {
    throw "The install folder '$InstallRoot' contains one of the characters % "" ' `` ; ^ ! # `$ - choose a folder without them."
}
$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
# Files that carry paths are written as UTF-8 without a byte-order mark: ASCII turns a Korean folder name into "?".
function Write-Utf8([string]$Path, $Lines) {
    [IO.File]::WriteAllLines($Path, [string[]]@($Lines), (New-Object Text.UTF8Encoding $false))
}
$installContext=$null
function Step($m) {
    if ($installContext) { Set-SawInstallStage $installContext $m }
    Write-Host ""; Write-Host "==> $m" -ForegroundColor Cyan
}
function Protect-Path([string]$path) {
    if ($DevNoAcl) { return }
    # (OI)(CI) inheritance flags are for folders only: on a FILE icacls reports success but leaves an empty DACL
    # (nobody, not even the service account, can read it) - so files get plain grants
    $inherit = if (Test-Path -LiteralPath $path -PathType Container) { "(OI)(CI)" } else { "" }
    $owner = if ($NoAdmin) { "*$($me)" } else { "*S-1-5-32-544" }
    & icacls $path /inheritance:r /grant:r "$($owner):$($inherit)F" "*S-1-5-18:$($inherit)F" | Out-Null
    if ($LASTEXITCODE) { throw "setting permissions on $path failed" }
}
function New-Secret([int]$n = 24) {
    $b = New-Object byte[] $n
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    # guarantee the password policy (upper, lower, digit, symbol) regardless of the random part
    return "Sw!" + (([Convert]::ToBase64String($b) -replace '[+/=]', '')) + "7a"
}

# ---------------------------------------------------------------- 0. pre-flight
Step "Pre-flight checks"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $NoServices -and -not $NoAdmin) {
    throw "Run this script in an elevated (Administrator) PowerShell, or use -NoAdmin on a PC without admin rights."
}
$os = Get-CimInstance Win32_OperatingSystem
$ramGB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
$drive = (Split-Path -Qualifier $InstallRoot)
$freeGB = [math]::Round((Get-PSDrive ($drive.TrimEnd(':'))).Free / 1GB, 1)
Write-Host "OS: $($os.Caption) build $($os.BuildNumber); RAM ${ramGB} GB; free on ${drive}: ${freeGB} GB"
$cores = (Get-CimInstance Win32_Processor | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
Write-Host "CPU logical processors: $cores"
if ($ramGB -lt 8) { Write-Warning "Less than 8 GB RAM: keep -OpenSearchHeapGB 1 and expect slower analysis." }
if ($cores -lt 4) { Write-Warning "Fewer than 4 logical processors: large files will take noticeably longer." }
# memory sizing when not given explicitly: leave room for Windows, the browser and Office on a desktop PC
if (-not $PSBoundParameters.ContainsKey("OpenSearchHeapGB")) {
    $OpenSearchHeapGB = if ($ramGB -ge 30) { 4 } elseif ($ramGB -ge 15) { 2 } else { 1 }
}
if (-not $PSBoundParameters.ContainsKey("PgSharedBuffers") -and $ramGB -lt 12) { $PgSharedBuffers = "128MB" }
$bindHost = "0.0.0.0"
if ($LocalOnly) {
    $bindHost = "127.0.0.1"
    if (-not $PSBoundParameters.ContainsKey("HostName")) { $HostName = "localhost" }
    $ExtraNames = @($ExtraNames) + @("127.0.0.1")
    if ($AllowFrom.Count -gt 0) { Write-Warning "-LocalOnly ignores -AllowFrom (no inbound access)."; $AllowFrom = @() }
}
Write-Host "Profile: $(if ($LocalOnly) { 'analyst PC (local only)' } else { 'server' }); OpenSearch heap ${OpenSearchHeapGB} GB; PostgreSQL shared_buffers $PgSharedBuffers"
if ($OpenSearchHeapGB -gt [math]::Floor($ramGB / 2)) { throw "OpenSearch heap ($OpenSearchHeapGB GB) must be <= half of RAM." }
# Verify all files and required payloads; no bypass switch is provided.
& (Join-Path $BundleDir "verify-bundle.ps1") -BundleDir $BundleDir
if ($BaselineBundleDir) { & (Join-Path $BundleDir "verify-bundle.ps1") -BundleDir $BaselineBundleDir }
if (@($PostgresPort, $OpenSearchPort, $OpenSearchTransportPort, $Port | Select-Object -Unique).Count -ne 4) { throw "Ports must be distinct" }
. (Join-Path $BundleDir 'app\deploy\windows\install-paths.ps1')
. (Join-Path $BundleDir 'app\deploy\windows\install-state.ps1')
. (Join-Path $BundleDir 'app\deploy\windows\install-python.ps1')
$layout=Get-SawInstallLayout $InstallRoot
Write-Host "설치 위치: $($layout.root)"
Write-Host "DB: $($layout.database)"
Write-Host "검색 색인: $($layout.indices)"
Write-Host "분석 원본: $($layout.evidence)"
Write-Host "모델 / 백업: $($layout.models) / $($layout.backup)"
Write-Host "여유 공간 $freeGB GB (설치 최소 20GB, 원본·색인·모델·백업 용량은 별도 확보)"
$options=@{noAdmin=[bool]$NoAdmin;noServices=[bool]$NoServices;localOnly=[bool]$LocalOnly;
    hostName=$HostName;port=$Port;postgresPort=$PostgresPort;opensearchPort=$OpenSearchPort;
    opensearchTransportPort=$OpenSearchTransportPort;heapGB=$OpenSearchHeapGB;sharedBuffers=$PgSharedBuffers}
$installContext=Enter-SawInstall -InstallRoot $InstallRoot -BundleDir $BundleDir -Options $options -BaselineBundleDir $BaselineBundleDir
$InstallRoot=$installContext.Root
try {
if ($installContext.Mode -eq 'verify') {
    Assert-SawCompletedInstall $installContext $BundleDir $options
    Write-Host "기존 설치 검증 완료. 계정·비밀값·데이터·설정과 서비스 실행 상태를 변경하지 않았습니다."
    Write-Host "설치 위치: $InstallRoot / 프로그램 업데이트는 새 매체의 update.ps1을 사용하세요."
    return
}
if ($freeGB -lt 20) { throw "At least 20 GB free disk is required on $drive (evidence and indices need more)." }
$payloadBundle=$installContext.PayloadBundle
$payloadManifest=Read-SawInstallManifest (Join-Path $payloadBundle 'release-manifest.json')
Assert-SawApplicationFiles $InstallRoot $payloadManifest -AllowMissing
$dirs = @{ app = "app"; data = "data\saw"; objects = "data\objects"; logs = "logs\saw"; tls = "tls"; secrets = "secrets";
           service = "service"; backup = "backup" }
foreach ($k in @($dirs.Keys)) { $dirs[$k] = Join-Path $InstallRoot $dirs[$k]; New-Item -ItemType Directory -Force $dirs[$k] | Out-Null }
if ($installContext.Mode -eq 'new') {
    foreach ($k in @("secrets", "tls", "data", "objects", "logs", "backup")) { Protect-Path $dirs[$k] }
}

# ---------------------------------------------------------------- 1. Python runtime
Step "Python 3.12 runtime"
if ($PythonExe) { throw "This release uses its bundled standalone Python; external interpreters are not accepted." }
$venv = Join-Path $InstallRoot "venv"
$scripts = Join-Path $venv "Scripts"
$site = Join-Path $venv "Lib\site-packages"
$vpy = Join-Path $scripts "python.exe"
# install-python.ps1 verifies python-3.12.10-embed-amd64.zip and uses offline --no-index wheels.
$vpy=Ensure-SawPythonRuntime -BundleDir $payloadBundle -InstallRoot $InstallRoot

# ---------------------------------------------------------------- 2. application files
Step "Application files"
$src = Join-Path $payloadBundle "app"
& robocopy $src $dirs.app /E /XC /XN /XO /XD var __pycache__ /XF .env /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "copying application files failed (robocopy $LASTEXITCODE)" }

New-Item -ItemType Directory -Force (Join-Path $InstallRoot 'models') | Out-Null
if (Test-Path -LiteralPath (Join-Path $BundleDir 'llm-runtime')) {
    & robocopy (Join-Path $payloadBundle 'llm-runtime') (Join-Path $InstallRoot 'llm-runtime') /E /XC /XN /XO /NFL /NDL /NJH /NJS /NP | Out-Null
    if ($LASTEXITCODE -ge 8) { throw 'LLM runtime copy failed' }
}
$runtimeManifest = Join-Path $InstallRoot 'llm-runtime\runtime-manifest.json'
$runtimePin = ''
if (Test-Path -LiteralPath $runtimeManifest) {
    $stream = [IO.File]::OpenRead($runtimeManifest); $hash = [Security.Cryptography.SHA256]::Create()
    try { $runtimePin = ([BitConverter]::ToString($hash.ComputeHash($stream))).Replace('-','').ToLowerInvariant() }
    finally { $stream.Dispose(); $hash.Dispose() }
}
# ---------------------------------------------------------------- 3. PostgreSQL + OpenSearch
$common = @{ BundleDir = $BundleDir; InstallRoot = $InstallRoot }
if ($NoServices) { $common.NoService = $true }
if ($NoAdmin) { $common.UserMode = $true }
Step "OpenSearch"
$osArgs = $common.Clone(); $osArgs.HeapGB = $OpenSearchHeapGB; $osArgs.Port = $OpenSearchPort; $osArgs.TransportPort = $OpenSearchTransportPort
if ($DevNoAcl) { $osArgs.DevNoAcl = $true }
& (Join-Path $BundleDir "app\deploy\windows\setup-opensearch.ps1") @osArgs
# Preserve official JDK binaries and use their C runtime in place, scoped to child processes.
$runtimeBin = Join-Path $InstallRoot 'opensearch-2.19.6\jdk\bin'
$env:PATH = $runtimeBin + ';' + $scripts + ';' + (Join-Path $env:SystemRoot 'System32') + ';' + $env:SystemRoot
Step "PostgreSQL"
$pgArgs = $common.Clone(); $pgArgs.SharedBuffers = $PgSharedBuffers; $pgArgs.Port = $PostgresPort; $pgArgs.SecretsDir = $dirs.secrets; $pgArgs.RuntimeBin = $runtimeBin
if ($DevNoAcl) { $pgArgs.DevNoAcl = $true }
& (Join-Path $BundleDir "app\deploy\windows\setup-postgresql.ps1") @pgArgs

# ---------------------------------------------------------------- 4. configuration (.env, ACL-protected)
Step "Configuration"
$envFile = Join-Path $dirs.app ".env"
$pgPw = (Get-Content (Join-Path $dirs.secrets "postgres-saw.pw") -Raw).Trim()
$cfg = @(
    "# Generated by install.ps1 - contains the database password; readable by Administrators/SYSTEM only",
    "SAW_ENV=prod",
    "SAW_DATA_DIR=$($dirs.data)",
    "SAW_DATABASE_URL=postgresql+psycopg://saw:$pgPw@127.0.0.1:$PostgresPort/saw",
    "SAW_SCHEMA_MODE=migrate",
    "SAW_EVENT_STORE=opensearch",
    "SAW_OPENSEARCH_URL=http://127.0.0.1:$OpenSearchPort",
    # Every profile acknowledges a stored batch only after its translog is durable.
    "SAW_OPENSEARCH_DURABILITY=request",
    "SAW_OBJECT_STORE=local",
    "SAW_OBJECT_STORE_ROOT=$($dirs.objects)",
    "SAW_JOB_RUNNER=inprocess",
    "SAW_JOB_WORKERS=1",
    "SAW_RAW_STORE=auto",
    "SAW_COOKIE_SECURE=true",
    "SAW_WEB_DIST=$(Join-Path $dirs.app 'apps\web\dist')",
    "SAW_LLM_MODELS_ROOT=$(Join-Path $InstallRoot 'models')",
    "SAW_LLM_RUNTIME_ROOT=$(Join-Path $InstallRoot 'llm-runtime')",
    "SAW_LLM_SYNTHETIC_INVESTIGATION_IDS=[]",
    "SAW_LLM_RUNTIME_MANIFEST_SHA256=$runtimePin",
    "SAW_LLM_CPU_WORK_ROOT=$(Join-Path $dirs.data 'ai-work')"
)
if (Test-Path -LiteralPath $envFile) {
    Assert-SawInstalledConfiguration $InstallRoot $options
} else {
    Write-Utf8 $envFile $cfg
    Protect-Path $envFile
}
$pgPw=$null; $cfg=$null

# ---------------------------------------------------------------- 5. TLS certificate
Step "TLS certificate"
$crt = Join-Path $dirs.tls "saw.crt"; $key = Join-Path $dirs.tls "saw.key"
if ((Test-Path -LiteralPath $crt) -xor (Test-Path -LiteralPath $key)) { throw 'Incomplete existing TLS pair; preserve and review it before retry' }
if (Test-Path -LiteralPath $crt) {
    if (($CertFile -and (Get-SawFileDigest $crt) -ne (Get-SawFileDigest $CertFile)) -or
        ($KeyFile -and (Get-SawFileDigest $key) -ne (Get-SawFileDigest $KeyFile))) { throw 'Existing TLS differs; certificate rotation is a separate operation' }
} elseif ($CertFile -and $KeyFile) {
    Copy-Item $CertFile $crt -Force; Copy-Item $KeyFile $key -Force
} elseif (-not (Test-Path $crt)) {
    $names = @($HostName) + $ExtraNames | Where-Object { $_ } | Select-Object -Unique
    $nameArgs = @(); foreach ($n in $names) { $nameArgs += @("--name", $n) }
    Push-Location $dirs.app
    & $vpy -m saw.cli make-cert @nameArgs --out $dirs.tls
    Pop-Location
    if ($LASTEXITCODE) { throw "certificate generation failed" }
}
Protect-Path $dirs.tls

# ---------------------------------------------------------------- 5b. user-mode processes (-NoAdmin)
$ctl = Join-Path $InstallRoot "saw-ctl.ps1"
if (-not (Test-Path -LiteralPath (Join-Path $InstallRoot "saw-ctl.json"))) {
    @{ port = $Port; opensearchPort = $OpenSearchPort; postgresPort = $PostgresPort } | ConvertTo-Json |
        Set-Content -Path (Join-Path $InstallRoot "saw-ctl.json") -Encoding ASCII
}
if ($NoAdmin -and -not $NoServices) {
    Step "Start SAW as user processes (no services)"
    if (-not (Test-Path -LiteralPath $ctl)) { Copy-Item (Join-Path $src "deploy\windows\saw-ctl.ps1") $ctl }
    elseif ((Get-SawFileDigest $ctl) -ne (Get-SawFileDigest (Join-Path $src "deploy\windows\saw-ctl.ps1"))) { throw 'Existing control script changed; preserve and review' }
    & $ctl start  # same process: throws with the reason if a component does not come up
}

# ---------------------------------------------------------------- 6. schema + first administrator
Step "Database schema and initial administrator"
Push-Location $dirs.app
if ($NoServices) { Write-Host "(dry run: PostgreSQL/OpenSearch are not running as services; skipping schema/admin)" }
else {
    $adminPwFile = Join-Path $dirs.secrets "initial-admin.pw"
    & $vpy -m saw.cli migrate
    if ($LASTEXITCODE) { throw "database migration failed" }
    $adminQuery="import base64;exec(base64.b64decode('ZnJvbSBzcWxhbGNoZW15IGltcG9ydCBzZWxlY3QKZnJvbSBzYXcuc3RvcmFnZS5tb2RlbHMgaW1wb3J0IFVzZXIKZnJvbSBzYXcuc3RvcmFnZS5kYiBpbXBvcnQgc2Vzc2lvbl9zY29wZQpmcm9tIHNhdyBpbXBvcnQgY29udGFpbmVyCmNvbnRhaW5lci5idWlsZCgpCndpdGggc2Vzc2lvbl9zY29wZSgpIGFzIHM6CiAgICBwcmludCgxIGlmIHMuZXhlY3V0ZShzZWxlY3QoVXNlci5pZCkud2hlcmUoVXNlci51c2VybmFtZT09J2FkbWluJykpLmZpcnN0KCkgZWxzZSAwKQo='))"
    $adminStatus=& $vpy -B -c $adminQuery
    if ($LASTEXITCODE -ne 0 -or $adminStatus -notin @('1','0')) { throw 'Cannot verify existing administrator; no password was generated' }
    if ($adminStatus -eq '0') {
        if (-not (Test-Path -LiteralPath $adminPwFile)) { Set-Content -Path $adminPwFile -Value (New-Secret) -NoNewline -Encoding ASCII }
        & $vpy -m saw.cli create-user admin --role admin --display-name "SAW Administrator" --password-file $adminPwFile --if-missing
        if ($LASTEXITCODE) { throw "initial administrator creation failed" }
    } else { Write-Host 'Existing administrator preserved; no initial password was regenerated.' }
}
Pop-Location

# ---------------------------------------------------------------- 7. Windows service (WinSW) or user shortcuts
if ($NoAdmin -and -not $NoServices -and -not $SkipShortcuts) {
    Step "Start-menu shortcuts (current user)"
    $shell = New-Object -ComObject WScript.Shell
    $menu = Join-Path ([Environment]::GetFolderPath("Programs")) "SAW"
    New-Item -ItemType Directory -Force $menu | Out-Null
    $ps = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    function New-Shortcut([string]$path, [string]$action, [string]$style) {
        $lnk = $shell.CreateShortcut($path)
        $lnk.TargetPath = $ps
        $lnk.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle $style -File `"$ctl`" $action"
        $lnk.WorkingDirectory = $InstallRoot
        $lnk.Save()
    }
    New-Shortcut (Join-Path $menu "SAW start.lnk") "start" "Normal"
    New-Shortcut (Join-Path $menu "SAW stop.lnk") "stop" "Normal"
    New-Shortcut (Join-Path $menu "SAW status.lnk") "status" "Normal"
    Set-Content -Path (Join-Path $menu "SAW open.url") -Encoding ASCII -Value @("[InternetShortcut]", "URL=https://localhost:$Port/")
    $startup = Join-Path ([Environment]::GetFolderPath("Startup")) "SAW start.lnk"
    if ($AutoStartAtLogon) { New-Shortcut $startup "start" "Hidden"; Write-Host "SAW starts automatically at logon." }
    elseif (Test-Path $startup) { Remove-Item $startup -Force }
}
if (-not $NoServices -and -not $NoAdmin) {
    Step "SAW Windows service"
    $exe = Join-Path $dirs.service "saw-service.exe"
    $xml = Join-Path $dirs.service "saw-service.xml"
    $existingSaw=Get-CimInstance Win32_Service -Filter "Name='saw'"
    if ($existingSaw -and $existingSaw.PathName.Trim('"') -ine $exe) { throw 'The saw service belongs to another installation; no service was changed' }
    if (-not (Test-Path -LiteralPath $exe)) { Copy-Item (Join-Path $BundleDir "winsw\WinSW-x64.exe") $exe }
    elseif ((Get-SawFileDigest $exe) -ne (Get-SawFileDigest (Join-Path $BundleDir "winsw\WinSW-x64.exe"))) { throw 'Existing service wrapper differs from pinned media' }
    $tmpl = Get-Content (Join-Path $src "deploy\windows\saw-service.xml") -Raw
    # the folder is text inside XML: "&" or "<" in its name must be written as entities or the service cannot load
    $rootXml = [System.Security.SecurityElement]::Escape($InstallRoot)
    $tmpl = $tmpl.Replace("{{ROOT}}", $rootXml).Replace("{{PORT}}", "$Port").Replace("{{HOST}}", $bindHost)
    if (Test-Path -LiteralPath $xml) {
        if ([IO.File]::ReadAllText($xml).Trim() -cne $tmpl.Trim()) { throw 'Existing SAW service configuration differs; preserve and review' }
    } else { Write-Utf8 $xml $tmpl }
    [xml](Get-Content -LiteralPath $xml -Raw -Encoding UTF8) | Out-Null  # fails here, with the reason, if it is not valid XML
    if (-not $existingSaw) {
        & $exe install
        if ($LASTEXITCODE -ne 0 -or -not (Get-Service -Name "saw" -ErrorAction SilentlyContinue)) { throw "SAW service registration failed (exit $LASTEXITCODE)" }
    }
    if ((Get-Service -Name "saw").Status -ne 'Running') {
        & $exe start
        if ($LASTEXITCODE -ne 0) { throw "SAW service start failed (exit $LASTEXITCODE)" }
    }
    if ($AllowFrom.Count -gt 0) {
        Step "Windows Firewall"
        $existingRule=Get-NetFirewallRule -DisplayName "SAW HTTPS" -ErrorAction SilentlyContinue
        if ($existingRule) { Write-Warning 'Existing SAW HTTPS firewall rule preserved; verify its selected port and analyst subnets.' }
        else { New-NetFirewallRule -DisplayName "SAW HTTPS" -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow `
            -RemoteAddress $AllowFrom -Profile Domain, Private | Out-Null }
    } elseif (-not $LocalOnly) {
        Write-Warning "No -AllowFrom given: no inbound firewall rule was created (analyst PCs cannot connect yet)."
    }
    Step "Health check"
    $ok = $false
    for ($i = 0; $i -lt 40 -and -not $ok; $i++) {
        Start-Sleep -Seconds 3
        try { $r = & $vpy -m saw.devtools.runtime_health --kind api --port $Port --tls-name $HostName --ca $crt 2>$null; $ok = ($LASTEXITCODE -eq 0) } catch { $ok = $false }
    }
    if (-not $ok) { throw "SAW did not become healthy; see $($dirs.logs) and $InstallRoot\logs\opensearch" }
    Write-Host $r
}

if ($NoServices) { throw 'Configuration-only preparation ended; service/schema/admin verification was not performed. Installation is not complete.' }
Copy-Item -LiteralPath (Join-Path $payloadBundle "release-manifest.json") -Destination (Join-Path $InstallRoot "installed-release-manifest.json") -Force
Assert-SawCompletedInstall $installContext $BundleDir $options -RequireLive
Complete-SawInstall $installContext
Write-Host "설치 완료"
Write-Host "URL:            https://$($HostName):$Port/"
Write-Host "Initial admin:  user 'admin', password in $($dirs.secrets)\initial-admin.pw (log in, enroll MFA, change it, delete the file)"
Write-Host "Certificate:    $crt  (if self-signed, distribute it to analyst PCs as a trusted root)"
Write-Host "Logs:           $InstallRoot\logs"
if ($NoAdmin) {
    Write-Host "Start / stop:   Start menu > SAW > 'SAW start' / 'SAW stop'  (or: powershell -ExecutionPolicy Bypass -File `"$ctl`" start|stop|status)"
    Write-Host "Note:           without a service SAW does not run after a reboot until started (use -AutoStartAtLogon to start at logon)."
}

} catch {
    $nativeCode=1
    if ($_.Exception.Message -match '\(exit (-?\d+)\)') { $nativeCode=[int]$matches[1] }
    if ($installContext) {
        Set-SawInstallFailed $installContext $nativeCode
        Write-Host "설치 실패: 단계=$($installContext.State.stage); 종료코드=$nativeCode; 설치 위치=$InstallRoot"
        Write-Host "완료 단계: $(@($installContext.State.completed) -join ', ')"
        Write-Host "원인 확인 후 같은 매체·같은 설치 경로·같은 옵션으로 재실행하세요. Python이나 데이터 폴더를 삭제하지 마세요."
    }
    throw
} finally {
    if ($installContext) { Exit-SawInstall $installContext }
}
