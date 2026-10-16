# SAW offline installer for Windows 10/Server (target: Windows 10 Enterprise LTSC 2019 x64; target validation pending). ADR-0016.
# Run from the bundle root in an elevated PowerShell:
#   powershell -ExecutionPolicy Bypass -File .\install.ps1 -HostName saw.corp.local -AllowFrom 10.20.0.0/16
# Single analyst PC (browser on the same machine, nothing exposed to the network):
#   powershell -ExecutionPolicy Bypass -File .\install.ps1 -LocalOnly
# Analyst PC WITHOUT administrator rights (normal PowerShell; no services, installs under %LOCALAPPDATA%\SAW,
# started/stopped with saw-ctl.ps1 or the Start-menu shortcuts):
#   powershell -ExecutionPolicy Bypass -File .\install.ps1 -NoAdmin [-AutoStartAtLogon]
# Fresh installation only. Use the verified new media update.ps1 for a stopped existing installation.
[CmdletBinding()]
param(
    [string]$BundleDir = "",                        # default: the folder containing this script
    [string]$InstallRoot = "C:\SAW",
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
function Step($m) { Write-Host ""; Write-Host "==> $m" -ForegroundColor Cyan }
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
if ($freeGB -lt 20) { throw "At least 20 GB free disk is required on $drive (evidence and indices need more)." }
# Verify all files and required payloads; no bypass switch is provided.
& (Join-Path $BundleDir "verify-bundle.ps1") -BundleDir $BundleDir
if (Test-Path -LiteralPath (Join-Path $InstallRoot "app\.env")) { throw "An installation already exists. Use saw-ctl.ps1 restart; use the verified new media update.ps1 for upgrades." }
if (@($PostgresPort, $OpenSearchPort, $OpenSearchTransportPort, $Port | Select-Object -Unique).Count -ne 4) { throw "Ports must be distinct" }
# Establish exact private inheritance before creating code, configuration, or keys.
. (Join-Path $BundleDir 'app\deploy\windows\install-paths.ps1')
$InstallRoot = Initialize-SawInstallRoot -InstallRoot $InstallRoot -BundleDir $BundleDir -NoAdmin:$NoAdmin
$dirs = @{ app = "app"; data = "data\saw"; objects = "data\objects"; logs = "logs\saw"; tls = "tls"; secrets = "secrets";
           service = "service"; backup = "backup" }
foreach ($k in @($dirs.Keys)) { $dirs[$k] = Join-Path $InstallRoot $dirs[$k]; New-Item -ItemType Directory -Force $dirs[$k] | Out-Null }
foreach ($k in @("secrets", "tls", "data", "objects", "logs", "backup")) { Protect-Path $dirs[$k] }

# ---------------------------------------------------------------- 1. Python runtime
Step "Python 3.12 runtime"
if ($PythonExe) { throw "This release uses its bundled standalone Python; external interpreters are not accepted." }
$venv = Join-Path $InstallRoot "venv"
$scripts = Join-Path $venv "Scripts"
$site = Join-Path $venv "Lib\site-packages"
$vpy = Join-Path $scripts "python.exe"
if (Test-Path -LiteralPath $vpy) { throw "Existing Python runtime: choose a fresh install directory." }
New-Item -ItemType Directory -Force $scripts, $site | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $BundleDir "python\python-3.12.10-embed-amd64.zip"), $scripts)
[IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $BundleDir "bootstrap\pip-25.1.1-py3-none-any.whl"), $site)
Write-Utf8 (Join-Path $scripts "python312._pth") @('python312.zip','.','../Lib/site-packages','../../app','import site')
$env:PIP_CONFIG_FILE = 'NUL'; $env:PIP_NO_INDEX = '1'; $env:PIP_DISABLE_PIP_VERSION_CHECK = '1'
& $vpy -m pip install --quiet --no-index --no-cache-dir --no-warn-script-location --find-links (Join-Path $BundleDir "wheels") --target $site -r (Join-Path $BundleDir "app\deploy\windows\requirements.txt")
if ($LASTEXITCODE) { throw "offline package install failed" }
& $vpy -m pip check
if ($LASTEXITCODE) { throw "pip check failed" }

# ---------------------------------------------------------------- 2. application files
Step "Application files"
$src = Join-Path $BundleDir "app"
& robocopy $src $dirs.app /E /XD var __pycache__ /XF .env /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "copying application files failed (robocopy $LASTEXITCODE)" }

New-Item -ItemType Directory -Force (Join-Path $InstallRoot 'models') | Out-Null
if (Test-Path -LiteralPath (Join-Path $BundleDir 'llm-runtime')) {
    & robocopy (Join-Path $BundleDir 'llm-runtime') (Join-Path $InstallRoot 'llm-runtime') /E /NFL /NDL /NJH /NJS /NP | Out-Null
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
& (Join-Path $src "deploy\windows\setup-opensearch.ps1") @osArgs
# Preserve official JDK binaries and use their C runtime in place, scoped to child processes.
$runtimeBin = Join-Path $InstallRoot 'opensearch-2.19.6\jdk\bin'
$env:PATH = $runtimeBin + ';' + $scripts + ';' + (Join-Path $env:SystemRoot 'System32') + ';' + $env:SystemRoot
Step "PostgreSQL"
$pgArgs = $common.Clone(); $pgArgs.SharedBuffers = $PgSharedBuffers; $pgArgs.Port = $PostgresPort; $pgArgs.SecretsDir = $dirs.secrets; $pgArgs.RuntimeBin = $runtimeBin
if ($DevNoAcl) { $pgArgs.DevNoAcl = $true }
& (Join-Path $src "deploy\windows\setup-postgresql.ps1") @pgArgs

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
if (Test-Path $envFile) { & icacls $envFile /reset | Out-Null }  # repairs an empty DACL left by older installers
Write-Utf8 $envFile $cfg
Protect-Path $envFile

# ---------------------------------------------------------------- 5. TLS certificate
Step "TLS certificate"
$crt = Join-Path $dirs.tls "saw.crt"; $key = Join-Path $dirs.tls "saw.key"
if ($CertFile -and $KeyFile) {
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
@{ port = $Port; opensearchPort = $OpenSearchPort; postgresPort = $PostgresPort } | ConvertTo-Json |
    Set-Content -Path (Join-Path $InstallRoot "saw-ctl.json") -Encoding ASCII
if ($NoAdmin -and -not $NoServices) {
    Step "Start SAW as user processes (no services)"
    Copy-Item (Join-Path $src "deploy\windows\saw-ctl.ps1") $ctl -Force
    @{ port = $Port; opensearchPort = $OpenSearchPort; postgresPort = $PostgresPort } | ConvertTo-Json |
        Set-Content -Path (Join-Path $InstallRoot "saw-ctl.json") -Encoding ASCII
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
    if (-not (Test-Path $adminPwFile)) { Set-Content -Path $adminPwFile -Value (New-Secret) -NoNewline -Encoding ASCII }
    & $vpy -m saw.cli create-user admin --role admin --display-name "SAW Administrator" --password-file $adminPwFile --if-missing
    if ($LASTEXITCODE) { throw "initial administrator creation failed" }
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
    Copy-Item (Join-Path $BundleDir "winsw\WinSW-x64.exe") $exe -Force
    $tmpl = Get-Content (Join-Path $src "deploy\windows\saw-service.xml") -Raw
    # the folder is text inside XML: "&" or "<" in its name must be written as entities or the service cannot load
    $rootXml = [System.Security.SecurityElement]::Escape($InstallRoot)
    $tmpl = $tmpl.Replace("{{ROOT}}", $rootXml).Replace("{{PORT}}", "$Port").Replace("{{HOST}}", $bindHost)
    Write-Utf8 $xml $tmpl
    [xml](Get-Content -LiteralPath $xml -Raw -Encoding UTF8) | Out-Null  # fails here, with the reason, if it is not valid XML
    if (Get-Service -Name "saw" -ErrorAction SilentlyContinue) { & $exe stop | Out-Null; & $exe uninstall | Out-Null }
    & $exe install; if ($LASTEXITCODE) { throw "service install failed" }
    & $exe start
    if ($AllowFrom.Count -gt 0) {
        Step "Windows Firewall"
        Get-NetFirewallRule -DisplayName "SAW HTTPS" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        New-NetFirewallRule -DisplayName "SAW HTTPS" -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow `
            -RemoteAddress $AllowFrom -Profile Domain, Private | Out-Null
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

Copy-Item -LiteralPath (Join-Path $BundleDir "release-manifest.json") -Destination (Join-Path $InstallRoot "installed-release-manifest.json")

Step "Done"
Write-Host "URL:            https://$($HostName):$Port/"
Write-Host "Initial admin:  user 'admin', password in $($dirs.secrets)\initial-admin.pw (log in, enroll MFA, change it, delete the file)"
Write-Host "Certificate:    $crt  (if self-signed, distribute it to analyst PCs as a trusted root)"
Write-Host "Logs:           $InstallRoot\logs"
if ($NoAdmin) {
    Write-Host "Start / stop:   Start menu > SAW > 'SAW start' / 'SAW stop'  (or: powershell -ExecutionPolicy Bypass -File `"$ctl`" start|stop|status)"
    Write-Host "Note:           without a service SAW does not run after a reboot until started (use -AutoStartAtLogon to start at logon)."
}
