# SAW - PostgreSQL setup for Windows from the EDB binaries zip (ADR-0016). PowerShell 5.1 compatible, offline.
# Loopback-only cluster with SCRAM auth; creates role/database "saw". Passwords are generated, never printed.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BundleDir,
    [string]$InstallRoot = "C:\SAW",
    [int]$Port = 5432,
    [string]$RuntimeBin = "",
    [string]$ServiceName = "saw-postgresql",
    [string]$SecretsDir = "",                 # default: <InstallRoot>\secrets (ACL: Administrators + SYSTEM only)
    [string]$SharedBuffers = "256MB",         # small-server defaults; raise on larger hosts
    [switch]$NoService,
    [switch]$UserMode,                        # no administrator rights: no service, data owned by the current user,
                                              # started with pg_ctl (saw-ctl.ps1 starts/stops it later)
    [switch]$DevNoAcl                         # developer verification only: skip secrets ACL hardening
)
$ErrorActionPreference = "Stop"
if (-not $RuntimeBin) { $RuntimeBin = Join-Path $InstallRoot 'opensearch-2.19.6\jdk\bin' }
$expectedRuntime = [IO.Path]::GetFullPath((Join-Path $InstallRoot 'opensearch-2.19.6\jdk\bin'))
if ([IO.Path]::GetFullPath($RuntimeBin) -ne $expectedRuntime -or -not (Test-Path -LiteralPath (Join-Path $RuntimeBin 'vcruntime140.dll'))) { throw 'Bundled JDK C runtime missing' }
$privatePath = $RuntimeBin + ';' + (Join-Path $env:SystemRoot 'System32') + ';' + $env:SystemRoot
$env:PATH = $privatePath
if (-not $SecretsDir) { $SecretsDir = Join-Path $InstallRoot "secrets" }
$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

function New-Secret([int]$n = 32) {
    $bytes = New-Object byte[] $n
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return ([Convert]::ToBase64String($bytes) -replace '[+/=]', '').Substring(0, [Math]::Min(40, $n))
}

function Protect-Dir([string]$path) {
    # Only Administrators and SYSTEM (the services run as LocalSystem or a dedicated account added later);
    # in user mode the current user (who runs the processes) and SYSTEM
    if ($UserMode) { & icacls $path /inheritance:r /grant:r "*$($me):(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" | Out-Null; return }
    & icacls $path /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" | Out-Null
}

function Write-PostgresqlServiceXml([string]$Template, [string]$Destination, [string]$Root, [string]$Name, [string]$ChildPath) {
    if ($Name -notmatch '^[A-Za-z0-9_.-]+$') { throw 'Invalid PostgreSQL service name' }
    $xml = [IO.File]::ReadAllText($Template, [Text.Encoding]::UTF8)
    $xml = $xml.Replace('{{ROOT}}', [Security.SecurityElement]::Escape($Root))
    $xml = $xml.Replace('{{NAME}}', [Security.SecurityElement]::Escape($Name))
    $xml = $xml.Replace('{{PATH}}', [Security.SecurityElement]::Escape($ChildPath))
    $null = [xml]$xml
    [IO.File]::WriteAllText($Destination, $xml, (New-Object Text.UTF8Encoding $false))
}
# END PostgreSQL XML renderer

function Get-PostgresqlServiceAction($Existing, [string]$ServiceExe, [string]$PgCtl, [string]$Data) {
    if ($null -eq $Existing) { return 'create' }
    # Never replace a live cluster, another installation, or a different account.
    if ($Existing.State -ne 'Stopped') { throw 'PostgreSQL service must be stopped before reinstalling; stop dependent SAW services first' }
    if ($Existing.StartName -notin @('NT AUTHORITY\NetworkService', 'NT AUTHORITY\NETWORK SERVICE')) { throw 'NetworkService identity required for PostgreSQL reinstall' }
    $command = $Existing.PathName.Trim()
    if ($command -ieq ('"' + $ServiceExe + '"') -or $command -ieq $ServiceExe) { return 'reuse' }
    $legacy = '^"?' + [regex]::Escape($PgCtl) + '"?\s+runservice\b'
    $cluster = '(?:^|\s)-D\s+"' + [regex]::Escape($Data) + '"(?:\s|$)'
    if ($command -match $legacy -and $command -match $cluster) { return 'migrate' }
    throw 'Unrecognized PostgreSQL service registration; no service was changed'
}
# END PostgreSQL registration classifier


function Wait-PostgresqlServiceReady([string]$ReadyCommand, [int]$DbPort, [int]$Attempts = 60) {
    for ($attempt = 0; $attempt -lt $Attempts; $attempt++) {
        & $ReadyCommand -h 127.0.0.1 -p $DbPort -U postgres -t 1 *> $null
        if ($LASTEXITCODE -eq 0) { return }
        Start-Sleep -Seconds 1
    }
    throw 'PostgreSQL service readiness deadline exceeded; inspect its protected log'
}
# END PostgreSQL readiness

$zip = Get-ChildItem (Join-Path $BundleDir "postgresql") -Filter "postgresql-*-windows-x64-binaries.zip" | Select-Object -First 1
if (-not $zip) { throw "postgresql binaries zip not found under $BundleDir\postgresql" }
$pg = Join-Path $InstallRoot "pgsql"
$bin = Join-Path $pg "bin"
$data = Join-Path $InstallRoot "data\postgresql"

$serviceDir = Join-Path $InstallRoot 'service'
$serviceExe = Join-Path $serviceDir ($ServiceName + '.exe')
$serviceXml = Join-Path $serviceDir ($ServiceName + '.xml')
$serviceAction = 'create'
if (-not $UserMode -and -not $NoService) {
    if ($ServiceName -notmatch '^[A-Za-z0-9_.-]+$') { throw 'Invalid PostgreSQL service name' }
    $existing = Get-CimInstance Win32_Service -Filter ("Name='" + $ServiceName + "'")
    $serviceAction = Get-PostgresqlServiceAction $existing $serviceExe (Join-Path $bin 'pg_ctl.exe') $data
}

if (-not (Test-Path (Join-Path $bin "postgres.exe"))) {
    Write-Host "Extracting $($zip.Name) ..."
    New-Item -ItemType Directory -Force $InstallRoot | Out-Null
    $tar = Join-Path $env:SystemRoot "System32\tar.exe"
    if (Test-Path $tar) { & $tar -xf $zip.FullName -C $InstallRoot } else { Expand-Archive $zip.FullName -DestinationPath $InstallRoot }
}
New-Item -ItemType Directory -Force $SecretsDir | Out-Null
if (-not $DevNoAcl) { Protect-Dir $SecretsDir }
$suFile = Join-Path $SecretsDir "postgres-superuser.pw"
$appFile = Join-Path $SecretsDir "postgres-saw.pw"
if (-not (Test-Path $suFile)) { Set-Content -Path $suFile -Value (New-Secret) -NoNewline -Encoding ASCII }
if (-not (Test-Path $appFile)) { Set-Content -Path $appFile -Value (New-Secret) -NoNewline -Encoding ASCII }

if (-not (Test-Path (Join-Path $data "PG_VERSION"))) {
    Write-Host "Initialising cluster at $data ..."
    New-Item -ItemType Directory -Force (Split-Path $data) | Out-Null
    & (Join-Path $bin "initdb.exe") -D $data -U postgres --pwfile=$suFile -A scram-sha-256 -E UTF8 --locale=C
    if ($LASTEXITCODE -ne 0) { throw "initdb failed" }
    $conf = @"

# --- SAW (deploy/windows/setup-postgresql.ps1) ---
listen_addresses = '127.0.0.1'
port = $Port
shared_buffers = $SharedBuffers
max_connections = 50
password_encryption = scram-sha-256
log_timezone = 'UTC'
timezone = 'UTC'
"@
    Add-Content -Path (Join-Path $data "postgresql.conf") -Value $conf -Encoding ASCII
    Set-Content -Path (Join-Path $data "pg_hba.conf") -Encoding ASCII -Value @(
        "# SAW: loopback only, SCRAM",
        "host    all    all    127.0.0.1/32    scram-sha-256",
        "host    all    all    ::1/128         scram-sha-256")
}
if ($UserMode -and -not $DevNoAcl) {
    Protect-Dir $data
} elseif (-not $DevNoAcl) {
    # Data readable only by the service account (NetworkService, like the EDB installer), Administrators and SYSTEM
    & icacls $data /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-20:(OI)(CI)F" | Out-Null
}

$started = $false
if ($UserMode) {
    $pgLog = Join-Path $InstallRoot "logs\postgresql"
    New-Item -ItemType Directory -Force $pgLog | Out-Null
    & (Join-Path $bin "pg_ctl.exe") status -D $data *> $null
    if ($LASTEXITCODE -ne 0) {
        # started through the shell and waited for by process: a piped call would hang (postgres inherits the pipe)
        $p = Start-Process -FilePath (Join-Path $bin "pg_ctl.exe") -WindowStyle Hidden -PassThru `
            -ArgumentList ('start -w -t 120 -D "{0}" -l "{1}"' -f $data, (Join-Path $pgLog "postgresql.log"))
        $null = $p.Handle
        $p.WaitForExit()
        if ($p.ExitCode -ne 0) { throw "PostgreSQL did not start (user mode); see $pgLog" }
    }
    $started = $true
} elseif (-not $NoService) {
    # pg_ctl register inherits SCM's environment, not the installer's private PATH.
    # WinSW v2.12.0 supplies that child environment without changing machine PATH.
    $pgLog = Join-Path $InstallRoot 'logs\postgresql'
    New-Item -ItemType Directory -Force $serviceDir, $pgLog | Out-Null
    if (-not $DevNoAcl) {
        . (Join-Path $PSScriptRoot 'install-paths.ps1')
        Grant-SawPostgresqlRuntimeAccess -InstallRoot $InstallRoot
        & icacls $serviceDir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-20:(OI)(CI)RX' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL service directory ACL failed' }
        & icacls $pgLog /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-20:(OI)(CI)M' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL log directory ACL failed' }
    }
    Copy-Item -LiteralPath (Join-Path $BundleDir 'winsw\WinSW-x64.exe') -Destination $serviceExe -Force
    Write-PostgresqlServiceXml (Join-Path $PSScriptRoot 'postgresql-service.xml') $serviceXml $InstallRoot $ServiceName $privatePath
    if ($serviceAction -eq 'migrate') {
        # Only a stopped legacy registration belonging to this exact cluster reaches here.
        & (Join-Path $bin 'pg_ctl.exe') unregister -N $ServiceName
        if ($LASTEXITCODE -ne 0) { throw 'Legacy PostgreSQL service unregister failed' }
    }
    if ($serviceAction -ne 'reuse') {
        & $serviceExe install
        if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL WinSW service install failed' }
    }
    Start-Service $ServiceName
    Wait-PostgresqlServiceReady (Join-Path $bin 'pg_isready.exe') $Port
    $started = $true
}

if ($started) {
    $env:PGPASSWORD = (Get-Content $suFile -Raw)
    $appPw = (Get-Content $appFile -Raw)
    $psql = Join-Path $bin "psql.exe"
    $exists = & $psql -h 127.0.0.1 -p $Port -U postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname='saw'"
    if ($exists -ne "1") {
        & $psql -h 127.0.0.1 -p $Port -U postgres -v ON_ERROR_STOP=1 -q -c "CREATE ROLE saw LOGIN PASSWORD '$appPw'"
        & $psql -h 127.0.0.1 -p $Port -U postgres -v ON_ERROR_STOP=1 -q -c "CREATE DATABASE saw OWNER saw ENCODING 'UTF8' TEMPLATE template0"
    }
    Remove-Item Env:PGPASSWORD
}
Write-Host "PostgreSQL configured (127.0.0.1:$Port, data $data). App password file: $appFile"
