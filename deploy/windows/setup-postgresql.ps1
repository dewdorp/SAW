# SAW - PostgreSQL setup for Windows from the EDB binaries zip (ADR-0016). PowerShell 5.1 compatible, offline.
# Loopback-only cluster with SCRAM auth; creates role/database "saw". Passwords are generated, never printed.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BundleDir,
    [string]$InstallRoot = "C:\SAW",
    [int]$Port = 5432,
    [string]$ServiceName = "saw-postgresql",
    [string]$SecretsDir = "",                 # default: <InstallRoot>\secrets (ACL: Administrators + SYSTEM only)
    [string]$SharedBuffers = "256MB",         # small-server defaults; raise on larger hosts
    [switch]$NoService,
    [switch]$UserMode,                        # no administrator rights: no service, data owned by the current user,
                                              # started with pg_ctl (saw-ctl.ps1 starts/stops it later)
    [switch]$DevNoAcl                         # developer verification only: skip secrets ACL hardening
)
$ErrorActionPreference = "Stop"
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

$zip = Get-ChildItem (Join-Path $BundleDir "postgresql") -Filter "postgresql-*-windows-x64-binaries.zip" | Select-Object -First 1
if (-not $zip) { throw "postgresql binaries zip not found under $BundleDir\postgresql" }
$pg = Join-Path $InstallRoot "pgsql"
$bin = Join-Path $pg "bin"
$data = Join-Path $InstallRoot "data\postgresql"

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
    if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
        & (Join-Path $bin "pg_ctl.exe") register -N $ServiceName -D $data -S auto -w -U "NT AUTHORITY\NetworkService"
        if ($LASTEXITCODE -ne 0) { throw "pg_ctl register failed" }
        & sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/300000 | Out-Null
    }
    Start-Service $ServiceName
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
