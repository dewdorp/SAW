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
. (Join-Path $PSScriptRoot 'setup-postgresql-state.ps1')
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
    if ($UserMode) { & icacls $path /inheritance:r /grant:r "*$($me):(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" | Out-Null; if ($LASTEXITCODE -ne 0) { throw "PostgreSQL secrets ACL failed (exit $LASTEXITCODE)" }; return }
    & icacls $path /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "PostgreSQL secrets ACL failed (exit $LASTEXITCODE)" }
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
    if ($Existing.StartName -notin @('NT AUTHORITY\NetworkService', 'NT AUTHORITY\NETWORK SERVICE')) { throw 'NetworkService identity required for PostgreSQL reinstall' }
    $command = $Existing.PathName.Trim()
    if ($command -ieq ('"' + $ServiceExe + '"') -or $command -ieq $ServiceExe) { return 'reuse' }
    $legacy = '^"?' + [regex]::Escape($PgCtl) + '"?\s+runservice\b'
    $cluster = '(?:^|\s)-D\s+"' + [regex]::Escape($Data) + '"(?:\s|$)'
    if ($command -match $legacy -and $command -match $cluster) {
        if ($Existing.State -ne 'Stopped') { throw 'Legacy PostgreSQL service must be stopped before explicit migration; no service was changed' }
        return 'migrate'
    }
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
    if ($serviceAction -eq 'reuse') {
        Assert-SawPostgresqlServiceConfig $serviceXml $InstallRoot $ServiceName $privatePath
        Assert-SawPostgresqlWrapper $serviceExe (Join-Path $BundleDir 'winsw\WinSW-x64.exe')
    }
}

$runtimePython = Join-Path $InstallRoot 'venv\Scripts\python.exe'
$runtimeVerifier = Join-Path (Split-Path (Split-Path $PSScriptRoot)) 'saw\devtools\postgresql_runtime.py'
if (-not [IO.File]::Exists($runtimePython) -or -not [IO.File]::Exists($runtimeVerifier)) {
    throw 'PostgreSQL runtime verification requires the prepared SAW Python and verified installation media'
}
& $runtimePython -B $runtimeVerifier --archive $zip.FullName --root $InstallRoot
if ($LASTEXITCODE -ne 0) { throw "PostgreSQL runtime verification/recovery failed (exit $LASTEXITCODE); existing binaries preserved" }
foreach ($exe in @('postgres.exe','initdb.exe','pg_ctl.exe','pg_controldata.exe','pg_isready.exe','psql.exe')) {
    if (-not [IO.File]::Exists((Join-Path $bin $exe))) { throw "PostgreSQL runtime incomplete ($exe missing); existing files were preserved" }
}
$version = & (Join-Path $bin 'postgres.exe') --version 2>&1
if ($LASTEXITCODE -ne 0 -or "$version" -notmatch '^postgres \(PostgreSQL\) 16\.15$') { throw 'PostgreSQL runtime version is incompatible with this media' }
$null = Assert-SawPostgresqlLocalPath $data $InstallRoot
$null = Assert-SawPostgresqlLocalPath $SecretsDir $InstallRoot
$clusterState = Get-SawPostgresqlClusterState $data $bin
$suFile = Join-Path $SecretsDir "postgres-superuser.pw"
$appFile = Join-Path $SecretsDir "postgres-saw.pw"
if ($clusterState -eq 'initialized' -and (-not [IO.File]::Exists($suFile) -or -not [IO.File]::Exists($appFile))) {
    throw 'Existing PostgreSQL cluster secrets are missing; no password was generated or changed'
}
$secretsExisted = Test-Path -LiteralPath $SecretsDir
New-Item -ItemType Directory -Force $SecretsDir | Out-Null
if (-not $DevNoAcl -and -not $secretsExisted) { Protect-Dir $SecretsDir }
foreach ($file in @($suFile, $appFile)) {
    $null = Assert-SawPostgresqlLocalPath $file $InstallRoot
    if (-not [IO.File]::Exists($file)) { Set-Content -LiteralPath $file -Value (New-Secret) -NoNewline -Encoding ASCII }
    if ((Get-Item -LiteralPath $file).Length -eq 0) { throw 'PostgreSQL secret file is empty; no existing secret was replaced' }
}
if ($clusterState -eq 'fresh') {
    Write-Host "Initialising cluster at $data ..."
    New-Item -ItemType Directory -Force $data | Out-Null
    $init = {
        # Configure inside initdb, so its success already includes the selected
        # port and loopback/SCRAM policy even if the installer stops immediately.
        $settings = @('-c', "port=$Port", '-c', 'listen_addresses=127.0.0.1',
            '-c', "shared_buffers=$SharedBuffers", '-c', 'max_connections=50',
            '-c', 'password_encryption=scram-sha-256', '-c', 'log_timezone=UTC', '-c', 'timezone=UTC')
        Invoke-SawPostgresqlInitInput $bin {
            param($InputDirectory)
            & (Join-Path $bin "initdb.exe") -D $data -U postgres --pwfile=$suFile -A scram-sha-256 -E UTF8 --locale=C -L $InputDirectory @settings
            $code = $LASTEXITCODE
            if ($code -ne 0) { throw "PostgreSQL initdb failed (exit $code), data $data; preserved for same-root retry or inspection" }
        }
        if ((Get-SawPostgresqlClusterState $data $bin) -ne 'initialized') { throw 'PostgreSQL initdb postcondition failed' }
    }
    if ($DevNoAcl) { & $init }
    elseif ($UserMode) { Invoke-SawPostgresqlPasswordAccess $InstallRoot $suFile $init }
    else {
        # initdb drops administrative group rights on Windows. Grant its actual SID,
        # temporarily, only the runtime, new data directory and this one password file.
        $runtimeScopes = @(
            @{Path=$InstallRoot; Rights='Traverse'; Inherit='None'},
            @{Path=$pg; Rights='ReadAndExecute'; Inherit='ContainerInherit,ObjectInherit'},
            @{Path=(Split-Path (Split-Path $RuntimeBin)); Rights='Traverse'; Inherit='None'},
            @{Path=(Split-Path $RuntimeBin); Rights='Traverse'; Inherit='None'},
            @{Path=$RuntimeBin; Rights='ReadAndExecute'; Inherit='ContainerInherit,ObjectInherit'},
            @{Path=(Split-Path $data); Rights='Traverse'; Inherit='None'},
            @{Path=$data; Rights='FullControl'; Inherit='ContainerInherit,ObjectInherit'}
        )
        Invoke-SawPostgresqlTemporaryAccess $runtimeScopes {
            Invoke-SawPostgresqlPasswordAccess $InstallRoot $suFile $init
        }
    }

}
if ($clusterState -eq 'fresh' -and $UserMode -and -not $DevNoAcl) {
    Protect-Dir $data
} elseif ($clusterState -eq 'fresh' -and -not $DevNoAcl) {
    # Data readable only by the service account (NetworkService, like the EDB installer), Administrators and SYSTEM
    & icacls $data /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-20:(OI)(CI)F" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "PostgreSQL data ACL failed (exit $LASTEXITCODE)" }
}

Assert-SawPostgresqlClusterConfig $data $bin $Port

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
        if ($p.ExitCode -ne 0) { throw "PostgreSQL did not start in user mode (exit $($p.ExitCode)); see $pgLog" }
    }
    $started = $true
} elseif (-not $NoService) {
    # pg_ctl register inherits SCM's environment, not the installer's private PATH.
    # WinSW v2.12.0 supplies that child environment without changing machine PATH.
    $pgLog = Join-Path $InstallRoot 'logs\postgresql'
    New-Item -ItemType Directory -Force $serviceDir, $pgLog | Out-Null
    if (-not $DevNoAcl -and $serviceAction -ne 'reuse') {
        . (Join-Path $PSScriptRoot 'install-paths.ps1')
        Grant-SawPostgresqlRuntimeAccess -InstallRoot $InstallRoot
        & icacls $serviceDir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-20:(OI)(CI)RX' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL service directory ACL failed' }
        & icacls $pgLog /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-20:(OI)(CI)M' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL log directory ACL failed' }
    }
    if ($serviceAction -ne 'reuse') {
        Initialize-SawPostgresqlServiceFiles $serviceExe $serviceXml (Join-Path $BundleDir 'winsw\WinSW-x64.exe') (Join-Path $PSScriptRoot 'postgresql-service.xml') $InstallRoot $ServiceName $privatePath
    }
    if ($serviceAction -eq 'migrate') {
        # Only a stopped legacy registration belonging to this exact cluster reaches here.
        & (Join-Path $bin 'pg_ctl.exe') unregister -N $ServiceName
        if ($LASTEXITCODE -ne 0) { throw 'Legacy PostgreSQL service unregister failed' }
    }
    if ($serviceAction -ne 'reuse') {
        & $serviceExe install
        if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL WinSW service install failed' }
    }
    $registered = Get-CimInstance Win32_Service -Filter ("Name='" + $ServiceName + "'")
    if ($null -eq $registered -or (Get-PostgresqlServiceAction $registered $serviceExe (Join-Path $bin 'pg_ctl.exe') $data) -ne 'reuse') {
        throw 'PostgreSQL service registration postcondition failed; Start-Service was not called'
    }
    Assert-SawPostgresqlServiceConfig $serviceXml $InstallRoot $ServiceName $privatePath
    if ($registered.State -eq 'Stopped') { Start-Service $ServiceName }
    elseif ($registered.State -ne 'Running') { throw 'PostgreSQL service is transitioning; retry after its state settles' }
    Wait-PostgresqlServiceReady (Join-Path $bin 'pg_isready.exe') $Port
    $started = $true
}

if ($started) {
    $suPw = [IO.File]::ReadAllText($suFile).Trim()
    $appPw = [IO.File]::ReadAllText($appFile).Trim()
    $psql = Join-Path $bin "psql.exe"
    try {
        $actualData = Get-SawPostgresqlDataDirectory $psql $Port $suPw
        if ([IO.Path]::GetFullPath($actualData).TrimEnd('\') -ine [IO.Path]::GetFullPath($data).TrimEnd('\')) {
            throw 'PostgreSQL endpoint belongs to another data directory; no application role or database was changed'
        }
        # Verify the effective settings on the authenticated, identity-matched
        # NetworkService-backed server, never by invoking postgres.exe as admin.
        $expectedLive = @{port=[string]$Port; listen_addresses='127.0.0.1'; password_encryption='scram-sha-256'}
        foreach ($setting in $expectedLive.Keys) {
            $actual = Invoke-SawPostgresqlSql $psql $Port 'postgres' 'postgres' $suPw ("SELECT current_setting('" + $setting + "')")
            if ($actual -cne $expectedLive[$setting]) {
                throw "Running NetworkService PostgreSQL security configuration differs: $setting"
            }
        }
        $exists = Invoke-SawPostgresqlSql $psql $Port 'postgres' 'postgres' $suPw "SELECT 1 FROM pg_roles WHERE rolname='saw'"
        if ($exists -ne '1') {
            $quoted = $appPw.Replace("'", "''")
            $null = Invoke-SawPostgresqlSql $psql $Port 'postgres' 'postgres' $suPw ("CREATE ROLE saw LOGIN PASSWORD '" + $quoted + "'")
        }
        $dbExists = Invoke-SawPostgresqlSql $psql $Port 'postgres' 'postgres' $suPw "SELECT 1 FROM pg_database WHERE datname='saw'"
        if ($dbExists -ne '1') {
            $null = Invoke-SawPostgresqlSql $psql $Port 'postgres' 'postgres' $suPw "CREATE DATABASE saw OWNER saw ENCODING 'UTF8' TEMPLATE template0"
        }
        $ready = Invoke-SawPostgresqlSql $psql $Port 'saw' 'saw' $appPw 'SELECT current_user'
        if ($ready -cne 'saw') { throw 'PostgreSQL application identity readiness failed' }
    } finally { $suPw=$null; $appPw=$null; $quoted=$null }
}
Write-Host "PostgreSQL configured (127.0.0.1:$Port, data $data). App password file: $appFile"
