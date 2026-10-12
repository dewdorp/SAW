# SAW backup (run elevated, e.g. as a nightly scheduled task). PostgreSQL dump + OpenSearch snapshot + evidence files.
#   powershell -ExecutionPolicy Bypass -File C:\SAW\app\deploy\windows\backup.ps1 [-KeepDays 14]
# Copy C:\SAW\backup to separate media regularly; a backup on the same disk does not survive disk failure.
[CmdletBinding()]
param([string]$InstallRoot = "C:\SAW", [int]$KeepDays = 14, [switch]$ApplyRetention)
$ErrorActionPreference = "Stop"
$env:PSModulePath = (Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\Modules") + ";" + $env:PSModulePath
$cfg = Get-Content -LiteralPath (Join-Path $InstallRoot 'saw-ctl.json') -Raw | ConvertFrom-Json
$osHome = Join-Path $InstallRoot 'opensearch-2.19.6'
$env:PATH = (Join-Path $osHome 'jdk\bin') + ';' + (Join-Path $env:SystemRoot 'System32') + ';' + $env:SystemRoot
$osUrl = "http://127.0.0.1:$($cfg.opensearchPort)"
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$bk = Join-Path $InstallRoot "backup"
New-Item -ItemType Directory -Force (Join-Path $bk "postgresql"), (Join-Path $bk "objects") | Out-Null

# 1. PostgreSQL (custom format, restorable with pg_restore)
$env:PGPASSWORD = (Get-Content (Join-Path $InstallRoot "secrets\postgres-superuser.pw") -Raw).Trim()
$dump = Join-Path $bk "postgresql\saw-$stamp.dump"
& (Join-Path $InstallRoot "pgsql\bin\pg_dump.exe") -h 127.0.0.1 -p $cfg.postgresPort -U postgres -Fc -f $dump saw
$rc = $LASTEXITCODE
Remove-Item Env:PGPASSWORD
if ($rc) { throw "pg_dump failed" }

# 2. OpenSearch snapshot into path.repo (registered on first use)
$repoPath = (Join-Path $bk "opensearch") -replace '\\', '/'
$body = @{ type = 'fs'; settings = @{ location = $repoPath; compress = $true } } | ConvertTo-Json -Compress
Invoke-RestMethod -Method Put -Uri "$osUrl/_snapshot/saw" -ContentType 'application/json' -Body $body | Out-Null
$snapshotBody = @{ indices = 'saw-*'; include_global_state = $false } | ConvertTo-Json -Compress
$snap = Invoke-RestMethod -Method Put -Uri "$osUrl/_snapshot/saw/saw-$($stamp.ToLower())?wait_for_completion=true" -ContentType 'application/json' -Body $snapshotBody
if ($snap.snapshot.state -ne 'SUCCESS') { throw 'OpenSearch snapshot failed' }

# 3. Evidence originals and artifacts (incremental mirror)
& robocopy (Join-Path $InstallRoot "data\objects") (Join-Path $bk "objects") /E /R:2 /W:5 /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "evidence copy failed" }

# Retention is explicit; the default backup does not delete previous recovery points.
if ($ApplyRetention) {
Get-ChildItem (Join-Path $bk "postgresql") -Filter *.dump | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$KeepDays) } | Remove-Item
$old = (Get-Date).AddDays(-$KeepDays)
$list = Invoke-RestMethod -Uri "$osUrl/_snapshot/saw/_all"
foreach ($s in $list.snapshots) {
    if ([DateTimeOffset]::FromUnixTimeMilliseconds($s.start_time_in_millis).LocalDateTime -lt $old) {
        Invoke-RestMethod -Method Delete -Uri "$osUrl/_snapshot/saw/$($s.snapshot)" | Out-Null
    }
}
}
Write-Host "Backup complete: $dump, snapshot saw-$($stamp.ToLower()), evidence mirror"
