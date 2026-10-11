# SAW backup (run elevated, e.g. as a nightly scheduled task). PostgreSQL dump + OpenSearch snapshot + evidence files.
#   powershell -ExecutionPolicy Bypass -File C:\SAW\app\deploy\windows\backup.ps1 [-KeepDays 14]
# Copy C:\SAW\backup to separate media regularly; a backup on the same disk does not survive disk failure.
[CmdletBinding()]
param([string]$InstallRoot = "C:\SAW", [int]$KeepDays = 14)
$ErrorActionPreference = "Stop"
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$bk = Join-Path $InstallRoot "backup"
New-Item -ItemType Directory -Force (Join-Path $bk "postgresql"), (Join-Path $bk "objects") | Out-Null

# 1. PostgreSQL (custom format, restorable with pg_restore)
$env:PGPASSWORD = (Get-Content (Join-Path $InstallRoot "secrets\postgres-superuser.pw") -Raw).Trim()
$dump = Join-Path $bk "postgresql\saw-$stamp.dump"
& (Join-Path $InstallRoot "pgsql\bin\pg_dump.exe") -h 127.0.0.1 -U postgres -Fc -f $dump saw
$rc = $LASTEXITCODE
Remove-Item Env:PGPASSWORD
if ($rc) { throw "pg_dump failed" }

# 2. OpenSearch snapshot into path.repo (registered on first use)
$repoPath = (Join-Path $bk "opensearch") -replace '\\', '/'
$body = '{"type":"fs","settings":{"location":"' + $repoPath + '","compress":true}}'
& curl.exe -s -X PUT "http://127.0.0.1:9200/_snapshot/saw" -H "Content-Type: application/json" -d $body | Out-Null
$snap = & curl.exe -s -X PUT "http://127.0.0.1:9200/_snapshot/saw/saw-$($stamp.ToLower())?wait_for_completion=true" -H "Content-Type: application/json" -d '{"indices":"saw-*","include_global_state":false}'
if ($snap -notmatch '"state":"SUCCESS"') { throw "OpenSearch snapshot failed: $snap" }

# 3. Evidence originals and artifacts (incremental mirror)
& robocopy (Join-Path $InstallRoot "data\objects") (Join-Path $bk "objects") /MIR /R:2 /W:5 /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "evidence copy failed" }

# Retention
Get-ChildItem (Join-Path $bk "postgresql") -Filter *.dump | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$KeepDays) } | Remove-Item
$old = (Get-Date).AddDays(-$KeepDays)
$list = & curl.exe -s "http://127.0.0.1:9200/_snapshot/saw/_all" | ConvertFrom-Json
foreach ($s in $list.snapshots) {
    if ([DateTimeOffset]::FromUnixTimeMilliseconds($s.start_time_in_millis).LocalDateTime -lt $old) {
        & curl.exe -s -X DELETE "http://127.0.0.1:9200/_snapshot/saw/$($s.snapshot)" | Out-Null
    }
}
Write-Host "Backup complete: $dump, snapshot saw-$($stamp.ToLower()), evidence mirror"
