# SAW - OpenSearch single-node setup for Windows (ADR-0016). PowerShell 5.1 compatible, offline.
# Loopback-only node used by SAW alone: security plugin removed, only ISM + job-scheduler + nori kept (low memory).
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BundleDir,      # offline-bundle root (contains opensearch\*.zip)
    [string]$InstallRoot = "C:\SAW",
    [int]$HeapGB = 1,                                       # JVM heap; <= 50% of RAM, 1-2 GB on small servers
    [int]$Port = 9200,
    [int]$TransportPort = 9300,
    [string]$ServiceName = "saw-opensearch",
    [switch]$NoService,                                     # configure only (e.g. developer verification)
    [switch]$UserMode,                                      # no administrator rights: no service; saw-ctl.ps1 runs it
    [switch]$DevNoAcl
)
if ($UserMode) { $NoService = $true }
$ErrorActionPreference = "Stop"
$KeepPlugins = @("opensearch-index-management", "opensearch-job-scheduler")

$zip = Get-ChildItem (Join-Path $BundleDir "opensearch") -Filter "opensearch-*-windows-x64.zip" | Select-Object -First 1
$nori = Get-ChildItem (Join-Path $BundleDir "opensearch") -Filter "analysis-nori-*.zip" | Select-Object -First 1
if (-not $zip -or -not $nori) { throw "opensearch zip or analysis-nori zip not found under $BundleDir\opensearch" }
$version = $zip.Name -replace '^opensearch-(.+)-windows-x64\.zip$', '$1'
$home_ = Join-Path $InstallRoot "opensearch-$version"
$data = Join-Path $InstallRoot "data\opensearch"
$logs = Join-Path $InstallRoot "logs\opensearch"

if (-not (Test-Path $home_)) {
    Write-Host "Extracting $($zip.Name) to $InstallRoot ..."
    New-Item -ItemType Directory -Force $InstallRoot | Out-Null
    $tar = Join-Path $env:SystemRoot "System32\tar.exe"
    if (Test-Path $tar) { & $tar -xf $zip.FullName -C $InstallRoot } else { Expand-Archive $zip.FullName -DestinationPath $InstallRoot }
}
New-Item -ItemType Directory -Force $data, $logs, (Join-Path $InstallRoot "backup\opensearch") | Out-Null
$bin = Join-Path $home_ "bin"
$env:OPENSEARCH_JAVA_HOME = Join-Path $home_ "jdk"

Write-Host "Trimming plugins (keep: $($KeepPlugins -join ', '), analysis-nori) ..."
# Delete plugin folders directly: 'opensearch-plugin remove' refuses plugins that others extend, and order varies by release
foreach ($p in Get-ChildItem (Join-Path $home_ "plugins") -Directory) {
    if ($KeepPlugins -notcontains $p.Name -and $p.Name -ne "analysis-nori") {
        $pluginPath = (Resolve-Path -LiteralPath $p.FullName).Path
        if (-not $pluginPath.StartsWith((Join-Path $home_ 'plugins') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe plugin path' }
        Remove-Item -LiteralPath $pluginPath -Recurse -Force
        $cfg = Join-Path $home_ ("config\" + $p.Name)
        if (Test-Path -LiteralPath $cfg) {
            $configPath = (Resolve-Path -LiteralPath $cfg).Path
            if (-not $configPath.StartsWith((Join-Path $home_ 'config') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe plugin config path' }
            Remove-Item -LiteralPath $configPath -Recurse -Force
        }
    }
}
if (-not (Test-Path (Join-Path $home_ "plugins\analysis-nori"))) {
    $uri = "file:///" + ($nori.FullName -replace '\\', '/')
    & (Join-Path $bin "opensearch-plugin.bat") install --batch $uri
    if ($LASTEXITCODE -ne 0) { throw "analysis-nori install failed" }
}

$yml = @"
# Managed by SAW deploy/windows/setup-opensearch.ps1
cluster.name: saw
node.name: saw-node-1
path.data: "$($data -replace '\\', '/')"
path.logs: "$($logs -replace '\\', '/')"
network.host: 127.0.0.1
http.port: $Port
transport.port: $TransportPort
discovery.type: single-node
bootstrap.memory_lock: false
path.repo: ["$((Join-Path $InstallRoot 'backup\opensearch') -replace '\\', '/')"]
# SAW creates its own monthly indices; system indices of ISM/job-scheduler also need auto-create
action.auto_create_index: "+saw*,+.opendistro-*,+.plugins-*,+.opensearch-*,-*"
cluster.routing.allocation.disk.watermark.low: 85%
cluster.routing.allocation.disk.watermark.high: 90%
cluster.routing.allocation.disk.watermark.flood_stage: 95%
"@
# UTF-8 without a byte-order mark (YAML's encoding): ASCII would turn a Korean install folder into "?"
[IO.File]::WriteAllText((Join-Path $home_ "config\opensearch.yml"), $yml, (New-Object Text.UTF8Encoding $false))
$jvmd = Join-Path $home_ "config\jvm.options.d"
New-Item -ItemType Directory -Force $jvmd | Out-Null
Set-Content -Path (Join-Path $jvmd "saw-heap.options") -Value @("-Xms$($HeapGB)g", "-Xmx$($HeapGB)g") -Encoding ASCII

if ($UserMode -and -not $DevNoAcl) {  # runs as the current user: indices readable by that user and SYSTEM only
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    foreach ($d in @($data, $logs)) { & icacls $d /inheritance:r /grant:r "*$($me):(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" | Out-Null }
} elseif (-not $DevNoAcl) {  # service runs as LocalSystem: indices readable by Administrators/SYSTEM only
    foreach ($d in @($data, $logs)) { & icacls $d /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" | Out-Null }
}
if (-not $NoService) {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) { & (Join-Path $bin "opensearch-service.bat") remove $ServiceName | Out-Null }
    & (Join-Path $bin "opensearch-service.bat") install $ServiceName
    if ($LASTEXITCODE -ne 0) { throw "OpenSearch service install failed" }
    & sc.exe config $ServiceName start= delayed-auto | Out-Null
    & sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/300000 | Out-Null
    Start-Service $ServiceName
}
Write-Host "OpenSearch $version configured at $home_ (http://127.0.0.1:$Port, heap $($HeapGB)g)."
