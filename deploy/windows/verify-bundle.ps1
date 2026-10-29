# Verify complete media before executing any payload. Windows PowerShell 5.1.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$BundleDir)
$ErrorActionPreference = 'Stop'
function Stop-Media([string]$Code,[string]$Location='release-manifest.json',[string]$Expected='valid complete offline media',[string]$Actual='verification failed') {
    $error = New-Object IO.InvalidDataException('Release media verification failed')
    $error.Data['SawCode']=$Code
    $error.Data['SawLocation']=$Location
    $error.Data['SawExpected']=$Expected
    $error.Data['SawActual']=$Actual
    throw $error
}
try {
$root = (Resolve-Path -LiteralPath $BundleDir).Path.TrimEnd('\')
$manifest = Join-Path $root 'release-manifest.json'
if (-not [IO.File]::Exists($manifest)) {
    if ([IO.File]::Exists((Join-Path $root 'pyproject.toml')) -or [IO.Directory]::Exists((Join-Path $root 'saw'))) {
        Stop-Media 'media_source_archive' 'release-manifest.json' 'offline release asset' 'source archive'
    }
    Stop-Media 'media_manifest_missing' 'release-manifest.json' 'release manifest' 'missing'
}
$manifestItem=Get-Item -LiteralPath $manifest -Force
if ($manifestItem.Length -gt 8388608 -or ($manifestItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    Stop-Media 'media_manifest_invalid'
}
$doc = [IO.File]::ReadAllText($manifest,[Text.Encoding]::UTF8) | ConvertFrom-Json
if ($doc.schema -ne 'saw.offline-release/1' -or $doc.model_weights_included -isnot [bool] -or $doc.model_weights_included) {
    Stop-Media 'media_manifest_invalid'
}
$required = @('llm-runtime/runtime-manifest.json','llm-runtime/llama-completion.exe','llm-runtime/llama-tokenize.exe','llm-runtime/licenses/LLAMA-MIT.txt','llm-runtime/licenses/GCC-RUNTIME-EXCEPTION.txt','install.ps1','verify-bundle.ps1','python/python-3.12.10-embed-amd64.zip','postgresql/postgresql-16.15-1-windows-x64-binaries.zip','opensearch/opensearch-2.19.6-windows-x64.zip','opensearch/analysis-nori-2.19.6.zip','winsw/WinSW-x64.exe','bootstrap/pip-25.1.1-py3-none-any.whl','app/apps/web/dist/index.html','app/deploy/windows/requirements.txt')
# Older media remains valid; only new desktop media requires these entry points.
$desktopProperty = $null
if ($null -ne $doc.metadata) { $desktopProperty = $doc.metadata.PSObject.Properties['desktop_update_ui'] }
if ($null -ne $desktopProperty) {
    $desktopVersion = $desktopProperty.Value
    if (($desktopVersion -isnot [int] -and $desktopVersion -isnot [long]) -or $desktopVersion -ne 1) {
        Stop-Media 'media_manifest_invalid'
    }
    $required += @('UPDATE-SAW.cmd','update-ui.ps1','update-ui.psm1','update-worker.ps1',
        'app/deploy/windows/UPDATE-SAW.cmd','app/deploy/windows/update-ui.ps1',
        'app/deploy/windows/update-ui.psm1','app/deploy/windows/update-worker.ps1',
        'app/saw/devtools/desktop_update.py')
}

if ($null -ne $doc.metadata -and $null -ne $doc.metadata.PSObject.Properties['updater_inspection']) {
    $version=$doc.metadata.updater_inspection
    if (($version -isnot [int] -and $version -isnot [long]) -or $version -ne 1) { Stop-Media 'media_manifest_invalid' }
    $required+=@('app/saw/devtools/update_diagnostics.py','test-update-environment.ps1','app/deploy/windows/test-update-environment.ps1')
}
function File-Hash([string]$path) {
    $stream = [IO.File]::OpenRead($path)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','').ToLowerInvariant() }
    finally { $stream.Dispose(); $sha.Dispose() }
}
if ($doc.files -isnot [Array] -or $doc.files.Count -gt 100000) { Stop-Media 'media_manifest_invalid' }
$expected = @{}
foreach ($row in $doc.files) {
    if ($row.path -isnot [string]) { Stop-Media 'media_manifest_invalid' }
    $rel = $row.path
    if (-not $rel -or $rel.Contains('\') -or $rel -match '[:*?"<>|\x00-\x1f]') { Stop-Media 'media_manifest_invalid' }
    foreach ($part in $rel.Split('/')) {
        if ($part -in @('','.','..') -or $part -match '[. ]$' -or $part -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)') {
            Stop-Media 'media_manifest_invalid'
        }
        if ($part -in @('.env','var','secrets','.git','.qa','offline-bundle','node_modules')) { Stop-Media 'media_manifest_invalid' }
    }
    if ($rel -match '\.(gguf|safetensors|pt|ckpt|db|sqlite)$') { Stop-Media 'media_manifest_invalid' }
    if ($rel -in @('release-manifest.json','SHA256SUMS.txt') -or $expected.ContainsKey($rel)) { Stop-Media 'media_manifest_invalid' }
    if ($row.sha256 -isnot [string] -or $row.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        ($row.bytes -isnot [int] -and $row.bytes -isnot [long]) -or $row.bytes -lt 0) { Stop-Media 'media_manifest_invalid' }
    $expected[$rel] = $row
}
foreach ($rel in $required) {
    if (-not $expected.ContainsKey($rel)) { Stop-Media 'media_payload_missing' $rel 'required manifest entry' 'missing' }
}
$all = @(Get-ChildItem -LiteralPath $root -Recurse -Force)
foreach ($entry in $all) {
    if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { Stop-Media 'media_manifest_invalid' '<linked-entry>' 'ordinary file' 'reparse point' }
}
$actual=@{}
foreach ($file in $all | Where-Object { -not $_.PSIsContainer }) {
    $rel = $file.FullName.Substring($root.Length + 1).Replace('\','/')
    if ($rel -in @('release-manifest.json','SHA256SUMS.txt')) { continue }
    if ($actual.ContainsKey($rel)) { Stop-Media 'media_manifest_invalid' }
    $actual[$rel]=$file
}
foreach ($rel in ($expected.Keys | Sort-Object)) {
    if (-not $actual.ContainsKey($rel)) { Stop-Media 'media_file_missing' $rel 'manifest file' 'missing' }
}
foreach ($rel in $actual.Keys) {
    if (-not $expected.ContainsKey($rel)) { Stop-Media 'media_unexpected_file' '<unlisted-file>' 'manifest files only' 'unlisted file' }
}
foreach ($rel in ($expected.Keys | Sort-Object)) {
    $hash=File-Hash $actual[$rel].FullName
    if ($actual[$rel].Length -ne $expected[$rel].bytes -or $hash -cne $expected[$rel].sha256) {
        Stop-Media 'media_hash_mismatch' $rel $expected[$rel].sha256 $hash
    }
}
Write-Host "Complete media verified: $($actual.Count) files"
} catch {
    if ($_.Exception.Data['SawCode']) { throw }
    Stop-Media 'media_manifest_invalid'
}
