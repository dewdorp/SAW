# Assemble an immutable model-free release from already pinned public build inputs.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$InputDir,
    [Parameter(Mandatory=$true)][string]$NativeRuntime,
    [Parameter(Mandatory=$true)][string]$OutDir,
    [string]$Python = ''
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if (-not $Python) { $Python = Join-Path $repo '.venv\Scripts\python.exe' }
if (Test-Path -LiteralPath $OutDir) { throw 'Choose a fresh output directory; media is immutable.' }
Push-Location $repo
try {
    & $Python -B -m saw.devtools.build_release --inputs $InputDir --native $NativeRuntime --out $OutDir
    if ($LASTEXITCODE) { throw 'Release assembly failed' }
} finally { Pop-Location }
