# Build the SAW offline install bundle on an internet-connected Windows PC (x64, Python 3.12, Node.js for the web build).
#   powershell -ExecutionPolicy Bypass -File deploy\windows\build-bundle.ps1 [-OutDir D:\saw-bundle] [-SkipWebBuild]
# Copy the resulting folder to the air-gapped server (after your media scanning procedure) and run install.ps1 there.
[CmdletBinding()]
param(
    [string]$OutDir = "",
    [string]$Python = "",                 # Python 3.12 x64 used to build wheels (default: repo .venv)
    [switch]$SkipWebBuild
)
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if (-not $OutDir) { $OutDir = Join-Path $Repo "offline-bundle" }
if (-not $Python) { $Python = Join-Path $Repo ".venv\Scripts\python.exe" }

# Pinned third-party versions (update together with docs/INSTALL-WINDOWS.md)
$OpenSearch = "2.19.6"; $Postgres = "16.15-1"; $PyVer = "3.12.10"; $WinSW = "2.12.0"
$Downloads = @(
    @{ dir = "opensearch"; url = "https://artifacts.opensearch.org/releases/bundle/opensearch/$OpenSearch/opensearch-$OpenSearch-windows-x64.zip"; sha512 = $true },
    @{ dir = "opensearch"; url = "https://artifacts.opensearch.org/releases/plugins/analysis-nori/$OpenSearch/analysis-nori-$OpenSearch.zip"; sha512 = $true },
    @{ dir = "postgresql"; url = "https://get.enterprisedb.com/postgresql/postgresql-$Postgres-windows-x64-binaries.zip" },
    @{ dir = "python"; url = "https://www.python.org/ftp/python/$PyVer/python-$PyVer-amd64.exe"; signed = "Python Software Foundation" },
    @{ dir = "winsw"; url = "https://github.com/winsw/winsw/releases/download/v$WinSW/WinSW-x64.exe" }
)

function Step($m) { Write-Host ""; Write-Host "==> $m" -ForegroundColor Cyan }

Step "Third-party binaries"
foreach ($d in $Downloads) {
    $dir = Join-Path $OutDir $d.dir
    New-Item -ItemType Directory -Force $dir | Out-Null
    $name = Split-Path $d.url -Leaf
    $dest = Join-Path $dir $name
    if (-not (Test-Path $dest)) {
        Write-Host "download $name"
        Invoke-WebRequest -Uri $d.url -OutFile "$dest.part" -UseBasicParsing
        Move-Item "$dest.part" $dest
    }
    if ($d.sha512) {
        $sumFile = "$dest.sha512"
        if (-not (Test-Path $sumFile)) { Invoke-WebRequest -Uri "$($d.url).sha512" -OutFile $sumFile -UseBasicParsing }
        $expected = ((Get-Content $sumFile -Raw).Trim() -split '\s+')[0]
        if ((Get-FileHash $dest -Algorithm SHA512).Hash -ne $expected.ToUpper()) { throw "SHA-512 mismatch: $name" }
        Write-Host "  sha512 OK  $name"
    }
    if ($d.signed) {
        $sig = Get-AuthenticodeSignature $dest
        if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch $d.signed) { throw "Authenticode check failed: $name" }
        Write-Host "  signature OK  $name ($($d.signed))"
    }
}

Step "Python wheels (offline)"
$v = & $Python -c "import sys,platform; print(f'{sys.version_info[0]}.{sys.version_info[1]} {platform.machine()}')"
if ($v -ne "3.12 AMD64") { throw "wheels must be built with 64-bit Python 3.12 (got: $v)" }
$wheels = Join-Path $OutDir "wheels"
New-Item -ItemType Directory -Force $wheels | Out-Null
& $Python -m pip wheel --quiet --no-deps -r (Join-Path $Repo "deploy\windows\requirements.txt") -w $wheels
if ($LASTEXITCODE) { throw "pip wheel failed" }

Step "Web UI build"
$web = Join-Path $Repo "apps\web"
if (-not $SkipWebBuild) {
    Push-Location $web
    if (Get-Command pnpm -ErrorAction SilentlyContinue) { & pnpm build } else { & npm run build }
    $rc = $LASTEXITCODE
    Pop-Location
    if ($rc) { throw "web build failed" }
}
if (-not (Test-Path (Join-Path $web "dist\index.html"))) { throw "apps\web\dist missing (build the web UI)" }

Step "Application files"
$app = Join-Path $OutDir "app"
if (Test-Path $app) { Remove-Item -Recurse -Force $app }
New-Item -ItemType Directory -Force $app | Out-Null
foreach ($d in @("saw", "data", "deploy", "docs")) {
    & robocopy (Join-Path $Repo $d) (Join-Path $app $d) /E /XD __pycache__ /XF *.pyc /NFL /NDL /NJH /NJS /NP | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "copy $d failed" }
}
& robocopy (Join-Path $web "dist") (Join-Path $app "apps\web\dist") /E /NFL /NDL /NJH /NJS /NP | Out-Null
foreach ($f in @("README.md", "pyproject.toml", "ENV-VERIFICATION.md")) { Copy-Item (Join-Path $Repo $f) $app }
foreach ($f in @("install.ps1", "uninstall.ps1", "backup.ps1")) { Copy-Item (Join-Path $Repo "deploy\windows\$f") $OutDir -Force }
Copy-Item (Join-Path $Repo "docs\INSTALL-WINDOWS.md") $OutDir -Force

Step "SBOM and third-party notices"
Push-Location $Repo
& $Python -m saw.devtools.sbom --out $OutDir
$rc = $LASTEXITCODE
Pop-Location
if ($rc) { throw "SBOM generation failed" }

Step "SHA256SUMS.txt"
$sums = Join-Path $OutDir "SHA256SUMS.txt"
$root = (Resolve-Path $OutDir).Path.TrimEnd('\') + '\'
Get-ChildItem $OutDir -Recurse -File | Where-Object { $_.FullName -ne $sums -and $_.Name -notlike "*.part" } | Sort-Object FullName |
    ForEach-Object { "{0} *{1}" -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash, $_.FullName.Substring($root.Length) } |
    Set-Content -Path $sums -Encoding ASCII
$size = [math]::Round(((Get-ChildItem $OutDir -Recurse -File | Measure-Object Length -Sum).Sum) / 1MB)
Write-Host "Bundle ready: $OutDir ($size MB). Record the SHA-256 of SHA256SUMS.txt in your transfer log:"
(Get-FileHash $sums -Algorithm SHA256).Hash
