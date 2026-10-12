#requires -Version 7.0
# Build-machine only (PowerShell 7). Offline installation uses prebuilt binaries; it never invokes this script.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$CacheDir,
    [Parameter(Mandatory=$true)][string]$WorkDir,
    [Parameter(Mandatory=$true)][string]$OutputDir,
    [ValidateRange(1,8)][int]$Jobs = 4,
    [switch]$AllowDownload
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$utf8 = New-Object System.Text.UTF8Encoding($false)

function Assert-SafeAbsolute([string]$Value) {
    if (-not [IO.Path]::IsPathRooted($Value) -or $Value.StartsWith('\\')) { throw 'An absolute local path is required.' }
    $full = [IO.Path]::GetFullPath($Value).TrimEnd('\')
    if ($full.Substring([IO.Path]::GetPathRoot($full).Length).Contains(':')) { throw 'Alternate streams are forbidden.' }
    $cursor = $full
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse points are forbidden.' }
        }
        $parent = Split-Path -Parent $cursor
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
    return $full
}
function Assert-Hash([string]$Path, [string]$Expected) {
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Expected) { throw ('Checksum mismatch: '+[IO.Path]::GetFileName($Path)) }
}
function Get-Pinned($Entry, [string]$Folder) {
    $destination = Join-Path $Folder $Entry.name
    if (!(Test-Path -LiteralPath $destination)) {
        if (!$AllowDownload) { throw ('Missing pinned input: '+$Entry.name+'; use -AllowDownload only on the authorized build machine.') }
        Invoke-WebRequest -UseBasicParsing -Uri $Entry.url -OutFile $destination
    }
    Assert-Hash $destination $Entry.sha256
    return $destination
}
$CacheDir = Assert-SafeAbsolute $CacheDir
$WorkDir = Assert-SafeAbsolute $WorkDir
$OutputDir = Assert-SafeAbsolute $OutputDir
if ((Test-Path -LiteralPath $WorkDir) -or (Test-Path -LiteralPath $OutputDir)) { throw 'WorkDir and OutputDir must be new directories; existing files are never replaced.' }
if ($WorkDir -eq $CacheDir -or $OutputDir -eq $CacheDir -or $OutputDir.StartsWith($WorkDir+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Build, cache and output directories must be separate.' }
New-Item -ItemType Directory -Path $CacheDir -Force | Out-Null
$pins = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'native-ai-source-pins.json') -Raw | ConvertFrom-Json
if ($pins.schema -ne 'saw.native-source-pins/1' -or $pins.commit -ne 'd81235049384534c167caea52b85a694f6103d14' -or $pins.version -ne 'b11429') { throw 'Unexpected source contract.' }
$archives = @{}
foreach ($entry in $pins.downloads) { $archives[$entry.name] = Get-Pinned $entry $CacheDir }
$licenseCache = Join-Path $CacheDir 'license-inputs'
New-Item -ItemType Directory -Path $licenseCache -Force | Out-Null
foreach ($entry in $pins.licenses) { $null = Get-Pinned $entry $licenseCache }
New-Item -ItemType Directory -Path $WorkDir | Out-Null
$tools = Join-Path $WorkDir 'tools'
$sourceRoot = Join-Path $WorkDir 'source'
Expand-Archive -LiteralPath $archives['winlibs-x86_64-posix-seh-gcc-14.2.0-mingw-w64ucrt-12.0.0-r3.zip'] -DestinationPath $tools
Expand-Archive -LiteralPath $archives['cmake.zip'] -DestinationPath $tools
Expand-Archive -LiteralPath $archives['llama-source.zip'] -DestinationPath $sourceRoot
$source = Join-Path $sourceRoot ('llama.cpp-'+$pins.commit)
$cmake = Join-Path $tools 'cmake-3.31.6-windows-x86_64\bin\cmake.exe'
$compilerBin = Join-Path $tools 'mingw64\bin'
$build = Join-Path $WorkDir 'build'
$configureLog = Join-Path $WorkDir 'configure.log'
$buildLog = Join-Path $WorkDir 'build.log'
$oldPath = $env:PATH
$oldCeiling = $env:GIT_CEILING_DIRECTORIES
try {
    $env:PATH = $compilerBin+';'+$oldPath
    $env:GIT_CEILING_DIRECTORIES = $sourceRoot
    $options = @('-G','MinGW Makefiles','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=gcc','-DCMAKE_CXX_COMPILER=g++',
      '-DCMAKE_C_FLAGS=-D_WIN32_WINNT=0x0A00','-DCMAKE_CXX_FLAGS=-D_WIN32_WINNT=0x0A00',
      '-DCMAKE_EXE_LINKER_FLAGS=-static -static-libgcc -static-libstdc++',
      '-DBUILD_SHARED_LIBS=OFF','-DGGML_STATIC=ON','-DGGML_NATIVE=OFF','-DGGML_SSE42=OFF','-DGGML_BMI2=OFF',
      '-DGGML_AVX=OFF','-DGGML_AVX2=OFF','-DGGML_FMA=OFF','-DGGML_F16C=OFF','-DGGML_OPENMP=OFF',
      '-DGGML_BACKEND_DL=OFF','-DGGML_CCACHE=OFF','-DLLAMA_OPENSSL=OFF','-DLLAMA_SUBPROCESS=OFF',
      '-DLLAMA_BUILD_TESTS=OFF','-DLLAMA_BUILD_EXAMPLES=OFF','-DLLAMA_BUILD_SERVER=OFF','-DLLAMA_BUILD_APP=OFF',
      '-DLLAMA_BUILD_UI=OFF','-DLLAMA_USE_PREBUILT_UI=OFF','-DLLAMA_BUILD_NUMBER=11429',('-DLLAMA_BUILD_COMMIT='+$pins.commit))
    & $cmake -S $source -B $build @options *> $configureLog
    if ($LASTEXITCODE -ne 0) { throw ('Native configure failed; see '+$configureLog) }
    & $cmake --build $build --target llama-completion llama-tokenize --parallel $Jobs *> $buildLog
    if ($LASTEXITCODE -ne 0) { throw ('Native build failed; see '+$buildLog) }
} finally {
    $env:PATH = $oldPath
    $env:GIT_CEILING_DIRECTORIES = $oldCeiling
}
$imports = @{}
$versions = @{}
foreach ($name in @('llama-completion.exe','llama-tokenize.exe')) {
    $exe = Join-Path $build ('bin\'+$name)
    $dump = & (Join-Path $compilerBin 'objdump.exe') -p $exe
    if ($LASTEXITCODE -ne 0) { throw 'PE import inspection failed.' }
    $imports[$name] = @($dump | Select-String 'DLL Name:' | ForEach-Object { $_.Line.Split(':')[1].Trim() })
    if ($imports[$name].Count -eq 0) { throw 'Missing PE import inventory.' }
    foreach ($dll in $imports[$name]) {
        if ($dll -notmatch '^(ADVAPI32|KERNEL32|SHELL32|WS2_32)\.dll$' -and $dll -notmatch '^api-ms-win-crt-[a-z0-9-]+\.dll$') { throw ('Unexpected runtime DLL: '+$dll) }
    }
    $version = (& $exe --version 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or !$version.Contains('build 11429, commit '+$pins.commit)) { throw 'Native version probe failed.' }
    $versions[$name] = $version
}
New-Item -ItemType Directory -Path (Join-Path $OutputDir 'licenses') | Out-Null
foreach ($name in @('llama-completion.exe','llama-tokenize.exe')) { Copy-Item -LiteralPath (Join-Path $build ('bin\'+$name)) -Destination (Join-Path $OutputDir $name) }
foreach ($entry in $pins.licenses) { Copy-Item -LiteralPath (Join-Path $licenseCache $entry.name) -Destination (Join-Path $OutputDir ('licenses\'+$entry.name)) }
Copy-Item -LiteralPath (Join-Path $source 'LICENSE') -Destination (Join-Path $OutputDir 'licenses\LLAMA-MIT.txt')
Copy-Item -LiteralPath (Join-Path $source 'licenses\LICENSE-jsonhpp') -Destination (Join-Path $OutputDir 'licenses\JSONHPP-MIT.txt')
Copy-Item -LiteralPath (Join-Path $source 'vendor\cpp-httplib\LICENSE') -Destination (Join-Path $OutputDir 'licenses\HTTPLIB-MIT.txt')
Copy-Item -LiteralPath (Join-Path $tools 'mingw64\version_info.txt') -Destination (Join-Path $OutputDir 'licenses\WINLIBS-VERSION.txt')
$provenance = [ordered]@{schema='saw.native-build/1';pins=$pins;compiler='GNU GCC 14.2.0';cmake='3.31.6';
 target='Windows 10 x64';cpu_baseline='SSE2';options=$options;imports=$imports;versions=$versions;source_modified=$false;
 ltsc2019_execution='NOT_RUN';model_weights_included=$false;build_artifacts_bit_reproducible='NOT_CLAIMED'}
[IO.File]::WriteAllText((Join-Path $OutputDir 'build-provenance.json'),($provenance | ConvertTo-Json -Depth 12),$utf8)
$files = @(Get-ChildItem -LiteralPath $OutputDir -Recurse -File | Sort-Object FullName | ForEach-Object {
    [ordered]@{path=$_.FullName.Substring($OutputDir.Length+1).Replace('\','/');bytes=$_.Length;sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
})
$manifest = [ordered]@{schema='saw.local-cpu-runtime/1';version=$pins.version;commit=$pins.commit;files=$files}
[IO.File]::WriteAllText((Join-Path $OutputDir 'runtime-manifest.json'),($manifest | ConvertTo-Json -Depth 8),$utf8)
$pin = (Get-FileHash -LiteralPath (Join-Path $OutputDir 'runtime-manifest.json') -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Output ('Runtime created: '+$OutputDir)
Write-Output ('Manifest SHA256: '+$pin)
Write-Output 'Native PE imports and version verified. LPAC, model inference and clean LTSC 2019 execution require separate validation.'
