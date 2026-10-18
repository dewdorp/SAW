# Resume only the pinned SAW-owned embedded Python. The caller verifies all media
# payloads and holds the per-installation lock before invoking this helper.
function Get-SawPythonHash([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-SawPythonTree([string]$Path) {
    $cursor = [IO.Path]::GetFullPath($Path)
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Python runtime path contains a reparse point: $cursor"
            }
        }
        $parent = Split-Path -Parent $cursor
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
    if (-not (Test-Path -LiteralPath $Path)) { return }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "Python runtime must be a directory: $Path"
    }
    $pending = New-Object 'Collections.Generic.Stack[string]'
    $pending.Push($Path)
    while ($pending.Count) {
        foreach ($item in @(Get-ChildItem -LiteralPath $pending.Pop() -Force -ErrorAction Stop)) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Python runtime contains a reparse point: $($item.FullName)"
            }
            if ($item.PSIsContainer) { $pending.Push($item.FullName) }
        }
    }
}

function Write-SawPythonMarker([string]$Path, $Marker) {
    $temporary = "$Path.new-$([Guid]::NewGuid().ToString('N'))"
    [IO.File]::WriteAllText($temporary, ($Marker | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding $false))
    if (Test-Path -LiteralPath $Path) {
        [IO.File]::Replace($temporary, $Path, [NullString]::Value)
    } else {
        [IO.File]::Move($temporary, $Path)
    }
}

function Get-SawPythonInputs([string]$BundleDir) {
    $archive = Join-Path $BundleDir 'python\python-3.12.10-embed-amd64.zip'
    $bootstrap = Join-Path $BundleDir 'bootstrap\pip-25.1.1-py3-none-any.whl'
    $requirements = Join-Path $BundleDir 'app\deploy\windows\requirements.txt'
    foreach ($path in @($archive, $bootstrap, $requirements)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing local Python payload: $path" }
    }
    $archiveHash = Get-SawPythonHash $archive
    if ($archiveHash -ne '4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3') {
        throw "The Python archive does not match the pinned 3.12.10 x64 payload: $archive"
    }
    return @{
        archive = $archive; bootstrap = $bootstrap; requirements = $requirements
        archive_sha256 = $archiveHash; requirements_sha256 = (Get-SawPythonHash $requirements)
        bootstrap_sha256 = (Get-SawPythonHash $bootstrap)
    }
}

function Test-SawPythonRuntimeFiles([string]$Runtime, $Inputs, [bool]$AllowTruncatedFiles = $false) {
    $scripts = Join-Path $Runtime 'Scripts'
    $missing = New-Object 'Collections.Generic.List[string]'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($Inputs.archive)
    try {
        foreach ($entry in $archive.Entries) {
            if (-not $entry.Name) { continue }
            if ($entry.FullName -eq 'python312._pth') {
                $stream = $entry.Open(); $hash = [Security.Cryptography.SHA256]::Create()
                try { $originalPthHash = ([BitConverter]::ToString($hash.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
                finally { $stream.Dispose(); $hash.Dispose() }
                continue
            }
            $path = Join-Path $scripts $entry.FullName
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                $missing.Add($entry.FullName)
                continue
            }
            $stream = $entry.Open(); $hash = [Security.Cryptography.SHA256]::Create()
            try { $expected = ([BitConverter]::ToString($hash.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
            finally { $stream.Dispose(); $hash.Dispose() }
            $actualHash = Get-SawPythonHash $path
            if ($actualHash -ne $expected) {
                $length = (Get-Item -LiteralPath $path).Length
                if ($AllowTruncatedFiles -and $length -lt $entry.Length) {
                    $prefix = New-Object byte[] ([int]$length)
                    $stream = $entry.Open(); $hash = [Security.Cryptography.SHA256]::Create()
                    try {
                        $offset = 0
                        while ($offset -lt $prefix.Length) {
                            $read = $stream.Read($prefix, $offset, $prefix.Length - $offset)
                            if ($read -eq 0) { throw "Truncated verified media entry: $($entry.FullName)" }
                            $offset += $read
                        }
                        $prefixHash = ([BitConverter]::ToString($hash.ComputeHash($prefix))).Replace('-', '').ToLowerInvariant()
                    } finally { $stream.Dispose(); $hash.Dispose() }
                    if ($prefixHash -eq $actualHash) {
                        $missing.Add($entry.FullName)
                        continue
                    }
                }
                throw "Incompatible or modified embedded Python file; preserved without repair: $path"
            }
        }
    } finally { $archive.Dispose() }
    $pth = Join-Path $scripts 'python312._pth'
    if (Test-Path -LiteralPath $pth -PathType Leaf) {
        $actual = ([IO.File]::ReadAllText($pth) -replace "\r\n", [string][char]10).TrimEnd([char[]]@([char]13, [char]10))
        $expected = @('python312.zip', '.', '../Lib/site-packages', '../../app', 'import site') -join [string][char]10
        if ($actual -cne $expected) {
            if ($AllowTruncatedFiles -and (Get-SawPythonHash $pth) -eq $originalPthHash) {
                $missing.Add('python312._pth')
            } else {
                throw "Python path configuration is not the SAW layout; preserved without repair: $pth"
            }
        }
    } else { $missing.Add('python312._pth') }
    return @($missing)
}

function Test-SawPythonDependencies([string]$Python, [string]$Requirements) {
    # The embedded _pth imports site even with -S; reject hooks before execution.
    # -B keeps verification read-only for an accepted runtime.
    $probe = @'
import importlib
import importlib.metadata
import json
import os
import re
import struct
import sys
scripts = os.path.dirname(os.path.abspath(sys.executable))
sys.path[:] = [os.path.join(scripts, "python312.zip"), scripts,
               os.path.normpath(os.path.join(scripts, "../Lib/site-packages"))]
if tuple(sys.version_info[:3]) != (3, 12, 10) or struct.calcsize("P") != 8:
    print(json.dumps({"ok": False, "reason": "version-or-architecture"}))
    raise SystemExit(3)
try:
    with open(sys.argv[1], encoding="utf-8-sig") as source:
        rows = source.readlines()
    for row in rows:
        requirement = row.split("#", 1)[0].strip()
        if not requirement:
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9.+!-]+)", requirement)
        if not match:
            raise ValueError("unpinned dependency")
        if importlib.metadata.version(match[1]) != match[2]:
            raise ValueError("dependency version mismatch")
    for module in ("fastapi", "uvicorn", "sqlalchemy", "psycopg", "opensearchpy",
                   "yaml", "orjson", "regex", "cryptography.fernet", "argon2",
                   "pydantic", "grpc", "jq", "sigma", "drain3", "tldextract", "pyotp"):
        importlib.import_module(module)
    from pip._internal.operations.check import create_package_set_from_installed, check_package_set
    packages, parsing_errors = create_package_set_from_installed()
    missing, conflicting = check_package_set(packages)
    if parsing_errors or missing or conflicting:
        raise ValueError("dependency closure")
except Exception as exc:
    print(json.dumps({"ok": False, "reason": "dependency-validation", "error_type": type(exc).__name__}))
    raise SystemExit(4)
print(json.dumps({"ok": True, "python": "3.12.10", "bits": 64}))
'@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($probe))
    $beforeErrorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $Python -B -S -c "import base64;exec(base64.b64decode('$encoded'))" $Requirements 2>&1)
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $beforeErrorPreference }
    if ($code -ne 0) { return $false }
    try {
        $result = ($output -join [string][char]10) | ConvertFrom-Json
        return ($result.ok -eq $true -and $result.python -eq '3.12.10' -and $result.bits -eq 64)
    } catch { return $false }
}

function Assert-SawPythonRepairStopped([string]$InstallRoot) {
    # A healthy runtime can be reused while running, but replacing it requires
    # a stopped installation. Read process/service paths, never command arguments.
    try {
        $processes = @(Get-CimInstance -ClassName Win32_Process -Property Name,ProcessId,ExecutablePath -ErrorAction Stop)
        $services = @(Get-CimInstance -ClassName Win32_Service -Property Name,State,PathName -ErrorAction Stop)
    } catch {
        throw "Cannot verify running processes/services before Python repair; no runtime was moved."
    }
    $prefix = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\') + '\'
    foreach ($process in $processes) {
        $path = [string]$process.ExecutablePath
        if (-not $path) {
            if ([string]$process.Name -match '^python(?:w|\d+(?:\.\d+)?)?\.exe$') {
                throw "Cannot verify executable path of Python process $($process.ProcessId); stop it or verify access before repair."
            }
            continue
        }
        $path = $path.Replace('/', '\')
        if ($path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "A running process uses this installation (PID $($process.ProcessId)); stop SAW before Python repair."
        }
    }
    foreach ($service in $services) {
        if ($service.State -eq 'Stopped') { continue }
        $path = [string]$service.PathName
        if (-not $path -and $service.Name -in @('saw', 'saw-postgresql', 'saw-opensearch')) {
            throw "Cannot verify active SAW service path ($($service.Name)); no runtime was moved."
        }
        if ($path.Replace('/', '\').IndexOf($prefix, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw "An active service uses this installation ($($service.Name)); stop SAW before Python repair."
        }
    }
}

function Ensure-SawPythonRuntime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$BundleDir,
        [Parameter(Mandatory = $true)][string]$InstallRoot,
        [switch]$ValidateOnly
    )
    $root = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
    $bundle = [IO.Path]::GetFullPath($BundleDir).TrimEnd('\')
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw "The protected installation root must exist: $root" }
    if ($root -eq $bundle -or $root.StartsWith($bundle + '\', [StringComparison]::OrdinalIgnoreCase) -or
        $bundle.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Python installation and media directories must be separate."
    }
    $runtime = Join-Path $root 'venv'
    Assert-SawPythonTree $runtime
    $inputs = Get-SawPythonInputs $bundle
    foreach ($directory in @((Join-Path $runtime 'Scripts'), (Join-Path $runtime 'Lib\site-packages'), (Join-Path $root 'app'))) {
        if (Test-Path -LiteralPath $directory -PathType Container) {
            foreach ($entry in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)) {
                if ($entry.Name -match '\.pth$|^(sitecustomize|usercustomize)(\.|$)') {
                    throw "Unapproved Python startup hook; preserved without execution: $($entry.FullName)"
                }
            }
        }
    }
    $scripts = Join-Path $runtime 'Scripts'
    $site = Join-Path $runtime 'Lib\site-packages'
    $python = Join-Path $scripts 'python.exe'
    $markerPath = Join-Path $runtime '.saw-python-runtime.json'
    $marker = [ordered]@{
        schema = 'saw.python-runtime/1'; install_root = $root; python = '3.12.10'; architecture = 'amd64'
        archive_sha256 = $inputs.archive_sha256; requirements_sha256 = $inputs.requirements_sha256
        bootstrap_sha256 = $inputs.bootstrap_sha256; state = 'preparing'
    }
    $managed = $false
    if (Test-Path -LiteralPath (Join-Path $runtime 'pyvenv.cfg')) {
        throw "A developer or external Python venv is not a SAW embedded runtime: $runtime"
    }
    if (Test-Path -LiteralPath $markerPath -PathType Leaf) {
        try { $existing = [IO.File]::ReadAllText($markerPath) | ConvertFrom-Json }
        catch { throw "Malformed Python ownership marker; runtime preserved: $markerPath" }
        foreach ($key in @('schema', 'install_root', 'python', 'architecture', 'archive_sha256', 'requirements_sha256', 'bootstrap_sha256')) {
            if ($existing.$key -ne $marker[$key]) {
                throw "Python ownership or package conflict ($key); runtime preserved: $runtime"
            }
        }
        if ($existing.state -notin @('preparing', 'ready')) { throw "Unknown Python preparation state: $runtime" }
        $managed = $true
    }
    if (Test-Path -LiteralPath $runtime) {
        $missing = @(Test-SawPythonRuntimeFiles -Runtime $runtime -Inputs $inputs -AllowTruncatedFiles:($managed -and $existing.state -eq 'preparing'))
        if ($missing.Count -eq 0 -and (Test-SawPythonDependencies -Python $python -Requirements $inputs.requirements)) {
            if (-not $ValidateOnly -and (-not $managed -or $existing.state -ne 'ready')) {
                $marker.state = 'ready'
                Write-SawPythonMarker -Path $markerPath -Marker $marker
            }
            return $python
        }
        if ($ValidateOnly) { throw "Python runtime is incomplete; validation made no changes: $runtime" }
        if (-not $managed) {
            throw "Unowned incomplete Python directory; files preserved. Verify its origin before recovery: $runtime"
        }
        # Retain the complete incomplete tree, including unknown operator files.
        # Rename is limited to this root, and reparse points were rejected above.
        Assert-SawPythonRepairStopped -InstallRoot $root
        $retained = Join-Path $root ('venv.retained-' + [Guid]::NewGuid().ToString('N').Substring(0, 12))
        [IO.Directory]::Move($runtime, $retained)
        Write-Verbose "Incomplete Python retained at $retained"
    } elseif ($ValidateOnly) { throw "Python runtime is absent: $runtime" }

    $null = New-Item -ItemType Directory -Path $runtime
    Write-SawPythonMarker -Path $markerPath -Marker $marker
    $null = New-Item -ItemType Directory -Path $scripts, $site -Force
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($inputs.archive, $scripts)
    [IO.Compression.ZipFile]::ExtractToDirectory($inputs.bootstrap, $site)
    [IO.File]::WriteAllLines((Join-Path $scripts 'python312._pth'),
        [string[]]@('python312.zip', '.', '../Lib/site-packages', '../../app', 'import site'),
        (New-Object Text.UTF8Encoding $false))
    $original = @{}
    foreach ($key in @('PIP_CONFIG_FILE', 'PIP_NO_INDEX', 'PIP_DISABLE_PIP_VERSION_CHECK')) {
        $original[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
    }
    $beforeErrorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $env:PIP_CONFIG_FILE = 'NUL'; $env:PIP_NO_INDEX = '1'; $env:PIP_DISABLE_PIP_VERSION_CHECK = '1'
        $output = @(& $python -B -S -m pip install --quiet --no-index --no-cache-dir --no-compile --no-warn-script-location --find-links (Join-Path $bundle 'wheels') --target $site -r $inputs.requirements 2>&1)
        $code = $LASTEXITCODE
        if ($code -ne 0) { throw "Offline Python dependencies failed (exit $code); prepared runtime retained: $runtime" }
    } finally {
        $ErrorActionPreference = $beforeErrorPreference
        foreach ($key in $original.Keys) { [Environment]::SetEnvironmentVariable($key, $original[$key], 'Process') }
    }
    $missing = @(Test-SawPythonRuntimeFiles -Runtime $runtime -Inputs $inputs)
    if ($missing.Count -gt 0 -or -not (Test-SawPythonDependencies -Python $python -Requirements $inputs.requirements)) {
        throw "Python post-install verification failed; prepared runtime retained: $runtime"
    }
    $marker.state = 'ready'
    Write-SawPythonMarker -Path $markerPath -Marker $marker
    return $python
}
