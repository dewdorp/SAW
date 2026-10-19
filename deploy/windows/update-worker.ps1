# Private native bootstrap for the desktop updater. PowerShell 5.1.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('inspect','apply','restore','start')][string]$Action,
    [Parameter(Mandatory=$true)][string]$InstallRoot,
    [Parameter(Mandatory=$true)][string]$BundleDir,
    [Parameter(Mandatory=$true)][string]$StateDir,
    [string]$BaselineBundleDir = '',
    [string]$RecoveryPoint = '',
    [switch]$MaintenanceConfirmed,
    [switch]$ConfirmPointInTimeRecovery
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$env:PSModulePath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules'
$stateWritable = $false
$lock = $null
$process = $null
$failureCode = 'unsafe_worker_path'
$exitCode = 1

function Assert-LocalDirectory([string]$Value, [bool]$MustExist = $true) {
    if ($Value -notmatch '^[A-Za-z]:[\\/]') { throw 'Local absolute directory required' }
    $tail = $Value.Substring(3).Replace('/','\').TrimEnd('\')
    if (-not $tail -or $tail -match '[:*?"<>|\x00-\x1f]') { throw 'Unsafe local directory' }
    foreach ($part in $tail.Split('\')) {
        if ($part -in @('','.','..') -or $part -match '[. ]$' -or
            $part -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)') { throw 'Aliased local directory' }
    }
    $full = [IO.Path]::GetFullPath($Value).TrimEnd('\')
    $drive = New-Object IO.DriveInfo([IO.Path]::GetPathRoot($full))
    if ($drive.DriveType -eq [IO.DriveType]::Network) { throw 'Network directory refused' }
    $cursor = $full
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw 'Non-directory or reparse path refused'
            }
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ($cursor -eq $parent) { break }
        $cursor = $parent
    }
    if ($MustExist -and -not [IO.Directory]::Exists($full)) { throw 'Directory missing' }
    return $full
}

function Test-Nested([string]$Left, [string]$Right) {
    return ($Left.Equals($Right,[StringComparison]::OrdinalIgnoreCase) -or
        $Left.StartsWith($Right + '\',[StringComparison]::OrdinalIgnoreCase) -or
        $Right.StartsWith($Left + '\',[StringComparison]::OrdinalIgnoreCase))
}

function Assert-PrivateState([string]$Path) {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $sections = [Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner
    $acl = [IO.Directory]::GetAccessControl($Path,$sections)
    if (-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value) {
        throw 'Private current-user ownership required'
    }
    $full = [Security.AccessControl.FileSystemRights]::FullControl
    $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $granted = @{}
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        $owner = $rule.IdentityReference.Value
        if ($owner -notin @($sid.Value,$system.Value)) { throw 'Foreign access to private state refused' }
        if (($rule.FileSystemRights -band $full) -eq $full -and
            ($rule.InheritanceFlags -band $inherit) -eq $inherit -and
            $rule.PropagationFlags -eq [Security.AccessControl.PropagationFlags]::None) { $granted[$owner] = $true }
    }
    if (-not $granted[$sid.Value] -or -not $granted[$system.Value]) { throw 'Private state inheritance required' }
    if (@(Get-ChildItem -LiteralPath $Path -Force).Count -ne 0) { throw 'A new empty worker directory is required' }
}

function Write-WorkerState([string]$Status, [string]$Code, [string]$Message) {
    $value = [ordered]@{
        schema='saw.desktop-update/1'; action=$Action; phase='bootstrap'; status=$Status
        message=$Message; code=$Code; install_root=$InstallRoot
        requires_admin=$false; needs_acceptance=$false
    }
    if ($RecoveryPoint) { $value.recovery_point = $RecoveryPoint }
    $path = Join-Path $StateDir 'state.json'
    if (Test-Path -LiteralPath $path) {
        $item = Get-Item -LiteralPath $path -Force
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unsafe state file' }
    }
    $temporary = Join-Path $StateDir ('.state-' + [guid]::NewGuid().ToString('N') + '.json')
    # Specify ownership at creation: elevated tokens may default to Administrators.
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $security = New-Object Security.AccessControl.FileSecurity
    $security.SetOwner($sid)
    $security.SetAccessRuleProtection($true,$false)
    foreach ($id in @($sid,(New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($id,'FullControl','Allow')
        $security.AddAccessRule($rule)
    }
    $stream = [IO.FileStream]::new($temporary,[IO.FileMode]::CreateNew,
        [Security.AccessControl.FileSystemRights]::Write,[IO.FileShare]::None,
        4096,[IO.FileOptions]::None,$security)
    try {
        $encoding = New-Object Text.UTF8Encoding($false)
        $bytes = $encoding.GetBytes(($value | ConvertTo-Json -Depth 6))
        $stream.Write($bytes,0,$bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
    if ([IO.File]::Exists($path)) { [IO.File]::Replace($temporary,$path,[NullString]::Value) }
    else { [IO.File]::Move($temporary,$path) }
}

function Expand-VerifiedRuntime([string]$Archive, [string]$Destination) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        $names = @{}
        [long]$total = 0
        if ($zip.Entries.Count -gt 10000) { throw 'Unexpected runtime archive' }
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName.Replace('\','/').TrimEnd('/')
            if (-not $name -or $name -match '[:*?"<>|\x00-\x1f]') { throw 'Unsafe runtime entry' }
            foreach ($part in $name.Split('/')) {
                if ($part -in @('','.','..') -or $part -match '[. ]$' -or
                    $part -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)') { throw 'Unsafe runtime entry' }
            }
            if ($names.ContainsKey($name)) { throw 'Duplicate runtime entry' }
            $names[$name] = $true
            $target = [IO.Path]::GetFullPath((Join-Path $Destination $name))
            if (-not $target.StartsWith($Destination + '\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Runtime entry escape refused' }
            $total += $entry.Length
            if ($total -gt 536870912) { throw 'Unexpected runtime size' }
        }
    } finally { $zip.Dispose() }
    [IO.Compression.ZipFile]::ExtractToDirectory($Archive,$Destination)
    if (-not [IO.File]::Exists((Join-Path $Destination 'python.exe'))) { throw 'Runtime executable missing' }
}

function Quote-NativeArgument([string]$Value) {
    # Windows CommandLineToArgvW/CRT escaping, without a shell.
    $quoted = [regex]::Replace($Value,'(\\*)"', { param($m) ($m.Groups[1].Value * 2) + '\"' })
    $quoted = [regex]::Replace($quoted,'(\\+)$', { param($m) $m.Groups[1].Value * 2 })
    return '"' + $quoted + '"'
}

function Read-ControllerState {
    $path = Join-Path $StateDir 'state.json'
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer -or $item.Length -gt 1048576 -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Invalid controller result' }
    $value = [IO.File]::ReadAllText($path,[Text.Encoding]::UTF8) | ConvertFrom-Json
    if ($value.schema -ne 'saw.desktop-update/1' -or $value.action -ne $Action -or
        -not ([string]$value.install_root).Equals($InstallRoot,[StringComparison]::OrdinalIgnoreCase) -or
        $value.status -notin @('ready','completed','failed') -or
        [string]$value.code -notmatch '^[a-z][a-z0-9_]{0,79}$') { throw 'Invalid controller result' }
    return $value
}

try {
    $StateDir = Assert-LocalDirectory $StateDir
    $InstallRoot = Assert-LocalDirectory $InstallRoot
    $BundleDir = Assert-LocalDirectory $BundleDir
    if ($BaselineBundleDir) { $BaselineBundleDir = Assert-LocalDirectory $BaselineBundleDir }
    if ($RecoveryPoint) { $RecoveryPoint = Assert-LocalDirectory $RecoveryPoint $false }
    foreach ($other in @($InstallRoot,$BundleDir,$BaselineBundleDir,$RecoveryPoint)) {
        if ($other -and (Test-Nested $StateDir $other)) { throw 'Worker directories overlap' }
    }
    if (Test-Nested $InstallRoot $BundleDir) { throw 'Media and installation overlap' }
    if ($RecoveryPoint -and ((Test-Nested $RecoveryPoint $InstallRoot) -or (Test-Nested $RecoveryPoint $BundleDir))) {
        throw 'Recovery directory overlaps media or installation'
    }
    Assert-PrivateState $StateDir
    # Never reuse a status folder or overwrite a concurrently running worker.
    $lock = [IO.File]::Open((Join-Path $StateDir 'worker.lock'),[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    $stateWritable = $true
    Set-Location -LiteralPath $StateDir
    $failureCode = 'confirmation_required'
    if ($Action -in @('apply','restore') -and (-not $MaintenanceConfirmed -or -not $RecoveryPoint)) {
        throw 'Maintenance acknowledgement and recovery location required'
    }
    if ($Action -eq 'restore' -and -not $ConfirmPointInTimeRecovery) { throw 'Point-in-time acknowledgement required' }
    Get-ChildItem Env:SAW_* | ForEach-Object { Remove-Item -LiteralPath ('Env:' + $_.Name) }
    Write-WorkerState 'working' 'verify_media' '설치 매체 전체를 확인하고 있습니다.'
    $failureCode = 'media_verification_failed'
    # Use this trusted entry point's verifier, not a script selected from another folder.
    & (Join-Path $PSScriptRoot 'verify-bundle.ps1') -BundleDir $BundleDir *> $null
    $controller = Join-Path $BundleDir 'app\saw\devtools\desktop_update.py'
    if (-not [IO.File]::Exists($controller)) { throw 'Desktop controller missing' }
    $failureCode = 'runtime_bootstrap_failed'
    Write-WorkerState 'working' 'prepare_runtime' '검증된 실행 환경을 준비하고 있습니다.'
    $runtime = Join-Path $StateDir 'runtime'
    Expand-VerifiedRuntime (Join-Path $BundleDir 'python\python-3.12.10-embed-amd64.zip') $runtime
    $arguments = @('-I','-B',$controller,$Action,'--install-root',$InstallRoot,'--bundle-dir',$BundleDir,'--state-dir',$StateDir)
    if ($BaselineBundleDir) { $arguments += @('--baseline-bundle-dir',$BaselineBundleDir) }
    if ($RecoveryPoint) { $arguments += @('--recovery-point',$RecoveryPoint) }
    if ($MaintenanceConfirmed) { $arguments += '--maintenance-confirmed' }
    if ($ConfirmPointInTimeRecovery) { $arguments += '--confirm-point-in-time-recovery' }
    $failureCode = 'controller_failed'
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = Join-Path $runtime 'python.exe'
    $info.Arguments = (($arguments | ForEach-Object { Quote-NativeArgument $_ }) -join ' ')
    $info.WorkingDirectory = $StateDir
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    if (-not $process.Start()) { throw 'Controller did not start' }
    # Drain both pipes without retaining raw output or risking a full-pipe deadlock.
    $stdout = $process.StandardOutput.BaseStream.CopyToAsync([IO.Stream]::Null)
    $stderr = $process.StandardError.BaseStream.CopyToAsync([IO.Stream]::Null)
    $process.WaitForExit()
    $stdout.GetAwaiter().GetResult()
    $stderr.GetAwaiter().GetResult()
    $failureCode = 'invalid_controller_result'
    $result = Read-ControllerState
    if ($process.ExitCode -eq 0 -and (($Action -eq 'inspect' -and $result.status -eq 'ready') -or
        ($Action -ne 'inspect' -and $result.status -eq 'completed'))) {
        $exitCode = 0
    } elseif ($process.ExitCode -ne 0 -and $result.status -eq 'failed') {
        # Preserve the controller's safe diagnosis and retained-artifact references.
        $exitCode = 1
    } else { throw 'Controller exit and result disagree' }
} catch {
    if ($stateWritable) {
        try {
            Write-WorkerState 'failed' $failureCode '작업을 완료하지 못했습니다. 설치와 복구 폴더를 보관하고 화면의 오류 코드를 확인하세요.'
        } catch { }
    }
    # Raw exceptions, native output and environment values must not reach the UI.
    Write-Output '업데이트 작업을 완료하지 못했습니다. 설치와 복구 폴더를 그대로 보관하세요.'
} finally {
    if ($null -ne $process) { $process.Dispose() }
    if ($null -ne $lock) { $lock.Dispose() }
}
exit $exitCode
