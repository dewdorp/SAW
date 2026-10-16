# Stopped-install application update and whole-installation recovery. PowerShell 5.1.
# Run from verified new media, never from inside the installation being restored.
[CmdletBinding()]
param(
    [ValidateSet('plan','apply','restore')][string]$Action = 'plan',
    [Parameter(Mandatory=$true)][string]$InstallRoot,
    [string]$BundleDir = '',
    [string]$BaselineBundleDir = '',
    [string]$RecoveryPoint = '',
    [switch]$ConfirmPointInTimeRecovery
)
$ErrorActionPreference = 'Stop'
$env:PSModulePath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules'
if (-not $BundleDir) { $BundleDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
function Assert-LocalPath([string]$Value) {
    $path = [IO.Path]::GetFullPath($Value)
    if ($path.StartsWith('\\') -or $path -eq [IO.Path]::GetPathRoot($path)) { throw 'A local non-root path is required' }
    $part = $path
    while ($part) {
        if (Test-Path -LiteralPath $part) {
            if ((Get-Item -LiteralPath $part -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse path refused' }
        }
        $parent = [IO.Path]::GetDirectoryName($part)
        if ($parent -eq $part) { break }
        $part = $parent
    }
    return $path
}
$BundleDir = Assert-LocalPath $BundleDir
$InstallRoot = Assert-LocalPath $InstallRoot
if ($BaselineBundleDir) { $BaselineBundleDir = Assert-LocalPath $BaselineBundleDir }
if ($RecoveryPoint) { $RecoveryPoint = Assert-LocalPath $RecoveryPoint }
if ($Action -in @('apply','restore') -and -not $RecoveryPoint) { throw 'RecoveryPoint is required' }
if ($Action -eq 'restore' -and -not $ConfirmPointInTimeRecovery) { throw 'ConfirmPointInTimeRecovery is required: newer records are retained separately, not merged' }
# No package code or runtime is executed until the entire media is checked.
& (Join-Path $BundleDir 'verify-bundle.ps1') -BundleDir $BundleDir
$tempParent = Assert-LocalPath ([IO.Path]::GetTempPath().TrimEnd('\'))
$scratch = Join-Path $tempParent ('SAW-update-runtime-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
foreach ($id in @($sid,(New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))) {
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($id,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
    $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $scratch -AclObject $acl
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $BundleDir 'python\python-3.12.10-embed-amd64.zip'), $scratch)
$python = Join-Path $scratch 'python.exe'
$script = Join-Path $BundleDir 'app\saw\devtools\offline_update.py'
$args_ = @('-I','-B',$script,$Action,'--install-root',$InstallRoot,'--bundle-dir',$BundleDir)
if ($BaselineBundleDir) { $args_ += @('--baseline-bundle-dir',$BaselineBundleDir) }
if ($RecoveryPoint) { $args_ += @('--recovery-point',$RecoveryPoint) }
if ($ConfirmPointInTimeRecovery) { $args_ += '--confirm-point-in-time-recovery' }
Get-ChildItem Env:SAW_* | ForEach-Object { Remove-Item -LiteralPath ('Env:' + $_.Name) }
# A temporary interpreter and working directory permit whole-root renames on Windows.
Push-Location $scratch
try {
    & $python @args_
    $code = $LASTEXITCODE
} finally {
    Pop-Location
}
if ($code -ne 0) { throw 'Update/recovery did not complete; preserve recovery directories and inspect the non-secret result' }
Write-Host 'The installation remains stopped. Start it separately and complete acceptance checks.'
Write-Host ('Temporary standalone runtime retained at: ' + $scratch)
