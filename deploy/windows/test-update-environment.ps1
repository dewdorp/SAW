# Read-only onsite updater acceptance evidence. Windows PowerShell 5.1.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$InstallRoot,
    [Parameter(Mandatory=$true)][string]$BundleDir,
    [string]$OriginalMedia = '',
    [string]$EvidenceParent = '',
    [switch]$FullInventory
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$env:PSModulePath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules'
$process = $null

function Test-SawNativeTarget {
    param($OperatingSystem,[version]$PowerShellVersion,[bool]$Is64BitProcess,[bool]$Is64BitOperatingSystem)
    # ProductType 1 is a client. Enterprise S/N are SKUs 125/126; build alone
    # also matches Server 2019 and non-LTSC clients, which are not this target.
    return ([int]$OperatingSystem.ProductType -eq 1 -and
        [int]$OperatingSystem.OperatingSystemSKU -in @(125,126) -and
        [string]$OperatingSystem.BuildNumber -eq '17763' -and
        [string]$OperatingSystem.Version -match '^10\.0\.17763(?:\.|$)' -and
        $PowerShellVersion.Major -eq 5 -and $PowerShellVersion.Minor -eq 1 -and
        $Is64BitProcess -and $Is64BitOperatingSystem)
}

function Get-SawNativeDigest([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-SawNativeInventory {
    param([string]$Root,[switch]$Full)
    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $queue = [Collections.Generic.Queue[string]]::new()
    $queue.Enqueue($rootPath)
    $rows = [Collections.Generic.List[string]]::new()
    $fileCount = 0
    $directoryCount = 0
    $static = @('app','venv','service','pgsql','llm-runtime','tls','secrets','opensearch-2.19.6')
    while ($queue.Count) {
        $path = $queue.Dequeue()
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Inventory reparse point refused' }
        $relative = if ($path -eq $rootPath) { '.' } else { $path.Substring($rootPath.Length + 1).Replace('\','/') }
        $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
        $sddl = $acl.GetSecurityDescriptorSddlForm(
            [Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner)
        $aclDigest = Get-SawNativeDigest ([Text.Encoding]::UTF8.GetBytes($sddl))
        if ($item.PSIsContainer) {
            $directoryCount++
            $rows.Add('D|' + $relative + '|' + $aclDigest)
            foreach ($child in Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop) {
                if (-not $Full -and $child.PSIsContainer) {
                    if ($path -eq $rootPath -and $child.Name -notin $static) { continue }
                    if ($relative -eq 'opensearch-2.19.6' -and $child.Name -notin @('bin','config','lib','jdk','plugins')) { continue }
                    if ($relative -eq 'app' -and $child.Name -eq 'var') { continue }
                }
                $queue.Enqueue($child.FullName)
            }
        } else {
            $fileCount++
            $stream = [IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
            $sha = [Security.Cryptography.SHA256]::Create()
            try {
                $length = $stream.Length
                $hash = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','').ToLowerInvariant()
                if ($length -ne $stream.Length) { throw 'Inventory file changed during read' }
            } finally { $stream.Dispose(); $sha.Dispose() }
            $rows.Add('F|' + $relative + '|' + $length + '|' + $hash + '|' + $aclDigest)
        }
        if ($rows.Count -gt 2000000) { throw 'Inventory limit exceeded' }
    }
    $ordered = @($rows | Sort-Object)
    return [pscustomobject]@{
        scope = if ($Full) { 'full_installation' } else { 'static_program_configuration_runtime' }
        files = $fileCount; directories = $directoryCount
        digest = Get-SawNativeDigest ([Text.Encoding]::UTF8.GetBytes(($ordered -join [char]10)))
    }
}

function Get-SawNativeServices {
    param([string]$Root)
    $paths = [ordered]@{
        saw='service\saw-service.exe'
        'saw-postgresql'='service\saw-postgresql.exe'
        'saw-opensearch'='opensearch-2.19.6\bin\opensearch-service-x64.exe'
    }
    $all = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)
    foreach ($name in $paths.Keys) {
        $services = @($all | Where-Object { $_.Name -ceq $name })
        if ($services.Count -ne 1) {
            [pscustomobject]@{name=$name;present=$false;account='<missing>';executable='<missing>';state='<missing>';pid=0}
            continue
        }
        $service = $services[0]
        $account = switch -Regex ([string]$service.StartName) {
            '^(LocalSystem|NT AUTHORITY\\SYSTEM)$' { 'LocalSystem'; break }
            '^NT AUTHORITY\\(NetworkService|NETWORK SERVICE)$' { 'NetworkService'; break }
            default { '<custom-or-unverified>' }
        }
        $binary = Join-Path $Root $paths[$name]
        $suffix = if ($name -eq 'saw-opensearch') { '\s+//RS//saw-opensearch' } else { '' }
        $binaryMatches = ([string]$service.PathName) -match ('^\s*"?' + [regex]::Escape($binary) + '"?' + $suffix + '\s*$')
        $state = if ($service.State -in @('Running','Stopped','Start Pending','Stop Pending','Paused','Pause Pending','Continue Pending')) {
            [string]$service.State
        } else { '<unverified>' }
        [pscustomobject]@{
            name=$name;present=$true;account=$account
            executable=if ($binaryMatches) { '<install-root>/' + $paths[$name].Replace('\','/') } else { '<unverified>' }
            state=$state;pid=[int64]$service.ProcessId
        }
    }
}

function Get-SawNativeRegistryViews {
    $prefix = 'SOFTWARE\Apache Software Foundation\ProcRun 2.0\saw-opensearch\Parameters'
    foreach ($view in @('Registry32','Registry64')) {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::$view)
        $parameters = $null
        try {
            $parameters = $base.OpenSubKey($prefix,$false)
            $kinds = [ordered]@{}
            foreach ($pair in @(@('Java','Jvm'),@('Java','Options'),@('Java','Options9'),@('Start','WorkingPath'))) {
                $key = $base.OpenSubKey(($prefix + '\' + $pair[0]),$false)
                try {
                    $kind = '<missing>'
                    if ($null -ne $key -and $key.GetValueNames() -contains $pair[1]) { $kind = [string]$key.GetValueKind($pair[1]) }
                    $kinds[$pair[0] + '/' + $pair[1]] = $kind
                } finally { if ($null -ne $key) { $key.Dispose() } }
            }
            [pscustomobject]@{view=$view;present=($null -ne $parameters);value_kinds=$kinds}
        } finally { if ($null -ne $parameters) { $parameters.Dispose() }; $base.Dispose() }
    }
}

try {
    # The trusted entry point's verifier runs before any selected media payload.
    & (Join-Path $PSScriptRoot 'verify-bundle.ps1') -BundleDir $BundleDir *> $null
    if ($OriginalMedia) { & (Join-Path $PSScriptRoot 'verify-bundle.ps1') -BundleDir $OriginalMedia *> $null }
    Import-Module (Join-Path $PSScriptRoot 'update-ui.psm1') -Force
    $InstallRoot = Get-SawUpdateLocalPath $InstallRoot
    $BundleDir = Get-SawUpdateLocalPath $BundleDir
    if ($OriginalMedia) { $OriginalMedia = Get-SawUpdateLocalPath $OriginalMedia }
    if (-not (Test-SawUpdatePathsSeparate $InstallRoot $BundleDir)) { throw 'Paths overlap' }
    $excluded = @($InstallRoot,$BundleDir,$OriginalMedia) | Where-Object { $_ }
    $evidence = New-SawUpdateStateDirectory -BasePath $EvidenceParent -ExcludedPaths $excluded
    $state = New-SawUpdateStateDirectory -BasePath $evidence -ExcludedPaths $excluded
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $beforeServices = @(Get-SawNativeServices $InstallRoot)
    $registry = @(Get-SawNativeRegistryViews)
    $before = Get-SawNativeInventory -Root $InstallRoot -Full:$FullInventory
    $startArgs = @{WorkerPath=(Join-Path $PSScriptRoot 'update-worker.ps1');Action='inspect';InstallRoot=$InstallRoot;BundleDir=$BundleDir;StateDir=$state;BaselineBundleDir=$OriginalMedia}
    $start = New-SawWorkerStartInfo @startArgs
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($start)
    $stdout = $process.StandardOutput.BaseStream.CopyToAsync([IO.Stream]::Null)
    $stderr = $process.StandardError.BaseStream.CopyToAsync([IO.Stream]::Null)
    $process.WaitForExit()
    $stdout.GetAwaiter().GetResult()
    $stderr.GetAwaiter().GetResult()
    $resultArgs = @{StatePath=(Join-Path $state 'state.json');Action='inspect';InstallRoot=$InstallRoot;ExitCode=$process.ExitCode}
    $result = Get-SawUpdateResult @resultArgs
    $after = Get-SawNativeInventory -Root $InstallRoot -Full:$FullInventory
    $afterServices = @(Get-SawNativeServices $InstallRoot)
    $sameServices = (($beforeServices | ConvertTo-Json -Depth 5 -Compress) -ceq ($afterServices | ConvertTo-Json -Depth 5 -Compress))
    $sameInventory = ($before.digest -ceq $after.digest)
    $target = Test-SawNativeTarget -OperatingSystem $os -PowerShellVersion $PSVersionTable.PSVersion `
        -Is64BitProcess ([Environment]::Is64BitProcess) -Is64BitOperatingSystem ([Environment]::Is64BitOperatingSystem)
    $admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $report = [ordered]@{
        schema='saw.updater-native-acceptance/1';utc=[DateTime]::UtcNow.ToString('o')
        status=if ($result.accepted -and -not $result.requires_admin -and $sameServices -and $sameInventory) { 'inspection_verified' } else { 'incomplete' }
        target_ltsc17763_ps51_x64=$target
        os=@{caption=[string]$os.Caption;version=[string]$os.Version;build=[string]$os.BuildNumber;architecture=[string]$os.OSArchitecture;product_type=[int]$os.ProductType;sku=[int]$os.OperatingSystemSKU}
        powershell=[string]$PSVersionTable.PSVersion
        token=@{user_sid=$identity.User.Value;default_owner_sid=$identity.Owner.Value;administrator=$admin}
        service_before=$beforeServices;service_after=$afterServices;service_unchanged=$sameServices
        registry_views=$registry
        inspection=@{accepted=[bool]$result.accepted;requires_admin=[bool]$result.requires_admin;code=[string]$result.code;mode=[string]$result.mode}
        inventory_before=$before;inventory_after=$after;inventory_unchanged=$sameInventory
        update_restore_and_reboot_acceptance='not_run'
    }
    $reportPath = Join-Path $evidence 'native-acceptance.json'
    [IO.File]::WriteAllText($reportPath,($report | ConvertTo-Json -Depth 10),(New-Object Text.UTF8Encoding $false))
    Write-Output ('검사 기록: ' + $reportPath)
    if ($report.status -ne 'inspection_verified' -or -not $target -or -not $admin) { exit 2 }
    exit 0
} catch {
    # Never print raw exception text, registry values, credentials, or command lines.
    Write-Output '현장 검사를 완료하지 못했습니다. 설치와 매체를 보존하고 보호된 검사 폴더를 확인하세요.'
    exit 1
} finally {
    if ($null -ne $process) { $process.Dispose() }
}
