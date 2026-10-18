# SAW - OpenSearch single-node setup for Windows (ADR-0016). PowerShell 5.1 compatible, offline.
# Every native child gets its dedicated Java environment; existing services and operator config are preserved.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BundleDir,
    [string]$InstallRoot = "C:\SAW",
    [int]$HeapGB = 1,
    [int]$Port = 9200,
    [int]$TransportPort = 9300,
    [string]$ServiceName = "saw-opensearch",
    [switch]$NoService,
    [switch]$UserMode,
    [switch]$DevNoAcl,
    [switch]$ValidateOnly
)

function Invoke-SawOpenSearchNative {
    param([string]$FilePath, [string[]]$Arguments, [hashtable]$Environment = @{})
    # Quotes in command arguments are unsupported by these setup commands. Reject instead of shell expansion.
    $quoted = @($Arguments | ForEach-Object {
        if ($_ -match '["\r\n]') { throw "Unsupported native argument for $FilePath" }
        '"' + $_.TrimEnd('\') + '"'
    })
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    if ($FilePath -match '\.(bat|cmd)$') {
        if ($FilePath -match '["%\r\n]') { throw "Unsupported batch path: $FilePath" }
        $psi.FileName = Join-Path $env:SystemRoot 'System32\cmd.exe'
        $psi.Arguments = '/d /s /c ""' + $FilePath + '" ' + ($quoted -join ' ') + '"'
    } else {
        $psi.FileName = $FilePath
        $psi.Arguments = $quoted -join ' '
    }
    # Do not inherit another application's Java options, configuration, or procrun overrides.
    foreach ($name in @($psi.EnvironmentVariables.Keys)) {
        if ($name -match '^(OPENSEARCH_|JAVA_|_JAVA_OPTIONS$|JDK_JAVA_OPTIONS$|SERVICE_|PR_|LOG_OPTS$)') {
            $psi.EnvironmentVariables.Remove($name)
        }
    }
    foreach ($name in $Environment.Keys) { $psi.EnvironmentVariables[$name] = [string]$Environment[$name] }
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $psi
    try {
        if (-not $process.Start()) { throw "Cannot start $FilePath" }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        return [pscustomobject]@{ ExitCode = $process.ExitCode; Output = $stdout.Result + $stderr.Result }
    } finally { $process.Dispose() }
}

function Get-SawOpenSearchJava {
    param([string]$OpenSearchHome, [string]$Version, [string]$ArchivePath = '')
    $jdk = Join-Path $OpenSearchHome 'jdk'
    $java = Join-Path $jdk 'bin\java.exe'
    $jvm = Join-Path $jdk 'bin\server\jvm.dll'
    foreach ($path in @($jdk, $java, $jvm, (Join-Path $jdk 'release'))) {
        if (-not (Test-Path -LiteralPath $path)) { throw "OpenSearch Java validation failed: required bundled path missing: $path" }
    }
    $release = [IO.File]::ReadAllText((Join-Path $jdk 'release'))
    if ($Version -ne '2.19.6' -or $release -notmatch '(?m)^JAVA_VERSION="(21\.0\.11)"\r?$' -or
        $release -notmatch '(?m)^OS_ARCH="x86_64"\r?$') {
        throw "OpenSearch Java compatibility conflict: expected bundled JDK 21.0.11 x64 for OpenSearch 2.19.6 at $jdk"
    }
    if ($ArchivePath) { Assert-SawOpenSearchRuntimeArchive -OpenSearchHome $OpenSearchHome -ArchivePath $ArchivePath -Version $Version }
    $releaseVersion = [regex]::Match($release, '(?m)^JAVA_VERSION="([^"]+)"').Groups[1].Value
    $environment = @{
        JAVA_HOME = $jdk; OPENSEARCH_JAVA_HOME = $jdk
        OPENSEARCH_HOME = $OpenSearchHome; OPENSEARCH_PATH_CONF = (Join-Path $OpenSearchHome 'config')
    }
    $result = Invoke-SawOpenSearchNative -FilePath $java -Arguments @('-XshowSettings:properties', '-version') -Environment $environment
    if ($result.ExitCode -ne 0) {
        throw "OpenSearch Java validation failed at $java (exit $($result.ExitCode)): $($result.Output)"
    }
    if ($result.Output -notmatch '(?m)^\s*sun.arch.data.model\s*=\s*64\s*$' -or
        $result.Output -notmatch '(?m)^\s*java.specification.version\s*=\s*21\s*$' -or
        $result.Output -notmatch ('(?m)^\s*java.version\s*=\s*' + [regex]::Escape($releaseVersion) + '\s*$')) {
        throw "OpenSearch Java validation failed: runtime version/64-bit architecture differs from bundled release at $jdk"
    }
    return [pscustomobject]@{ Home = $jdk; Java = $java; Jvm = $jvm; Environment = $environment }
}

function Get-SawOpenSearchServiceRecord {
    param([string]$Name)
    if ($Name -notmatch '^[A-Za-z0-9_.-]+$') { throw "Invalid OpenSearch service name" }
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
    if (-not $service) { return $null }
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    $key = $null; $start = $null
    try {
        $prefix = 'SOFTWARE\Apache Software Foundation\ProcRun 2.0\' + $Name + '\Parameters'
        $key = $base.OpenSubKey($prefix + '\Java')
        $start = $base.OpenSubKey($prefix + '\Start')
        return [pscustomobject]@{
            BinaryPath = $service.PathName; State = $service.State
            Jvm = $(if ($key) { $key.GetValue('Jvm') } else { $null })
            Options = $(if ($key) { @($key.GetValue('Options')) + @($key.GetValue('Options9')) } else { @() })
            WorkingPath = $(if ($start) { $start.GetValue('WorkingPath') } else { $null })
        }
    } finally {
        if ($key) { $key.Dispose() }; if ($start) { $start.Dispose() }; $base.Dispose()
    }
}

function Assert-SawOpenSearchService {
    param($Record, [string]$Name, [string]$OpenSearchHome, [string]$Jvm)
    if (-not $Record) { throw "OpenSearch service registration did not create service '$Name' for $OpenSearchHome" }
    $exe = Join-Path $OpenSearchHome 'bin\opensearch-service-x64.exe'
    $expectedBinary = '^\s*"?'+ [regex]::Escape($exe) + '"?\s+//RS//' + [regex]::Escape($Name) + '\s*$'
    $expectedHome = '-Dopensearch.path.home=' + $OpenSearchHome
    $expectedConfig = '-Dopensearch.path.conf=' + (Join-Path $OpenSearchHome 'config')
    $options = @($Record.Options | Where-Object { $_ } | ForEach-Object { $_ -replace '"', '' })
    if ($Record.BinaryPath -notmatch $expectedBinary -or $Record.Jvm -ine $Jvm -or
        $Record.WorkingPath -ine $OpenSearchHome -or $options -inotcontains $expectedHome -or $options -inotcontains $expectedConfig) {
        throw "OpenSearch service conflict: '$Name' executable/JVM/working/config paths do not match $OpenSearchHome; existing service was not changed"
    }
    # Reject duplicate conflicting home/conf options even when the expected value is also present.
    foreach ($option in $options) {
        if (($option -like '-Dopensearch.path.home=*' -and $option -ine $expectedHome) -or
            ($option -like '-Dopensearch.path.conf=*' -and $option -ine $expectedConfig)) {
            throw "OpenSearch service conflict: '$Name' has ambiguous home/config options; existing service was not changed"
        }
    }
}

function Assert-SawOpenSearchConfig {
    param([string]$OpenSearchHome, [string]$Data, [string]$Logs, [int]$Port, [int]$TransportPort, [int]$HeapGB)
    $path = Join-Path $OpenSearchHome 'config\opensearch.yml'
    if (-not (Test-Path -LiteralPath $path)) { throw "OpenSearch configuration missing: $path; preserve data and repair from the same verified media" }
    $text = [IO.File]::ReadAllText($path)
    if ($text -notmatch '(?m)^# Managed by SAW deploy/windows/setup-opensearch\.ps1') {
        throw "OpenSearch configuration conflict at ${path}: not a recognized SAW configuration; no overwrite performed"
    }
    $required = @{
        'network.host' = '127.0.0.1'; 'http.port' = [string]$Port; 'transport.port' = [string]$TransportPort
        'path.data' = ($Data -replace '\\','/'); 'path.logs' = ($Logs -replace '\\','/')
        'discovery.type' = 'single-node'
    }
    foreach ($name in $required.Keys) {
        $rows = [regex]::Matches($text, '(?m)^\s*' + [regex]::Escape($name) + '\s*:\s*(.+?)\s*$')
        if ($rows.Count -ne 1) { throw "OpenSearch configuration conflict at $path for $name; no overwrite performed" }
        $value = $rows[0].Groups[1].Value.Trim().Trim('"', "'") -replace '\\','/'
        if ($value -cne $required[$name]) { throw "OpenSearch configuration conflict at $path for $name; retry with its original settings" }
    }
    $heapPath = Join-Path $OpenSearchHome 'config\jvm.options.d\saw-heap.options'
    if (-not (Test-Path -LiteralPath $heapPath)) { throw "OpenSearch heap configuration missing at $heapPath; no overwrite performed" }
    $heapText = [IO.File]::ReadAllText($heapPath)
    foreach ($option in @("-Xms$($HeapGB)g", "-Xmx$($HeapGB)g")) {
        if ($heapText -notmatch ('(?m)^' + [regex]::Escape($option) + '\s*$')) {
            throw "OpenSearch heap configuration conflict at $heapPath; retry with its original HeapGB"
        }
    }
}

function Test-SawOpenSearchArchiveFile {
    param([string]$Path, $Entry)
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Length -gt $Entry.Length) { return $false }
    # Only an exact archive prefix can be attributed to interrupted extraction.
    $source = $Entry.Open()
    $archiveHash = [Security.Cryptography.SHA256]::Create()
    $fileHash = [Security.Cryptography.SHA256]::Create()
    $input = $null
    try {
        $buffer = New-Object byte[] 65536
        [long]$remaining = $item.Length
        while ($remaining -gt 0) {
            $count = $source.Read($buffer, 0, [int][Math]::Min($remaining, $buffer.Length))
            if ($count -eq 0) { return $false }
            $null = $archiveHash.TransformBlock($buffer, 0, $count, $buffer, 0)
            $remaining -= $count
        }
        $null = $archiveHash.TransformFinalBlock($buffer, 0, 0)
        $input = [IO.File]::OpenRead($Path)
        $actual = $fileHash.ComputeHash($input)
        return ([BitConverter]::ToString($actual) -ceq [BitConverter]::ToString($archiveHash.Hash))
    } finally {
        if ($input) { $input.Dispose() }
        $source.Dispose(); $archiveHash.Dispose(); $fileHash.Dispose()
    }
}

function Preserve-SawOpenSearchPartialRuntime {
    param([string]$OpenSearchHome, [string]$ArchivePath, [string]$NoriArchivePath)
    # A preparation receipt identifies an attempt, not ownership of later edits.
    # Validate the whole old tree before retaining it or touching any active file.
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archives = New-Object Collections.Generic.List[object]
    try {
        $runtimeArchive = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
        $archives.Add($runtimeArchive)
        $noriArchive = [IO.Compression.ZipFile]::OpenRead($NoriArchivePath)
        $archives.Add($noriArchive)
        $entries = @{}
        $directories = @{}
        $prefix = [IO.Path]::GetFileName($OpenSearchHome) + '/'
        foreach ($entry in $runtimeArchive.Entries) {
            if ($entry.FullName.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                $relative = $entry.FullName.Substring($prefix.Length).TrimEnd('/')
                if (-not $relative) { continue }
                if ($entry.Name) { $entries[$relative] = $entry } else { $directories[$relative] = $true }
            }
        }
        foreach ($entry in $noriArchive.Entries) {
            $relative = 'plugins/analysis-nori/' + $entry.FullName.TrimEnd('/')
            if ($entry.Name) {
                if (-not $entries.ContainsKey($relative)) { $entries[$relative] = $entry }
            } else { $directories[$relative] = $true }
        }
        foreach ($relative in @($entries.Keys) + @($directories.Keys)) {
            $parent = $relative
            while ($parent.Contains('/')) {
                $parent = $parent.Substring(0, $parent.LastIndexOf('/'))
                $directories[$parent] = $true
            }
        }
        $queue = New-Object 'Collections.Generic.Queue[string]'
        $queue.Enqueue($OpenSearchHome)
        while ($queue.Count) {
            $path = $queue.Dequeue()
            $item = Get-Item -LiteralPath $path -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "OpenSearch partial runtime has a reparse point; all files preserved: $path"
            }
            $relative = $path.Substring($OpenSearchHome.Length).TrimStart('\').Replace('\', '/')
            if ($item.PSIsContainer) {
                if ($relative -and -not $directories.ContainsKey($relative)) {
                    throw "OpenSearch partial runtime has an unknown directory; all files preserved: $path"
                }
                foreach ($child in Get-ChildItem -LiteralPath $path -Force) { $queue.Enqueue($child.FullName) }
            } elseif (-not $entries.ContainsKey($relative) -or
                -not (Test-SawOpenSearchArchiveFile -Path $path -Entry $entries[$relative])) {
                throw "OpenSearch partial runtime contains a modified or unknown file; all files preserved: $path"
            }
        }
        $retained = $OpenSearchHome + '.retained-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
        $parent = [IO.Path]::GetDirectoryName($OpenSearchHome)
        if ([IO.Path]::GetDirectoryName($retained) -ine $parent) { throw 'Unsafe OpenSearch recovery destination' }
        [IO.Directory]::Move($OpenSearchHome, $retained)
        Write-Host "Interrupted OpenSearch runtime retained at $retained"
    } finally {
        foreach ($archive in $archives) { $archive.Dispose() }
    }
}

function Assert-SawOpenSearchRuntimeArchive {
    param([string]$OpenSearchHome, [string]$ArchivePath, [string]$Version)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        $prefix = [IO.Path]::GetFileName($OpenSearchHome) + '/'
        $required = @(('lib/opensearch-' + $Version + '.jar'), 'bin/opensearch-service-x64.exe', 'jdk/bin/java.exe', 'jdk/bin/server/jvm.dll')
        $found = @{}
        foreach ($entry in $archive.Entries) {
            if (-not $entry.FullName.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { continue }
            $relative = $entry.FullName.Substring($prefix.Length)
            if ($relative -notin $required -and $relative -notlike 'lib/*.jar') { continue }
            $found[$relative] = $true
            $path = Join-Path $OpenSearchHome $relative
            if (-not [IO.File]::Exists($path) -or (Get-Item -LiteralPath $path -Force).Length -ne $entry.Length -or
                -not (Test-SawOpenSearchArchiveFile -Path $path -Entry $entry)) {
                throw "OpenSearch runtime differs from verified media; no service was changed: $path"
            }
        }
        foreach ($relative in $required) {
            if (-not $found.ContainsKey($relative)) { throw "OpenSearch media lacks required runtime: $relative" }
        }
    } finally { $archive.Dispose() }
}

function Initialize-SawOpenSearchPolicyReader {
    if ('SawOpenSearchServicePolicy' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class SawOpenSearchServicePolicy {
    [StructLayout(LayoutKind.Sequential)] private struct FailureActions {
        public uint ResetPeriod; public IntPtr Reboot; public IntPtr Command; public uint Count; public IntPtr Actions;
    }
    public sealed class Action { public uint Type; public uint Delay; }
    public sealed class Policy { public bool DelayedAutoStart; public uint ResetPeriod; public Action[] Actions; }
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] private static extern IntPtr OpenSCManager(string machine, string database, uint access);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] private static extern IntPtr OpenService(IntPtr manager, string name, uint access);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] private static extern bool QueryServiceConfig2(IntPtr service, uint level, IntPtr buffer, uint size, out uint needed);
    [DllImport("advapi32.dll")] private static extern bool CloseServiceHandle(IntPtr handle);
    private static IntPtr Query(IntPtr service, uint level) {
        uint needed;
        QueryServiceConfig2(service, level, IntPtr.Zero, 0, out needed);
        if (needed == 0 || needed > 1048576) throw new Win32Exception(Marshal.GetLastWin32Error());
        IntPtr buffer = Marshal.AllocHGlobal((int)needed);
        if (!QueryServiceConfig2(service, level, buffer, needed, out needed)) {
            int error = Marshal.GetLastWin32Error(); Marshal.FreeHGlobal(buffer); throw new Win32Exception(error);
        }
        return buffer;
    }
    public static Policy Read(string name) {
        IntPtr manager=OpenSCManager(null,null,1);
        if (manager==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        IntPtr service=IntPtr.Zero, delayed=IntPtr.Zero, failure=IntPtr.Zero;
        try {
            service=OpenService(manager,name,1);
            if (service==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            delayed=Query(service,3); failure=Query(service,2);
            FailureActions f=(FailureActions)Marshal.PtrToStructure(failure,typeof(FailureActions));
            if(f.Count>1024 || (f.Count>0 && f.Actions==IntPtr.Zero)) throw new InvalidOperationException("Invalid service recovery policy");
            Action[] actions=new Action[f.Count];
            for(int i=0;i<actions.Length;i++) {
                IntPtr action=IntPtr.Add(f.Actions,i*8);
                actions[i]=new Action { Type=(uint)Marshal.ReadInt32(action), Delay=(uint)Marshal.ReadInt32(action,4) };
            }
            return new Policy { DelayedAutoStart=Marshal.ReadInt32(delayed)!=0, ResetPeriod=f.ResetPeriod, Actions=actions };
        } finally {
            if(delayed!=IntPtr.Zero) Marshal.FreeHGlobal(delayed);
            if(failure!=IntPtr.Zero) Marshal.FreeHGlobal(failure);
            if(service!=IntPtr.Zero) CloseServiceHandle(service);
            CloseServiceHandle(manager);
        }
    }
}
'@
}

function Get-SawOpenSearchServicePolicy {
    param([string]$Name)
    if ($Name -notmatch '^[A-Za-z0-9_.-]+$') { throw 'Invalid OpenSearch service name' }
    Initialize-SawOpenSearchPolicyReader
    $service = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
    if (-not $service) { throw 'OpenSearch service policy cannot be read: service missing' }
    $policy = [SawOpenSearchServicePolicy]::Read($Name)
    return [pscustomobject]@{StartMode=$service.StartMode; DelayedAutoStart=$policy.DelayedAutoStart;
        ResetPeriod=$policy.ResetPeriod; Actions=@($policy.Actions)}
}

function Assert-SawOpenSearchServicePolicy {
    param($Policy, [switch]$RequireRecovery)
    if ($Policy.StartMode -ne 'Auto') {
        throw 'OpenSearch service is not configured for automatic startup; existing operator policy was preserved'
    }
    if ($RequireRecovery) {
        $actions = @($Policy.Actions)
        if (-not $Policy.DelayedAutoStart -or $Policy.ResetPeriod -ne 86400 -or $actions.Count -ne 3 -or
            $actions[0].Type -ne 1 -or $actions[0].Delay -ne 60000 -or
            $actions[1].Type -ne 1 -or $actions[1].Delay -ne 60000 -or
            $actions[2].Type -ne 1 -or $actions[2].Delay -ne 300000) {
            throw 'OpenSearch service startup/recovery policy postcondition failed; retry with the same installation media'
        }
    }
}

function Save-SawOpenSearchPreparation {
    param([string]$Path, [string]$OpenSearchHome, [string]$Version, [bool]$Configured, [bool]$ServicePolicyPending = $false, [string]$ServiceName = 'saw-opensearch')
    $temporary = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    $value = @{ schema = 1; home = $OpenSearchHome; version = $Version; configured = $Configured; service_policy_pending = $ServicePolicyPending; service_name = $ServiceName } | ConvertTo-Json -Compress
    [IO.File]::WriteAllText($temporary, $value, (New-Object Text.UTF8Encoding $false))
    if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($temporary, $Path, [NullString]::Value) }
    else { [IO.File]::Move($temporary, $Path) }
}

if ($UserMode) { $NoService = $true }
$ErrorActionPreference = "Stop"
if ($HeapGB -lt 1 -or $Port -lt 1 -or $Port -gt 65535 -or $TransportPort -lt 1 -or $TransportPort -gt 65535) {
    throw 'Invalid OpenSearch heap or port'
}
$KeepPlugins = @("opensearch-index-management", "opensearch-job-scheduler")
$zip = @(Get-ChildItem (Join-Path $BundleDir "opensearch") -Filter "opensearch-*-windows-x64.zip")
$nori = @(Get-ChildItem (Join-Path $BundleDir "opensearch") -Filter "analysis-nori-*.zip")
if ($zip.Count -ne 1 -or $nori.Count -ne 1) { throw "Exactly one OpenSearch and one analysis-nori archive required under $BundleDir\opensearch" }
$zip = $zip[0]; $nori = $nori[0]
$version = $zip.Name -replace '^opensearch-(.+)-windows-x64\.zip$', '$1'
if ($version -ne '2.19.6' -or $nori.Name -ne "analysis-nori-$version.zip") { throw 'OpenSearch/nori version conflict with pinned 2.19.6 package' }
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
$home_ = Join-Path $InstallRoot "opensearch-$version"
$data = Join-Path $InstallRoot "data\opensearch"
$logs = Join-Path $InstallRoot "logs\opensearch"
$bin = Join-Path $home_ "bin"
$preparationPath = Join-Path $InstallRoot 'opensearch-setup-state.json'
$existingService = $null
if (-not $NoService) {
    $existingService = Get-SawOpenSearchServiceRecord -Name $ServiceName
    if ($existingService) {
        Assert-SawOpenSearchService -Record $existingService -Name $ServiceName -OpenSearchHome $home_ -Jvm (Join-Path $home_ 'jdk\bin\server\jvm.dll')
    }
}
if ($ValidateOnly) {
    $javaInfo = Get-SawOpenSearchJava -OpenSearchHome $home_ -Version $version -ArchivePath $zip.FullName
    Assert-SawOpenSearchConfig -OpenSearchHome $home_ -Data $data -Logs $logs -Port $Port -TransportPort $TransportPort -HeapGB $HeapGB
    $noriDescriptor = Join-Path $home_ 'plugins\analysis-nori\plugin-descriptor.properties'
    if (-not (Test-Path -LiteralPath $noriDescriptor)) { throw "OpenSearch analysis-nori descriptor missing at $noriDescriptor" }
    $noriMetadata = [IO.File]::ReadAllText($noriDescriptor)
    if ($noriMetadata -notmatch '(?m)^opensearch.version=2\.19\.6\s*$' -or $noriMetadata -notmatch '(?m)^name=analysis-nori\s*$') {
        throw "OpenSearch analysis-nori version/name conflict at $noriDescriptor"
    }
    if (-not $NoService) {
        Assert-SawOpenSearchService -Record $existingService -Name $ServiceName -OpenSearchHome $home_ -Jvm $javaInfo.Jvm
        Assert-SawOpenSearchServicePolicy (Get-SawOpenSearchServicePolicy $ServiceName)
    }
    Write-Host "OpenSearch $version configuration/runtime verified without changes at $home_ (service registration checked: $(-not $NoService))"
    return
}
$fresh = -not (Test-Path -LiteralPath $home_)
$preparing = $false
$servicePolicyPending = $false
if (Test-Path -LiteralPath $preparationPath) {
    $prepared = [IO.File]::ReadAllText($preparationPath) | ConvertFrom-Json
    if ($prepared.schema -ne 1 -or $prepared.home -ine $home_ -or $prepared.version -ne $version) {
        throw "OpenSearch preparation state conflict at $preparationPath"
    }
    $preparing = -not $prepared.configured
    $servicePolicyPending = ($prepared.service_policy_pending -eq $true)
    if ($servicePolicyPending -and $prepared.service_name -cne $ServiceName) { throw 'OpenSearch pending service policy belongs to another service; no service was changed' }
}
$configurationRecovered = $false
if ($preparing -and -not $fresh) {
    $existingConfig = Join-Path $home_ 'config\opensearch.yml'
    if ((Test-Path -LiteralPath $existingConfig) -and
        [IO.File]::ReadAllText($existingConfig) -match '(?m)^# Managed by SAW deploy/windows/setup-opensearch\.ps1') {
        # A crash after config writes but before the receipt must not overwrite later operator edits.
        Assert-SawOpenSearchConfig -OpenSearchHome $home_ -Data $data -Logs $logs -Port $Port -TransportPort $TransportPort -HeapGB $HeapGB
        $preparing = $false
        $configurationRecovered = $true
    }
}
if ($fresh -or $preparing) {
    if ($existingService) { throw 'OpenSearch service exists but runtime preparation is incomplete; repair requires an explicit maintenance procedure' }
    if ($preparing -and -not $fresh) {
        Preserve-SawOpenSearchPartialRuntime -OpenSearchHome $home_ -ArchivePath $zip.FullName -NoriArchivePath $nori.FullName
    }
    New-Item -ItemType Directory -Force $InstallRoot | Out-Null
    if ($fresh) { Save-SawOpenSearchPreparation -Path $preparationPath -OpenSearchHome $home_ -Version $version -Configured $false -ServiceName $ServiceName }
    Write-Host "Extracting $($zip.Name) to $InstallRoot ..."
    $tar = Join-Path $env:SystemRoot "System32\tar.exe"
    if (Test-Path -LiteralPath $tar) {
        $result = Invoke-SawOpenSearchNative -FilePath $tar -Arguments @('-xf', $zip.FullName, '-C', $InstallRoot)
        if ($result.ExitCode -ne 0) { throw "OpenSearch extraction failed (exit $($result.ExitCode)): $($result.Output)" }
    } else { Expand-Archive -LiteralPath $zip.FullName -DestinationPath $InstallRoot -Force }
}
$javaInfo = Get-SawOpenSearchJava -OpenSearchHome $home_ -Version $version -ArchivePath $zip.FullName
if (-not $fresh -and -not $preparing) {
    Assert-SawOpenSearchConfig -OpenSearchHome $home_ -Data $data -Logs $logs -Port $Port -TransportPort $TransportPort -HeapGB $HeapGB
}
New-Item -ItemType Directory -Force $data, $logs, (Join-Path $InstallRoot "backup\opensearch") | Out-Null
if ($fresh -or $preparing) {
    Write-Host "Preparing bundled plugins (keep: $($KeepPlugins -join ', '), analysis-nori) ..."
    # Only a runtime created by this setup operation may have its bundled plugins trimmed.
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
}
if (-not (Test-Path -LiteralPath (Join-Path $home_ "plugins\analysis-nori"))) {
    $uri = (New-Object Uri($nori.FullName)).AbsoluteUri
    $result = Invoke-SawOpenSearchNative -FilePath (Join-Path $bin "opensearch-plugin.bat") -Arguments @('install', '--batch', $uri) -Environment $javaInfo.Environment
    if ($result.ExitCode -ne 0 -or -not (Test-Path -LiteralPath (Join-Path $home_ 'plugins\analysis-nori\plugin-descriptor.properties'))) {
        throw "OpenSearch analysis-nori installation failed (exit $($result.ExitCode)): $($result.Output)"
    }
}
if ($fresh -or $preparing) {
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
action.auto_create_index: "+saw*,+.opendistro-*,+.plugins-*,+.opensearch-*,-*"
cluster.routing.allocation.disk.watermark.low: 85%
cluster.routing.allocation.disk.watermark.high: 90%
cluster.routing.allocation.disk.watermark.flood_stage: 95%
"@
    [IO.File]::WriteAllText((Join-Path $home_ "config\opensearch.yml"), $yml, (New-Object Text.UTF8Encoding $false))
    $jvmd = Join-Path $home_ "config\jvm.options.d"
    New-Item -ItemType Directory -Force $jvmd | Out-Null
    Set-Content -LiteralPath (Join-Path $jvmd "saw-heap.options") -Value @("-Xms$($HeapGB)g", "-Xmx$($HeapGB)g") -Encoding ASCII
    if (-not $DevNoAcl) {
        $sid = if ($UserMode) { [Security.Principal.WindowsIdentity]::GetCurrent().User.Value } else { 'S-1-5-32-544' }
        foreach ($d in @($data, $logs)) {
            & icacls $d /inheritance:r /grant:r "*$($sid):(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "OpenSearch ACL setup failed at $d (exit $LASTEXITCODE)" }
        }
    }
    Assert-SawOpenSearchConfig -OpenSearchHome $home_ -Data $data -Logs $logs -Port $Port -TransportPort $TransportPort -HeapGB $HeapGB
    Save-SawOpenSearchPreparation -Path $preparationPath -OpenSearchHome $home_ -Version $version -Configured $true -ServicePolicyPending $servicePolicyPending -ServiceName $ServiceName
}
if ($configurationRecovered) {
    Save-SawOpenSearchPreparation -Path $preparationPath -OpenSearchHome $home_ -Version $version -Configured $true -ServicePolicyPending $servicePolicyPending -ServiceName $ServiceName
}
if (-not $NoService) {
    if (-not $existingService) {
        $servicePolicyPending = $true
        Save-SawOpenSearchPreparation -Path $preparationPath -OpenSearchHome $home_ -Version $version -Configured $true -ServicePolicyPending $true -ServiceName $ServiceName
        $registrationEnvironment = $javaInfo.Environment.Clone()
        $registrationEnvironment.OPENSEARCH_START_TYPE = 'auto'
        $result = Invoke-SawOpenSearchNative -FilePath (Join-Path $bin 'opensearch-service.bat') -Arguments @('install', $ServiceName) -Environment $registrationEnvironment
        # The pinned batch script can return zero on an invalid JAVA_HOME. Check BOTH result and persisted registration.
        $existingService = Get-SawOpenSearchServiceRecord -Name $ServiceName
        if ($result.ExitCode -ne 0) { throw "OpenSearch service registration failed at $home_ (exit $($result.ExitCode), service present: $([bool]$existingService)): $($result.Output)" }
        Assert-SawOpenSearchService -Record $existingService -Name $ServiceName -OpenSearchHome $home_ -Jvm $javaInfo.Jvm
    }
    if ($servicePolicyPending) {
        foreach ($arguments in @(@('config', $ServiceName, 'start=', 'delayed-auto'),
                                 @('failure', $ServiceName, 'reset=', '86400', 'actions=', 'restart/60000/restart/60000/restart/300000'))) {
            $result = Invoke-SawOpenSearchNative -FilePath (Join-Path $env:SystemRoot 'System32\sc.exe') -Arguments $arguments
            if ($result.ExitCode -ne 0) { throw "OpenSearch service policy failed (exit $($result.ExitCode)): $($result.Output)" }
        }
        Assert-SawOpenSearchServicePolicy (Get-SawOpenSearchServicePolicy $ServiceName) -RequireRecovery
        Save-SawOpenSearchPreparation -Path $preparationPath -OpenSearchHome $home_ -Version $version -Configured $true -ServicePolicyPending $false -ServiceName $ServiceName
    } else {
        Assert-SawOpenSearchServicePolicy (Get-SawOpenSearchServicePolicy $ServiceName)
    }
    if ($existingService.State -ne 'Running') {
        Start-Service -Name $ServiceName -ErrorAction Stop
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
        $existingService = Get-SawOpenSearchServiceRecord -Name $ServiceName
        Assert-SawOpenSearchService -Record $existingService -Name $ServiceName -OpenSearchHome $home_ -Jvm $javaInfo.Jvm
        if ($existingService.State -ne 'Running') { throw "OpenSearch service did not reach Running at $home_" }
    }
}
Write-Host "OpenSearch $version validated at $home_ (http://127.0.0.1:$Port, heap $($HeapGB)g)."
