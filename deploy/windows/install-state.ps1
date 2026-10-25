# Installation journal, lock, evidence checks and selected-drive layout. PowerShell 5.1.
# Dot-source only from fully verified media; no secrets are stored in this journal.
function Get-SawInstallLayout([string]$InstallRoot) {
    $root = Get-SawLocalDirectoryPath $InstallRoot
    return [ordered]@{ root=$root; volume=[IO.Path]::GetPathRoot($root); application=(Join-Path $root 'app');
        database=(Join-Path $root 'data\postgresql'); indices=(Join-Path $root 'data\opensearch');
        evidence=(Join-Path $root 'data\objects'); models=(Join-Path $root 'models');
        logs=(Join-Path $root 'logs'); backup=(Join-Path $root 'backup') }
}
function Get-SawFileDigest([string]$Path) {
    $stream=[IO.File]::OpenRead($Path); $sha=[Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','').ToLowerInvariant() }
    finally { $stream.Dispose(); $sha.Dispose() }
}
function Initialize-SawInstallScanNative {
    if ('SawInstallScanNative' -as [type]) { return }
    Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class SawInstallScanNative {
 [StructLayout(LayoutKind.Sequential)] struct FileInfo {
  public uint Attributes;
  public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
  public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
 }
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
 static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
 [DllImport("kernel32.dll", SetLastError=true)]
 static extern bool GetFileInformationByHandle(SafeFileHandle handle,out FileInfo info);
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
 static extern uint GetFileAttributesW(string path);
 static string Identity(SafeFileHandle handle) {
  FileInfo info;
  if(!GetFileInformationByHandle(handle,out info)) throw new Win32Exception(Marshal.GetLastWin32Error());
  if((info.Attributes & 0x400)!=0 || (info.Attributes & 0x10)==0)
   throw new System.IO.IOException("Relcache parent is not an ordinary directory");
  return info.Volume.ToString("X8")+info.IndexHigh.ToString("X8")+info.IndexLow.ToString("X8");
 }
 static SafeFileHandle Open(string path,uint share) {
  // Metadata only; OPEN_REPARSE_POINT prevents following a substituted junction.
  SafeFileHandle handle=CreateFileW(path,0,share,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
  if(handle.IsInvalid) { int error=Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error); }
  return handle;
 }
 public static string DirectoryIdentity(string path) {
  using(SafeFileHandle handle=Open(path,7)) { return Identity(handle); }
 }
 public static bool MissingRelcache(string path,string[] parents,string[] identities) {
  var handles=new List<SafeFileHandle>();
  try {
   for(int i=0;i<parents.Length;i++) {
    // Omit FILE_SHARE_DELETE while confirming absence: none of these parents
    // can be renamed/replaced between identity validation and the leaf lookup.
    SafeFileHandle handle=Open(parents[i],3); handles.Add(handle);
    if(Identity(handle)!=identities[i]) throw new System.IO.IOException("Relcache parent changed during installation verification");
   }
   if(GetFileAttributesW(path)!=UInt32.MaxValue) return false;
   int error=Marshal.GetLastWin32Error();
   if(error==2) return true; // ERROR_FILE_NOT_FOUND only, never PATH_NOT_FOUND/access denied.
   throw new Win32Exception(error);
  } finally { foreach(SafeFileHandle handle in handles) handle.Dispose(); }
 }
}
"@
}
function Test-SawVanishedRelcache([string]$Path,[string]$Root,[hashtable]$Parents) {
    $paths=New-Object 'Collections.Generic.List[string]'
    $ids=New-Object 'Collections.Generic.List[string]'
    $parent=[IO.Path]::GetDirectoryName($Path)
    while ($true) {
        if (-not $Parents.ContainsKey($parent)) { throw 'Relcache parent was not verified' }
        $acl=Get-Acl -LiteralPath $parent -ErrorAction Stop
        if ($acl.Sddl -cne $Parents[$parent].Sddl) { throw 'Relcache parent access policy changed during verification' }
        $paths.Insert(0,$parent); $ids.Insert(0,$Parents[$parent].Identity)
        if ($parent -ieq $Root) { break }
        $parent=[IO.Path]::GetDirectoryName($parent)
    }
    return [SawInstallScanNative]::MissingRelcache($Path,$paths.ToArray(),$ids.ToArray())
}
function Assert-SawPrivateInstall([string]$Root) {
    # Read metadata before executing installed code or reading private configuration.
    $trusted=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')
    $queue=New-Object 'Collections.Generic.Queue[object]'
    $parents=@{}
    $queue.Enqueue(@{Path=$Root; Directory=$true; Reparse=$false})
    while ($queue.Count) {
        $entry=$queue.Dequeue(); $path=$entry.Path
        $rel=$path.Substring($Root.Length).TrimStart('\').Replace('\','/').ToLowerInvariant()
        if ($entry.Reparse) { throw "Installation contained a reparse point when enumerated: $path" }
        try {
            $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Installation contains a reparse point: $path" }
            $acl=Get-Acl -LiteralPath $path -ErrorAction Stop
        } catch {
            # PostgreSQL atomically replaces/unlinks only these disposable relcache
            # files. Never excuse a missing directory, config, code, or access error.
            if (-not $entry.Directory -and $_.Exception -is [Management.Automation.ItemNotFoundException] -and
                $rel -match '^data/postgresql/(global|base/[0-9]+)/pg_internal\.init(?:\.[0-9]+)?$' -and
                (Test-SawVanishedRelcache $path $Root $parents)) { continue }
            throw
        }
        $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin $trusted -and -not ($owner -eq 'S-1-5-20' -and $rel -match '^(data/postgresql|logs/postgresql)(/|$)')) { throw "Installation owner needs review: $path" }
        foreach ($ace in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            # OWNER RIGHTS refers to the already validated actual owner.
            $effectiveSid=$ace.IdentityReference.Value
            if ($effectiveSid -eq 'S-1-3-4') { $effectiveSid=$owner }
            if ($effectiveSid -in $trusted) { continue }
            $rel=$path.Substring($Root.Length).TrimStart('\').Replace('\','/').ToLowerInvariant()
            # Existing PostgreSQL service access is scoped; no access to secrets or application data.
            if ($effectiveSid -eq 'S-1-5-20' -and (
                ($rel -in @('','data','logs','venv','opensearch-2.19.6','opensearch-2.19.6/jdk') -and [int]$ace.FileSystemRights -eq 0x100020 -and $ace.InheritanceFlags -eq 'None') -or
                ($rel -match '^(pgsql|venv/scripts|opensearch-2.19.6/jdk/bin)(/|$)' -and [int]$ace.FileSystemRights -eq 0x1200a9) -or
                ($rel -match '^data/postgresql(/|$)' -and [int]$ace.FileSystemRights -eq 0x1f01ff) -or
                ($rel -match '^logs/postgresql(/|$)' -and [int]$ace.FileSystemRights -eq 0x1301bf) -or
                ($rel -match '^service(/|$)' -and [int]$ace.FileSystemRights -eq 0x1200a9))) { continue }
            throw "Installation grants unrelated access; no ACL was changed: $path"
        }
        if ($item.PSIsContainer) {
            if ($rel -in @('','data','data/postgresql','data/postgresql/global','data/postgresql/base') -or
                $rel -match '^data/postgresql/base/[0-9]+$') {
                Initialize-SawInstallScanNative
                $parents[$path]=@{Identity=[SawInstallScanNative]::DirectoryIdentity($path); Sddl=$acl.Sddl}
            }
            foreach ($child in Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop) {
                $queue.Enqueue(@{Path=$child.FullName; Directory=$child.PSIsContainer;
                    Reparse=[bool]($child.Attributes -band [IO.FileAttributes]::ReparsePoint)})
            }
        }
    }
}
function Read-SawInstallManifest([string]$Path) {
    $doc=[IO.File]::ReadAllText($Path,[Text.Encoding]::UTF8) | ConvertFrom-Json
    if ($doc.schema -ne 'saw.offline-release/1') { throw 'Unsupported installed manifest' }
    $seen=@{}
    foreach ($row in $doc.files) {
        $rel=[string]$row.path
        if (-not $rel -or $rel.Contains('\') -or $rel -match '[:*?"<>|\x00-\x1f]' -or $seen.ContainsKey($rel)) { throw 'Unsafe installed manifest path' }
        foreach ($part in $rel.Split('/')) {
            if ($part -in @('','.','..') -or $part -match '[. ]$' -or $part -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)' -or
                $part -in @('.env','var','secrets','.git','.qa')) { throw 'Unsafe installed manifest component' }
        }
        if ([string]$row.sha256 -cnotmatch '^[0-9a-f]{64}$' -or $row.bytes -lt 0) { throw 'Invalid installed manifest digest' }
        $seen[$rel]=$true
    }
    foreach ($required in @('app/pyproject.toml','app/saw/cli.py','app/apps/web/dist/index.html','app/deploy/windows/requirements.txt')) {
        if (-not $seen.ContainsKey($required)) { throw "Installed manifest lacks required payload: $required" }
    }
    return $doc
}
function Assert-SawApplicationFiles([string]$Root, $Manifest, [switch]$AllowMissing) {
    foreach ($row in $Manifest.files) {
        if ($row.path -notlike 'app/*' -and $row.path -notlike 'llm-runtime/*') { continue }
        $path=Join-Path $Root $row.path
        if (-not [IO.File]::Exists($path)) {
            if ($AllowMissing) { continue }
            throw "Installed payload missing: $($row.path)"
        }
        if ((Get-Item -LiteralPath $path).Length -ne $row.bytes -or (Get-SawFileDigest $path) -ne $row.sha256) {
            throw "Installed payload changed; preserve user edits and review before retry: $($row.path)"
        }
    }
}
function Write-SawInstallState($Context) {
    $path=Join-Path $Context.Root '.saw-install-state.json'
    $temp=Join-Path $Context.Root ('.saw-install-state.'+[guid]::NewGuid().ToString('N')+'.tmp')
    [IO.File]::WriteAllText($temp, ($Context.State | ConvertTo-Json -Depth 12), (New-Object Text.UTF8Encoding $false))
    if ([IO.File]::Exists($path)) { [IO.File]::Replace($temp,$path,[NullString]::Value) } else { [IO.File]::Move($temp,$path) }
}
function Enter-SawInstall([string]$InstallRoot,[string]$BundleDir,[hashtable]$Options,[string]$BaselineBundleDir='') {
    $root=Get-SawLocalDirectoryPath $InstallRoot
    $media=Get-SawLocalDirectoryPath $BundleDir
    if ($root -ieq $media -or $root.StartsWith($media+'\',[StringComparison]::OrdinalIgnoreCase) -or
        $media.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Installation and media directories must be separate' }
    $hasFiles=[IO.Directory]::Exists($root) -and @(Get-ChildItem -LiteralPath $root -Force).Count -gt 0
    if (-not $hasFiles) { $root=Initialize-SawInstallRoot $root $media -NoAdmin:$Options.noAdmin }
    else { Assert-SawPrivateInstall $root }
    $lockPath=Join-Path ([IO.Path]::GetDirectoryName($root)) ('.'+[IO.Path]::GetFileName($root)+'.saw-maintenance.lock')
    if (Test-Path -LiteralPath $lockPath) {
        if ((Get-Item -LiteralPath $lockPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Unsafe installation lock' }
    }
    $stream=$null
    try {
        $stream=[IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::ReadWrite)
        $stream.Lock(0,1)
    } catch { if ($stream) { $stream.Dispose() }; throw 'Another installation or update holds this installation lock; retry after it exits' }
    try {
        $statePath=Join-Path $root '.saw-install-state.json'
        $installed=Join-Path $root 'installed-release-manifest.json'
        $pin=Get-SawFileDigest (Join-Path $media 'release-manifest.json')
        $context=[pscustomobject]@{Root=$root;Lock=$stream;State=$null;Mode='new';PayloadBundle=$media;ActiveStage=''}
        if ([IO.File]::Exists($statePath)) {
            $state=[IO.File]::ReadAllText($statePath,[Text.Encoding]::UTF8)|ConvertFrom-Json
            if ($state.schema -ne 'saw.install-state/1' -or $state.root -ine $root) { throw 'Invalid or relocated installation state' }
            foreach ($key in $Options.Keys) {
                if (($state.options.$key | ConvertTo-Json -Compress) -cne ($Options[$key] | ConvertTo-Json -Compress)) {
                    throw "Installation option conflict: $key; repeat the original options"
                }
            }
            $context.State=$state
            if ($state.status -eq 'complete') { $context.Mode='verify'; return $context }
            if ($state.media_sha256 -ne $pin) { throw 'Incomplete installation requires the same verified media; use the documented baseline recovery procedure' }
            if ($state.payload_bundle_sha256 -ne $pin) {
                if (-not $BaselineBundleDir -or (Get-SawFileDigest (Join-Path $BaselineBundleDir 'release-manifest.json')) -ne $state.payload_bundle_sha256) {
                    throw 'The original verified baseline media is required to resume this installation'
                }
                $context.PayloadBundle=Get-SawLocalDirectoryPath $BaselineBundleDir
            }
            $state.previous_status=$state.status
            $state.status='running'
            $context.Mode='resume'
        } elseif ($hasFiles) {
            if ([IO.File]::Exists($installed)) {
                $null=Read-SawInstallManifest $installed
                $context.Mode='verify'; return $context
            }
            if (-not $BaselineBundleDir) { throw 'Unrecorded partial installation: provide its original verified -BaselineBundleDir; no files were changed' }
            $baseline=Get-SawLocalDirectoryPath $BaselineBundleDir
            $manifest=Read-SawInstallManifest (Join-Path $baseline 'release-manifest.json')
            if (-not [IO.File]::Exists((Join-Path $root 'app\pyproject.toml'))) { throw 'No verifiable SAW application exists; unknown directory was preserved' }
            Assert-SawApplicationFiles $root $manifest -AllowMissing
            $context.PayloadBundle=$baseline; $context.Mode='resume'
        }
        if (-not $context.State) {
            $context.State=[ordered]@{schema='saw.install-state/1';root=$root;media_sha256=$pin;
                payload_bundle_sha256=(Get-SawFileDigest (Join-Path $context.PayloadBundle 'release-manifest.json'));
                options=$Options;status='running';previous_status='';stage='preflight';completed=@();exit_code=0}
        }
        Write-SawInstallState $context
        return $context
    } catch { $stream.Unlock(0,1); $stream.Dispose(); throw }
}
function Set-SawInstallStage($Context,[string]$Stage) {
    if (-not $Context -or -not $Context.State) { return }
    if ($Context.ActiveStage -and $Context.ActiveStage -ne $Stage -and $Context.ActiveStage -notin $Context.State.completed) {
        $Context.State.completed=@($Context.State.completed)+@($Context.ActiveStage)
    }
    $Context.ActiveStage=$Stage
    $Context.State.stage=$Stage; $Context.State.status='running';$Context.State.exit_code=0
    Write-SawInstallState $Context
}
function Set-SawInstallFailed($Context,[int]$Code) {
    if (-not $Context -or -not $Context.State -or $Context.Mode -eq 'verify') { return }
    $Context.State.status='failed';$Context.State.exit_code=$Code
    Write-SawInstallState $Context
}
function Complete-SawInstall($Context) {
    if ($Context.State.stage -notin $Context.State.completed) { $Context.State.completed=@($Context.State.completed)+@($Context.State.stage) }
    $Context.State.status='complete';$Context.State.stage='complete';$Context.State.exit_code=0
    Write-SawInstallState $Context
}
function Exit-SawInstall($Context) {
    if ($Context -and $Context.Lock) { try { $Context.Lock.Unlock(0,1) } finally { $Context.Lock.Dispose() } }
}
function Assert-SawInstalledConfiguration([string]$Root,[hashtable]$Options) {
    $envPath=Join-Path $Root 'app\.env'
    if (-not [IO.File]::Exists($envPath)) { throw 'Installed configuration missing; no secret was generated' }
    $values=@{}
    foreach ($line in [IO.File]::ReadAllLines($envPath,[Text.Encoding]::UTF8)) {
        if ($line -match '^([A-Z0-9_]+)=(.*)$') { $values[$matches[1]]=$matches[2] }
    }
    $expected=@{SAW_DATA_DIR=(Join-Path $Root 'data\saw');SAW_OBJECT_STORE_ROOT=(Join-Path $Root 'data\objects');
        SAW_WEB_DIST=(Join-Path $Root 'app\apps\web\dist');SAW_LLM_MODELS_ROOT=(Join-Path $Root 'models')}
    foreach ($key in $expected.Keys) {
        if (-not $values.ContainsKey($key) -or [IO.Path]::GetFullPath($values[$key]) -ine $expected[$key]) {
            throw "Existing configuration path conflicts with installation root: $key"
        }
    }
    if ($values.SAW_DATABASE_URL -notmatch ('@127\.0\.0\.1:'+ $Options.postgresPort +'/saw$') -or
        $values.SAW_OPENSEARCH_URL -ne ('http://127.0.0.1:'+$Options.opensearchPort)) { throw 'Existing database/search endpoint conflicts with selected ports' }
    $ctlPath=Join-Path $Root 'saw-ctl.json'
    if ([IO.File]::Exists($ctlPath)) {
        $ctl=[IO.File]::ReadAllText($ctlPath)|ConvertFrom-Json
        foreach ($key in @('port','postgresPort','opensearchPort')) {
            if ($ctl.$key -ne $Options[$key]) { throw "Existing control configuration conflicts: $key" }
        }
    }
}
function Assert-SawCompletedPostgresqlRuntime([string]$Root,[string]$BundleDir) {
    $archives=@(Get-ChildItem -LiteralPath (Join-Path $BundleDir 'postgresql') -Filter 'postgresql-*-windows-x64-binaries.zip' -File)
    if ($archives.Count -ne 1) { throw 'Exactly one verified PostgreSQL runtime archive is required' }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive=[IO.Compression.ZipFile]::OpenRead($archives[0].FullName)
    $required=@('postgres.exe','initdb.exe','pg_ctl.exe','pg_controldata.exe','pg_isready.exe','psql.exe')
    $found=@{}
    try {
        foreach ($entry in $archive.Entries) {
            $relative=$entry.FullName.Replace('\','/')
            if ($relative -notmatch '^pgsql/bin/([^/]+\.(exe|dll))$') { continue }
            $found[$matches[1]]=$true
            $path=Join-Path $Root $relative
            if (-not [IO.File]::Exists($path) -or (Get-Item -LiteralPath $path -Force).Length -ne $entry.Length) {
                throw "Installed PostgreSQL runtime is missing or modified; no repair was performed: $relative"
            }
            $stream=$entry.Open(); $sha=[Security.Cryptography.SHA256]::Create()
            try { $expected=([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','').ToLowerInvariant() }
            finally { $stream.Dispose(); $sha.Dispose() }
            if ((Get-SawFileDigest $path) -cne $expected) {
                throw "Installed PostgreSQL runtime differs from verified media; no repair was performed: $relative"
            }
        }
        foreach ($name in $required) {
            if (-not $found.ContainsKey($name)) { throw "Verified PostgreSQL archive lacks required executable: $name" }
        }
    } finally { $archive.Dispose() }
}

function Assert-SawCompletedInstall($Context,[string]$BundleDir,[hashtable]$Options,[switch]$RequireLive) {
    $root=$Context.Root
    $installedManifest=Join-Path $root 'installed-release-manifest.json'
    if ($Context.State -and $Context.State.payload_bundle_sha256 -ne (Get-SawFileDigest $installedManifest) -and
        (Get-SawFileDigest (Join-Path $BundleDir 'release-manifest.json')) -ne (Get-SawFileDigest $installedManifest)) {
        throw 'Installed manifest differs from recorded payload; no file was changed'
    }
    $manifest=Read-SawInstallManifest $installedManifest
    Assert-SawApplicationFiles $root $manifest
    $null=Ensure-SawPythonRuntime -InstallRoot $root -BundleDir $BundleDir -ValidateOnly
    Assert-SawInstalledConfiguration $root $Options
    $searchArgs=@{BundleDir=$BundleDir;InstallRoot=$root;HeapGB=$Options.heapGB;Port=$Options.opensearchPort;
        TransportPort=$Options.opensearchTransportPort;ValidateOnly=$true}
    if ($Options.noAdmin) { $searchArgs.UserMode=$true }
    if ($Options.noServices) { $searchArgs.NoService=$true }
    & (Join-Path $BundleDir 'app\deploy\windows\setup-opensearch.ps1') @searchArgs
    foreach ($rel in @('tls\saw.crt','tls\saw.key','secrets\postgres-superuser.pw','secrets\postgres-saw.pw',
        'pgsql\bin\pg_controldata.exe','data\postgresql\PG_VERSION','data\postgresql\global\pg_control',
        'data\postgresql\postgresql.conf','data\postgresql\pg_hba.conf','opensearch-2.19.6\config\opensearch.yml',
        'opensearch-2.19.6\jdk\bin\java.exe','opensearch-2.19.6\jdk\bin\server\jvm.dll')) {
        $path=Join-Path $root $rel
        if (-not [IO.File]::Exists($path) -or (Get-Item -LiteralPath $path).Length -eq 0) { throw "Installed component missing: $rel" }
    }
    Assert-SawCompletedPostgresqlRuntime $root $BundleDir
    $savedPath=$env:PATH
    try {
        $env:PATH=(Join-Path $root 'opensearch-2.19.6\jdk\bin')+';'+$env:SystemRoot+'\System32'
        $pgVersion=& (Join-Path $root 'pgsql\bin\postgres.exe') --version 2>&1
        $pgVersionCode=$LASTEXITCODE
        if ($pgVersionCode -ne 0 -or "$pgVersion".Trim() -cne 'postgres (PostgreSQL) 16.15') {
            throw "Existing PostgreSQL runtime version check failed (exit $pgVersionCode); no repair was performed"
        }
        & (Join-Path $root 'pgsql\bin\pg_controldata.exe') -D (Join-Path $root 'data\postgresql') *> $null
        if ($LASTEXITCODE -ne 0) { throw "Existing database control check failed (exit $LASTEXITCODE); no initdb was run" }
    } finally { $env:PATH=$savedPath }
    if (-not $Options.noAdmin -and -not $Options.noServices) {
        . (Join-Path $BundleDir 'app\deploy\windows\setup-postgresql-state.ps1')
        $childPath=(Join-Path $root 'opensearch-2.19.6\jdk\bin')+';'+(Join-Path $env:SystemRoot 'System32')+';'+$env:SystemRoot
        Assert-SawPostgresqlServiceConfig (Join-Path $root 'service\saw-postgresql.xml') $root 'saw-postgresql' $childPath
        [xml]$appService=[IO.File]::ReadAllText((Join-Path $root 'service\saw-service.xml'))
        $bind=if($Options.localOnly){'127.0.0.1'}else{'0.0.0.0'}
        $arguments='-m saw.cli serve --host '+$bind+' --port '+$Options.port+' --cert "'+(Join-Path $root 'tls\saw.crt')+'" --key "'+(Join-Path $root 'tls\saw.key')+'"'
        if ($appService.service.id -ne 'saw' -or $appService.service.executable -ine (Join-Path $root 'venv\Scripts\python.exe') -or
            $appService.service.workingdirectory -ine (Join-Path $root 'app') -or $appService.service.arguments -cne $arguments) {
            throw 'Existing SAW service configuration conflicts; no service was changed'
        }
        $wrapperHash=Get-SawFileDigest (Join-Path $BundleDir 'winsw\WinSW-x64.exe')
        foreach ($wrapper in @('service\saw-service.exe','service\saw-postgresql.exe')) {
            if ((Get-SawFileDigest (Join-Path $root $wrapper)) -ne $wrapperHash) { throw 'Installed service wrapper differs from pinned media' }
        }
        foreach ($pair in @(@('saw','service\saw-service.exe'),@('saw-postgresql','service\saw-postgresql.exe'),@('saw-opensearch','opensearch-2.19.6\bin\opensearch-service-x64.exe'))) {
            $svc=Get-CimInstance Win32_Service -Filter ("Name='"+$pair[0]+"'")
            $exe=Join-Path $root $pair[1]
            if (-not $svc -or $svc.PathName -notmatch ('^"?'+[regex]::Escape($exe)+'"?(\s|$)')) { throw "Service missing or belongs to another installation: $($pair[0])" }
        }
    }
    $schema=[string]$manifest.metadata.application_schema
    if (-not $schema) {
        $versions=@($manifest.files | ForEach-Object {
            if ($_.path -match '^app/saw/storage/migrations/versions/(\d{4})_.*\.py$') { $matches[1] }
        } | Sort-Object)
        if (-not $versions.Count) { throw 'Installed schema revision cannot be determined from verified payload' }
        $schema=$versions[-1]
    }
    $liveRequired=[bool]$RequireLive
    if (-not $Options.noAdmin -and -not $Options.noServices) {
        foreach ($name in @('saw','saw-postgresql','saw-opensearch')) {
            if ((Get-Service -Name $name).Status -eq 'Running') { $liveRequired=$true }
        }
    }
    foreach ($process in Get-CimInstance Win32_Process) {
        if ($process.ExecutablePath -and $process.ExecutablePath.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)) {
            $liveRequired=$true
        }
    }
    $verifyArgs=@('-B','-S',(Join-Path $BundleDir 'app\saw\devtools\install_verify.py'),'--root',$root,
        '--host',$Options.hostName,'--port',[string]$Options.port,'--pg-port',[string]$Options.postgresPort,
        '--os-port',[string]$Options.opensearchPort,'--schema',$schema)
    if ($liveRequired) { $verifyArgs+=@('--require-live') }
    $output=& (Join-Path $root 'venv\Scripts\python.exe') @verifyArgs
    $verifyCode=$LASTEXITCODE
    $report=$output | ConvertFrom-Json
    if ($verifyCode -ne 0 -or -not $report.ok) {
        $failed=@($report.checks.PSObject.Properties | Where-Object { $_.Value.status -ne 'PASS' } | ForEach-Object { $_.Name })
        throw "Installed runtime verification failed (exit $verifyCode): $($failed -join ', '); no state was replaced"
    }
    if ($report.ready) { Write-Host '인증서·DB·검색·웹 실행 상태 검증 완료.' }
    else { Write-Host '중지 상태: 파일·구성·인증서 검증 완료. 로그인·검색·웹 실행 상태는 미검증이며 서비스를 시작하지 않았습니다.' }

}
