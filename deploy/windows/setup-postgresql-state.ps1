function Restore-SawPostgresqlAccess([string]$Path, [string]$Sddl, [bool]$Directory) {
    if (-not ('SawPostgresqlAclNative' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SawPostgresqlAclNative {
 [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string s, uint r, out IntPtr d, IntPtr size);
 [DllImport("advapi32.dll", SetLastError=true)] public static extern bool GetSecurityDescriptorControl(IntPtr d, out ushort c, out uint r);
 [DllImport("advapi32.dll", SetLastError=true)] public static extern bool SetSecurityDescriptorControl(IntPtr d, ushort interest, ushort value);
 [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern bool SetFileSecurity(string p, uint flags, IntPtr d);
 [DllImport("kernel32.dll")] public static extern IntPtr LocalFree(IntPtr p);
}
'@
    }
    $descriptor=[IntPtr]::Zero
    if (-not [SawPostgresqlAclNative]::ConvertStringSecurityDescriptorToSecurityDescriptor($Sddl,1,[ref]$descriptor,[IntPtr]::Zero)) { throw 'Cannot parse PostgreSQL original access policy' }
    try {
        [uint16]$control=0; [uint32]$revision=0
        if (-not [SawPostgresqlAclNative]::GetSecurityDescriptorControl($descriptor,[ref]$control,[ref]$revision)) { throw 'Cannot read PostgreSQL inheritance controls' }
        if (($control -band 0x0400) -ne 0 -and -not [SawPostgresqlAclNative]::SetSecurityDescriptorControl($descriptor,0x0100,0x0100)) { throw 'Cannot preserve PostgreSQL inheritance controls' }
        [uint32]$flags=4
        if (-not [SawPostgresqlAclNative]::SetFileSecurity($Path,$flags,$descriptor)) { throw 'Cannot restore PostgreSQL access policy' }
    } finally { $null=[SawPostgresqlAclNative]::LocalFree($descriptor) }
}

# PostgreSQL installation-state and narrowly scoped ACL helpers. PowerShell 5.1.
function Assert-SawPostgresqlLocalPath([string]$Path, [string]$Root) {
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $base = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    if ($full -ine $base -and -not $full.StartsWith($base + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'PostgreSQL path is outside the selected installation root'
    }
    $part = $full
    while ($part) {
        if (Test-Path -LiteralPath $part) {
            if ((Get-Item -LiteralPath $part -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'PostgreSQL reparse paths require manual review'
            }
        }
        $parent = [IO.Path]::GetDirectoryName($part)
        if ($parent -eq $part) { break }
        $part = $parent
    }
    return $full
}

function Invoke-SawPostgresqlTemporaryAccess([object[]]$Scopes, [scriptblock]$Action) {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $saved = @{}
    $changed = New-Object Collections.Generic.List[object]
    try {
        # Capture every existing affected DACL before any inherited ACE can change.
        foreach ($scope in $Scopes) {
            $paths = @([string]$scope.Path)
            if ($scope.Inherit -ne 'None') {
                $paths += @(Get-ChildItem -LiteralPath $scope.Path -Force -Recurse | ForEach-Object {
                    if ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'PostgreSQL runtime reparse paths require review' }
                    $_.FullName
                })
            }
            foreach ($path in $paths) {
                if ($saved.ContainsKey($path)) { continue }
                $isDir = [IO.Directory]::Exists($path)
                if ($isDir) { $acl = [IO.Directory]::GetAccessControl($path, [Security.AccessControl.AccessControlSections]::Access) }
                else { $acl = [IO.File]::GetAccessControl($path, [Security.AccessControl.AccessControlSections]::Access) }
                $saved[$path] = @{Path=$path; Directory=$isDir; Sddl=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)}
            }
        }
        foreach ($scope in $Scopes) {
            $path = [string]$scope.Path
            $item = $saved[$path]
            if ($item.Directory) { $acl = [IO.Directory]::GetAccessControl($path, [Security.AccessControl.AccessControlSections]::Access) }
            else { $acl = [IO.File]::GetAccessControl($path, [Security.AccessControl.AccessControlSections]::Access) }
            $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid,$scope.Rights,$scope.Inherit,'None','Allow')
            $acl.AddAccessRule($rule)
            $changed.Add($scope)
            if ($scope.Inherit -eq 'None') {
                # Noninheritable traversal/read must not recalculate sibling ACLs.
                Restore-SawPostgresqlAccess $path ($acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)) $item.Directory
            } else { [IO.Directory]::SetAccessControl($path, $acl) }
        }
        & $Action
    } finally {
        $restoreFailures = @()
        # Remove inherited temporary rights from newly created data files first.
        foreach ($scope in $changed) {
            if ($scope.Inherit -eq 'None') { continue }
            try {
                $item=$saved[[string]$scope.Path]
                $acl=New-Object Security.AccessControl.DirectorySecurity
                $acl.SetSecurityDescriptorSddlForm($item.Sddl,[Security.AccessControl.AccessControlSections]::Access)
                [IO.Directory]::SetAccessControl($item.Path,$acl)
            } catch { $restoreFailures += $scope.Path }
        }
        foreach ($item in @($saved.Values | Sort-Object { $_.Path.Length })) {
            try { Restore-SawPostgresqlAccess $item.Path $item.Sddl $item.Directory }
            catch { $restoreFailures += $item.Path }
        }
        if ($restoreFailures.Count) { throw ('PostgreSQL temporary ACL restoration failed at: ' + ($restoreFailures -join ', ')) }
    }
}

function Invoke-SawPostgresqlPasswordAccess([string]$Root, [string]$PasswordFile, [scriptblock]$Action) {
    $file = Assert-SawPostgresqlLocalPath $PasswordFile $Root
    if (-not [IO.File]::Exists($file)) { throw 'PostgreSQL password file missing; existing secrets were not regenerated' }
    $scopes = @(@{Path=$file; Rights='Read'; Inherit='None'})
    $part = [IO.Path]::GetDirectoryName($file)
    $base = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    while ($part) {
        $scopes = @(@{Path=$part; Rights='Traverse'; Inherit='None'}) + $scopes
        if ($part -ieq $base) { break }
        $part = [IO.Path]::GetDirectoryName($part)
    }
    Invoke-SawPostgresqlTemporaryAccess $scopes $Action
}

function Get-SawPostgresqlClusterState([string]$Data, [string]$Bin) {
    if (-not (Test-Path -LiteralPath $Data)) { return 'fresh' }
    if (-not [IO.Directory]::Exists($Data) -or ((Get-Item -LiteralPath $Data -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'PostgreSQL data path is not an ordinary directory'
    }
    if (@(Get-ChildItem -LiteralPath $Data -Force).Count -eq 0) { return 'fresh' }
    foreach ($relative in @('PG_VERSION','global\pg_control','postgresql.conf','pg_hba.conf','pg_ident.conf','base','global','pg_wal','pg_xact')) {
        $path = Join-Path $Data $relative
        if (-not (Test-Path -LiteralPath $path)) { throw "PostgreSQL data is incomplete ($relative missing); no initialization or deletion was performed" }
        $null = Assert-SawPostgresqlLocalPath $path $Data
    }
    if ([IO.File]::ReadAllText((Join-Path $Data 'PG_VERSION')).Trim() -ne '16') { throw 'PostgreSQL cluster major version is incompatible; no data was changed' }
    if ((Get-Item -LiteralPath (Join-Path $Data 'global\pg_control')).Length -ne 8192) { throw 'PostgreSQL control file is incomplete; no data was changed' }
    $control = Join-Path $Bin 'pg_controldata.exe'
    if (-not [IO.File]::Exists($control)) { throw 'PostgreSQL control-file verifier is missing' }
    $report = & $control $Data 2>&1
    $code = $LASTEXITCODE
    if ($code -ne 0 -or -not $report) { throw "PostgreSQL control-file validation failed (exit $code); no initialization was attempted" }
    return 'initialized'
}

function Invoke-SawPostgresqlSql([string]$Psql, [int]$Port, [string]$User, [string]$Database, [string]$Password, [string]$Sql) {
    if ($User -notin @('postgres','saw') -or $Database -notin @('postgres','saw')) { throw 'Unexpected PostgreSQL bootstrap identity' }
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $Psql
    $info.Arguments = "-X -h 127.0.0.1 -p $Port -U $User -d $Database -v ON_ERROR_STOP=1 -Atq"
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.StandardOutputEncoding = New-Object Text.UTF8Encoding($false,$true)
    $info.EnvironmentVariables['PGCLIENTENCODING'] = 'UTF8'
    $info.EnvironmentVariables['PGPASSWORD'] = $Password
    $info.EnvironmentVariables['PGCONNECT_TIMEOUT'] = '10'
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    try {
        $null = $process.Start()
        $out = $process.StandardOutput.ReadToEndAsync()
        $err = $process.StandardError.ReadToEndAsync()
        # SQL and secrets travel over private stdin, never the command line.
        $inputBytes=(New-Object Text.UTF8Encoding($false,$true)).GetBytes($Sql+[Environment]::NewLine)
        $process.StandardInput.BaseStream.Write($inputBytes,0,$inputBytes.Length)
        $process.StandardInput.Close()
        if (-not $process.WaitForExit(60000)) { $process.Kill(); throw 'PostgreSQL application initialization timed out' }
        $stdout = $out.GetAwaiter().GetResult()
        $null = $err.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            # psql errors can echo SQL containing a password: do not forward them.
            throw "PostgreSQL application initialization failed (exit $($process.ExitCode)); check connection and existing credentials"
        }
        return $stdout.Trim()
    } finally { $process.Dispose() }
}

function Get-SawPostgresqlDataDirectory([string]$Psql, [int]$Port, [string]$Password) {
    # Native Windows PostgreSQL returns filesystem paths in its ANSI code page.
    # textsend transports those bytes without psql discarding invalid UTF8.
    $hex=Invoke-SawPostgresqlSql $Psql $Port 'postgres' 'postgres' $Password "SELECT encode(pg_catalog.textsend(current_setting('data_directory')), 'hex')"
    if (-not $hex -or $hex -notmatch '^(?:[0-9a-fA-F]{2})+$') { throw 'PostgreSQL native data-directory identity is invalid' }
    if (-not ('SawPostgresqlEncodingNative' -as [type])) {
        Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public static class SawPostgresqlEncodingNative {
 [DllImport("kernel32.dll")] public static extern uint GetACP();
}
'@
    }
    $bytes=New-Object byte[] ($hex.Length/2)
    for($i=0;$i -lt $bytes.Length;$i++) { $bytes[$i]=[Convert]::ToByte($hex.Substring($i*2,2),16) }
    $encoding=[Text.Encoding]::GetEncoding([int][SawPostgresqlEncodingNative]::GetACP(), (New-Object Text.EncoderExceptionFallback), (New-Object Text.DecoderExceptionFallback))
    return $encoding.GetString($bytes)
}

function Assert-SawPostgresqlServiceConfig([string]$Path, [string]$Root, [string]$Name, [string]$ChildPath) {
    if (-not [IO.File]::Exists($Path)) { throw 'Existing PostgreSQL service configuration is missing; no service was changed' }
    try { [xml]$xml = [IO.File]::ReadAllText($Path) }
    catch { throw 'Existing PostgreSQL service configuration is invalid; no service was changed' }
    $s = $xml.service
    if ($s.id -cne $Name -or $s.executable -ine (Join-Path $Root 'pgsql\bin\postgres.exe') -or
        $s.startarguments -cne ('-D "' + (Join-Path $Root 'data\postgresql') + '"') -or
        $s.stopexecutable -ine (Join-Path $Root 'pgsql\bin\pg_ctl.exe') -or
        $s.stoparguments -cne ('stop -D "' + (Join-Path $Root 'data\postgresql') + '" -m fast -w -t 120') -or
        $s.workingdirectory -ine (Join-Path $Root 'pgsql\bin') -or
        $s.serviceaccount.domain -ine 'NT AUTHORITY' -or $s.serviceaccount.user -ine 'NetworkService' -or
        @($s.env | Where-Object { $_.name -eq 'PATH' -and $_.value -ceq $ChildPath }).Count -ne 1) {
        throw 'Existing PostgreSQL service configuration conflicts with selected installation; no service was changed'
    }
}

function Assert-SawPostgresqlClusterConfig([string]$Data, [string]$Bin, [int]$Port) {
    $expected=@{port=[string]$Port;listen_addresses='127.0.0.1';password_encryption='scram-sha-256'}
    foreach($name in $expected.Keys) {
        $value=& (Join-Path $Bin 'postgres.exe') -D $Data -C $name 2>&1
        $code=$LASTEXITCODE
        if($code -ne 0 -or "$value".Trim() -cne $expected[$name]) {
            throw "PostgreSQL existing configuration $name conflicts with this installation (exit $code); files preserved, review the interrupted configuration before retry"
        }
    }
    foreach($line in [IO.File]::ReadAllLines((Join-Path $Data 'pg_hba.conf'))) {
        $line=($line -split '#',2)[0].Trim()
        if(-not $line) { continue }
        $fields=$line -split '\s+'
        if($fields[0] -eq 'local') {
            if($fields.Count -lt 4 -or $fields[3] -cne 'scram-sha-256') { throw 'PostgreSQL local authentication policy requires review; no configuration was overwritten' }
        } elseif($fields[0] -in @('host','hostssl','hostnossl')) {
            if($fields.Count -lt 5 -or $fields[3] -notin @('127.0.0.1/32','::1/128') -or $fields[4] -cne 'scram-sha-256') {
                throw 'PostgreSQL loopback SCRAM authentication policy requires review; no configuration was overwritten'
            }
        } else { throw 'PostgreSQL authentication includes unsupported directives; review without overwriting' }
    }
}

function Assert-SawPostgresqlWrapper([string]$Exe, [string]$BundledWrapper) {
    if (-not [IO.File]::Exists($Exe) -or
        (Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash -cne (Get-FileHash -LiteralPath $BundledWrapper -Algorithm SHA256).Hash) {
        throw 'Existing PostgreSQL service wrapper differs from verified media; no service file was changed'
    }
}

function Initialize-SawPostgresqlServiceFiles([string]$Exe, [string]$Xml, [string]$BundledWrapper, [string]$Template, [string]$Root, [string]$Name, [string]$ChildPath) {
    if (Test-Path -LiteralPath $Exe) { Assert-SawPostgresqlWrapper $Exe $BundledWrapper }
    if (Test-Path -LiteralPath $Xml) { Assert-SawPostgresqlServiceConfig $Xml $Root $Name $ChildPath }
    if (-not [IO.File]::Exists($Exe)) { Copy-Item -LiteralPath $BundledWrapper -Destination $Exe }
    if (-not [IO.File]::Exists($Xml)) { Write-PostgresqlServiceXml $Template $Xml $Root $Name $ChildPath }
}

function Invoke-SawPostgresqlInitInput([string]$Bin, [scriptblock]$Action) {
    $runtime=[IO.Path]::GetFullPath((Split-Path $Bin))
    $share=Assert-SawPostgresqlLocalPath (Join-Path $runtime 'share') $runtime
    if (-not [IO.Directory]::Exists($share)) { throw 'PostgreSQL initialization input directory is missing' }
    if ($share -notmatch '[^\x00-\x7F]') { & $Action $share; return }
    if (([Security.Principal.WindowsIdentity]::GetCurrent()).IsSystem) {
        throw 'Non-ASCII PostgreSQL initialization requires an interactive administrator/user; LocalSystem aliases would be global'
    }
    # initdb embeds its input filename in UTF8 SQL using the Windows ANSI bytes.
    # An ASCII session-local DOS device avoids that conversion without changing
    # the installation path, database encoding, files, or filesystem ACLs.
    if (-not ('SawPostgresqlInputNative' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class SawPostgresqlInputNative {
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern bool DefineDosDevice(uint flags, string name, string target);
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern uint QueryDosDevice(string name, StringBuilder target, int size);
}
'@
    }
    $name='SAWPG-'+[Guid]::NewGuid().ToString('N')
    $target='\??\'+$share
    $before=New-Object Text.StringBuilder 32768
    if ([SawPostgresqlInputNative]::QueryDosDevice($name,$before,$before.Capacity) -ne 0 -or
        [Runtime.InteropServices.Marshal]::GetLastWin32Error() -ne 2) {
        throw 'PostgreSQL initialization input alias conflicts; no mapping was changed'
    }
    # RAW_TARGET_PATH | NO_BROADCAST_SYSTEM: no drive letter or global setting.
    if (-not [SawPostgresqlInputNative]::DefineDosDevice(9,$name,$target)) {
        throw 'Cannot create the session-local PostgreSQL initialization input alias'
    }
    try {
        $actual=New-Object Text.StringBuilder 32768
        if ([SawPostgresqlInputNative]::QueryDosDevice($name,$actual,$actual.Capacity) -eq 0 -or
            $actual.ToString() -cne $target) { throw 'PostgreSQL initialization input alias target validation failed' }
        & $Action ('\\.\'+$name+'\')
    } finally {
        # Remove only this exact mapping, never another target for the name.
        if (-not [SawPostgresqlInputNative]::DefineDosDevice(15,$name,$target)) {
            throw 'Cannot remove the session-local PostgreSQL initialization input alias'
        }
    }
}
