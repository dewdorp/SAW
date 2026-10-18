# Private installation-root creation and minimal PostgreSQL service runtime access.
# Dot-source only from verified media. PowerShell 5.1; no service registration.
function Get-SawLocalDirectoryPath([string]$Value) {
    foreach ($part in ($Value -split '[\\/]')) {
        if ($part -and $part -notin @('.','..') -and
            ($part -match '[. ]$' -or $part -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)')) {
            throw 'Aliased Windows installation path is refused'
        }
    }
    $path = [IO.Path]::GetFullPath($Value)
    if ($path.StartsWith('\\') -or $path -eq [IO.Path]::GetPathRoot($path)) {
        throw 'A local non-root directory is required'
    }
    $path = $path.TrimEnd('\','/')
    $part = $path
    while ($part) {
        if (Test-Path -LiteralPath $part) {
            $item = Get-Item -LiteralPath $part -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse installation paths are refused' }
        }
        $parent = [IO.Path]::GetDirectoryName($part)
        if ($parent -eq $part) { break }
        $part = $parent
    }
    return $path
}

function New-SawInstallRootAcl([switch]$NoAdmin) {
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $ownerSid = if ($NoAdmin) { [Security.Principal.WindowsIdentity]::GetCurrent().User.Value } else { 'S-1-5-32-544' }
    foreach ($sidText in @($ownerSid, 'S-1-5-18') | Select-Object -Unique) {
        $sid = New-Object Security.Principal.SecurityIdentifier($sidText)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    return $acl
}

function Get-SawDirectoryOwnerSid([string]$Path) {
    $policy = [IO.Directory]::GetAccessControl($Path, [Security.AccessControl.AccessControlSections]::Owner)
    return $policy.GetOwner([Security.Principal.SecurityIdentifier]).Value
}

function Initialize-SawInstallRoot([string]$InstallRoot, [string]$BundleDir, [switch]$NoAdmin) {
    $root = Get-SawLocalDirectoryPath $InstallRoot
    $media = Get-SawLocalDirectoryPath $BundleDir
    if (-not [IO.Directory]::Exists($media)) { throw 'Installation media directory is missing' }
    if ($root -ieq $media -or $root.StartsWith($media + '\', [StringComparison]::OrdinalIgnoreCase) -or
        $media.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Installation and media directories must be separate'
    }
    if (-not [IO.Directory]::Exists([IO.Path]::GetDirectoryName($root))) { throw 'Create the installation parent directory first' }
    if (Test-Path -LiteralPath $root) {
        if (-not [IO.Directory]::Exists($root) -or @(Get-ChildItem -LiteralPath $root -Force).Count -ne 0) {
            throw 'Choose a new or empty installation directory; existing files were not changed'
        }
        # An unrelated owner could restore its own access after exact DACL replacement.
        $trustedOwners = @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value, 'S-1-5-18', 'S-1-5-32-544')
        if ((Get-SawDirectoryOwnerSid $root) -notin $trustedOwners) {
            throw 'Installation directory owner requires administrator review; nothing was changed'
        }
    }
    $acl = New-SawInstallRootAcl -NoAdmin:$NoAdmin
    if ([IO.Directory]::Exists($root)) {
        # Exact replacement also removes unrelated explicit allow ACEs on an empty root.
        Set-Acl -LiteralPath $root -AclObject $acl
    } else {
        # Apply the protected DACL during creation, before any private child can exist.
        $null = [IO.Directory]::CreateDirectory($root, $acl)
    }
    $actual = Get-Acl -LiteralPath $root
    $expected = @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | ForEach-Object { $_.IdentityReference.Value })
    $rules = @($actual.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    if (-not $actual.AreAccessRulesProtected -or $rules.Count -ne $expected.Count) { throw 'Private installation root ACL was not applied' }
    foreach ($rule in $rules) {
        if ($rule.IdentityReference.Value -notin $expected -or $rule.AccessControlType -ne 'Allow' -or
            $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
            $rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit' -or
            $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None -or $rule.IsInherited) {
            throw 'Private installation root ACL was not applied'
        }
    }
    if (@(Get-ChildItem -LiteralPath $root -Force).Count -ne 0) { throw 'Installation directory changed during preparation' }
    return $root
}

function Grant-SawPostgresqlRuntimeAccess([string]$InstallRoot) {
    $root = Get-SawLocalDirectoryPath $InstallRoot
    $traverse = @('.', 'data', 'logs', 'venv', 'opensearch-2.19.6', 'opensearch-2.19.6\jdk')
    $runtime = @('pgsql', 'venv\Scripts', 'opensearch-2.19.6\jdk\bin')
    $paths = @{}
    foreach ($relative in @($traverse) + @($runtime)) {
        $path = Get-SawLocalDirectoryPath (Join-Path $root $relative)
        if (-not [IO.Directory]::Exists($path)) { throw 'Required PostgreSQL runtime directory is missing' }
        $paths[$relative] = $path
    }
    $sid = New-Object Security.Principal.SecurityIdentifier('S-1-5-20')
    foreach ($relative in @($traverse) + @($runtime)) {
        $path = $paths[$relative]
        $acl = [IO.Directory]::GetAccessControl($path, [Security.AccessControl.AccessControlSections]::Access)
        $rights = if ($relative -in $runtime) { 'ReadAndExecute' } else { 'Traverse' }
        $inherit = if ($relative -in $runtime) { 'ContainerInherit,ObjectInherit' } else { 'None' }
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, $rights, $inherit, 'None', 'Allow')
        $acl.AddAccessRule($rule)
        [IO.Directory]::SetAccessControl($path, $acl)
    }
}
