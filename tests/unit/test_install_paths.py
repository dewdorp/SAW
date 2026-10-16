"""Installer roots must protect code and generated keys before any child exists."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "deploy/windows/install-paths.ps1"
pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows DACL contract")

def ps_literal(value):
    return "'" + str(value).replace("'", "''") + "'"

def run_ps(tmp_path, body):
    assert HELPER.is_file(), "The install root security helper is missing"
    script = tmp_path / "acl-probe.ps1"
    script.write_text(
        "$ErrorActionPreference='Stop'\n"
        "$env:PSModulePath=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/Modules'\n"
        "[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)\n"
        ". " + ps_literal(HELPER) + "\n" + body,
        encoding="utf-8-sig")
    result = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                             "-File", str(script)], capture_output=True, timeout=90)
    assert result.returncode == 0, (result.stdout + result.stderr).decode("utf-8", "replace")
    return json.loads(result.stdout.decode("utf-8-sig"))

ACL_READER = """
function Read-TestAcl([string]$Path) {
    $acl=Get-Acl -LiteralPath $Path
    $entries=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | ForEach-Object {
        @{ sid=$_.IdentityReference.Value; rights=[int]$_.FileSystemRights;
           type=[string]$_.AccessControlType; inherited=$_.IsInherited;
           inheritance=[int]$_.InheritanceFlags; propagation=[int]$_.PropagationFlags }
    })
    return @{ protected=$acl.AreAccessRulesProtected; entries=$entries }
}
"""

@pytest.mark.parametrize("existing_empty", [False, True])
def test_root_and_generated_children_do_not_inherit_broad_parent_access(tmp_path, existing_empty):
    media = tmp_path / "media"
    media.mkdir()
    broad = tmp_path / "broad-parent"
    broad.mkdir()
    target = broad / "new-install"
    if existing_empty:
        target.mkdir()
    body = ACL_READER + f"""
$parent={ps_literal(broad)}; $root={ps_literal(target)}
$wide=[IO.Directory]::GetAccessControl($parent, [Security.AccessControl.AccessControlSections]::Access)
$wide.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
    (New-Object Security.Principal.SecurityIdentifier('S-1-5-11')),
    'Modify','ContainerInherit,ObjectInherit','None','Allow')))
[IO.Directory]::SetAccessControl($parent, $wide)
if (Test-Path -LiteralPath $root) {{
    $wide=[IO.Directory]::GetAccessControl($root, [Security.AccessControl.AccessControlSections]::Access)
    $wide.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')),
        'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')))
    [IO.Directory]::SetAccessControl($root, $wide)
}}
$null=Initialize-SawInstallRoot -InstallRoot $root -BundleDir {ps_literal(media)} -NoAdmin
$before=@(Get-ChildItem -LiteralPath $root -Force).Count
foreach($relative in @('app/var','venv/Scripts','service','secrets')) {{
    $null=New-Item -ItemType Directory -Path (Join-Path $root $relative) -Force
    [IO.File]::WriteAllText((Join-Path $root ($relative+'/synthetic.txt')),'synthetic')
}}
@{{ user=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value; before=$before;
   root=Read-TestAcl $root; keyParent=Read-TestAcl (Join-Path $root 'app/var');
   code=Read-TestAcl (Join-Path $root 'venv/Scripts/synthetic.txt');
   secret=Read-TestAcl (Join-Path $root 'secrets/synthetic.txt') }} | ConvertTo-Json -Depth 8 -Compress
"""
    result = run_ps(tmp_path, body)
    assert result["before"] == 0
    expected = {result["user"], "S-1-5-18"}
    assert result["root"]["protected"]
    for field in ("root", "keyParent", "code", "secret"):
        entries = result[field]["entries"]
        assert {row["sid"] for row in entries} == expected
        assert all(row["type"] == "Allow" and row["rights"] == 2032127 for row in entries)

@pytest.mark.parametrize("case", ["nonempty", "file", "same_media", "media_parent", "inside_media", "drive_root"])
def test_unsafe_or_used_install_root_is_rejected_without_changing_files_or_acl(tmp_path, case):
    media = tmp_path / "media"
    media.mkdir()
    marker = tmp_path / "untouched.txt"
    marker.write_text("keep", encoding="utf-8")
    target = tmp_path / "candidate"
    if case == "nonempty":
        target.mkdir()
        (target / "existing.txt").write_text("keep", encoding="utf-8")
    elif case == "file":
        target.write_text("keep", encoding="utf-8")
    else:
        target = {"same_media": media, "media_parent": tmp_path,
                  "inside_media": media / "new-install", "drive_root": Path(tmp_path.anchor)}[case]
    body = f"""
$target={ps_literal(target)}; $watch={ps_literal(tmp_path)}
$before=(Get-Acl -LiteralPath $watch).Sddl
$targetBefore=if (Test-Path -LiteralPath $target) {{ (Get-Acl -LiteralPath $target).Sddl }} else {{ $null }}
$rejected=$false
try {{ $null=Initialize-SawInstallRoot -InstallRoot $target -BundleDir {ps_literal(media)} -NoAdmin }}
catch {{ $rejected=$true }}
@{{ rejected=$rejected; unchanged=((Get-Acl -LiteralPath $watch).Sddl -ceq $before);
   targetUnchanged=($null -eq $targetBefore -or (Get-Acl -LiteralPath $target).Sddl -ceq $targetBefore);
   marker=[IO.File]::ReadAllText({ps_literal(marker)}) }} | ConvertTo-Json -Compress
"""
    result = run_ps(tmp_path, body)
    assert result == {"rejected": True, "unchanged": True, "targetUnchanged": True, "marker": "keep"}
    if case == "nonempty":
        assert (target / "existing.txt").read_text() == "keep"
    if case == "inside_media":
        assert not target.exists()

def test_reparse_install_root_and_parent_are_rejected(tmp_path):
    media = tmp_path / "media"
    media.mkdir()
    external = tmp_path / "synthetic-external"
    external.mkdir()
    body = f"""
$link=Join-Path {ps_literal(tmp_path)} 'junction'
$null=New-Item -ItemType Junction -Path $link -Target {ps_literal(external)}
$before=(Get-Acl -LiteralPath {ps_literal(external)}).Sddl
$results=@()
foreach($target in @($link,(Join-Path $link 'new-install'))) {{
    $rejected=$false
    try {{ $null=Initialize-SawInstallRoot -InstallRoot $target -BundleDir {ps_literal(media)} -NoAdmin }}
    catch {{ $rejected=$true }}
    $results+=$rejected
}}
@{{ rejected=$results; unchanged=((Get-Acl -LiteralPath {ps_literal(external)}).Sddl -ceq $before);
   children=@(Get-ChildItem -LiteralPath {ps_literal(external)} -Force).Count }} | ConvertTo-Json -Compress
"""
    result = run_ps(tmp_path, body)
    assert result == {"rejected": [True, True], "unchanged": True, "children": 0}

def test_service_policy_and_network_service_rights_do_not_expose_application_secrets(tmp_path):
    media = tmp_path / "media"
    media.mkdir()
    target = tmp_path / "service-contract"
    body = ACL_READER + f"""
$root={ps_literal(target)}
$null=Initialize-SawInstallRoot -InstallRoot $root -BundleDir {ps_literal(media)} -NoAdmin
foreach($relative in @('pgsql/bin','pgsql/lib','venv/Scripts','opensearch-2.19.6/jdk/bin',
                       'data/postgresql','logs/postgresql','app/var','secrets','tls')) {{
    $null=New-Item -ItemType Directory -Path (Join-Path $root $relative) -Force
    [IO.File]::WriteAllText((Join-Path $root ($relative+'/synthetic.txt')),'synthetic')
}}
Grant-SawPostgresqlRuntimeAccess -InstallRoot $root
$service=New-SawInstallRootAcl
$serviceSids=@($service.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) |
    ForEach-Object {{ $_.IdentityReference.Value }})
$checked=@{{}}
foreach($relative in @('.','pgsql/bin/synthetic.txt','venv/Scripts/synthetic.txt',
                       'opensearch-2.19.6/jdk/bin/synthetic.txt','app/var/synthetic.txt',
                       'secrets/synthetic.txt','tls/synthetic.txt')) {{
    $checked[$relative]=Read-TestAcl (Join-Path $root $relative)
}}
@{{ serviceSids=$serviceSids; serviceProtected=$service.AreAccessRulesProtected; checked=$checked }} |
    ConvertTo-Json -Depth 10 -Compress
"""
    result = run_ps(tmp_path, body)
    assert set(result["serviceSids"]) == {"S-1-5-32-544", "S-1-5-18"}
    assert result["serviceProtected"]
    checked = result["checked"]
    ns = lambda path: [row for row in checked[path]["entries"] if row["sid"] == "S-1-5-20"]
    root_rule = ns(".")
    assert len(root_rule) == 1 and root_rule[0]["inheritance"] == 0
    assert root_rule[0]["rights"] == 0x100020
    assert not root_rule[0]["rights"] & (1 | 2 | 4 | 65536 | 262144)
    for path in ("pgsql/bin/synthetic.txt", "venv/Scripts/synthetic.txt",
                 "opensearch-2.19.6/jdk/bin/synthetic.txt"):
        rules = ns(path)
        assert len(rules) == 1 and rules[0]["rights"] == 0x1200A9
        assert not rules[0]["rights"] & (2 | 4 | 65536 | 262144)
    for path in ("app/var/synthetic.txt", "secrets/synthetic.txt", "tls/synthetic.txt"):
        assert not ns(path)

def test_synthetic_key_keeps_bytes_and_encryption_after_reload_under_private_root(tmp_path, monkeypatch):
    from saw.core.security import secrets as crypto
    media = tmp_path / "media"
    media.mkdir()
    target = tmp_path / "key-contract"
    run_ps(tmp_path, f"$null=Initialize-SawInstallRoot -InstallRoot {ps_literal(target)} "
           f"-BundleDir {ps_literal(media)} -NoAdmin; '{{\"ready\":true}}'")
    monkeypatch.setattr(crypto, "VAR", target / "app/var")
    monkeypatch.delenv("SAW_SECRET_KEY", raising=False)
    crypto._fernet.cache_clear()
    try:
        token = crypto.encrypt("synthetic check")
        key = target / "app/var/secret.key"
        before = key.read_bytes()
        crypto._fernet.cache_clear()
        assert crypto.decrypt(token) == "synthetic check"
        assert crypto.encrypt("second synthetic check") != token
        assert key.read_bytes() == before
        result = run_ps(tmp_path, ACL_READER + f"""
@{{ user=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;
   key=Read-TestAcl {ps_literal(key)} }} | ConvertTo-Json -Depth 8 -Compress
""")
        assert {entry["sid"] for entry in result["key"]["entries"]} == {result["user"], "S-1-5-18"}
    finally:
        crypto._fernet.cache_clear()

def test_installer_preflight_applies_private_root_before_creating_application_tree(tmp_path):
    source = (ROOT / "deploy/windows/install.ps1").read_text(encoding="utf-8")
    protect = source[source.index("function Protect-Path"):source.index("function New-Secret")]
    preflight = source[source.index("# Verify all files and required payloads"):source.index("# ---------------------------------------------------------------- 1.")]
    media = tmp_path / "media"
    scripts = media / "app/deploy/windows"
    scripts.mkdir(parents=True)
    (scripts / "install-paths.ps1").write_bytes(HELPER.read_bytes())
    (media / "verify-bundle.ps1").write_text("param([string]$BundleDir)\n", encoding="utf-8")
    target = tmp_path / "new-install"
    body = ACL_READER + f"""
$BundleDir={ps_literal(media)}; $InstallRoot={ps_literal(target)}
$NoAdmin=$true; $DevNoAcl=$false
$me=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$PostgresPort=25432; $OpenSearchPort=29200; $OpenSearchTransportPort=29300; $Port=28443
$wide=[IO.Directory]::GetAccessControl({ps_literal(tmp_path)}, [Security.AccessControl.AccessControlSections]::Access)
$wide.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
    (New-Object Security.Principal.SecurityIdentifier('S-1-5-11')),
    'Modify','ContainerInherit,ObjectInherit','None','Allow')))
[IO.Directory]::SetAccessControl({ps_literal(tmp_path)}, $wide)
{protect}
{preflight}
$null=New-Item -ItemType Directory -Path (Join-Path $InstallRoot 'app/var')
@{{ root=Read-TestAcl $InstallRoot; app=Read-TestAcl (Join-Path $InstallRoot 'app/var');
   user=$me }} | ConvertTo-Json -Depth 8 -Compress
"""
    result = run_ps(tmp_path, body)
    assert result["root"]["protected"]
    expected = {result["user"], "S-1-5-18"}
    assert {row["sid"] for row in result["root"]["entries"]} == expected
    assert {row["sid"] for row in result["app"]["entries"]} == expected

def test_untrusted_owner_on_empty_root_is_rejected_before_acl_change(tmp_path):
    media = tmp_path / "media"
    media.mkdir()
    target = tmp_path / "existing-empty"
    target.mkdir()
    result = run_ps(tmp_path, f"""
$root={ps_literal(target)}
$before=(Get-Acl -LiteralPath $root).Sddl
# Inject only owner metadata: taking ownership requires privileges absent in this test.
function Get-SawDirectoryOwnerSid([string]$Path) {{ return 'S-1-5-21-101-202-303-1001' }}
$rejected=$false
try {{ $null=Initialize-SawInstallRoot -InstallRoot $root -BundleDir {ps_literal(media)} -NoAdmin }}
catch {{ $rejected=$true }}
@{{ rejected=$rejected; unchanged=((Get-Acl -LiteralPath $root).Sddl -ceq $before);
   children=@(Get-ChildItem -LiteralPath $root -Force).Count }} | ConvertTo-Json -Compress
""")
    assert result == {"rejected": True, "unchanged": True, "children": 0}
