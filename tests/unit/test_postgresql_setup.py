"""PostgreSQL setup must resume without reinitializing or exposing credentials."""
from pathlib import Path
import json
import os
import subprocess
import pytest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "deploy/windows/setup-postgresql-state.ps1"
pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell and ACL contract")

def q(value):
    return "'" + str(value).replace("'", "''") + "'"

def run_ps(tmp_path, body, timeout=90):
    assert HELPER.is_file(), "PostgreSQL resume/ACL helper missing"
    path=tmp_path / "postgresql-probe.ps1"
    path.write_text("$ErrorActionPreference='Stop'\n$env:PSModulePath=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/Modules'\n[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)\n. " + q(HELPER) + "\n" + body, encoding="utf-8-sig")
    done=subprocess.run(["powershell.exe","-NoProfile","-ExecutionPolicy","Bypass","-File",str(path)],capture_output=True,timeout=timeout)
    assert done.returncode == 0, (done.stdout+done.stderr).decode("utf-8","replace")
    return json.loads(done.stdout.decode("utf-8-sig"))

@pytest.mark.parametrize("kind", ["empty","marker_only","wrong_version","unknown"])
def test_cluster_state_does_not_trust_version_marker(tmp_path,kind):
    data=tmp_path/"data"; data.mkdir()
    if kind in {"marker_only","wrong_version"}:
        (data/"PG_VERSION").write_text("16" if kind=="marker_only" else "15")
    if kind=="unknown": (data/"customer.txt").write_text("keep")
    r=run_ps(tmp_path,f"""
$rejected=$false; $state=$null
try {{ $state=Get-SawPostgresqlClusterState {q(data)} {q(tmp_path/"bin")} }}
catch {{ $rejected=$true }}
@{{ state=$state; rejected=$rejected }} | ConvertTo-Json -Compress
""")
    assert r["rejected"] == (kind!="empty")
    if kind=="empty": assert r["state"]=="fresh"
    if kind=="unknown": assert (data/"customer.txt").read_text()=="keep"

def test_temporary_password_access_is_scoped_and_restored_on_failure(tmp_path):
    root=tmp_path/"install"; (root/"secrets").mkdir(parents=True)
    secret=root/"secrets"/"postgres-superuser.pw"; secret.write_text("synthetic-test-only")
    other=root/"secrets"/"untouched.pw"; other.write_text("synthetic-other-only")
    r=run_ps(tmp_path,f"""
$root={q(root)}; $secret={q(secret)}; $other={q(other)}
$before=(Get-Acl -LiteralPath $secret).Sddl; $otherBefore=(Get-Acl -LiteralPath $other).Sddl
$directoryBefore=(Get-Acl -LiteralPath (Split-Path $secret)).Sddl
$failed=$false
try {{ Invoke-SawPostgresqlPasswordAccess $root $secret {{ throw 'synthetic process failure' }} }}
catch {{ $failed=$_.Exception.Message -match 'synthetic process failure' }}
@{{ failed=$failed; restored=((Get-Acl -LiteralPath $secret).Sddl -ceq $before);
    directoryRestored=((Get-Acl -LiteralPath (Split-Path $secret)).Sddl -ceq $directoryBefore);
    otherUnchanged=((Get-Acl -LiteralPath $other).Sddl -ceq $otherBefore) }} | ConvertTo-Json -Compress
""")
    assert r["failed"] and r["restored"] and r["directoryRestored"] and r["otherUnchanged"], r

def test_pg_service_same_root_running_is_reused(tmp_path):
    source=(ROOT/"deploy/windows/setup-postgresql.ps1").read_text(encoding="utf-8-sig")
    func=source[source.index("function Get-PostgresqlServiceAction("):source.index("# END PostgreSQL registration classifier")]
    r=run_ps(tmp_path,func+r"""
$existing=@{State='Running';StartName='NT AUTHORITY\NetworkService';PathName='"C:\SAW\service\saw-postgresql.exe"'}
$action=Get-PostgresqlServiceAction $existing 'C:\SAW\service\saw-postgresql.exe' 'C:\SAW\pgsql\bin\pg_ctl.exe' 'C:\SAW\data\postgresql'
@{action=$action} | ConvertTo-Json -Compress
""")
    assert r["action"]=="reuse"

def test_bootstrap_does_not_put_password_in_command_line():
    source=(ROOT/"deploy/windows/setup-postgresql.ps1").read_text(encoding="utf-8-sig")
    assert '-c "CREATE ROLE saw LOGIN PASSWORD' not in source
    assert "Invoke-SawPostgresqlSql" in source

NATIVE_ROOT = os.environ.get("PG_NATIVE_TEST_ROOT")

@pytest.mark.skipif(not NATIVE_ROOT, reason="explicit isolated PostgreSQL binary directory required")
def test_native_initdb_ba_system_only_secret_and_exact_acl_restore(tmp_path):
    """Actual initdb must fail without SID read, then succeed via temporary grant."""
    native=Path(NATIVE_ROOT)
    bin_dir=native/"pgsql/bin"
    runtime=native/"opensearch-2.19.6/jdk/bin"
    assert (bin_dir/"initdb.exe").is_file()
    root=tmp_path/"SAW 한글 test"; root.mkdir()
    secret_dir=root/"secrets"; secret_dir.mkdir()
    secret=secret_dir/"postgres-superuser.pw"
    secret.write_text(os.urandom(24).hex(),encoding="ascii")
    other=secret_dir/"unrelated.pw"; other.write_text(os.urandom(24).hex(),encoding="ascii")
    result=run_ps(tmp_path, f"""
$root={q(root)}; $file={q(secret)}; $secrets={q(secret_dir)}; $bin={q(bin_dir)}
$env:PATH={q(runtime)}+';'+$env:SystemRoot+'\\System32;'+$env:SystemRoot
$original=(Get-Acl -LiteralPath $secrets).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
$acl=New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
foreach($s in @('S-1-5-18','S-1-5-32-544')) {{
 $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($s)),'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
}}
function Run-Native([string]$Data) {{
 $info=New-Object Diagnostics.ProcessStartInfo
 $info.FileName=Join-Path $bin 'initdb.exe'
 $info.Arguments='-D "'+$Data+'" -U postgres --pwfile="'+$file+'" -A scram-sha-256 -E UTF8 --locale=C'
 $info.UseShellExecute=$false; $info.CreateNoWindow=$true; $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
 $p=New-Object Diagnostics.Process; $p.StartInfo=$info; $null=$p.Start()
 $o=$p.StandardOutput.ReadToEndAsync(); $e=$p.StandardError.ReadToEndAsync()
 if(-not $p.WaitForExit(120000)) {{ $p.Kill(); throw 'native initdb timed out' }}
 $out=$o.GetAwaiter().GetResult(); $err=$e.GetAwaiter().GetResult()
 $r=@{{exit=$p.ExitCode; denied=($err -match 'Permission denied|권한|거부'); errorLength=$err.Length}}
 $p.Dispose(); return $r
}}
try {{
 [IO.Directory]::SetAccessControl($secrets,$acl)
 $before=[IO.File]::GetAccessControl($file,[Security.AccessControl.AccessControlSections]::Access).Sddl
 $dirBefore=[IO.Directory]::GetAccessControl($secrets,[Security.AccessControl.AccessControlSections]::Access).Sddl
 $otherBefore=[IO.File]::GetAccessControl({q(other)},[Security.AccessControl.AccessControlSections]::Access).Sddl
 $red=Run-Native (Join-Path $root 'red')
 # This host is not elevated: call the production ACL core on already known
 # synthetic paths (the full installer validates paths under its admin token).
 $green=Invoke-SawPostgresqlTemporaryAccess @(
   @{{Path=$secrets;Rights='Traverse';Inherit='None'}},
   @{{Path=$file;Rights='Read';Inherit='None'}}
 ) {{ Run-Native (Join-Path $root 'green') }}
 $state=Get-SawPostgresqlClusterState (Join-Path $root 'green') $bin
 $conf=Join-Path $root 'green\\postgresql.conf'
 $beforeConfig=[IO.File]::ReadAllText($conf); $wrongConfigRejected=$false
 try {{ Assert-SawPostgresqlClusterConfig (Join-Path $root 'green') $bin 55457 }}
 catch {{ $wrongConfigRejected=$_.Exception.Message -match 'existing configuration' }}
 $configPreserved=[IO.File]::ReadAllText($conf) -ceq $beforeConfig
 [IO.File]::AppendAllText($conf, ([Environment]::NewLine+"port = 55457"+[Environment]::NewLine+"listen_addresses = '127.0.0.1'"+[Environment]::NewLine+"password_encryption = scram-sha-256"+[Environment]::NewLine),[Text.Encoding]::ASCII)
 Assert-SawPostgresqlClusterConfig (Join-Path $root 'green') $bin 55457
 $configHash=(Get-FileHash -LiteralPath $conf -Algorithm SHA256).Hash
 $secondState=Get-SawPostgresqlClusterState (Join-Path $root 'green') $bin
 Assert-SawPostgresqlClusterConfig (Join-Path $root 'green') $bin 55457
 $unchangedAfterRepeat=(Get-FileHash -LiteralPath $conf -Algorithm SHA256).Hash -ceq $configHash
 @{{red=$red; green=$green; state=$state; wrongConfigRejected=$wrongConfigRejected; configPreserved=$configPreserved; repeatPreserved=$unchangedAfterRepeat; restored=([IO.File]::GetAccessControl($file,[Security.AccessControl.AccessControlSections]::Access).Sddl -ceq $before);
    directoryRestored=([IO.Directory]::GetAccessControl($secrets,[Security.AccessControl.AccessControlSections]::Access).Sddl -ceq $dirBefore);
    otherUnchanged=([IO.File]::GetAccessControl({q(other)},[Security.AccessControl.AccessControlSections]::Access).Sddl -ceq $otherBefore)}} | ConvertTo-Json -Depth 4 -Compress
}} finally {{ Restore-SawPostgresqlAccess $secrets $original $true }}
""",timeout=260)
    assert result["red"]["exit"] != 0 and result["red"]["denied"], result
    assert result["green"]["exit"] == 0 and result["state"] == "initialized", result
    assert result["restored"] and result["directoryRestored"] and result["otherUnchanged"], result
    assert result["wrongConfigRejected"] and result["configPreserved"] and result["repeatPreserved"], result

@pytest.mark.parametrize("case", ["foreign_wrapper", "foreign_xml", "valid_reuse"])
def test_service_files_are_preserved_or_rejected_before_overwrite(tmp_path, case):
    source=(ROOT/"deploy/windows/setup-postgresql.ps1").read_text(encoding="utf-8-sig")
    render=source[source.index("function Write-PostgresqlServiceXml("):source.index("# END PostgreSQL XML renderer")]
    exe=tmp_path/"service.exe"; exe.write_bytes(b"foreign" if case=="foreign_wrapper" else b"verified-wrapper")
    wrapper=tmp_path/"media.exe"; wrapper.write_bytes(b"verified-wrapper")
    xml=tmp_path/"service.xml"
    result=run_ps(tmp_path,render+f"""
$exe={q(exe)}; $xml={q(xml)}; $template={q(ROOT/"deploy/windows/postgresql-service.xml")}
Write-PostgresqlServiceXml $template $xml 'C:\\SAW' 'saw-postgresql' 'private-path'
if({q(case)} -eq 'foreign_xml') {{ [IO.File]::WriteAllText($xml,'<foreign/>') }}
$beforeExe=(Get-FileHash $exe).Hash; $beforeXml=(Get-FileHash $xml).Hash
$rejected=$false
try {{ Initialize-SawPostgresqlServiceFiles $exe $xml {q(wrapper)} $template 'C:\\SAW' 'saw-postgresql' 'private-path' }}
catch {{ $rejected=$true }}
@{{rejected=$rejected; unchanged=(((Get-FileHash $exe).Hash -ceq $beforeExe) -and ((Get-FileHash $xml).Hash -ceq $beforeXml))}} | ConvertTo-Json -Compress
""")
    assert result["rejected"] == (case!="valid_reuse"), result
    assert result["unchanged"]

@pytest.mark.skipif(not NATIVE_ROOT, reason="explicit isolated PostgreSQL binary directory required")
def test_native_initdb_success_already_has_selected_secure_configuration(tmp_path):
    """A crash immediately after initdb must not leave another port/default policy."""
    native=Path(NATIVE_ROOT)
    source=(ROOT/"deploy/windows/setup-postgresql.ps1").read_text(encoding="utf-8-sig")
    init=source[source.index("    $init = {"):source.index("    if ($DevNoAcl) { & $init }")]
    secret=tmp_path/"synthetic.pw";secret.write_text(os.urandom(24).hex(),encoding="ascii")
    root=tmp_path/"new selected root";root.mkdir()
    data=root/"data"
    result=run_ps(tmp_path,f"""
$env:PATH={q(native/"opensearch-2.19.6/jdk/bin")}+';'+$env:SystemRoot+'\\System32;'+$env:SystemRoot
$bin={q(native/"pgsql/bin")};$data={q(data)};$suFile={q(secret)};$Port=55457;$SharedBuffers='128MB'
{init}
$null=& $init
Assert-SawPostgresqlClusterConfig $data $bin $Port
@{{state=(Get-SawPostgresqlClusterState $data $bin)}} | ConvertTo-Json -Compress
""",timeout=200)
    assert result["state"]=="initialized"


@pytest.mark.skipif(not NATIVE_ROOT, reason="explicit isolated PostgreSQL binary directory required")
def test_native_initdb_with_korean_runtime_share_and_data_paths(tmp_path):
    """Exercise the entire runtime in Korean paths, not just a Korean PGDATA."""
    import shutil
    native=Path(NATIVE_ROOT)
    root=tmp_path/"SAW 관제 runtime"
    for name in ("bin","lib","share"):
        shutil.copytree(native/"pgsql"/name,root/"pgsql"/name)
    secret=root/"synthetic.pw";secret.write_text(os.urandom(24).hex(),encoding="ascii")
    data=root/"data"/"postgresql"
    data.parent.mkdir()
    source=(ROOT/"deploy/windows/setup-postgresql.ps1").read_text(encoding="utf-8-sig")
    init=source[source.index("    $init = {"):source.index("    if ($DevNoAcl) { & $init }")]
    import socket
    with socket.socket() as listener:
        listener.bind(("127.0.0.1",0));port=listener.getsockname()[1]
    result=run_ps(tmp_path,f"""
$env:PATH={q(native/"opensearch-2.19.6/jdk/bin")}+';'+$env:SystemRoot+'\\System32;'+$env:SystemRoot
$bin={q(root/"pgsql/bin")};$data={q(data)};$suFile={q(secret)};$Port={port};$SharedBuffers='128MB'
{init}
$null=& $init
Assert-SawPostgresqlClusterConfig $data $bin $Port
$conf=[IO.File]::ReadAllText((Join-Path $data 'postgresql.conf'))
$info=New-Object Diagnostics.ProcessStartInfo
$info.FileName=Join-Path $bin 'postgres.exe'
$info.Arguments='--single -D "'+$data+'" postgres'
$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardInput=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
$p=New-Object Diagnostics.Process;$p.StartInfo=$info;$null=$p.Start()
$o=$p.StandardOutput.ReadToEndAsync();$e=$p.StandardError.ReadToEndAsync()
$p.StandardInput.WriteLine("SELECT count(*) FROM pg_proc WHERE prosrc LIKE '%SAWPG-%' OR probin LIKE '%SAWPG-%';")
$p.StandardInput.WriteLine("SELECT count(*) FROM pg_settings WHERE setting LIKE '%SAWPG-%';")
$p.StandardInput.WriteLine("SELECT count(*) FROM pg_db_role_setting WHERE setconfig::text LIKE '%SAWPG-%';")
$p.StandardInput.Close()
if(-not $p.WaitForExit(60000)) {{$p.Kill();throw 'catalog readback timed out'}}
$output=$o.GetAwaiter().GetResult();$null=$e.GetAwaiter().GetResult();$exit=$p.ExitCode;$p.Dispose()
if($exit -ne 0) {{throw 'catalog readback failed'}}
$ctl=Join-Path $bin 'pg_ctl.exe'
$started=$false;$pathMatches=$false;$koreanRoundtrip=$false
try {{
 $process=Start-Process -FilePath $ctl -WindowStyle Hidden -PassThru -ArgumentList ('start -w -t 45 -D "'+$data+'" -l "'+{q(root/"native.log")}+'"')
 $null=$process.Handle;$process.WaitForExit()
 if($process.ExitCode -ne 0) {{throw 'native PostgreSQL start failed'}}
 $started=$true
 $password=[IO.File]::ReadAllText($suFile)
 $env:PGCLIENTENCODING='WIN949'
 $actual=Get-SawPostgresqlDataDirectory (Join-Path $bin 'psql.exe') $Port $password
 $pathMatches=[IO.Path]::GetFullPath($actual) -ieq [IO.Path]::GetFullPath($data)
 $roundtrip=Invoke-SawPostgresqlSql (Join-Path $bin 'psql.exe') $Port 'postgres' 'postgres' $password "CREATE TEMP TABLE saw_utf8_probe(value text); INSERT INTO saw_utf8_probe VALUES ('한글 관제 보안'); SELECT value FROM saw_utf8_probe;"
 $koreanRoundtrip=$roundtrip -ceq '한글 관제 보안'
}} finally {{
 if($started) {{ & $ctl stop -D $data -m fast -w -t 45 *> $null; if($LASTEXITCODE -ne 0) {{throw 'native PostgreSQL stop failed'}} }}
 $password=$null
}}
@{{state=(Get-SawPostgresqlClusterState $data $bin); configClean=($conf -notmatch 'SAWPG-'); zeroCounts=([regex]::Matches($output,'count = "0"')).Count; pathMatches=$pathMatches; koreanRoundtrip=$koreanRoundtrip}} | ConvertTo-Json -Compress
""",timeout=200)
    assert result["state"]=="initialized"
    assert result["configClean"] and result["zeroCounts"]==3, result
    assert result["pathMatches"] and result["koreanRoundtrip"], result


def test_initdb_input_alias_is_scoped_and_removed_on_failure(tmp_path):
    root=tmp_path/"관제 runtime"
    (root/"pgsql/bin").mkdir(parents=True)
    (root/"pgsql/share").mkdir()
    sample=root/"pgsql/share/sql_features.txt";sample.write_text("synthetic fixture")
    result=run_ps(tmp_path,f"""
$script:aliasPath=$null; $failed=$false; $readable=$false
$shareAcl=(Get-Acl -LiteralPath {q(root/'pgsql/share')}).Sddl
$fileAcl=(Get-Acl -LiteralPath {q(sample)}).Sddl
try {{
 Invoke-SawPostgresqlInitInput {q(root/"pgsql/bin")} {{
   param($InputDirectory)
   $script:aliasPath=$InputDirectory
   $script:readable=[IO.File]::ReadAllText((Join-Path $InputDirectory 'sql_features.txt')) -ceq 'synthetic fixture'
   throw 'synthetic initdb error'
 }}
}} catch {{ $failed=$_.Exception.Message -eq 'synthetic initdb error' }}
@{{failed=$failed; readable=$script:readable; ascii=($script:aliasPath -notmatch '[^\x00-\x7F]'); removed=(-not [IO.File]::Exists((Join-Path $script:aliasPath 'sql_features.txt'))); original=([IO.File]::ReadAllText({q(sample)}) -ceq 'synthetic fixture'); aclUnchanged=(((Get-Acl -LiteralPath {q(root/'pgsql/share')}).Sddl -ceq $shareAcl) -and ((Get-Acl -LiteralPath {q(sample)}).Sddl -ceq $fileAcl))}} | ConvertTo-Json -Compress
""")
    assert result["failed"] and result["readable"] and result["ascii"] and result["removed"] and result["original"] and result["aclUnchanged"], result


def test_initdb_input_alias_conflict_preserves_existing_mapping(tmp_path):
    import uuid
    root=tmp_path/"관제 conflict"
    (root/"pgsql/bin").mkdir(parents=True);(root/"pgsql/share").mkdir()
    sample=root/"pgsql/share/sql_features.txt";sample.write_text("synthetic conflict")
    name="SAWPG-"+uuid.uuid4().hex
    source=HELPER.read_text(encoding="utf-8-sig")
    function=source[source.index("function Invoke-SawPostgresqlInitInput("):]
    function=function.replace("$name='SAWPG-'+[Guid]::NewGuid().ToString('N')","$name='"+name+"'")
    result=run_ps(tmp_path,f'''
Invoke-SawPostgresqlInitInput {q(root/"pgsql/bin")} {{ param($d) }}
$name={q(name)};$target='\\??\\'+{q(root/"pgsql/share")}
if(-not [SawPostgresqlInputNative]::DefineDosDevice(9,$name,$target)) {{throw 'test mapping failed'}}
try {{
 {function}
 $rejected=$false
 try {{ Invoke-SawPostgresqlInitInput {q(root/"pgsql/bin")} {{throw 'must not execute'}} }}
 catch {{$rejected=$_.Exception.Message -match 'alias conflicts'}}
 $actual=New-Object Text.StringBuilder 32768
 $exists=[SawPostgresqlInputNative]::QueryDosDevice($name,$actual,$actual.Capacity) -ne 0
 @{{rejected=$rejected; preserved=($exists -and $actual.ToString() -ceq $target)}} | ConvertTo-Json -Compress
}} finally {{ if(-not [SawPostgresqlInputNative]::DefineDosDevice(15,$name,$target)) {{throw 'test cleanup failed'}} }}
''')
    assert result["rejected"] and result["preserved"], result


def test_postgresql_native_path_uses_lossless_ansi_bytes(tmp_path):
    result=run_ps(tmp_path,r"""
$script:query=$null
$expected='C:\SAW '+[char]0xad00+[char]0xc81c+'\data\postgresql'
$script:hex=([BitConverter]::ToString([Text.Encoding]::Default.GetBytes($expected))).Replace('-','').ToLowerInvariant()
function Invoke-SawPostgresqlSql { param($Psql,$Port,$User,$Database,$Password,$Sql) $script:query=$Sql;return $script:hex }
$actual=Get-SawPostgresqlDataDirectory 'synthetic.exe' 55459 'not-a-real-password'
@{same=($actual -ceq $expected); bytes=($script:query -match 'textsend' -and $script:query -match 'hex')} | ConvertTo-Json -Compress
""")
    assert result["same"] and result["bytes"], result


def test_non_ascii_initdb_input_rejects_system_global_alias(tmp_path):
    root=tmp_path/"관제 system"
    (root/"pgsql/bin").mkdir(parents=True);(root/"pgsql/share").mkdir()
    source=HELPER.read_text(encoding="utf-8-sig")
    function=source[source.index("function Invoke-SawPostgresqlInitInput("):]
    function=function.replace("([Security.Principal.WindowsIdentity]::GetCurrent()).IsSystem","$true")
    result=run_ps(tmp_path,function+f"""
$rejected=$false
try {{Invoke-SawPostgresqlInitInput {q(root/"pgsql/bin")} {{throw 'must not execute'}}}}
catch {{$rejected=$_.Exception.Message -match 'LocalSystem'}}
@{{rejected=$rejected}} | ConvertTo-Json -Compress
""")
    assert result["rejected"]


@pytest.mark.parametrize(("config", "expected_ok"), [
    ("port = 55457\nlisten_addresses = '127.0.0.1'\npassword_encryption = scram-sha-256\n", True),
    ("port = 5432\nlisten_addresses = '127.0.0.1'\npassword_encryption = scram-sha-256\n", False),
    ("port = 55457\nport = 55457\nlisten_addresses = '127.0.0.1'\npassword_encryption = scram-sha-256\n", False),
    ("include = 'unsafe.conf'\nport = 55457\nlisten_addresses = '127.0.0.1'\npassword_encryption = scram-sha-256\n", False),
    ("port = 55457\nlisten_addresses = '*'\npassword_encryption = scram-sha-256\n", False),
])
def test_offline_pg_security_check_never_launches_admin_postgres(tmp_path, config, expected_ok):
    """Inspect only pinned config files before starting any service.

    No PostgreSQL executable exists at the supplied synthetic binary path,
    so this also guards against accidentally invoking postgres -C as admin.
    """
    cluster = tmp_path / "data"
    cluster.mkdir()
    (cluster / "postgresql.conf").write_text(config, encoding="ascii")
    (cluster / "pg_hba.conf").write_text(
        "host all all 127.0.0.1/32 scram-sha-256\n", encoding="ascii"
    )
    got = run_ps(tmp_path, f"""
$ok=$true;$reason=''
try {{ Assert-SawPostgresqlClusterConfig {q(cluster)} {q(tmp_path/"missing-bin")} 55457 }}
catch {{ $ok=$false; $reason=$_.Exception.Message }}
@{{ok=$ok;reason=$reason}} | ConvertTo-Json -Compress
""")
    assert got["ok"] is expected_ok, got


def test_postgresql_auto_conf_cannot_override_expected_security(tmp_path):
    cluster = tmp_path / "data"
    cluster.mkdir()
    (cluster / "postgresql.conf").write_text(
        "port=55457\nlisten_addresses='127.0.0.1'\npassword_encryption=scram-sha-256\n",
        encoding="ascii",
    )
    (cluster / "postgresql.auto.conf").write_text(
        "listen_addresses='*'\n", encoding="ascii",
    )
    (cluster / "pg_hba.conf").write_text(
        "host all all 127.0.0.1/32 scram-sha-256\n", encoding="ascii",
    )
    got = run_ps(tmp_path, f"""
$rejected=$false
try {{ Assert-SawPostgresqlClusterConfig {q(cluster)} {q(tmp_path/"missing-bin")} 55457 }}
catch {{ $rejected=$true }}
@{{rejected=$rejected}} | ConvertTo-Json -Compress
""")
    assert got["rejected"]
