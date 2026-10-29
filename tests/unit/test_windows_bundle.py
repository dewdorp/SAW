"""Windows air-gapped bundle: the pinned runtime closure must contain everything the profile needs."""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _pins() -> dict[str, str]:
    out = {}
    for line in (ROOT / "deploy/windows/requirements.txt").read_text(encoding="utf-8").splitlines():
        m = re.match(r"^([A-Za-z0-9_.\-]+)==([^\s#]+)", line)
        if m:
            out[m.group(1).lower().replace("_", "-")] = m.group(2)
    return out


def test_windows_extra_is_fully_pinned_including_psycopg_binary():
    """psycopg[binary] needs the separate psycopg-binary distribution (bundled libpq); without it the service cannot
    reach PostgreSQL because the PostgreSQL bin folder is not on PATH (regression found in the -NoAdmin install)."""
    pins = _pins()
    extra = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["optional-dependencies"]
    for req in extra["windows"]:
        name = re.split(r"[\[<>=]", req)[0].lower()
        assert name in pins, f"{name} missing from deploy/windows/requirements.txt"
        if "[binary]" in req:
            assert pins.get(f"{name}-binary") == pins[name], f"{name}-binary must be pinned to {pins[name]}"


def test_service_and_user_mode_scripts_bind_as_configured():
    xml = (ROOT / "deploy/windows/saw-service.xml").read_text(encoding="utf-8")
    assert "--host {{HOST}}" in xml
    ctl = (ROOT / "deploy/windows/saw-ctl.ps1").read_bytes()
    assert ctl.startswith(b"\xef\xbb\xbf"), "saw-ctl.ps1 contains Korean text: PowerShell 5.1 needs a UTF-8 BOM"
    assert b"--host 127.0.0.1" in ctl


def _ps_block(script: str, start: str, end: str) -> str:
    """Lines of an installer script from the one containing `start` to the one containing `end` (inclusive)."""
    lines = (ROOT / "deploy/windows" / script).read_text(encoding="utf-8-sig").splitlines()
    a = next(i for i, ln in enumerate(lines) if start in ln)
    b = next(i for i, ln in enumerate(lines) if end in ln and i >= a)
    return "\n".join(lines[a:b + 1])


def _run_ps(tmp_path, body: str) -> str:
    import subprocess

    script = tmp_path / "t.ps1"
    script.write_bytes(b"\xef\xbb\xbf" + ('$ErrorActionPreference = "Stop"\n' + body).encode("utf-8"))
    r = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "RemoteSigned", "-File", str(script)],
                       capture_output=True, timeout=120)
    assert r.returncode == 0, (r.stdout + r.stderr).decode("utf-8", "replace")
    return r.stdout.decode("utf-8", "replace")


WINDOWS_ONLY = __import__("pytest").mark.skipif(__import__("os").name != "nt", reason="runs the installer's PowerShell code")


@WINDOWS_ONLY
def test_service_definition_survives_ampersand_and_korean_in_the_install_folder(tmp_path):
    """Regression (comparison review): a folder named "SOC & Hunt" made saw-service.xml invalid, so the service could not load."""
    import xml.etree.ElementTree as ET

    root = "C:\\SOC & 관제 <1>\\SAW"
    out = tmp_path / "saw-service.xml"
    body = "\n".join([
        _ps_block("install.ps1", "function Write-Utf8", "}"),
        f"$InstallRoot = '{root}'; $Port = 8443; $bindHost = '0.0.0.0'; $xml = '{out}'",
        f"$tmpl = Get-Content '{ROOT / 'deploy/windows/saw-service.xml'}' -Raw",
        _ps_block("install.ps1", "$rootXml = ", "Out-Null"),
    ])
    _run_ps(tmp_path, body)
    raw = out.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf")
    svc = ET.fromstring(raw.decode("utf-8"))
    assert svc.findtext("executable") == root + "\\venv\\Scripts\\python.exe"
    assert f'--cert "{root}\\tls\\saw.crt"' in svc.findtext("arguments") and "--port 8443" in svc.findtext("arguments")
    assert svc.findtext("workingdirectory") == root + "\\app"


@WINDOWS_ONLY
def test_env_file_keeps_korean_paths_and_the_application_reads_them(tmp_path):
    """Regression (comparison review): .env was written as ASCII, turning a Korean data folder into question marks."""
    from pydantic_settings import BaseSettings, SettingsConfigDict

    from saw.config import Settings

    env = tmp_path / ".env"
    body = "\n".join([
        _ps_block("install.ps1", "function Write-Utf8", "}"),
        f"Write-Utf8 '{env}' @('# comment', 'SAW_DATA_DIR=D:\\보안관제 & SAW\\data', 'SAW_OPENSEARCH_DURABILITY=request')",
    ])
    _run_ps(tmp_path, body)
    assert not env.read_bytes().startswith(b"\xef\xbb\xbf") and "보안관제".encode() in env.read_bytes()

    class Probe(BaseSettings):
        model_config = SettingsConfigDict(env_prefix="SAW_", env_file=str(env), extra="ignore",
                                          env_file_encoding=Settings.model_config["env_file_encoding"])
        data_dir: str = ""
        opensearch_durability: str = ""

    got = Probe()
    assert got.data_dir == "D:\\보안관제 & SAW\\data" and got.opensearch_durability == "request"
    env.write_bytes(b"\xef\xbb\xbf" + env.read_bytes())            # a file saved by Notepad (with a byte-order mark)
    assert Probe().data_dir == "D:\\보안관제 & SAW\\data"


def test_installer_writes_path_files_as_utf8_and_refuses_unsafe_folder_names():
    inst = (ROOT / "deploy/windows/install.ps1").read_text(encoding="utf-8-sig")
    assert "Write-Utf8 $envFile $cfg" in inst and "SecurityElement]::Escape($InstallRoot)" in inst
    assert "Set-Content -Path $envFile" not in inst and "Set-Content -Path $xml" not in inst
    assert "if ($InstallRoot -match" in inst
    osx = (ROOT / "deploy/windows/setup-opensearch.ps1").read_text(encoding="utf-8-sig")
    assert 'opensearch.yml") -Value $yml -Encoding ASCII' not in osx and "UTF8Encoding $false" in osx


def test_shared_server_install_stores_every_batch_before_acknowledging():
    from saw.config import Settings
    from saw.storage.opensearch_store import index_template

    inst = (ROOT / "deploy/windows/install.ps1").read_text(encoding="utf-8-sig")
    assert "SAW_OPENSEARCH_DURABILITY=request" in inst
    assert "SAW_OPENSEARCH_DURABILITY=$(if" not in inst
    assert Settings.model_fields["opensearch_durability"].default == "request"
    assert index_template()["template"]["settings"]["translog"] == {"durability": "request"}
    assert index_template(durability="async")["template"]["settings"]["translog"]["durability"] == "async"

@WINDOWS_ONLY
def test_user_mode_health_uses_bundled_python_and_preserves_failure(tmp_path):
    text = (ROOT / "deploy/windows/saw-ctl.ps1").read_text(encoding="utf-8-sig")
    assert "curl.exe" not in text
    function = text[text.index("function Test-Up("):text.index("function Wait-Up(")]
    _run_ps(tmp_path, "\n".join([
        "$InstallRoot='C:\\synthetic'; $vpy='Invoke-MockRuntime'", function,
        "function Invoke-MockRuntime { $script:called=@($args); $global:LASTEXITCODE=$script:mockCode }",
        "$script:mockCode=1; if (Test-Up 'https://localhost:58443/api/v1/health') { throw 'failure accepted' }",
        "$script:mockCode=0; if (-not (Test-Up 'https://localhost:58443/api/v1/health')) { throw 'success rejected' }",
        "if ($script:called -notcontains 'api' -or $script:called -notcontains '--ca' -or $script:called -notcontains 58443) { throw 'TLS/port arguments lost' }",
        "if (-not (Test-Up 'http://127.0.0.1:59200/_cluster/health')) { throw 'search health rejected' }",
        "if ($script:called -notcontains 'opensearch' -or $script:called -contains '--ca') { throw 'search arguments wrong' }",
        "$vpy='missing-saw-python-xyz.exe'; if (Test-Up 'http://127.0.0.1:59200/_cluster/health') { throw 'missing runtime accepted' }",
    ]))

@WINDOWS_ONLY
def test_stop_keeps_store_running_if_flush_fails(tmp_path):
    text = (ROOT / "deploy/windows/saw-ctl.ps1").read_text(encoding="utf-8-sig")
    function = text[text.index("function Stop-All"):text.index("function Show-Status")]
    body = "\n".join([
        "$vpy='Invoke-MockRuntime'; $cfg=@{opensearchPort=59200}; $osUrl='http://localhost/_cluster/health'; $script:stopped=@()",
        "function Stop-Tracked($name) { $script:stopped += $name }",
        "function Get-Tracked($name) { return @{Id=123} }",
        "function Test-Up($url) { return $true }",
        "function Test-Pg { return $false }",
        "function Invoke-MockRuntime { $global:LASTEXITCODE=1 }", function,
        "try { Stop-All; throw 'flush was not attempted' } catch { if ($_.Exception.Message -notmatch 'flush failed') { throw } }",
        "if ($script:stopped.Count -ne 1 -or $script:stopped[0] -ne 'saw') { throw 'store was stopped after failed flush' }",
    ])
    _run_ps(tmp_path, body)

@WINDOWS_ONLY
def test_user_health_handles_unavailable_port_and_actual_http_503(tmp_path):
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(503)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    text = (ROOT / 'deploy/windows/saw-ctl.ps1').read_text(encoding='utf-8-sig')
    function = text[text.index('function Test-Up('):text.index('function Wait-Up(')]
    try:
        _run_ps(tmp_path, '\n'.join([
            f"$InstallRoot = '{tmp_path}'; $vpy = '{__import__('sys').executable}'", function,
            f"if (Test-Up 'http://127.0.0.1:{server.server_port}/_cluster/health') {{ throw '503 accepted' }}",
            "if (Test-Up 'http://127.0.0.1:1/_cluster/health') { throw 'unavailable listener accepted' }",
        ]))
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=3)

@WINDOWS_ONLY
def test_stop_does_not_flush_or_kill_a_tracked_unhealthy_store(tmp_path):
    text = (ROOT / 'deploy/windows/saw-ctl.ps1').read_text(encoding='utf-8-sig')
    function = text[text.index('function Stop-All'):text.index('function Show-Status')]
    _run_ps(tmp_path, '\n'.join([
        "$vpy='Invoke-MockRuntime'; $cfg=@{opensearchPort=59200}; $osUrl='http://localhost/_cluster/health'; $script:stopped=@()",
        "function Stop-Tracked($name) { $script:stopped += $name }",
        "function Get-Tracked($name) { return @{Id=123} }",
        "function Test-Up($url) { return $false }",
        "function Test-Pg { return $false }",
        "function Invoke-MockRuntime { throw 'unhealthy store flush was attempted' }", function,
        "try { Stop-All; throw 'unhealthy store was stopped' } catch { if ($_.Exception.Message -notmatch 'OpenSearch is unhealthy') { throw } }",
        "if ($script:stopped.Count -ne 1 -or $script:stopped[0] -ne 'saw') { throw 'store was stopped' }",
    ]))


@WINDOWS_ONLY
def test_postgresql_service_xml_preserves_identity_stop_and_private_path(tmp_path):
    """The service child must inherit its bundled runtime explicitly, not the installer's PATH."""
    import xml.etree.ElementTree as ET

    text = (ROOT / 'deploy/windows/setup-postgresql.ps1').read_text(encoding='utf-8-sig')
    assert 'function Write-PostgresqlServiceXml(' in text, 'PostgreSQL needs an explicit service child environment'
    function = text[text.index('function Write-PostgresqlServiceXml('):text.index('# END PostgreSQL XML renderer')]
    root = r'C:\SOC & 관제 <1>\SAW'
    runtime = root + r'\opensearch-2.19.6\jdk\bin'
    child_path = runtime + r';C:\Windows\System32;C:\Windows'
    out = tmp_path / 'postgresql-service.xml'
    _run_ps(tmp_path, '\n'.join([
        function,
        f"Write-PostgresqlServiceXml '{ROOT / 'deploy/windows/postgresql-service.xml'}' '{out}' '{root}' 'saw-postgresql' '{child_path}'",
    ]))
    raw = out.read_bytes()
    assert not raw.startswith(b'\xef\xbb\xbf')
    svc = ET.fromstring(raw)
    assert svc.findtext('executable') == root + r'\pgsql\bin\postgres.exe'
    assert svc.findtext('startarguments') == f'-D "{root}\\data\\postgresql"'
    assert svc.find('arguments') is None
    assert svc.findtext('stopexecutable') == root + r'\pgsql\bin\pg_ctl.exe'
    assert svc.findtext('stoparguments') == f'stop -D "{root}\\data\\postgresql" -m fast -w -t 120'
    assert svc.findtext('stoptimeout') == '150 sec'
    assert svc.findtext('serviceaccount/domain') == 'NT AUTHORITY'
    assert svc.findtext('serviceaccount/user') == 'NetworkService'
    assert svc.find('serviceaccount/password') is None
    assert svc.find("env[@name='PATH']").get('value') == child_path
    assert '%PATH%' not in raw.decode('utf-8')


@WINDOWS_ONLY
def test_postgresql_service_reinstall_refuses_running_or_unowned_registration(tmp_path):
    text = (ROOT / 'deploy/windows/setup-postgresql.ps1').read_text(encoding='utf-8-sig')
    assert 'function Get-PostgresqlServiceAction(' in text, 'Existing service identity must be checked before migration'
    function = text[text.index('function Get-PostgresqlServiceAction('):text.index('# END PostgreSQL registration classifier')]
    _run_ps(tmp_path, '\n'.join([
        function,
        r"$exe='C:\SAW\service\saw-postgresql.exe'; $ctl='C:\SAW\pgsql\bin\pg_ctl.exe'; $data='C:\SAW\data\postgresql'",
        "$r=Get-PostgresqlServiceAction $null $exe $ctl $data; if ($r -ne 'create') { throw 'new service rejected' }",
        "$svc=@{PathName='\"'+$exe+'\"'; State='Stopped'; StartName='NT AUTHORITY\\NetworkService'}",
        "$r=Get-PostgresqlServiceAction $svc $exe $ctl $data; if ($r -ne 'reuse') { throw 'owned wrapper rejected' }",
        "$svc.PathName='\"'+$ctl+'\" runservice -N saw-postgresql -D \"'+$data+'\" -w'; $r=Get-PostgresqlServiceAction $svc $exe $ctl $data; if ($r -ne 'migrate') { throw 'legacy stopped service rejected' }",
        "$svc.State='Running'; try { Get-PostgresqlServiceAction $svc $exe $ctl $data; throw 'accepted' } catch { if ($_.Exception.Message -notmatch 'must be stopped') { throw } }",
        "$svc.State='Stopped'; $svc.PathName='\"C:\\other\\pg_ctl.exe\" runservice -D \"'+$data+'\"'; try { Get-PostgresqlServiceAction $svc $exe $ctl $data; throw 'accepted' } catch { if ($_.Exception.Message -notmatch 'Unrecognized PostgreSQL service') { throw } }",
        "$svc.PathName='\"'+$ctl+'\" runservice -D \"C:\\other\\data\"'; try { Get-PostgresqlServiceAction $svc $exe $ctl $data; throw 'accepted' } catch { if ($_.Exception.Message -notmatch 'Unrecognized PostgreSQL service') { throw } }",
        "$svc.PathName='\"'+$exe+'\"'; $svc.StartName='LocalSystem'; try { Get-PostgresqlServiceAction $svc $exe $ctl $data; throw 'accepted' } catch { if ($_.Exception.Message -notmatch 'NetworkService identity required') { throw } }",
    ]))


@WINDOWS_ONLY
def test_postgresql_uninstall_uses_wrapper_and_refuses_unknown_service(tmp_path):
    text = (ROOT / 'deploy/windows/uninstall.ps1').read_text(encoding='utf-8-sig')
    assert 'function Remove-PostgresqlService(' in text, 'Uninstall must recognize the WinSW PostgreSQL registration'
    function = text[text.index('function Remove-PostgresqlService('):text.index('# END PostgreSQL service removal')]
    _run_ps(tmp_path, '\n'.join([
        function,
        r'''$InstallRoot='C:\SAW'; $script:service=@{PathName='"C:\SAW\service\saw-postgresql.exe"'; State='Running'}; $script:calls=@()''',
        "function Get-CimInstance { return $script:service }",
        "function Invoke-PostgresqlServiceCommand($exe, $verb) { $script:calls += $verb }",
        "Remove-PostgresqlService $InstallRoot; if (($script:calls -join ',') -ne 'stop,uninstall') { throw 'wrong wrapper removal sequence' }",
        r'''$script:service.PathName='"C:\foreign\service.exe"'; $script:calls=@()''',
        "try { Remove-PostgresqlService $InstallRoot; throw 'accepted' } catch { if ($_.Exception.Message -notmatch 'Unrecognized PostgreSQL service') { throw } }; if ($script:calls.Count) { throw 'unowned service modified' }",
    ]))


@WINDOWS_ONLY
def test_postgresql_service_waits_for_database_readiness_after_scm_start(tmp_path):
    text = (ROOT / 'deploy/windows/setup-postgresql.ps1').read_text(encoding='utf-8-sig')
    assert 'function Wait-PostgresqlServiceReady(' in text, 'SCM Running does not mean PostgreSQL accepts connections'
    function = text[text.index('function Wait-PostgresqlServiceReady('):text.index('# END PostgreSQL readiness')]
    # Fake executables only: no database, SCM, ACL, service registration or administrator operation.
    ready = tmp_path / 'pg_isready.ps1'
    ready.write_text("$global:probeTries += 1; $global:LASTEXITCODE = $(if ($global:probeTries -ge 3) { 0 } else { 1 })", encoding='utf-8')
    _run_ps(tmp_path, '\n'.join([
        function,
        '$global:probeTries=0',
        'function Start-Sleep { }',
        f"Wait-PostgresqlServiceReady '{ready}' 5432 3",
        "if ($global:probeTries -ne 3) { throw 'startup returned before database readiness' }",
        '$global:probeTries=0',
        f"try {{ Wait-PostgresqlServiceReady '{ready}' 5432 2; throw 'accepted' }} catch {{ if ($_.Exception.Message -notmatch 'readiness deadline') {{ throw }} }}",
    ]))


@WINDOWS_ONLY
def test_service_health_uses_verified_hostname_and_bundle_ca(tmp_path):
    text = (ROOT / "deploy/windows/install.ps1").read_text(encoding="utf-8-sig")
    assert "curl.exe" not in text
    block = _ps_block("install.ps1", 'Step "Health check"', "Write-Host $r")
    _run_ps(tmp_path, "\n".join([
        "$vpy='Invoke-MockRuntime'; $Port=58443; $HostName='saw.example.invalid'; $crt='C:\\test.crt'; $dirs=@{logs='logs'}",
        "function Step { }; function Start-Sleep { }",
        "function Invoke-MockRuntime { $script:called=@($args); $global:LASTEXITCODE=0; return 'ok' }", block,
        "if ($script:called -notcontains '--tls-name' -or $script:called -notcontains $HostName -or $script:called -notcontains '--ca' -or $script:called -notcontains $crt) { throw 'TLS identity lost' }",
        "function Invoke-MockRuntime { $global:LASTEXITCODE=1; return 'failed' }",
        "try { " + block + "; throw 'failed health accepted' } catch { if ($_.Exception.Message -notmatch 'did not become healthy') { throw } }",
    ]))
