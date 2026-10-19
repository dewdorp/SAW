"""Native PowerShell OpenSearch installer regressions; service mutation is stubbed."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import zipfile
import pytest

ROOT = Path(__file__).resolve().parents[2]
SETUP = ROOT / "deploy/windows/setup-opensearch.ps1"
pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell installer")

def literal(value):
    return "'" + str(value).replace("'", "''") + "'"

def run_ps(tmp_path, body):
    script = tmp_path / "probe.ps1"
    script.write_text(
        "$ErrorActionPreference='Stop'\n"
        "$env:PSModulePath=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/Modules'\n"
        "[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)\n" + body,
        encoding="utf-8-sig")
    result = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "RemoteSigned", "-File", str(script)],
                            capture_output=True, timeout=90)
    assert result.returncode == 0, (result.stdout + result.stderr).decode("utf-8", "replace")
    return json.loads(result.stdout.decode("utf-8-sig").strip().splitlines()[-1])

def fixture(tmp_path, *, missing=None):
    bundle = tmp_path / "media"
    (bundle / "opensearch").mkdir(parents=True)
    for name in ("opensearch-2.19.6-windows-x64.zip", "analysis-nori-2.19.6.zip"):
        (bundle / "opensearch" / name).touch()
    root = tmp_path / "보안 관제 & SAW"
    home = root / "opensearch-2.19.6"
    for name in ("bin", "config/jvm.options.d", "jdk/bin/server", "plugins/analysis-nori"):
        (home / name).mkdir(parents=True, exist_ok=True)
    for name in ("jdk/bin/java.exe", "jdk/bin/server/jvm.dll", "bin/opensearch-service-x64.exe"):
        if name != missing:
            (home / name).touch()
    (home / "plugins/analysis-nori/plugin-descriptor.properties").write_text("name=analysis-nori\nopensearch.version=2.19.6\n", encoding="ascii")
    (home / "jdk/release").write_text('JAVA_VERSION="21.0.11"\nOS_ARCH="x86_64"\n', encoding="ascii")
    (home / "bin/opensearch-service.bat").write_text("@exit /b 0\n", encoding="ascii")
    (home / "config/opensearch.yml").write_text(
        "# Managed by SAW deploy/windows/setup-opensearch.ps1\n"
        "cluster.name: saw\nnetwork.host: 127.0.0.1\nhttp.port: 9200\ntransport.port: 9300\n"
        f'path.data: "{(root / "data/opensearch").as_posix()}"\n'
        f'path.logs: "{(root / "logs/opensearch").as_posix()}"\n'
        "discovery.type: single-node\n# operator custom comment\n", encoding="utf-8")
    (home / "config/jvm.options.d/saw-heap.options").write_text("-Xms1g\n-Xmx1g\n# keep operator comment\n")
    (home / "lib").mkdir()
    (home / "lib/opensearch-2.19.6.jar").write_bytes(b"synthetic core engine")
    with zipfile.ZipFile(bundle / "opensearch/opensearch-2.19.6-windows-x64.zip", "w") as archive:
        for path in home.rglob("*"):
            if path.is_file():
                archive.write(path, path.relative_to(root).as_posix())
    return bundle, root, home

LOAD = f"""
$source=[IO.File]::ReadAllText({literal(SETUP)})
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
if($errors.Count) {{ throw 'PowerShell parse failure' }}
$functions=@($ast.FindAll({{ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }},$false))
foreach($fn in $functions) {{ . ([scriptblock]::Create($fn.Extent.Text)) }}
foreach($fn in ($functions | Sort-Object {{ $_.Extent.StartOffset }} -Descending)) {{
    $source=$source.Remove($fn.Extent.StartOffset,$fn.Extent.EndOffset-$fn.Extent.StartOffset)
}}
$source=$source.Substring($ast.ParamBlock.Extent.EndOffset)
"""

def setup_probe(tmp_path, *, initial="absent", registration="absent", missing=None, java_home="", preparing=False, policy="valid", pending=False, policy_effect=True, core=None):
    bundle, root, home = fixture(tmp_path, missing=missing)
    if core:
        target = home / "lib/opensearch-2.19.6.jar"
        if core == "missing": target.unlink()
        else: target.write_bytes(b"changed core engine")
    if preparing or pending:
        (root / "opensearch-setup-state.json").write_text(json.dumps({"schema": 1, "home": str(home), "version": "2.19.6", "configured": not preparing, "service_policy_pending": pending, "service_name": "saw-opensearch"}), encoding="utf-8")
    before = (home / "config/opensearch.yml").read_bytes()
    body = LOAD + f"""
$BundleDir={literal(bundle)}; $InstallRoot={literal(root)}; $HeapGB=1; $Port=9200; $TransportPort=9300
$ServiceName='saw-opensearch'; $NoService=$false; $UserMode=$false; $DevNoAcl=$true
$env:JAVA_HOME={literal(java_home)}; $env:OPENSEARCH_JAVA_HOME='unrelated-search-java'
$script:registered=$false; $script:started=0; $script:commands=@(); $script:recordCalls=0
$script:mode={literal(initial)}; $script:registration={literal(registration)}
$script:policy={literal(policy)}; $script:policyEffect={literal(str(policy_effect))}
function Get-Service {{ return $null }}
function Start-Service {{ $script:started++ }}
function sc.exe {{ $global:LASTEXITCODE=0 }}
function Get-SawOpenSearchServiceRecord([string]$Name) {{
    $script:recordCalls++
    if($script:mode -eq 'absent') {{ return $null }}
    $base={literal(home)}
    if($script:mode -eq 'foreign') {{ $base='D:\\other\\opensearch-2.19.6' }}
    return [pscustomobject]@{{ BinaryPath='"'+$base+'\\bin\\opensearch-service-x64.exe" //RS//saw-opensearch';
        Jvm=(Join-Path $base 'jdk/bin/server/jvm.dll'); WorkingPath=$base;
        Options=@(('-Dopensearch.path.home='+$base),('-Dopensearch.path.conf='+(Join-Path $base 'config')));
        State='Running' }}
}}
function Get-SawOpenSearchServicePolicy([string]$Name) {{
    return [pscustomobject]@{{ StartMode=$(if($script:policy -eq 'valid'){{'Auto'}}else{{'Manual'}});
        DelayedAutoStart=($script:policy -eq 'valid'); ResetPeriod=86400;
        Actions=@(@{{Type=1;Delay=60000}},@{{Type=1;Delay=60000}},@{{Type=1;Delay=300000}}) }}
}}
function Invoke-SawOpenSearchNative([string]$FilePath,[string[]]$Arguments,[hashtable]$Environment=@{{}}) {{
    if($FilePath -like '*sc.exe' -and $Arguments[0] -eq 'failure' -and $script:policyEffect -eq 'True') {{ $script:policy='valid' }}
    $script:commands+=@{{ file=$FilePath; args=@($Arguments); java=$Environment['JAVA_HOME']; osjava=$Environment['OPENSEARCH_JAVA_HOME']; startType=$Environment['OPENSEARCH_START_TYPE'] }}
    if($FilePath -like '*java.exe') {{
        return [pscustomobject]@{{ ExitCode=0; Output=(@('java.version = 21.0.11','sun.arch.data.model = 64','java.specification.version = 21') -join [Environment]::NewLine) }}
    }}
    if($FilePath -like '*opensearch-service.bat') {{
        $script:registered=$true
        if($script:registration -eq 'fail') {{ return [pscustomobject]@{{ExitCode=42;Output='synthetic registration failed'}} }}
        if($script:registration -eq 'valid') {{ $script:mode='valid' }}
    }}
    return [pscustomobject]@{{ ExitCode=0; Output='' }}
}}
$failure=$null
try {{ . ([scriptblock]::Create($source)) }} catch {{ $failure=$_.Exception.Message }}
@{{ failure=$failure; started=$script:started; registered=$script:registered; commands=@($script:commands);
    java=$env:JAVA_HOME; osjava=$env:OPENSEARCH_JAVA_HOME;
    pending=$(if(Test-Path -LiteralPath (Join-Path $InstallRoot 'opensearch-setup-state.json')) {{ ([IO.File]::ReadAllText((Join-Path $InstallRoot 'opensearch-setup-state.json'))|ConvertFrom-Json).service_policy_pending }} else {{ $false }}) }} | ConvertTo-Json -Depth 8 -Compress
"""
    result = run_ps(tmp_path, body)
    return result, before, (home / "config/opensearch.yml").read_bytes(), home

def test_zero_exit_registration_without_service_is_rejected_before_start(tmp_path):
    got, _, _, _ = setup_probe(tmp_path)
    assert got["failure"], "registration returned zero but no service exists"
    assert got["started"] == 0

@pytest.mark.parametrize("java_home", ["", r"C:\Other Product\Java"])
def test_dedicated_java_is_used_for_registration_without_mutating_parent_env(tmp_path, java_home):
    got, before, after, home = setup_probe(tmp_path, registration="valid", java_home=java_home)
    assert got["failure"] is None, got
    assert got["java"] == (java_home or None)
    assert got["osjava"] == "unrelated-search-java"
    register = [row for row in got["commands"] if row["file"].endswith("opensearch-service.bat")]
    assert len(register) == 1
    assert register[0]["java"] == register[0]["osjava"] == str(home / "jdk")
    assert before == after

@pytest.mark.parametrize("missing", ["jdk/bin/java.exe", "jdk/bin/server/jvm.dll"])
def test_missing_java_files_reject_before_register_and_start(tmp_path, missing):
    got, before, after, _ = setup_probe(tmp_path, missing=missing)
    assert got["failure"] and "Java" in got["failure"]
    assert not got["registered"] and got["started"] == 0
    assert before == after

def test_nonzero_service_registration_is_reported_and_never_started(tmp_path):
    got, _, _, _ = setup_probe(tmp_path, registration="fail")
    assert got["failure"] and "42" in got["failure"]
    assert got["started"] == 0

def test_correct_existing_service_reused_without_registration_or_restart(tmp_path):
    got, before, after, _ = setup_probe(tmp_path, initial="valid")
    assert got["failure"] is None, got
    assert not got["registered"] and got["started"] == 0
    assert not any(row["file"].endswith("sc.exe") for row in got["commands"])
    assert before == after

def test_foreign_same_named_service_rejected_without_changes(tmp_path):
    got, before, after, _ = setup_probe(tmp_path, initial="foreign")
    assert got["failure"] and "conflict" in got["failure"].lower()
    assert not got["registered"] and got["started"] == 0
    assert before == after

@pytest.mark.parametrize("property_name,value", [
    ("Jvm", r"C:\unrelated\jvm.dll"),
    ("WorkingPath", r"C:\elsewhere"),
    ("Options", ["-Dopensearch.path.home=C:\\other", "-Dopensearch.path.conf=C:\\other\\config"]),
    ("BinaryPath", r'"C:\elsewhere\service.exe" //RS//saw-opensearch'),
])
def test_persisted_service_registration_must_match_every_owned_path(tmp_path, property_name, value):
    body = LOAD + f"""
$base='D:\\SAW\\opensearch-2.19.6'
$record=[pscustomobject]@{{ BinaryPath='"'+$base+'\\bin\\opensearch-service-x64.exe" //RS//saw-opensearch';
    Jvm=$base+'\\jdk\\bin\\server\\jvm.dll'; WorkingPath=$base;
    Options=@(('-Dopensearch.path.home='+$base),('-Dopensearch.path.conf='+$base+'\\config')) }}
$record.{property_name}=({literal(json.dumps(value))}|ConvertFrom-Json)
$errorText=$null
try {{ Assert-SawOpenSearchService -Record $record -Name 'saw-opensearch' -OpenSearchHome $base -Jvm ($base+'\\jdk\\bin\\server\\jvm.dll') }}
catch {{ $errorText=$_.Exception.Message }}
@{{ failure=$errorText }}|ConvertTo-Json -Compress
"""
    got = run_ps(tmp_path, body)
    assert got["failure"] and "conflict" in got["failure"].lower()

@pytest.mark.parametrize("release,runtime,exit_code", [
    ('JAVA_VERSION="21.0.10"\nOS_ARCH="x86_64"\n', "java.version = 21.0.10\nsun.arch.data.model = 64\njava.specification.version = 21", 0),
    ('JAVA_VERSION="17.0.1"\nOS_ARCH="x86_64"\n', "java.version = 17.0.1", 0),
    ('JAVA_VERSION="21.0.11"\nOS_ARCH="x86_64"\n', "java.version = 21.0.11\nsun.arch.data.model = 32\njava.specification.version = 21", 0),
    ('JAVA_VERSION="21.0.11"\nOS_ARCH="x86_64"\n', "synthetic Java error", 9),
])
def test_java_probe_rejects_incompatible_or_failing_runtime(tmp_path, release, runtime, exit_code):
    _, _, home = fixture(tmp_path)
    (home / "jdk/release").write_text(release, encoding="ascii")
    body = LOAD + f"""
function Invoke-SawOpenSearchNative {{
    return [pscustomobject]@{{ExitCode={exit_code};Output={literal(runtime)}}}
}}
$failed=$false
try {{ $null=Get-SawOpenSearchJava -OpenSearchHome {literal(home)} -Version '2.19.6' }} catch {{ $failed=$true }}
@{{ failed=$failed }}|ConvertTo-Json -Compress
"""
    assert run_ps(tmp_path, body)["failed"]

def test_native_child_receives_isolated_environment_and_keeps_exit_code(tmp_path):
    child = tmp_path / "보안 테스트 & child.ps1"
    child.write_text(
        "[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)\n"
        "@{java=$env:JAVA_HOME;osjava=$env:OPENSEARCH_JAVA_HOME;opt=$env:JAVA_TOOL_OPTIONS;"
        "path=$args[0]}|ConvertTo-Json -Compress\nexit 7\n", encoding="utf-8-sig")
    path_argument = str(tmp_path / "한글 경로 & keep")
    body = LOAD + f"""
$env:JAVA_HOME='original-java'; $env:OPENSEARCH_JAVA_HOME='original-search'; $env:JAVA_TOOL_OPTIONS='unrelated'
$result=Invoke-SawOpenSearchNative -FilePath (Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe') -Arguments @('-NoProfile','-File',{literal(child)},{literal(path_argument)}) -Environment @{{ JAVA_HOME='bundled-java'; OPENSEARCH_JAVA_HOME='bundled-java' }}
@{{ code=$result.ExitCode; child=($result.Output|ConvertFrom-Json); java=$env:JAVA_HOME;
    osjava=$env:OPENSEARCH_JAVA_HOME; opt=$env:JAVA_TOOL_OPTIONS }}|ConvertTo-Json -Depth 5 -Compress
"""
    got = run_ps(tmp_path, body)
    assert got["code"] == 7
    assert got["child"] == {"java": "bundled-java", "osjava": "bundled-java", "opt": None, "path": path_argument}
    assert (got["java"], got["osjava"], got["opt"]) == ("original-java", "original-search", "unrelated")

def test_actual_bundled_java_probe(tmp_path):
    home = ROOT / ".qa/packaging/installed-new2-20261017/opensearch-2.19.6"
    if not (home / "jdk/bin/java.exe").is_file():
        pytest.skip("Native pinned JDK fixture not available")
    body = LOAD + f"""
$java=Get-SawOpenSearchJava -OpenSearchHome {literal(home)} -Version '2.19.6'
@{{ bundled=$java.Home; jvm=$java.Jvm }}|ConvertTo-Json -Compress
"""
    got = run_ps(tmp_path, body)
    assert got["bundled"] == str(home / "jdk")
    assert got["jvm"] == str(home / "jdk/bin/server/jvm.dll")

def test_validate_only_refuses_absent_service_without_any_filesystem_mutation(tmp_path):
    bundle, root, home = fixture(tmp_path)
    body = LOAD + f"""
$BundleDir={literal(bundle)}; $InstallRoot={literal(root)}; $HeapGB=1; $Port=9200; $TransportPort=9300
$ServiceName='saw-opensearch'; $NoService=$false; $UserMode=$false; $DevNoAcl=$true; $ValidateOnly=$true
$script:registered=$false
function Get-SawOpenSearchServiceRecord {{ return $null }}
function Invoke-SawOpenSearchNative([string]$FilePath) {{
    if($FilePath -like '*opensearch-service.bat') {{ $script:registered=$true }}
    return [pscustomobject]@{{ ExitCode=0; Output=(@('java.version = 21.0.11','sun.arch.data.model = 64','java.specification.version = 21') -join [Environment]::NewLine) }}
}}
$errorText=$null
try {{ . ([scriptblock]::Create($source)) }} catch {{ $errorText=$_.Exception.Message }}
@{{ failure=$errorText; registered=$script:registered; dataCreated=(Test-Path -LiteralPath (Join-Path $InstallRoot 'data'));
    receiptCreated=(Test-Path -LiteralPath (Join-Path $InstallRoot 'opensearch-setup-state.json')) }}|ConvertTo-Json -Compress
"""
    got=run_ps(tmp_path, body)
    assert got["failure"]
    assert not got["registered"] and not got["dataCreated"] and not got["receiptCreated"]

def test_native_batch_runner_handles_space_and_korean_filename_and_arguments(tmp_path):
    child = tmp_path / "한글 경로 & probe.cmd"
    child.write_text(
        '@echo off\nif not "%JAVA_HOME%"=="dedicated" exit /b 41\n'
        'if not "%OPENSEARCH_JAVA_HOME%"=="dedicated" exit /b 42\n'
        'if not "%~1"=="argument with & space" exit /b 43\n'
        'exit /b 7\n', encoding="ascii")
    body=LOAD + f"""
$result=Invoke-SawOpenSearchNative -FilePath {literal(child)} -Arguments @('argument with & space') -Environment @{{JAVA_HOME='dedicated';OPENSEARCH_JAVA_HOME='dedicated'}}
@{{code=$result.ExitCode}}|ConvertTo-Json -Compress
"""
    assert run_ps(tmp_path,body)["code"]==7


def test_interrupted_receipt_after_configuration_keeps_completed_operator_config(tmp_path):
    got, before, after, _ = setup_probe(tmp_path, preparing=True, registration="valid")
    assert got["failure"] is None, got
    assert before == after
    assert not any(row["file"].endswith("tar.exe") for row in got["commands"])


@pytest.mark.parametrize("case", ["operator_config", "operator_binary", "unknown_file", "interrupted_prefix"])
def test_preparing_runtime_never_overwrites_operator_files(tmp_path, case):
    import hashlib
    import zipfile

    bundle, root, home = fixture(tmp_path)
    config = home / "config/opensearch.yml"
    config.write_text("# bundled configuration\n", encoding="utf-8")
    binary = home / "jdk/bin/java.exe"
    binary.write_bytes(b"synthetic bundled binary payload")
    with zipfile.ZipFile(bundle / "opensearch/opensearch-2.19.6-windows-x64.zip", "w") as archive:
        for path in home.rglob("*"):
            if path.is_file():
                archive.write(path, str(path.relative_to(root)).replace("\\", "/"))
    with zipfile.ZipFile(bundle / "opensearch/analysis-nori-2.19.6.zip", "w") as archive:
        archive.writestr("plugin-descriptor.properties", "name=analysis-nori\nopensearch.version=2.19.6\n")
    if case == "operator_config":
        config.write_text("# bundled configuration\n# operator change\n", encoding="utf-8")
    elif case == "operator_binary":
        binary.write_bytes(b"different operator-provided executable")
    elif case == "unknown_file":
        (home / "operator-notes.txt").write_text("preserve operator notes", encoding="utf-8")
    else:
        binary.write_bytes(b"synthetic bundled")
    (root / "opensearch-setup-state.json").write_text(json.dumps({
        "schema": 1, "home": str(home), "version": "2.19.6", "configured": False}), encoding="utf-8")
    before = {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
              for path in root.rglob("*") if path.is_file()}
    body = LOAD + f"""
$BundleDir={literal(bundle)}; $InstallRoot={literal(root)}; $HeapGB=1; $Port=9200; $TransportPort=9300
$ServiceName='saw-opensearch'; $NoService=$true; $UserMode=$true; $DevNoAcl=$true; $ValidateOnly=$false
$script:originalRunner=(Get-Item Function:Invoke-SawOpenSearchNative).ScriptBlock
function Invoke-SawOpenSearchNative([string]$FilePath,[string[]]$Arguments,[hashtable]$Environment=@{{}}) {{
    if ($FilePath -like '*java.exe') {{
        return [pscustomobject]@{{ExitCode=0;Output="java.version = 21.0.11\nsun.arch.data.model = 64\njava.specification.version = 21"}}
    }}
    & $script:originalRunner -FilePath $FilePath -Arguments $Arguments -Environment $Environment
}}
$errorText=$null
try {{ . ([scriptblock]::Create($source)) }} catch {{ $errorText=$_.Exception.Message }}
@{{failure=$errorText}}|ConvertTo-Json -Compress
"""
    got = run_ps(tmp_path, body)
    if case == "interrupted_prefix":
        assert got["failure"] is None, got
        retained = list(root.glob("opensearch-2.19.6.retained-*"))
        assert len(retained) == 1
        assert (retained[0] / "jdk/bin/java.exe").read_bytes() == b"synthetic bundled"
        assert binary.read_bytes() == b"synthetic bundled binary payload"
    else:
        assert got["failure"], "Operator files must be rejected before extraction or configuration writes"
        after = {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in root.rglob("*") if path.is_file()}
        assert after == before
        assert not list(root.glob("opensearch-2.19.6.retained-*"))


@pytest.mark.parametrize("core", ["missing", "tampered"])
def test_missing_or_tampered_core_engine_fails_before_service_actions(tmp_path, core):
    got, before, after, _ = setup_probe(tmp_path, initial="valid", core=core)
    assert got["failure"]
    assert before == after and got["started"] == 0 and not got["registered"]
    assert not any(row["file"].endswith("java.exe") for row in got["commands"])


def test_owned_pending_service_policy_resumes_without_registration_or_restart(tmp_path):
    got, _, _, _ = setup_probe(tmp_path, initial="valid", pending=True, policy="manual")
    assert got["failure"] is None, got
    assert not got["registered"] and got["started"] == 0
    assert [r["args"][0] for r in got["commands"] if r["file"].endswith("sc.exe")] == ["config", "failure"]
    assert got["pending"] is False


def test_legacy_manual_service_policy_fails_without_overwriting_operator_choice(tmp_path):
    got, _, _, _ = setup_probe(tmp_path, initial="valid", policy="manual")
    assert got["failure"]
    assert not got["registered"] and got["started"] == 0
    assert not any(r["file"].endswith("sc.exe") for r in got["commands"])


def test_policy_zero_exit_without_applied_state_is_not_completed(tmp_path):
    got, _, _, _ = setup_probe(tmp_path, initial="valid", pending=True, policy="manual", policy_effect=False)
    assert got["failure"]
    assert got["pending"] is True
    assert got["started"] == 0


def test_new_service_receives_auto_start_and_clears_verified_policy_receipt(tmp_path):
    got, _, _, _ = setup_probe(tmp_path, registration="valid")
    assert got["failure"] is None, got
    registered = [r for r in got["commands"] if r["file"].endswith("opensearch-service.bat")]
    assert registered[0]["startType"] == "auto"
    assert got["pending"] is False


def test_service_policy_reader_compiles_without_accessing_services(tmp_path):
    got = run_ps(tmp_path, LOAD + """
Initialize-SawOpenSearchPolicyReader
@{available=([bool]('SawOpenSearchServicePolicy' -as [type]))}|ConvertTo-Json -Compress
""")
    assert got["available"]
