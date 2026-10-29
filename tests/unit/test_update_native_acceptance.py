"""Native read-only acceptance harness uses synthetic directories and SCM rows."""
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'deploy/windows/test-update-environment.ps1'
PS = Path(os.environ.get('SystemRoot', 'C:/Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows PowerShell acceptance harness')


def literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def powershell(code):
    code = "$env:PSModulePath=Join-Path $PSHOME 'Modules';$ProgressPreference='SilentlyContinue';" + code
    return subprocess.run([str(PS), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned', '-EncodedCommand',
                           base64.b64encode(code.encode('utf-16-le')).decode('ascii')],
                          capture_output=True, timeout=60, check=False)


def functions():
    return (
        "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);"
        "$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile("
        + literal(SCRIPT) + ",[ref]$tokens,[ref]$errors);if($errors.Count){throw 'syntax error'};"
        "$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)"
        " | ForEach-Object {Invoke-Expression $_.Extent.Text};"
    )


def test_native_harness_verification_failure_never_executes_worker(tmp_path):
    target = tmp_path / SCRIPT.name
    shutil.copyfile(SCRIPT, target)
    (tmp_path / 'verify-bundle.ps1').write_text("throw 'private-do-not-display'", encoding='utf-8')
    marker = tmp_path / 'must-not-exist'
    (tmp_path / 'update-worker.ps1').write_text(
        "[IO.File]::WriteAllText(" + literal(marker) + ",'executed')", encoding='utf-8')
    install, bundle = tmp_path / 'install', tmp_path / 'media'
    install.mkdir()
    bundle.mkdir()
    result = powershell('& ' + literal(target) + ' -InstallRoot ' + literal(install) +
                        ' -BundleDir ' + literal(bundle) + ' -EvidenceParent ' + literal(tmp_path))
    assert result.returncode != 0
    assert not marker.exists()
    assert b'private-do-not-display' not in result.stdout + result.stderr
    assert not list(tmp_path.glob('SAW-update-state-*'))


def test_native_inventory_detects_bytes_and_acl_without_outputting_paths(tmp_path):
    root = tmp_path / 'install'
    (root / 'app').mkdir(parents=True)
    (root / 'data').mkdir()
    secret = root / 'app' / '.env'
    secret.write_text('synthetic-private-do-not-display', encoding='utf-8')
    code = functions() + (
        '$a=Get-SawNativeInventory -Root ' + literal(root) + ';'
        '[IO.File]::WriteAllText(' + literal(root / 'data' / 'live.txt') + ",'changed');"
        '$b=Get-SawNativeInventory -Root ' + literal(root) + ';'
        '[IO.File]::WriteAllText(' + literal(secret) + ",'different-private-content');"
        '$c=Get-SawNativeInventory -Root ' + literal(root) + ';'
        '$acl=Get-Acl -LiteralPath ' + literal(secret) + ';$acl.SetAccessRuleProtection($true,$true);'
        'Set-Acl -LiteralPath ' + literal(secret) + ' -AclObject $acl;'
        '$d=Get-SawNativeInventory -Root ' + literal(root) + ';'
        '@{unchanged=($a.digest -eq $b.digest);bytes_changed=($b.digest -ne $c.digest);'
        'acl_changed=($c.digest -ne $d.digest);summary=$d}|ConvertTo-Json -Compress'
    )
    result = powershell(code)
    assert result.returncode == 0, result.stderr.decode(errors='replace')
    value = json.loads(result.stdout.decode('utf-8-sig'))
    assert value['unchanged'] and value['bytes_changed'] and value['acl_changed']
    assert 'synthetic-private' not in str(value) and '.env' not in str(value)


def test_native_service_report_redacts_unknown_accounts_and_commands(tmp_path):
    code = functions() + (
        "function Get-CimInstance { @("
        "[pscustomobject]@{Name='saw';StartName='custom-private-account';PathName='secret-command';State='Running';ProcessId=10},"
        "[pscustomobject]@{Name='saw-postgresql';StartName='NT AUTHORITY\\NetworkService';PathName='secret-command';State='Stopped';ProcessId=0},"
        "[pscustomobject]@{Name='saw-opensearch';StartName='LocalSystem';PathName='secret-command';State='Running';ProcessId=20})};"
        'Get-SawNativeServices -Root ' + literal(tmp_path) + ' | ConvertTo-Json -Compress'
    )
    result = powershell(code)
    assert result.returncode == 0, result.stderr.decode(errors='replace')
    value = result.stdout.decode('utf-8-sig')
    assert 'custom-private-account' not in value and 'secret-command' not in value
    rows = json.loads(value)
    assert rows[0]['account'] == '<custom-or-unverified>'
    assert rows[1]['account'] == 'NetworkService' and rows[2]['account'] == 'LocalSystem'


def test_native_target_requires_ltsc_client_edition_and_exact_runtime():
    cases = [
        ("ltsc", "17763", 1, 125, "10.0.17763", "5.1", True, True, True),
        ("ltsc_n", "17763", 1, 126, "10.0.17763", "5.1", True, True, True),
        ("server", "17763", 3, 7, "10.0.17763", "5.1", True, True, False),
        ("domain_controller", "17763", 2, 7, "10.0.17763", "5.1", True, True, False),
        ("enterprise_non_ltsc", "17763", 1, 4, "10.0.17763", "5.1", True, True, False),
        ("professional", "17763", 1, 48, "10.0.17763", "5.1", True, True, False),
        ("unknown_edition", "17763", 1, 0, "10.0.17763", "5.1", True, True, False),
        ("evaluation", "17763", 1, 129, "10.0.17763", "5.1", True, True, False),
        ("iot", "17763", 1, 191, "10.0.17763", "5.1", True, True, False),
        ("later_ltsc", "19044", 1, 125, "10.0.19044", "5.1", True, True, False),
        ("wrong_version", "17763", 1, 125, "6.3.17763", "5.1", True, True, False),
        ("pwsh", "17763", 1, 125, "10.0.17763", "7.4", True, True, False),
        ("process32", "17763", 1, 125, "10.0.17763", "5.1", False, True, False),
        ("os32", "17763", 1, 125, "10.0.17763", "5.1", True, False, False),
    ]
    code = functions() + "$rows=@();"
    for name, build, kind, sku, version, ps, process64, os64, _ in cases:
        code += (
            "$os=[pscustomobject]@{BuildNumber=" + literal(build)
            + ";ProductType=" + str(kind) + ";OperatingSystemSKU=" + str(sku)
            + ";Version=" + literal(version) + "};"
            "$actual=Test-SawNativeTarget -OperatingSystem $os -PowerShellVersion "
            + literal(ps) + " -Is64BitProcess $" + str(process64).lower()
            + " -Is64BitOperatingSystem $" + str(os64).lower() + ";"
            "$rows+=@{name=" + literal(name) + ";actual=$actual};"
        )
    code += "$rows|ConvertTo-Json -Compress"
    result = powershell(code)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    rows = json.loads(result.stdout.decode("utf-8-sig"))
    assert {r["name"]: r["actual"] for r in rows} == {
        row[0]: row[-1] for row in cases
    }
