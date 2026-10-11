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
    r = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)],
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
    assert "SAW_OPENSEARCH_DURABILITY=$(if ($LocalOnly) { 'async' } else { 'request' })" in inst
    assert Settings.model_fields["opensearch_durability"].default == "request"
    assert index_template()["template"]["settings"]["translog"] == {"durability": "request"}
    assert index_template(durability="async")["template"]["settings"]["translog"]["durability"] == "async"
