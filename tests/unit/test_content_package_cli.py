"""The offline authoring tool produces verified JSON and never runs bundled content."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def run(*args):
    return subprocess.run([sys.executable, "-m", "saw.devtools.content_package", *map(str, args)],
                          cwd=ROOT, capture_output=True, text=True, encoding="utf-8")


def test_cli_example_build_verify_and_failed_fixture_exit_codes(tmp_path):
    source = tmp_path / "example.json"
    result = run("example", source)
    assert result.returncode == 0, result.stderr
    doc = json.loads(source.read_text(encoding="utf-8"))
    assert doc["schema"] == "saw.content-package/1" and len(doc["entries"]) == 2
    assert run("verify", source).returncode == 0
    assert run("test", source).returncode == 0
    assert run("example", source).returncode != 0
    doc["entries"][0]["content"]["title"] = "edited synthetic title"
    source.write_text(json.dumps(doc), encoding="utf-8")
    assert run("verify", source).returncode != 0
    out = tmp_path / "rebuilt.json"
    assert run("build", source, out).returncode == 0
    assert run("verify", out).returncode == 0
    doc["entries"][0]["fixtures"][1]["events"][0]["url_path"] = "/saw-demo/restricted"
    source.write_text(json.dumps(doc), encoding="utf-8")
    failed = tmp_path / "failing-fixture.json"
    assert run("build", source, failed).returncode == 0
    assert run("test", failed).returncode != 0


def test_cli_rejects_scripts_without_creating_output(tmp_path):
    source, output = tmp_path / "bad.json", tmp_path / "output.json"
    source.write_text('{"schema":"saw.content-package/1","install_script":"evil.exe"}', encoding="utf-8")
    assert run("build", source, output).returncode != 0
    assert not output.exists()
