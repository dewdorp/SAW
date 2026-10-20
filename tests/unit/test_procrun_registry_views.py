"""Procrun x64 services may store settings in either Windows registry view."""
from __future__ import annotations

import importlib
import sys
import types

import pytest


class _Key:
    def __init__(self, values):
        self.values = values

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def _mock_registry(monkeypatch, root, *, view32="valid", view64="missing"):
    home = root / "opensearch-2.19.6"
    opts = ["-Dopensearch.path.home=" + str(home),
            "-Dopensearch.path.conf=" + str(home / "config")]
    entries = {}

    for view, state in ((32, view32), (64, view64)):
        if state == "missing":
            continue
        if state == "partial":
            entries[view, "Java"] = {"Jvm": str(home / "jdk/bin/server/jvm.dll"), "Options": opts}
            continue
        options = list(opts)
        if state == "conflict":
            options[0] = "-Dopensearch.path.home=C:\\unexpected"
        if state == "duplicate":
            options.append(options[0])
        if state == "badtype":
            options = "not a list"
        entries[view, "Java"] = {"Jvm": str(home / "jdk/bin/server/jvm.dll"), "Options": options}
        entries[view, "Start"] = {"WorkingPath": str(home)}

    fake = types.ModuleType("winreg")
    fake.HKEY_LOCAL_MACHINE = 1
    fake.KEY_READ = 2
    fake.KEY_WOW64_32KEY = 32
    fake.KEY_WOW64_64KEY = 64

    def open_key(hive, key, reserved, flags):
        assert hive == fake.HKEY_LOCAL_MACHINE
        assert key.startswith("SOFTWARE\\Apache Software Foundation\\ProcRun 2.0\\saw-opensearch\\Parameters\\")
        view = 32 if flags & 32 else 64
        branch = key.rsplit("\\", 1)[-1]
        if (view, branch) not in entries:
            raise FileNotFoundError(key)
        return _Key(entries[view, branch])

    def get_value(key, name):
        if name not in key.values:
            raise FileNotFoundError(name)
        return key.values[name], 1

    fake.OpenKey = open_key
    fake.QueryValueEx = get_value
    monkeypatch.setitem(sys.modules, "winreg", fake)


@pytest.mark.parametrize(("view32", "view64"), [
    ("valid", "missing"),
    ("missing", "valid"),
    ("valid", "valid"),
])
def test_procrun_accepts_verified_registry_view(monkeypatch, tmp_path, view32, view64):
    _mock_registry(monkeypatch, tmp_path, view32=view32, view64=view64)
    desktop = importlib.import_module("saw.devtools.desktop_update")
    desktop.WindowsController._verify_opensearch_procrun(tmp_path)


@pytest.mark.parametrize(("view32", "view64"), [
    ("missing", "missing"),
    ("partial", "missing"),
    ("missing", "partial"),
    ("valid", "conflict"),
    ("conflict", "valid"),
    ("valid", "partial"),
    ("duplicate", "missing"),
    ("badtype", "missing"),
])
def test_procrun_rejects_missing_partial_or_conflicting_views(monkeypatch, tmp_path, view32, view64):
    _mock_registry(monkeypatch, tmp_path, view32=view32, view64=view64)
    desktop = importlib.import_module("saw.devtools.desktop_update")
    with pytest.raises(desktop.DesktopError, match="service_configuration_unverified"):
        desktop.WindowsController._verify_opensearch_procrun(tmp_path)
