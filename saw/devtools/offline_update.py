"""Cold updates; run directly from verified media with an isolated interpreter."""
from __future__ import annotations
import argparse
import ast
from contextlib import contextmanager
from functools import wraps
import base64
import ctypes
import importlib.util
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import uuid
import zipfile
import hashlib
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

_spec = importlib.util.spec_from_file_location("_saw_release_manifest", Path(__file__).with_name("release_manifest.py"))
_manifest = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_manifest)
RUNTIME_DIRS = {"python", "postgresql", "opensearch", "wheels", "bootstrap", "winsw", "llm-runtime"}
PINS = {"python": "3.12.10", "postgresql": "16.15-1", "opensearch": "2.19.6"}

class UpdateError(ValueError):
    """An update or recovery precondition was not met."""

def _ps(script):
    script = "$env:PSModulePath=(Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/Modules'); " + script
    executable = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    result = subprocess.run([str(executable), "-NoProfile", "-NonInteractive", "-EncodedCommand",
                             base64.b64encode(script.encode("utf-16-le")).decode()],
                            capture_output=True, timeout=90, check=False)
    if result.returncode:
        raise UpdateError("Windows security/process inspection failed; no output was disclosed")
    return result.stdout.decode("utf-8-sig").strip()

def _literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def _windows_path_limit(path, *, directory):
    if os.name != "nt":
        return
    absolute = Path(os.path.abspath(path))
    def units(value):
        return len(str(value).encode("utf-16-le", errors="surrogatepass")) // 2
    # Include NUL in MAX_PATH, and reserve the documented 8.3 directory margin.
    if units(absolute) > (247 if directory else 259) or any(units(part) > 255 for part in absolute.parts[1:]):
        raise UpdateError("Windows path length exceeds the supported limit "
                          "(directories 247, files 259 UTF-16 units); use shorter installation/recovery paths")

def _preflight_rows(destination, rows):
    _windows_path_limit(destination, directory=True)
    for row in rows:
        target = destination if row["path"] == "." else destination / row["path"]
        _windows_path_limit(target, directory=bool(row.get("directory")))

def _preflight_copy(source, destination):
    if os.name != "nt":
        return
    _windows_path_limit(destination, directory=True)
    for path in _tree_paths(source):
        _windows_path_limit(destination / path.relative_to(source), directory=path.is_dir())

def _preflight_json(path):
    _windows_path_limit(path, directory=False)
    _windows_path_limit(path.with_name(path.name + ".writing"), directory=False)

def _restore_paths(root):
    for _attempt in range(10):
        token = uuid.uuid4().hex[:12]
        stage = root.with_name(".saw-r-" + token)
        retained = root.with_name(".saw-k-" + token)
        if not any(path.exists() or path.is_symlink() for path in (stage, retained)):
            return token, stage, retained
    raise UpdateError("Cannot reserve unique recovery sibling paths")


def _path(value, *, existing=True):
    path = Path(os.path.abspath(value))
    if str(path).startswith(("\\\\", "//")) or path == Path(path.anchor):
        raise UpdateError("A local non-root directory is required")
    for item in (path, *path.parents):
        if item.exists() or item.is_symlink():
            if item.is_symlink() or getattr(item.lstat(), "st_file_attributes", 0) & 0x400:
                raise UpdateError("Reparse points are not supported")
    if existing and not path.is_dir():
        raise UpdateError("Required directory is missing")
    return path

def _inside(path, root):
    return path == root or root in path.parents

def _separate(*paths):
    for index, left in enumerate(paths):
        for right in paths[index + 1:]:
            if _inside(left, right) or _inside(right, left):
                raise UpdateError("Installation, media and recovery directories must be separate")

def _acl(path):
    if os.name != "nt":
        return str(stat.S_IMODE(path.stat().st_mode))
    from ctypes import wintypes
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.GetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                       ctypes.POINTER(wintypes.DWORD)]
    needed = wintypes.DWORD()
    advapi.GetFileSecurityW(str(path), 4, None, 0, ctypes.byref(needed))
    buffer = ctypes.create_string_buffer(needed.value)
    if not needed.value or not advapi.GetFileSecurityW(str(path), 4, buffer, needed.value, ctypes.byref(needed)):
        raise UpdateError("Cannot read a file access policy")
    result = wintypes.LPWSTR()
    advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR), ctypes.c_void_p]
    if not advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(buffer, 1, 4, ctypes.byref(result), None):
        raise UpdateError("Cannot serialize a file access policy")
    try:
        return result.value
    finally:
        kernel = ctypes.WinDLL("kernel32")
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree(ctypes.cast(result, ctypes.c_void_p))

def _set_acl(path, policy):
    if os.name != "nt":
        os.chmod(path, int(policy))
        return
    from ctypes import wintypes
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    descriptor = ctypes.c_void_p()
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(policy, 1, ctypes.byref(descriptor), None):
        raise UpdateError("Cannot parse a file access policy")
    try:
        control, revision = wintypes.WORD(), wintypes.DWORD()
        advapi.GetSecurityDescriptorControl.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(wintypes.WORD), ctypes.POINTER(wintypes.DWORD)]
        if not advapi.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)):
            raise UpdateError("Cannot read access policy inheritance controls")
        if control.value & 0x0400:  # SE_DACL_AUTO_INHERITED
            # SetFileSecurity otherwise clears AI. Request the current inheritance
            # model without recomputing ACEs from the different recovery parent.
            advapi.SetSecurityDescriptorControl.argtypes = [ctypes.c_void_p, wintypes.WORD, wintypes.WORD]
            if not advapi.SetSecurityDescriptorControl(descriptor, 0x0100, 0x0100):
                raise UpdateError("Cannot preserve access policy inheritance controls")
        advapi.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
        flags = 4 | (0x80000000 if policy.startswith("D:P") else 0x20000000)
        if not advapi.SetFileSecurityW(str(path), flags, descriptor):
            raise UpdateError("Cannot preserve a file access policy")
        if _acl(path) != policy:
            raise UpdateError("Copied access policy differs before writing private content")
    finally:
        kernel = ctypes.WinDLL("kernel32")
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree(descriptor)


def _access_metadata(path):
    """Read owner and every ordinary DACL ACE; never read file contents."""
    from ctypes import wintypes
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.GetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                       ctypes.POINTER(wintypes.DWORD)]
    needed = wintypes.DWORD()
    advapi.GetFileSecurityW(str(path), 5, None, 0, ctypes.byref(needed))
    descriptor = ctypes.create_string_buffer(needed.value)
    if not needed.value or not advapi.GetFileSecurityW(str(path), 5, descriptor, needed.value, ctypes.byref(needed)):
        raise UpdateError("Cannot inspect installation access policy")
    advapi.GetSecurityDescriptorOwner.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
    owner, defaulted = ctypes.c_void_p(), wintypes.BOOL()
    if not advapi.GetSecurityDescriptorOwner(descriptor, ctypes.byref(owner), ctypes.byref(defaulted)) or not owner:
        raise UpdateError("Missing installation access policy owner")
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    kernel = ctypes.WinDLL("kernel32")
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    def sid_text(pointer):
        result = wintypes.LPWSTR()
        if not advapi.ConvertSidToStringSidW(pointer, ctypes.byref(result)):
            raise UpdateError("Unsupported installation access policy SID")
        try:
            return result.value
        finally:
            kernel.LocalFree(ctypes.cast(result, ctypes.c_void_p))
    owner_sid = sid_text(owner)
    present, dacl = wintypes.BOOL(), ctypes.c_void_p()
    advapi.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL)]
    if (not advapi.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present), ctypes.byref(dacl),
                                           ctypes.byref(defaulted)) or not present.value or not dacl):
        raise UpdateError("Missing or NULL installation access policy")
    class AclSize(ctypes.Structure):
        _fields_ = [("count", wintypes.DWORD), ("used", wintypes.DWORD), ("free", wintypes.DWORD)]
    size = AclSize()
    advapi.GetAclInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
    if not advapi.GetAclInformation(dacl, ctypes.byref(size), ctypes.sizeof(size), 2):
        raise UpdateError("Cannot inspect installation access policy entries")
    advapi.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    entries = []
    for index in range(size.count):
        ace = ctypes.c_void_p()
        if not advapi.GetAce(dacl, index, ctypes.byref(ace)):
            raise UpdateError("Cannot inspect installation access policy entry")
        header = ctypes.cast(ace, ctypes.POINTER(ctypes.c_ubyte))
        if header[0] not in (0, 1):  # ACCESS_ALLOWED_ACE / ACCESS_DENIED_ACE only.
            raise UpdateError("Unsupported installation access policy ACE type")
        mask = ctypes.c_uint32.from_address(ace.value + 4).value
        entries.append((header[0], header[1], mask, sid_text(ctypes.c_void_p(ace.value + 8))))
    return owner_sid, entries

def _network_service_scope(relative):
    name = relative.as_posix().casefold()
    if name in (".", "data", "logs", "venv", "opensearch-2.19.6", "opensearch-2.19.6/jdk"):
        return 0x100020, False, False  # Traverse only; never inherited.
    for prefix, mask, owner in (
        ("data/postgresql", 0x1F01FF, True),
        ("logs/postgresql", 0x1301BF, True),
        ("pgsql", 0x1200A9, False),
        ("service", 0x1200A9, False),
        ("venv/scripts", 0x1200A9, False),
        ("opensearch-2.19.6/jdk/bin", 0x1200A9, False),
    ):
        if name == prefix or name.startswith(prefix + "/"):
            return mask, True, owner
    return 0, False, False

def _access_gate(root, *, relative_base=Path("."), service_mode=None):
    """Refuse untrusted installation ACLs; never repair existing permissions."""
    if os.name != "nt":
        return
    paths = _tree_paths(root)
    current = _ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value")
    trusted = {current, "S-1-5-18", "S-1-5-32-544"}
    if service_mode is None:
        service_mode = (root / "service/saw-postgresql.exe").is_file()
    for path in paths:
        relative = relative_base / path.relative_to(root)
        try:
            owner, entries = _access_metadata(path)
            mask, inherit, service_owner = _network_service_scope(relative) if service_mode else (0, False, False)
            if owner not in trusted and not (owner == "S-1-5-20" and service_owner):
                raise UpdateError("Untrusted owner")
            for kind, flags, rights, sid in entries:
                if kind == 1 or sid in trusted:
                    continue
                if (sid != "S-1-5-20" or not mask or rights & ~mask
                        or (not inherit and flags & 0x03)):
                    raise UpdateError("Untrusted or excessive allow ACE")
        except UpdateError:
            raise UpdateError("Installation access policy requires administrator review: "
                              + relative.as_posix()) from None


def _private_directory(path):
    _windows_path_limit(path, directory=True)
    path.mkdir()
    if os.name == "nt":
        _ps("$ErrorActionPreference='Stop'; "
            "$acl=New-Object System.Security.AccessControl.DirectorySecurity; "
            "$acl.SetAccessRuleProtection($true,$false); "
            "$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User; "
            "foreach($id in @($sid,(New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))) { "
            "$rule=New-Object Security.AccessControl.FileSystemAccessRule($id,'FullControl','ContainerInherit,ObjectInherit','None','Allow'); "
            "$acl.AddAccessRule($rule) }; Set-Acl -LiteralPath " + _literal(path) + " -AclObject $acl")
    else:
        path.chmod(0o700)

def _tree_paths(root):
    _windows_path_limit(root, directory=True)
    _path(root)
    paths = [root]
    def enumeration_failed(_error):
        raise UpdateError("Cannot enumerate every directory; complete verification is required") from None
    for parent, directories, files in os.walk(root, followlinks=False, onerror=enumeration_failed):
        for name in directories + files:
            path = Path(parent) / name
            _windows_path_limit(path, directory=name in directories)
            if path.is_symlink() or getattr(path.lstat(), "st_file_attributes", 0) & 0x400:
                raise UpdateError("Reparse points are not supported")
            _manifest.safe_relative(path.relative_to(root).as_posix())
            paths.append(path)
    return [root, *sorted(paths[1:])]

def _inventory(root):
    entries = []
    for path in _tree_paths(root):
        if path.is_symlink() or getattr(path.lstat(), "st_file_attributes", 0) & 0x400:
            raise UpdateError("Reparse points are not supported")
        rel = "." if path == root else path.relative_to(root).as_posix()
        if rel != ".":
            _manifest.safe_relative(rel)
        if path.is_dir():
            entries.append({"path": rel, "directory": True, "acl": _acl(path)})
        elif path.is_file():
            before = path.stat()
            digest = _manifest.digest(path)
            after = path.stat()
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise UpdateError("Installation changed while reading")
            entries.append({"path": rel, "bytes": after.st_size, "sha256": digest, "acl": _acl(path)})
        else:
            raise UpdateError("Unsupported filesystem entry")
    return entries

def _copy_file(source, destination):
    _windows_path_limit(destination, directory=False)
    _windows_path_limit(destination.parent, directory=True)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.touch(exist_ok=False)
    # Install the original access policy before writing any private bytes.
    _set_acl(destination, _acl(source))
    shutil.copyfile(source, destination)
    shutil.copystat(source, destination)

def _copy_tree(source, destination):
    rows = _inventory(source)
    _preflight_rows(destination, rows)
    destination.mkdir()
    for row in rows:
        target = destination if row["path"] == "." else destination / row["path"]
        original = source if row["path"] == "." else source / row["path"]
        if row.get("directory"):
            target.mkdir(exist_ok=True)
            _set_acl(target, row["acl"])
        else:
            _copy_file(original, target)
    if _inventory(destination) != rows:
        raise UpdateError("Copied files or access policies do not match")


def _copy_public_file(source, destination, policy=None):
    _windows_path_limit(destination, directory=False)
    destination.touch(exist_ok=False)
    if policy is not None:
        _set_acl(destination, policy)
    # Otherwise the empty file inherits from its already validated parent.
    shutil.copyfile(source, destination)
    shutil.copystat(source, destination)

def _stage_public_app(source, destination, installed_app):
    rows = _inventory(source)
    _preflight_rows(destination, rows)
    destination.mkdir()
    _set_acl(destination, _acl(installed_app))
    for row in rows[1:]:
        target, original = destination / row["path"], installed_app / row["path"]
        policy = _acl(original) if original.exists() else None
        if row.get("directory"):
            target.mkdir()
            if policy is not None:
                _set_acl(target, policy)
        else:
            _copy_public_file(source / row["path"], target, policy)
    def contents(entries):
        return [{key: value for key, value in row.items() if key != "acl"} for row in entries]
    if contents(_inventory(destination)) != contents(rows):
        raise UpdateError("Staged application files do not match verified media")


def _json(path, data):
    _preflight_json(path)
    temp = path.with_name(path.name + ".writing")
    with temp.open("x", encoding="utf-8") as stream:
        json.dump(data, stream, ensure_ascii=True, indent=2)
        stream.write("\n")
    os.replace(temp, path)

def _config(root):
    values = {}
    for raw in (root / "app/.env").read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise UpdateError("Unsupported installation configuration")
        key, value = line.split("=", 1)
        if key in values or not re.fullmatch(r"SAW_[A-Z0-9_]+", key) or chr(36) + "{" in value:
            raise UpdateError("Ambiguous installation configuration")
        values[key] = value.strip().strip("'\"")
    required = {"SAW_ENV": "prod", "SAW_SCHEMA_MODE": "migrate", "SAW_EVENT_STORE": "opensearch",
                "SAW_OBJECT_STORE": "local"}
    if any(values.get(key) != value for key, value in required.items()):
        raise UpdateError("Only the bundled local PostgreSQL/OpenSearch profile is supported")
    if values.get("SAW_JOB_RUNNER", "inprocess") != "inprocess":
        raise UpdateError("External workers are not supported")
    paths = {
        "SAW_DATA_DIR": root / "data/saw", "SAW_OBJECT_STORE_ROOT": root / "data/objects",
        "SAW_LLM_MODELS_ROOT": root / "models", "SAW_LLM_RUNTIME_ROOT": root / "llm-runtime",
        "SAW_LLM_CPU_WORK_ROOT": root / "data/saw/ai-work", "SAW_WEB_DIST": root / "app/apps/web/dist",
    }
    for key, default in paths.items():
        value = values.get(key, str(default))
        if not value and key.startswith("SAW_LLM_"):
            continue
        candidate = Path(value)
        if not candidate.is_absolute() or not _inside(_path(candidate, existing=False), root):
            raise UpdateError("External or relative configured storage is not supported")
        if key != "SAW_WEB_DIST" and _inside(candidate, root / "app") and not _inside(candidate, root / "app/var"):
            raise UpdateError("Mutable state inside the replaceable application is not supported")
        if key == "SAW_WEB_DIST" and candidate != default:
            raise UpdateError("Customized UI locations are not supported")
    cfg = json.loads((root / "saw-ctl.json").read_text(encoding="utf-8-sig"))
    for key in ("port", "postgresPort", "opensearchPort"):
        if type(cfg.get(key)) is not int or not 1 <= cfg[key] <= 65535:
            raise UpdateError("Invalid installed port configuration")
    db = urlsplit(values.get("SAW_DATABASE_URL", ""))
    search = urlsplit(values.get("SAW_OPENSEARCH_URL", ""))
    if (db.scheme != "postgresql+psycopg" or db.hostname != "127.0.0.1"
            or db.port != cfg["postgresPort"] or db.path != "/saw" or db.query or db.fragment
            or search.scheme != "http" or search.hostname != "127.0.0.1"
            or search.port != cfg["opensearchPort"] or search.path not in ("", "/")
            or search.query or search.fragment):
        raise UpdateError("External or customized databases are not supported")
    pg = root / "data/postgresql"
    if (pg / "PG_VERSION").read_text().strip() != "16":
        raise UpdateError("PostgreSQL major version differs")
    for config_file in (pg / "postgresql.conf", pg / "postgresql.auto.conf"):
        if not config_file.exists():
            continue
        for line in config_file.read_text(encoding="utf-8-sig").splitlines():
            if re.match(r"^\s*(include(?:_if_exists|_dir)?|data_directory|hba_file|ident_file|external_pid_file|archive_command|restore_command)\b", line):
                raise UpdateError("Customized PostgreSQL storage configuration is not supported")
    config = (root / "opensearch-2.19.6/config/opensearch.yml").read_text(encoding="utf-8-sig")
    found = {}
    for line in config.splitlines():
        if re.match(r"^\s*path\.", line):
            key, value = line.split(":", 1)
            value = value.strip().strip("[]").strip().strip("'\"")
            if key.strip() not in ("path.data", "path.logs", "path.repo") or "," in value:
                raise UpdateError("Customized OpenSearch storage configuration is not supported")
            candidate = Path(value)
            if not candidate.is_absolute() or not _inside(_path(candidate, existing=False), root):
                raise UpdateError("External OpenSearch storage is not supported")
            found[key.strip()] = value
        if re.match(r"^\s*transport.port\s*:", line):
            cfg["transportPort"] = int(line.split(":", 1)[1].strip())
    if set(found) != {"path.data", "path.logs", "path.repo"} or "transportPort" not in cfg:
        raise UpdateError("Installed OpenSearch storage/transport configuration is incomplete")
    if not 1 <= cfg["transportPort"] <= 65535 or len(set(cfg.values())) != len(cfg):
        raise UpdateError("Installed ports must be valid and distinct")
    return values, cfg

def _stopped(root, cfg):
    for key in ("port", "postgresPort", "opensearchPort", "transportPort"):
        with socket.socket() as probe:
            probe.settimeout(0.3)
            if probe.connect_ex(("127.0.0.1", cfg[key])) == 0:
                raise UpdateError("All installed application and storage ports must be stopped")
    if os.name == "nt":
        output = _ps(
            "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=New-Object Text.UTF8Encoding($false); "
            "$root=" + _literal(str(root).rstrip("\\/") + "\\") + "; "
            "$processes=@(Get-CimInstance Win32_Process | Where-Object { "
            "($_.ExecutablePath -and $_.ExecutablePath.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)) -or "
            "($_.Name -ieq 'cmd.exe' -and $_.CommandLine -and $_.CommandLine.IndexOf($root,[StringComparison]::OrdinalIgnoreCase) -ge 0 "
            "-and ($_.CommandLine -match 'saw.cli|opensearch.bat')) }); "
            "$services=@(Get-CimInstance Win32_Service | Where-Object { $_.PathName -and "
            "$_.PathName.IndexOf($root,[StringComparison]::OrdinalIgnoreCase) -ge 0 -and $_.State -ne 'Stopped' }); "
            "@{processes=$processes.Count;services=$services.Count} | ConvertTo-Json -Compress")
        state = json.loads(output)
        if state["processes"] or state["services"]:
            raise UpdateError("Installed processes or services are still active")
        for name in ("saw", "opensearch"):
            file = root / "run" / (name + ".pid")
            if file.exists():
                value = file.read_text().strip()
                if not value.isdecimal() or not 0 < int(value) <= 0xFFFFFFFF:
                    raise UpdateError("Invalid tracked process state")
                kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
                kernel.OpenProcess.restype = ctypes.c_void_p
                kernel.CloseHandle.argtypes = [ctypes.c_void_p]
                ctypes.set_last_error(0)
                handle = kernel.OpenProcess(0x1000, False, int(value))
                error = ctypes.get_last_error()
                if handle:
                    kernel.CloseHandle(handle)
                    raise UpdateError("A tracked process still exists")
                if error != 87:  # ERROR_INVALID_PARAMETER is the only definite missing-PID result.
                    raise UpdateError("Cannot verify that a tracked process has stopped")
    if (root / "data/postgresql/postmaster.pid").exists():
        raise UpdateError("PostgreSQL still has a process lock; verify a clean stop")

def _baseline(root, bundle):
    if bundle:
        _tree_paths(bundle)
        _manifest.verify(bundle)
        return json.loads((bundle / "release-manifest.json").read_text(encoding="utf-8-sig"))
    path = root / "installed-release-manifest.json"
    if not path.is_file():
        raise UpdateError("Legacy installations require the verified original BaselineBundleDir")
    document = json.loads(path.read_text(encoding="utf-8-sig"))
    if document.get("schema") != "saw.offline-release/1" or document.get("model_weights_included") is not False:
        raise UpdateError("Invalid installed release identity")
    return document

def _runtime_rows(document):
    return sorted([row for row in document["files"] if row["path"].split("/")[0] in RUNTIME_DIRS
                   or row["path"] == "app/deploy/windows/requirements.txt"], key=lambda row: row["path"])

def _installed_source(root, baseline):
    expected = {}
    for row in baseline["files"]:
        rel = _manifest.safe_relative(row["path"])
        _manifest.public_path(rel)
        if rel.startswith(("app/", "llm-runtime/")):
            expected[rel] = row
            path = root / rel
            if not path.is_file() or path.stat().st_size != row["bytes"] or _manifest.digest(path) != row["sha256"]:
                raise UpdateError("Installed application/runtime differs from its release; reconcile local edits first")
    for path in _tree_paths(root / "app")[1:]:
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        parts = path.relative_to(root / "app").parts
        if rel == "app/.env" or parts[0] == "var" or "__pycache__" in parts:
            continue
        if rel not in expected:
            raise UpdateError("Unexpected installed application file; reconcile local files first")

def _installed_service_wrappers(root, bundle):
    service = root / "service"
    wrappers = ("saw-service", "saw-postgresql")
    executables = [path for path in _tree_paths(service)[1:] if path.is_file() and path.suffix.lower() == ".exe"] if service.exists() else []
    markers = any((service / (name + suffix)).exists()
                  for name in wrappers for suffix in (".xml", ".exe"))
    registered = False
    if os.name == "nt":
        state = json.loads(_ps(
            "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=New-Object Text.UTF8Encoding($false); "
            "$root=" + _literal(str(root).rstrip("\\/") + "\\") + "; "
            "$services=@(Get-CimInstance Win32_Service | Where-Object { $_.PathName -and "
            "$_.PathName.IndexOf($root,[StringComparison]::OrdinalIgnoreCase) -ge 0 }); "
            "@{registered=$services.Count} | ConvertTo-Json -Compress"))
        registered = state["registered"] > 0
    if not (markers or executables or registered):
        return  # install.ps1 -NoAdmin does not copy either WinSW executable.
    allowed = {service / (name + ".exe") for name in wrappers}
    if any(path not in allowed for path in executables):
        raise UpdateError("Unexpected installed service executable")
    pinned = bundle / "winsw/WinSW-x64.exe"
    size, wanted = pinned.stat().st_size, _manifest.digest(pinned)
    for path in allowed:
        if not path.is_file() or path.stat().st_size != size or _manifest.digest(path) != wanted:
            raise UpdateError("Installed service executable is missing or differs from pinned WinSW")

def _installed_runtime(root, bundle):
    _installed_service_wrappers(root, bundle)
    expected = set()
    def archive(relative, mapper):
        with zipfile.ZipFile(bundle / relative) as stream:
            for info in stream.infolist():
                if info.is_dir():
                    continue
                name = _manifest.safe_relative(info.filename)
                destination = mapper(name)
                if destination is None:
                    continue
                path = root / destination
                with stream.open(info) as content:
                    wanted = hashlib.file_digest(content, "sha256").hexdigest()
                if not path.is_file() or _manifest.digest(path) != wanted:
                    raise UpdateError("Installed runtime or dependency differs from the pinned media")
                expected.add(destination)
    archive("python/python-3.12.10-embed-amd64.zip",
            lambda name: None if name.endswith("._pth") else "venv/Scripts/" + name)
    pth = root / "venv/Scripts/python312._pth"
    if pth.read_text(encoding="utf-8-sig").splitlines() != [
            "python312.zip", ".", "../Lib/site-packages", "../../app", "import site"]:
        raise UpdateError("Installed Python import paths differ from the offline profile")
    archive("postgresql/postgresql-16.15-1-windows-x64-binaries.zip", lambda name: name)
    os_prefix = "opensearch-2.19.6/"
    def opensearch(name):
        relative = name.removeprefix(os_prefix)
        if relative.startswith("config/"):
            return None
        if relative.startswith("plugins/") and relative.split("/")[1] not in (
                "opensearch-index-management", "opensearch-job-scheduler"):
            return None
        return name
    archive("opensearch/opensearch-2.19.6-windows-x64.zip", opensearch)
    archive("opensearch/analysis-nori-2.19.6.zip",
            lambda name: os_prefix + "plugins/analysis-nori/" + name)
    def wheel(name):
        if ".data/" in name:
            raise UpdateError("Unsupported wheel installation layout")
        if ".dist-info/" in name and name.endswith("/RECORD"):
            return None
        return "venv/Lib/site-packages/" + name
    archive("bootstrap/pip-25.1.1-py3-none-any.whl", wheel)
    wheels = bundle / "wheels"
    for package in (_tree_paths(wheels)[1:] if wheels.exists() else []):
        if package.parent == wheels and package.is_file() and package.suffix.lower() == ".whl":
            archive(package.relative_to(bundle).as_posix(), wheel)
    for folder in ("venv/Scripts", "venv/Lib/site-packages", "pgsql", "opensearch-2.19.6"):
        for path in _tree_paths(root / folder):
            if not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            if relative in expected or "__pycache__" in path.parts:
                continue
            if relative == "venv/Scripts/python312._pth":
                continue
            if relative.startswith("venv/Lib/site-packages/"):
                tail = relative.removeprefix("venv/Lib/site-packages/")
                if ".dist-info/" in tail and tail.rsplit("/", 1)[-1] in ("RECORD", "INSTALLER", "REQUESTED"):
                    continue
                if tail.startswith(("bin/", "Scripts/")) and path.suffix.lower() == ".exe":
                    continue  # pip-generated entry points; SAW starts via python -m.
            if relative.startswith((os_prefix + "config/", os_prefix + "logs/", os_prefix + "data/")):
                continue
            raise UpdateError("Unexpected installed runtime/dependency file")

def _migration_chain(root, baseline, candidate):
    prefix = "app/saw/storage/migrations/versions/"
    old = {row["path"]: row["sha256"] for row in baseline["files"]
           if row["path"].startswith(prefix) and row["path"].endswith(".py")}
    new = {row["path"]: row["sha256"] for row in candidate["files"]
           if row["path"].startswith(prefix) and row["path"].endswith(".py")}
    if not old or any(new.get(path) != digest for path, digest in old.items()):
        raise UpdateError("Migration downgrade or changed migration history is not supported")
    revisions = {}
    for relative in new:
        tree = ast.parse((root / relative).read_text(encoding="utf-8-sig"))
        values = {}
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in ("revision", "down_revision"):
                        values[target.id] = ast.literal_eval(node.value)
        if not values:
            continue
        revision, parent = values.get("revision"), values.get("down_revision")
        if not isinstance(revision, str) or revision in revisions or (parent is not None and not isinstance(parent, str)):
            raise UpdateError("Unsupported migration lineage")
        revisions[revision] = parent
    heads = set(revisions) - {parent for parent in revisions.values() if parent}
    if len(heads) != 1:
        raise UpdateError("Migration lineage must have one head")
    visited = set()
    revision = next(iter(heads))
    while revision is not None:
        if revision in visited or revision not in revisions:
            raise UpdateError("Broken migration lineage")
        visited.add(revision)
        revision = revisions[revision]
    if len(visited) != len(revisions):
        raise UpdateError("Disconnected migration lineage")

@contextmanager
def _maintenance(root):
    root = _path(root)
    lock_path = _path(root.with_name("." + root.name + ".saw-maintenance.lock"), existing=False)
    if lock_path.exists() and (not lock_path.is_file() or lock_path.stat().st_nlink != 1):
        raise UpdateError("Unsafe installation maintenance lock")
    _windows_path_limit(lock_path, directory=False)
    stream = lock_path.open("a+b")
    acquired = False
    try:
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise UpdateError("Another installation maintenance operation is active") from None
        acquired = True
        yield
    finally:
        if acquired:
            stream.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        stream.close()

def _exclusive(function):
    @wraps(function)
    def wrapped(install_root, *args, **kwargs):
        with _maintenance(install_root):
            return function(install_root, *args, **kwargs)
    return wrapped

def plan(install_root, bundle_dir, baseline_dir=None):
    root, bundle = _path(install_root), _path(bundle_dir)
    baseline_dir = _path(baseline_dir) if baseline_dir else None
    _separate(root, bundle)
    if baseline_dir:
        _separate(root, baseline_dir)
    _access_gate(root)
    _tree_paths(bundle)
    _manifest.verify(bundle)
    next_release = json.loads((bundle / "release-manifest.json").read_text(encoding="utf-8-sig"))
    previous = _baseline(root, baseline_dir)
    if any(next_release.get("metadata", {}).get(key) != value for key, value in PINS.items()):
        raise UpdateError("Unsupported runtime pins")
    if _runtime_rows(previous) != _runtime_rows(next_release):
        raise UpdateError("Runtime or dependency changes require a separate upgrade")
    _migration_chain(bundle, previous, next_release)
    _tree_paths(root)
    _installed_source(root, previous)
    _installed_runtime(root, bundle)
    _, cfg = _config(root)
    _stopped(root, cfg)
    rows = _inventory(root)
    for prefix in (".saw-r-", ".saw-k-"):
        sibling = root.with_name(prefix + "0" * 12)
        _preflight_rows(sibling, rows)
        _preflight_copy(bundle / "app", sibling / "app")
    _preflight_copy(bundle / "app", root / "app")
    size = sum(row.get("bytes", 0) for row in rows)
    app_size = sum(row["bytes"] for row in next_release["files"] if row["path"].startswith("app/"))
    needed = size + app_size + sum(row.get("bytes", 0) for row in rows if row["path"].startswith("app/var/")) + 64 * 1024 * 1024
    if shutil.disk_usage(root.parent).free < needed:
        raise UpdateError("Insufficient free space for a complete recovery point and staged application")
    return {"status": "ready_stopped", "install_root": str(root), "snapshot_bytes": size,
            "required_free_bytes": needed, "free_bytes": shutil.disk_usage(root.parent).free,
            "target_manifest_sha256": _manifest.digest(bundle / "release-manifest.json")}

@_exclusive
def apply(install_root, bundle_dir, recovery_point, baseline_dir=None):
    root, bundle, recovery = _path(install_root), _path(bundle_dir), _path(recovery_point, existing=False)
    _separate(root, bundle, recovery)
    if baseline_dir:
        _separate(recovery, _path(baseline_dir))
    if recovery.exists() or not recovery.parent.is_dir() or root.drive.lower() != recovery.drive.lower():
        raise UpdateError("RecoveryPoint must be a fresh directory on the installation volume")
    result = plan(root, bundle, baseline_dir)
    if shutil.disk_usage(recovery.parent).free < result["required_free_bytes"]:
        raise UpdateError("Insufficient free space for a complete recovery point and staged application")
    _, cfg = _config(root)
    before = _inventory(root)
    snapshot, stage = recovery / "installation", recovery / "new-app"
    _preflight_rows(snapshot, before)
    _preflight_copy(root / "app", recovery / "previous-app")
    _preflight_copy(bundle / "app", stage)
    _windows_path_limit(stage / ".env", directory=False)
    if (root / "app/var").exists():
        _preflight_copy(root / "app/var", stage / "var")
    for name in ("recovery-point.json", "update-result.json", "restore-result-" + "0" * 12 + ".json"):
        _preflight_json(recovery / name)
    for name in ("saw-ctl.ps1", "installed-release-manifest.json", ".saw-u-" + "0" * 12):
        _windows_path_limit(root / name, directory=False)
    _private_directory(recovery)
    _copy_tree(root, snapshot)
    _stopped(root, cfg)
    if _inventory(root) != before or _inventory(snapshot) != before:
        raise UpdateError("Installation changed during the recovery copy")
    receipt = {"schema": "saw.cold-recovery/1", "created_at": datetime.now(UTC).isoformat(),
               "install_root": str(root), "files": before,
               "target_manifest_sha256": result["target_manifest_sha256"]}
    _json(recovery / "recovery-point.json", receipt)
    _stage_public_app(bundle / "app", stage, root / "app")
    _copy_file(root / "app/.env", stage / ".env")
    if (root / "app/var").exists():
        _copy_tree(root / "app/var", stage / "var")
    _access_gate(stage, relative_base=Path("app"), service_mode=False)
    _tree_paths(bundle)
    _manifest.verify(bundle)
    _stopped(root, cfg)
    if _inventory(root) != before:
        raise UpdateError("Installation changed before application switch")
    old_app = recovery / "previous-app"
    os.rename(root / "app", old_app)
    try:
        os.rename(stage, root / "app")
    except BaseException:
        os.rename(old_app, root / "app")
        raise
    for source, target in ((bundle / "app/deploy/windows/saw-ctl.ps1", root / "saw-ctl.ps1"),
                           (bundle / "release-manifest.json", root / "installed-release-manifest.json")):
        temporary = root / (".saw-u-" + uuid.uuid4().hex[:12])
        _copy_public_file(source, temporary, _acl(target) if target.exists() else None)
        os.replace(temporary, target)
    result.update(status="applied_stopped_schema_pending", recovery_point=str(recovery),
                  next_step="Start the installation to migrate. Restore the complete recovery point if acceptance fails.")
    _json(recovery / "update-result.json", result)
    return result

@_exclusive
def restore(install_root, recovery_point, *, confirm=False):
    if not confirm:
        raise UpdateError("Explicit ConfirmPointInTimeRecovery is required")
    root, recovery = _path(install_root), _path(recovery_point)
    _separate(root, recovery)
    _access_gate(root)
    receipt = json.loads((recovery / "recovery-point.json").read_text(encoding="utf-8"))
    if receipt.get("schema") != "saw.cold-recovery/1" or Path(receipt["install_root"]) != root:
        raise UpdateError("Recovery point belongs to a different absolute installation path")
    snapshot = recovery / "installation"
    _access_gate(snapshot)
    if _inventory(snapshot) != receipt["files"]:
        raise UpdateError("Recovery point files or access policies changed")
    _tree_paths(root)
    _, cfg = _config(root)
    _stopped(root, cfg)
    if shutil.disk_usage(root.parent).free < sum(row.get("bytes", 0) for row in receipt["files"]) + 64 * 1024 * 1024:
        raise UpdateError("Insufficient free space to stage complete recovery")
    token, stage, retained = _restore_paths(root)
    _preflight_rows(stage, receipt["files"])
    _preflight_rows(root, receipt["files"])
    _preflight_copy(root, retained)
    result_path = recovery / ("restore-result-" + token + ".json")
    _preflight_json(result_path)
    _copy_tree(snapshot, stage)
    if _inventory(stage) != receipt["files"]:
        raise UpdateError("Recovery staging verification failed")
    _stopped(root, cfg)
    _preflight_copy(root, retained)
    os.rename(root, retained)
    try:
        os.rename(stage, root)
    except BaseException:
        os.rename(retained, root)
        raise
    result = {"status": "restored_stopped", "install_root": str(root),
              "retained_installation": str(retained), "recovery_point": str(recovery),
              "newer_records": "Preserved in retained installation; reconciliation is explicit."}
    _json(result_path, result)
    return result

def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("plan", "apply", "restore"))
    parser.add_argument("--install-root", required=True, type=Path)
    parser.add_argument("--bundle-dir", type=Path)
    parser.add_argument("--baseline-bundle-dir", type=Path)
    parser.add_argument("--recovery-point", type=Path)
    parser.add_argument("--confirm-point-in-time-recovery", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.action == "restore":
            if not args.recovery_point:
                raise UpdateError("RecoveryPoint is required")
            result = restore(args.install_root, args.recovery_point, confirm=args.confirm_point_in_time_recovery)
        else:
            if not args.bundle_dir:
                raise UpdateError("BundleDir is required")
            if args.action == "plan":
                result = plan(args.install_root, args.bundle_dir, args.baseline_bundle_dir)
            else:
                if not args.recovery_point:
                    raise UpdateError("A fresh RecoveryPoint is required")
                result = apply(args.install_root, args.bundle_dir, args.recovery_point, args.baseline_bundle_dir)
        print(json.dumps(result, ensure_ascii=True))
        return 0
    except (UpdateError, _manifest.BundleError) as error:
        print("Update/recovery refused: " + str(error), file=sys.stderr)
        return 1
    except Exception:
        print("Update/recovery failed. No success was reported; preserve all recovery directories.", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
