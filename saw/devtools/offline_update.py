"""Cold updates; run directly from verified media with an isolated interpreter."""
from __future__ import annotations
import argparse
import ast
from contextlib import contextmanager
from functools import wraps
import base64
import ctypes
import csv
import io
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
    def __init__(self, message, *, code=None, diagnostics=None):
        self.code = code
        self.diagnostics = diagnostics
        super().__init__(message)

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

def _preflight_json(path, *, unique=False):
    _windows_path_limit(path, directory=False)
    suffix = "." + "0" * 12 + ".writing" if unique else ".writing"
    _windows_path_limit(path.with_name(path.name + suffix), directory=False)

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


_ACCESS_METADATA_FAILURES = {
    2: "access_metadata_file_missing",
    3: "access_metadata_path_missing",
    5: "access_metadata_denied",
    32: "access_metadata_sharing_violation",
    33: "access_metadata_lock_violation",
}
_TRANSIENT_ACCESS_REASONS = frozenset(_ACCESS_METADATA_FAILURES[code] for code in (2, 3, 32, 33))


def _access_metadata(path):
    """Read owner and every ordinary DACL ACE; never read file contents."""
    from ctypes import wintypes
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.GetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                       ctypes.POINTER(wintypes.DWORD)]
    advapi.GetFileSecurityW.restype = wintypes.BOOL
    needed = wintypes.DWORD()
    sized = advapi.GetFileSecurityW(str(path), 5, None, 0, ctypes.byref(needed))
    size_error = ctypes.get_last_error()  # Capture before allocation or another Windows call.
    if not needed.value or (not sized and size_error != 122):  # ERROR_INSUFFICIENT_BUFFER is expected.
        raise UpdateError("Cannot inspect installation access policy",
                          code=_ACCESS_METADATA_FAILURES.get(size_error, "access_metadata_unreadable"))
    descriptor = ctypes.create_string_buffer(needed.value)
    read = advapi.GetFileSecurityW(str(path), 5, descriptor, needed.value, ctypes.byref(needed))
    read_error = ctypes.get_last_error()
    if not read:
        raise UpdateError("Cannot inspect installation access policy",
                          code=_ACCESS_METADATA_FAILURES.get(read_error, "access_metadata_unreadable"))
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
            raise UpdateError("Unsupported installation access policy ACE type", code="unsupported_access_ace")
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

def _safe_access_path(relative):
    """Keep diagnostics useful for runtime files without naming private records."""
    name = relative.as_posix()
    fixed = {".", "app", "data", "logs", "models", "secrets", "tls", "run",
             "saw-ctl.json", "saw-ctl.ps1", ".saw-install-state.json",
             "installed-release-manifest.json", "recovery-point.json",
             "update-result.json", "state.json", "installation", "previous-app", "new-app",
             "app/.env", "data/postgresql", "logs/postgresql"}
    runtime = ("app/saw/", "app/deploy/", "venv/", "pgsql/", "llm-runtime/",
               "opensearch-2.19.6/bin/", "opensearch-2.19.6/lib/",
               "opensearch-2.19.6/jdk/", "opensearch-2.19.6/plugins/",
               "opensearch-2.19.6/config/")
    safe = len(name) <= 240 and re.fullmatch(r"[A-Za-z0-9_./@+ -]+", name) and ".." not in name.split("/")
    if safe and (name in fixed or name.startswith(runtime) or
                 name in {prefix.rstrip("/") for prefix in runtime}):
        return name
    return "<private-data>"


def _safe_access_sid(sid, current):
    if sid == current:
        return "current_user"
    return sid if sid in {"S-1-1-0", "S-1-3-4", "S-1-5-11", "S-1-5-18",
                          "S-1-5-20", "S-1-5-32-544", "S-1-5-32-545"} else "other"


def _owner_rights_service_change(source_owner, target_owner, entries):
    """Detect changed service access when identical OWNER RIGHTS ACEs change owner."""
    service = "S-1-5-20"
    if (source_owner == target_owner or service not in (source_owner, target_owner) or
            not any(sid == "S-1-3-4" and not flags & 8 for _, flags, _, sid in entries)):
        return None
    # Everyone, Authenticated Users and Service follow the service logon identity.
    # Builtin Users membership is configurable; its deny ACE cannot prove safety.
    principals = {service, "S-1-1-0", "S-1-5-11", "S-1-5-6"}
    def granted(owner, optional=None):
        active = principals | ({optional} if optional is not None else set())
        remaining, allowed = 0x1F01FF, 0
        for kind, flags, mask, sid in entries:
            if flags & 8:  # INHERIT_ONLY_ACE does not authorize this object.
                continue
            effective = owner if sid == "S-1-3-4" else sid
            if effective not in active:
                continue
            # Map generic file rights before comparing effective grants.
            expanded = mask & 0x1F01FF
            for generic, specific in ((0x10000000, 0x1F01FF), (0x80000000, 0x120089),
                                      (0x40000000, 0x120116), (0x20000000, 0x1200A0)):
                if mask & generic:
                    expanded |= specific
            applicable = expanded & remaining
            if kind == 0:
                allowed |= applicable
            remaining &= ~applicable
        return allowed
    def difference(optional=None):
        before, after = granted(source_owner, optional), granted(target_owner, optional)
        if before != after:
            return {"reason": "owner_rights_service_change", "sid": service,
                    "source_rights": before, "copied_rights": after}
        return None
    changed = difference()
    if changed:
        return changed
    optional = {sid for kind, flags, _, sid in entries
                if kind == 1 and not flags & 8 and sid not in principals and sid != "S-1-3-4"}
    if len(optional) > 32:
        return {"reason": "owner_rights_service_change", "sid": service,
                "comparison": "unproven_group_membership"}
    # For each access bit, the earliest matching ACE decides its grant. Any
    # combination of optional deny groups has one earliest such group; testing
    # each alone covers that decision without a powerset or token modification.
    for sid in sorted(optional):
        changed = difference(sid)
        if changed:
            return changed
    return None


def _assert_copy_owner_semantics(source, destination):
    if os.name != "nt":
        return
    source_owner, entries = _access_metadata(source)
    target_owner, _ = _access_metadata(destination)
    violation = _owner_rights_service_change(source_owner, target_owner, entries)
    if violation:
        raise UpdateError("Copying this owner-dependent policy would change service access",
                          code="owner_semantics_unpreserved", diagnostics={
                          "scope": "copy", "checked": 1, "violations": 1,
                          "items": [{"path": "<private-data>", **violation}], "truncated": False})


def _access_violations(path, current, relative=Path("."), service_mode=False, private=False,
                       copy_owner=None):
    """Evaluate OWNER RIGHTS as the validated actual owner, never as Everyone."""
    try:
        owner, entries = _access_metadata(path)
    except (UpdateError, OSError) as error:
        code = getattr(error, "code", None)
        reason = ("unsupported_ace" if code == "unsupported_access_ace" else
                  code if code in _ACCESS_METADATA_FAILURES.values() else "access_metadata_unreadable")
        return [{"reason": reason}]
    trusted = {current, "S-1-5-18"}
    if not private:
        trusted.add("S-1-5-32-544")
    mask, inherit, service_owner = _network_service_scope(relative) if service_mode and not private else (0, False, False)
    violations = []
    if owner not in trusted and not (owner == "S-1-5-20" and service_owner):
        violations.append({"reason": "untrusted_owner", "sid": _safe_access_sid(owner, current)})
    for kind, flags, rights, sid in entries:
        if kind == 1:
            continue
        # OWNER RIGHTS applies to the actual owner, including scoped service owners.
        effective = owner if sid == "S-1-3-4" else sid
        if effective in trusted:
            continue
        if (effective != "S-1-5-20" or not mask or rights & ~mask or
                (not inherit and flags & 0x03)):
            violations.append({"reason": "untrusted_allow", "sid": _safe_access_sid(sid, current),
                               "effective_sid": _safe_access_sid(effective, current),
                               "rights": int(rights), "flags": int(flags)})
    if copy_owner is not None:
        violation = _owner_rights_service_change(owner, copy_owner, entries)
        if violation:
            violations.append(violation)
    return violations


def _access_gate(root, *, relative_base=Path("."), service_mode=None, snapshot_root=None,
                 check_copy_semantics=False, retry_transient=False):
    """Verify every policy; opt-in live retries always start a complete fresh scan."""
    # Cold snapshots and all callers that do not explicitly opt in remain strict.
    limit = 3 if retry_transient and snapshot_root is None else 1
    for attempt in range(1, limit + 1):
        report = {"scope": "snapshot" if snapshot_root is not None else "installation",
                  "checked": 0, "violations": 0, "items": [], "truncated": False, "attempts": attempt}
        if os.name != "nt":
            return report
        if snapshot_root is not None and snapshot_root != root / "installation":
            raise UpdateError("Invalid snapshot access policy boundary", code="unsafe_access")
        try:
            paths = _tree_paths(root)
        except (UpdateError, OSError) as error:
            missing = getattr(error, "code", None) == "access_enumeration_missing"
            reason = "access_enumeration_missing" if missing else "access_enumeration_failed"
            report.update(violations=1, items=[{"path": ".", "reason": reason}])
            if missing and attempt < limit:
                continue
            raise UpdateError("Installation access policy inspection failed", code="unsafe_access",
                              diagnostics=report) from None
        # Token failures are never transient tree failures, including a missing shell executable.
        try:
            current = _ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value")
            copy_owner = (_ps("[Security.Principal.WindowsIdentity]::GetCurrent().Owner.Value")
                          if check_copy_semantics else None)
            if copy_owner is not None and not re.fullmatch(r"S-1-[0-9-]+", copy_owner):
                raise UpdateError("Cannot inspect the current token owner")
        except (UpdateError, OSError):
            report.update(violations=1, items=[{"path": ".", "reason": "access_enumeration_failed"}])
            raise UpdateError("Installation access policy inspection failed", code="unsafe_access",
                              diagnostics=report) from None
        scoped_mode = ((root / "service/saw-postgresql.exe").is_file()
                       if service_mode is None else service_mode)
        snapshot_service = bool(snapshot_root is not None and (snapshot_root / "service/saw-postgresql.exe").is_file())
        semantic_change, transient_only = False, True
        for path in paths:
            relative = relative_base / path.relative_to(root)
            scoped_service = scoped_mode
            if snapshot_root is not None:
                scoped_service = False
                if _inside(path, snapshot_root):
                    relative = path.relative_to(snapshot_root)
                    scoped_service = snapshot_service
            report["checked"] += 1
            violations = _access_violations(path, current, relative, scoped_service, copy_owner=copy_owner)
            for violation in violations:
                semantic_change |= violation["reason"] == "owner_rights_service_change"
                transient_only &= violation["reason"] in _TRANSIENT_ACCESS_REASONS
                report["violations"] += 1
                if len(report["items"]) < 30:
                    report["items"].append({"path": _safe_access_path(relative), **violation})
        report["truncated"] = report["violations"] > len(report["items"])
        if report["violations"]:
            # A real violation anywhere in the full scan prohibits retry, even beyond the display cap.
            if transient_only and attempt < limit:
                continue
            message = ("Copying an owner-dependent policy would change service access" if semantic_change else
                       "Installation access policy requires administrator review")
            raise UpdateError(message, code="owner_semantics_unpreserved" if semantic_change else "unsafe_access",
                              diagnostics=report)
        return report


@contextmanager
def _private_security_attributes(*, directory=False):
    """Supply the current user as owner before any private bytes can be written."""
    from ctypes import wintypes
    class SecurityAttributes(ctypes.Structure):
        _fields_ = [("length", wintypes.DWORD), ("descriptor", ctypes.c_void_p),
                    ("inherit_handle", wintypes.BOOL)]
    current = _ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value")
    if not re.fullmatch(r"S-\d+(?:-\d+)+", current):
        raise UpdateError("Cannot identify private object owner", code="unsafe_state_directory")
    inheritance = "OICI" if directory else ""
    policy = f"O:{current}D:P(A;{inheritance};FA;;;{current})(A;{inheritance};FA;;;SY)"
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    descriptor = ctypes.c_void_p()
    if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            policy, 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        yield SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
    finally:
        kernel.LocalFree(descriptor)


def _private_file_fd(path, flags):
    """Create a private file exclusively, independent of the token default owner."""
    if os.name != "nt":
        return os.open(path, flags, 0o600)
    from ctypes import wintypes
    import msvcrt
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    with _private_security_attributes() as attributes:
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                      ctypes.POINTER(type(attributes)), wintypes.DWORD,
                                      wintypes.DWORD, wintypes.HANDLE]
        access = 0xC0000000 if flags & os.O_RDWR else 0x40000000
        handle = kernel.CreateFileW(str(path), access, 0, ctypes.byref(attributes), 1, 0x80, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
    try:
        mode = os.O_RDWR if flags & os.O_RDWR else os.O_WRONLY
        return msvcrt.open_osfhandle(handle, mode | os.O_BINARY)
    except BaseException:
        kernel.CloseHandle(handle)
        raise


def _private_directory(path):
    _windows_path_limit(path, directory=True)
    if os.name != "nt":
        path.mkdir(mode=0o700)
        return
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    with _private_security_attributes(directory=True) as attributes:
        kernel.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(type(attributes))]
        kernel.CreateDirectoryW.restype = wintypes.BOOL
        if not kernel.CreateDirectoryW(str(path), ctypes.byref(attributes)):
            raise ctypes.WinError(ctypes.get_last_error())


def _tree_paths(root):
    _windows_path_limit(root, directory=True)
    _path(root)
    paths = [root]
    def enumeration_failed(error):
        raise error
    try:
        for parent, directories, files in os.walk(root, followlinks=False, onerror=enumeration_failed):
            for name in directories + files:
                path = Path(parent) / name
                _windows_path_limit(path, directory=name in directories)
                if path.is_symlink() or getattr(path.lstat(), "st_file_attributes", 0) & 0x400:
                    raise UpdateError("Reparse points are not supported")
                _manifest.safe_relative(path.relative_to(root).as_posix())
                paths.append(path)
    except OSError as error:
        native = getattr(error, "winerror", None)
        missing = (native in (2, 3) if native is not None else
                   isinstance(error, FileNotFoundError) or error.errno == 2)
        raise UpdateError("Cannot enumerate every directory; complete verification is required",
                          code="access_enumeration_missing" if missing else None) from None
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
    _assert_copy_owner_semantics(source, destination)
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
            _assert_copy_owner_semantics(original, target)
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


def _json(path, data, *, unique=False):
    _preflight_json(path, unique=unique)
    suffix = "." + uuid.uuid4().hex[:12] + ".writing" if unique else ".writing"
    temp = path.with_name(path.name + suffix)
    with open(temp, "x", encoding="utf-8", opener=_private_file_fd) as stream:
        json.dump(data, stream, ensure_ascii=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)

def _config(root, *, verified_application_config=None, verified_installation=None):
    source = root
    if verified_installation is not None:
        if root.exists() or verified_application_config is not None:
            raise UpdateError("Verified installation fallback requires a missing installation")
        source = _path(verified_installation)
    application_config = source / "app/.env"
    if verified_application_config is not None:
        # Only restore callers that already verified the full recovery inventory may
        # supply this fallback for the app-directory rename interruption window.
        if (root / "app").exists():
            raise UpdateError("Recovery configuration fallback requires a missing application directory")
        application_config = _path(verified_application_config, existing=False)
        if not application_config.is_file() or application_config.name != ".env":
            raise UpdateError("Invalid verified recovery configuration")
    values = {}
    for raw in application_config.read_text(encoding="utf-8-sig").splitlines():
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
    cfg = json.loads((source / "saw-ctl.json").read_text(encoding="utf-8-sig"))
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
    pg = source / "data/postgresql"
    if (pg / "PG_VERSION").read_text().strip() != "16":
        raise UpdateError("PostgreSQL major version differs")
    for config_file in (pg / "postgresql.conf", pg / "postgresql.auto.conf"):
        if not config_file.exists():
            continue
        for line in config_file.read_text(encoding="utf-8-sig").splitlines():
            if re.match(r"^\s*(include(?:_if_exists|_dir)?|data_directory|hba_file|ident_file|external_pid_file|archive_command|restore_command)\b", line):
                raise UpdateError("Customized PostgreSQL storage configuration is not supported")
    config = (source / "opensearch-2.19.6/config/opensearch.yml").read_text(encoding="utf-8-sig")
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

# One reviewed additive dependency transition; every other runtime change stays closed.
_XLSXWRITER_UPGRADE = {
    "old_requirements": {"path": "app/deploy/windows/requirements.txt", "bytes": 1421,
        "sha256": "ce97ae90f25093ba9f574d41ede60457d8cbd3a2287cd48cdb035d2be15b5f1f"},
    "new_requirements": {"path": "app/deploy/windows/requirements.txt", "bytes": 1440,
        "sha256": "bf75190bc504caaffca54e3a164d4c20d63ebcbc8d50d9a17647893861149c38"},
    "wheel": {"path": "wheels/xlsxwriter-3.2.9-py3-none-any.whl", "bytes": 175315,
        "sha256": "9a5db42bc5dff014806c58a20b9eae7322a134abb6fce3c92c181bfb275ec5b3"},
}


def _runtime_transition(previous, candidate):
    if any(document.get("metadata", {}).get(key) != value
           for document in (previous, candidate) for key, value in PINS.items()):
        raise UpdateError("Unsupported runtime pins", code="runtime_upgrade_unsupported")
    old_rows, new_rows = _runtime_rows(previous), _runtime_rows(candidate)
    old = {row["path"]: row for row in old_rows}
    new = {row["path"]: row for row in new_rows}
    if len(old) != len(old_rows) or len(new) != len(new_rows):
        raise UpdateError("Duplicate runtime paths", code="runtime_upgrade_unsupported")
    if old == new:
        return {"kind": "unchanged", "added_wheels": []}
    approved = _XLSXWRITER_UPGRADE
    requirement, wheel = approved["old_requirements"]["path"], approved["wheel"]["path"]
    if (old.get(requirement) != approved["old_requirements"] or
            new.get(requirement) != approved["new_requirements"] or
            new.get(wheel) != approved["wheel"] or set(new) - set(old) != {wheel} or
            set(old) - set(new) or any(old[path] != new[path] for path in old if path != requirement)):
        raise UpdateError("Runtime or dependency changes require a separate upgrade", code="runtime_upgrade_unsupported")
    return {"kind": "xlsxwriter-3.2.9", "added_wheels": [wheel]}


def _runtime_marker(root, bundle, profile, *, logical_root=None, required=False, allow_pending_addition=False):
    path = root / "venv/.saw-python-runtime.json"
    if not path.exists() and not required:
        return None
    _path(path, existing=False)
    if not path.is_file() or path.stat().st_nlink != 1 or path.stat().st_size > 16384:
        raise UpdateError("Invalid Python ownership marker", code="runtime_integrity_failed")
    try:
        marker = json.loads(path.read_text(encoding="utf-8-sig"))
    except (ValueError, OSError):
        raise UpdateError("Invalid Python ownership marker", code="runtime_integrity_failed") from None
    rows = {row["path"]: row for row in profile["files"]}
    expected = {"schema": "saw.python-runtime/1", "install_root": str(logical_root or root),
        "python": "3.12.10", "architecture": "amd64", "state": "ready",
        "archive_sha256": rows["python/python-3.12.10-embed-amd64.zip"]["sha256"],
        "bootstrap_sha256": rows["bootstrap/pip-25.1.1-py3-none-any.whl"]["sha256"],
        "requirements_sha256": rows["app/deploy/windows/requirements.txt"]["sha256"]}
    if allow_pending_addition:
        candidate = json.loads((bundle / "release-manifest.json").read_text(encoding="utf-8-sig"))
        if _runtime_transition(profile, candidate)["added_wheels"]:
            if marker.get("requirements_sha256") == _XLSXWRITER_UPGRADE["new_requirements"]["sha256"]:
                expected["requirements_sha256"] = marker["requirements_sha256"]
    if marker != expected:
        raise UpdateError("Python ownership marker differs from its verified profile", code="runtime_integrity_failed")
    return marker


def _dependency_files(bundle, logical_root):
    """Map only the byte-pinned pure-Python wheel; never import or execute it."""
    row = _XLSXWRITER_UPGRADE["wheel"]
    package = _path(bundle / row["path"], existing=False)
    if package.stat().st_size != row["bytes"] or _manifest.digest(package) != row["sha256"]:
        raise UpdateError("Approved additive wheel changed", code="runtime_integrity_failed")
    files = {}
    with zipfile.ZipFile(package) as archive:
        for entry in archive.infolist():
            if entry.is_dir():
                continue
            name = _manifest.safe_relative(entry.filename)
            if stat.S_ISLNK(entry.external_attr >> 16):
                raise UpdateError("Unsupported additive wheel member")
            data = archive.read(entry)
            if name == "xlsxwriter-3.2.9.data/scripts/vba_extract.py":
                if not data.startswith(b"#!python\n"):
                    raise UpdateError("Unsupported wheel installation layout")
                interpreter = os.fsencode(logical_root / "venv/Scripts/python.exe")
                if any(char in interpreter for char in (b"\0", b"\r", b"\n")):
                    raise UpdateError("Unsupported wheel installation layout")
                name = "bin/vba_extract.py"
                data = b"#!" + interpreter + os.linesep.encode("ascii") + data.partition(b"\n")[2]
            elif not name.startswith(("xlsxwriter/", "xlsxwriter-3.2.9.dist-info/")):
                raise UpdateError("Unsupported additive wheel member")
            destination = "venv/Lib/site-packages/" + name
            if destination in files:
                raise UpdateError("Duplicate additive wheel destination")
            files[destination] = data
    if not all(name in files for name in ("venv/Lib/site-packages/xlsxwriter/__init__.py",
            "venv/Lib/site-packages/bin/vba_extract.py", "venv/Lib/site-packages/xlsxwriter-3.2.9.dist-info/RECORD")):
        raise UpdateError("Incomplete additive wheel")
    # RECORD describes installed destinations and the rewritten script, not wheel .data paths.
    record = "venv/Lib/site-packages/xlsxwriter-3.2.9.dist-info/RECORD"
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for relative, data in sorted(files.items()):
        if relative != record:
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
            writer.writerow((relative.removeprefix("venv/Lib/site-packages/"), "sha256=" + digest, len(data)))
    writer.writerow((record.removeprefix("venv/Lib/site-packages/"), "", ""))
    files[record] = output.getvalue().encode("utf-8")
    return files


def _stage_dependency(root, bundle, profile, recovery):
    candidate = json.loads((bundle / "release-manifest.json").read_text(encoding="utf-8-sig"))
    if not _runtime_transition(profile, candidate)["added_wheels"]:
        return None
    marker = _runtime_marker(root, bundle, profile, required=True)
    files = _dependency_files(bundle, root)
    stage = recovery / "new-dependency"
    for relative in files:
        _windows_path_limit(root / relative, directory=False)
        _windows_path_limit(stage / relative, directory=False)
        if os.path.lexists(root / relative):
            raise UpdateError("Additive dependency destination already exists")
    _private_directory(stage)
    for relative, data in files.items():
        target = stage / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "xb", opener=_private_file_fd) as stream:
            stream.write(data)
    if {p.relative_to(stage).as_posix(): p.read_bytes() for p in _tree_paths(stage) if p.is_file()} != files:
        raise UpdateError("Staged dependency changed")
    marker = dict(marker, requirements_sha256=_XLSXWRITER_UPGRADE["new_requirements"]["sha256"])
    return {"stage": stage, "files": files, "marker": marker}


def _publish_dependency(root, staged):
    if staged is None:
        return
    for relative, data in staged["files"].items():
        source, destination = staged["stage"] / relative, root / relative
        _path(source, existing=False)
        _path(destination, existing=False)
        if os.path.lexists(destination) or source.read_bytes() != data:
            raise UpdateError("Additive dependency changed before publication")
    policy = _acl(root / "venv/Lib/site-packages/pip/__init__.py")
    for relative in staged["files"]:
        source, destination = staged["stage"] / relative, root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        _set_acl(source, policy)
        if _acl(source) != policy:
            raise UpdateError("Additive dependency access policy changed")
    for relative in staged["files"]:
        source, destination = staged["stage"] / relative, root / relative
        if os.path.lexists(destination) or source.read_bytes() != staged["files"][relative]:
            raise UpdateError("Additive dependency changed before atomic publication")
        # Recovery is on the installation volume. Never expose a partially copied live file.
        os.rename(source, destination)
    _json(root / "venv/.saw-python-runtime.json", staged["marker"])


def _installed_source(root, baseline):
    expected = {}
    for row in baseline["files"]:
        rel = _manifest.safe_relative(row["path"])
        _manifest.public_path(rel)
        if rel.startswith(("app/", "llm-runtime/")):
            expected[rel] = row
            path = root / rel
            if not path.is_file() or path.stat().st_size != row["bytes"] or _manifest.digest(path) != row["sha256"]:
                raise UpdateError("Installed application/runtime differs from its release; reconcile local edits first",
                                  code="source_changed", diagnostics={"location": rel, "expected": "original release file", "actual": "missing or changed"})
    for path in _tree_paths(root / "app")[1:]:
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        parts = path.relative_to(root / "app").parts
        if rel == "app/.env" or parts[0] == "var" or "__pycache__" in parts:
            continue
        if rel not in expected:
            raise UpdateError("Unexpected installed application file; reconcile local files first",
                              code="source_changed", diagnostics={"location": "<unlisted-application-file>", "expected": "release files only", "actual": "unlisted file"})

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

def _installed_runtime(root, bundle, profile=None, *, logical_root=None, allow_pending_addition=False):
    _installed_service_wrappers(root, bundle)
    logical_root = logical_root or root
    selected = None
    optional = {}
    if profile is not None:
        candidate = json.loads((bundle / "release-manifest.json").read_text(encoding="utf-8-sig"))
        transition = _runtime_transition(profile, candidate)
        selected = {row["path"] for row in _runtime_rows(profile)}
        if allow_pending_addition and transition["added_wheels"]:
            optional = _dependency_files(bundle, logical_root)
    marker_profile = profile or json.loads((bundle / "release-manifest.json").read_text(encoding="utf-8-sig"))
    marker_rows = {row["path"]: row for row in _runtime_rows(marker_profile)}
    required_marker = (marker_rows.get(_XLSXWRITER_UPGRADE["wheel"]["path"]) == _XLSXWRITER_UPGRADE["wheel"]
                       or bool(profile is not None and transition["added_wheels"]))
    _runtime_marker(root, bundle, marker_profile, logical_root=logical_root, required=required_marker,
                    allow_pending_addition=allow_pending_addition)
    expected = set()
    def archive(relative, mapper):
        with zipfile.ZipFile(bundle / relative) as stream:
            for info in stream.infolist():
                if info.is_dir():
                    continue
                name = _manifest.safe_relative(info.filename)
                target_script = (
                    relative == "wheels/xlsxwriter-3.2.9-py3-none-any.whl"
                    and name == "xlsxwriter-3.2.9.data/scripts/vba_extract.py")
                destination = ("venv/Lib/site-packages/bin/vba_extract.py"
                               if target_script else mapper(name))
                if destination is None:
                    continue
                path = root / destination
                with stream.open(info) as content:
                    if target_script:
                        # pip 25.1.1 fix_script rewrites only the first line for --target.
                        if content.readline(10) != b"#!python\n":
                            raise UpdateError("Unsupported wheel installation layout")
                        interpreter = os.fsencode(logical_root / "venv/Scripts/python.exe")
                        if any(char in interpreter for char in (b"\0", b"\r", b"\n")):
                            raise UpdateError("Unsupported wheel installation layout")
                        digest = hashlib.sha256(b"#!" + interpreter + os.linesep.encode("ascii"))
                        wanted = hashlib.file_digest(content, lambda digest=digest: digest).hexdigest()
                    else:
                        wanted = hashlib.file_digest(content, "sha256").hexdigest()
                if not path.is_file() or _manifest.digest(path) != wanted:
                    raise UpdateError("Installed runtime or dependency differs from the pinned media",
                                      code="runtime_integrity_failed", diagnostics={"location": destination, "expected": "pinned runtime file", "actual": "missing or changed"})
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
            relative = package.relative_to(bundle).as_posix()
            if selected is None or relative in selected:
                archive(relative, wheel)
    for folder in ("venv/Scripts", "venv/Lib/site-packages", "pgsql", "opensearch-2.19.6"):
        for path in _tree_paths(root / folder):
            if not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            if relative in optional:
                if path.read_bytes() != optional[relative]:
                    raise UpdateError("Partial additive dependency differs from pinned media", code="runtime_integrity_failed")
                continue
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
def _maintenance(root, *, allow_missing=False):
    root = _path(root, existing=not allow_missing)
    if not root.parent.is_dir():
        raise UpdateError("Installation parent is missing")
    lock_path = _path(root.with_name("." + root.name + ".saw-maintenance.lock"), existing=False)
    if lock_path.exists() and (not lock_path.is_file() or lock_path.stat().st_nlink != 1):
        raise UpdateError("Unsafe installation maintenance lock")
    _windows_path_limit(lock_path, directory=False)
    try:
        stream = (lock_path.open("r+b") if lock_path.exists() else
                  open(lock_path, "x+b", opener=_private_file_fd))
    except OSError:
        raise UpdateError("Another installation maintenance operation is active or its lock is unavailable",
                          code="maintenance_busy") from None
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
        restoring = function.__name__ == "restore"
        if restoring and not kwargs.get("confirm", False):
            raise UpdateError("Explicit ConfirmPointInTimeRecovery is required")
        with _maintenance(install_root, allow_missing=restoring):
            return function(install_root, *args, **kwargs)
    return wrapped

def plan(install_root, bundle_dir, baseline_dir=None):
    root, bundle = _path(install_root), _path(bundle_dir)
    baseline_dir = _path(baseline_dir) if baseline_dir else None
    _separate(root, bundle)
    if baseline_dir:
        _separate(root, baseline_dir)
    _access_gate(root, check_copy_semantics=True)
    _tree_paths(bundle)
    _manifest.verify(bundle)
    next_release = json.loads((bundle / "release-manifest.json").read_text(encoding="utf-8-sig"))
    previous = _baseline(root, baseline_dir)
    if any(next_release.get("metadata", {}).get(key) != value for key, value in PINS.items()):
        raise UpdateError("Unsupported runtime pins")
    transition = _runtime_transition(previous, next_release)
    _migration_chain(bundle, previous, next_release)
    _tree_paths(root)
    _installed_source(root, previous)
    _installed_runtime(root, bundle, profile=previous) if transition["added_wheels"] else _installed_runtime(root, bundle)
    if transition["added_wheels"]:
        _runtime_marker(root, bundle, previous, required=True)
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
    dependency_bytes = (2 * sum(map(len, _dependency_files(bundle, root).values())) + 16384
                        if transition["added_wheels"] else 0)
    needed = size + app_size + dependency_bytes + sum(row.get("bytes", 0) for row in rows if row["path"].startswith("app/var/")) + 64 * 1024 * 1024
    if shutil.disk_usage(root.parent).free < needed:
        raise UpdateError("Insufficient free space for a complete recovery point and staged application")
    return {"status": "ready_stopped", "install_root": str(root), "snapshot_bytes": size,
            "required_free_bytes": needed, "free_bytes": shutil.disk_usage(root.parent).free,
            "target_manifest_sha256": _manifest.digest(bundle / "release-manifest.json")}

def _write_cold_snapshot(root, recovery, cfg, before, *, target_manifest_sha256="", runtime_profile=None):
    snapshot = recovery / "installation"
    _copy_tree(root, snapshot)
    _stopped(root, cfg)
    if _inventory(root) != before or _inventory(snapshot) != before:
        raise UpdateError("Installation changed during the recovery copy")
    receipt = {"schema": "saw.cold-recovery/1", "created_at": datetime.now(UTC).isoformat(),
               "install_root": str(root), "files": before,
               "target_manifest_sha256": target_manifest_sha256}
    if runtime_profile is not None:
        receipt["runtime_profile"] = runtime_profile
    _json(recovery / "recovery-point.json", receipt)


@_exclusive
def backup(install_root, recovery_point):
    """Capture every stopped store, generation, runtime and private setting for whole restore."""
    root, recovery = _path(install_root), _path(recovery_point, existing=False)
    _separate(root, recovery)
    if recovery.exists() or not recovery.parent.is_dir() or root.drive.lower() != recovery.drive.lower():
        raise UpdateError("RecoveryPoint must be a fresh directory on the installation volume")
    _access_gate(root, check_copy_semantics=True)
    _, cfg = _config(root)
    _stopped(root, cfg)
    before = _inventory(root)
    size = sum(row.get("bytes", 0) for row in before)
    needed = size + 64 * 1024 * 1024
    if shutil.disk_usage(recovery.parent).free < needed:
        raise UpdateError("Insufficient free space for a complete recovery point")
    _preflight_rows(recovery / "installation", before)
    for prefix in (".saw-r-", ".saw-k-"):
        _preflight_rows(root.with_name(prefix + "0" * 12), before)
    _preflight_json(recovery / "recovery-point.json")
    _private_directory(recovery)
    profile = _baseline(root, None) if (root / "installed-release-manifest.json").exists() else None
    _write_cold_snapshot(root, recovery, cfg, before, runtime_profile=profile)
    return {"status": "backup_complete_stopped", "install_root": str(root),
            "recovery_point": str(recovery), "snapshot_bytes": size,
            "next_step": "Start the installation separately. Restore this entire point if recovery is required."}


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
    previous = _baseline(root, baseline_dir)
    _write_cold_snapshot(root, recovery, cfg, before,
                         target_manifest_sha256=result["target_manifest_sha256"], runtime_profile=previous)
    _stage_public_app(bundle / "app", stage, root / "app")
    dependency = _stage_dependency(root, bundle, previous, recovery)
    _copy_file(root / "app/.env", stage / ".env")
    if (root / "app/var").exists():
        _copy_tree(root / "app/var", stage / "var")
    _access_gate(stage, relative_base=Path("app"), service_mode=False)
    _tree_paths(bundle)
    _manifest.verify(bundle)
    _stopped(root, cfg)
    if _inventory(root) != before:
        raise UpdateError("Installation changed before application switch")
    _publish_dependency(root, dependency)
    if dependency is not None:
        _installed_runtime(root, bundle)
        _access_gate(root)
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

def _recovery_runtime_profile(recovery, bundle, baseline_dir=None):
    receipt_value = _restore_document(_path(recovery) / "recovery-point.json")
    root = _path(receipt_value.get("install_root", ""), existing=False)
    receipt, _ = _verified_restore_receipt(root, recovery)
    snapshot = recovery / "installation"
    recorded = receipt.get("runtime_profile")
    if (snapshot / "installed-release-manifest.json").is_file():
        profile = _baseline(snapshot, None)
        if recorded is not None and recorded != profile:
            raise UpdateError("Recovery runtime identities disagree", code="snapshot_verification_failed")
    elif recorded is not None:
        profile = recorded
    elif baseline_dir is not None:
        profile = _baseline(snapshot, baseline_dir)
    else:
        raise UpdateError("Legacy recovery requires its verified original BaselineBundleDir")
    _tree_paths(bundle)
    _manifest.verify(bundle)
    candidate = json.loads((bundle / "release-manifest.json").read_text(encoding="utf-8-sig"))
    _runtime_transition(profile, candidate)
    _installed_source(snapshot, profile)
    _installed_runtime(snapshot, bundle, profile=profile, logical_root=root)
    return profile


def _restore_document(path):
    _path(path, existing=False)
    if not path.is_file() or path.stat().st_nlink != 1 or path.stat().st_size > 64 * 1024 * 1024:
        raise UpdateError("Invalid recovery metadata", code="restore_journal_invalid")
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        raise UpdateError("Invalid recovery metadata", code="restore_journal_invalid") from None
    if not isinstance(value, dict):
        raise UpdateError("Invalid recovery metadata", code="restore_journal_invalid")
    return value


def _verified_restore_receipt(root, recovery):
    snapshot = recovery / "installation"
    _access_gate(recovery, snapshot_root=snapshot)
    receipt_path = recovery / "recovery-point.json"
    receipt = _restore_document(receipt_path)
    if (receipt.get("schema") != "saw.cold-recovery/1" or
            not isinstance(receipt.get("install_root"), str) or
            Path(receipt["install_root"]) != root or not isinstance(receipt.get("files"), list)):
        raise UpdateError("Recovery point belongs to a different absolute installation path",
                          code="snapshot_identity_unverified")
    if _inventory(snapshot) != receipt["files"]:
        raise UpdateError("Recovery point files or access policies changed", code="snapshot_verification_failed")
    return receipt, _manifest.digest(receipt_path)


_RESTORE_JOURNAL_KEYS = {"schema", "install_root", "receipt_sha256", "token", "stage",
                         "retained_installation", "retained_files", "phase"}


def _pending_restore(root, recovery):
    """Validate an interrupted transaction without changing ACLs, files, or names."""
    root, recovery = _path(root, existing=False), _path(recovery)
    _separate(root, recovery)
    journal_path = recovery / "restore-journal.json"
    if not os.path.lexists(journal_path):
        return None
    receipt, digest = _verified_restore_receipt(root, recovery)
    if os.name == "nt":
        current = _ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value")
        if _access_violations(journal_path, current, private=True) or not _acl(journal_path).startswith("D:P"):
            raise UpdateError("Recovery journal access policy changed", code="restore_journal_invalid")
    elif journal_path.stat().st_mode & 0o077:
        raise UpdateError("Recovery journal access policy changed", code="restore_journal_invalid")
    journal = _restore_document(journal_path)
    token = journal.get("token", "")
    if (set(journal) != _RESTORE_JOURNAL_KEYS or journal.get("schema") != "saw.restore-journal/1" or
            not isinstance(token, str) or not re.fullmatch(r"[a-f0-9]{12}", token) or
            journal.get("phase") not in ("staged", "root_retained", "complete") or
            journal.get("install_root") != str(root) or journal.get("receipt_sha256") != digest or
            not isinstance(journal.get("retained_files"), list)):
        raise UpdateError("Recovery journal identity changed", code="restore_journal_invalid")
    stage, retained = root.with_name(".saw-r-" + token), root.with_name(".saw-k-" + token)
    if journal.get("stage") != str(stage) or journal.get("retained_installation") != str(retained):
        raise UpdateError("Recovery journal paths changed", code="restore_journal_invalid")
    for path in (root, stage, retained):
        _path(path, existing=False)
        if path.exists() and not path.is_dir():
            raise UpdateError("Recovery transaction location is not a directory", code="restore_journal_invalid")
    locations = tuple(path.is_dir() for path in (root, stage, retained))
    if locations == (True, True, False):
        actual = "staged"
    elif locations == (False, True, True):
        actual = "root_retained"
    elif locations == (True, False, True):
        actual = "complete" if journal["phase"] == "complete" else "restored"
    else:
        raise UpdateError("Recovery transaction locations changed", code="restore_journal_invalid")
    if journal["phase"] == "complete" and actual != "complete":
        raise UpdateError("Completed recovery transaction changed", code="restore_journal_invalid")
    expected = [(stage, receipt["files"])] if stage.is_dir() else []
    if retained.is_dir():
        expected.append((retained, journal["retained_files"]))
    if actual == "staged":
        expected.append((root, journal["retained_files"]))
    elif actual == "restored":
        expected.append((root, receipt["files"]))
    for path, inventory in expected:
        _access_gate(path)
        if _inventory(path) != inventory:
            raise UpdateError("Recovery transaction files or access policies changed", code="restore_journal_invalid")
    return {**journal, "actual_phase": actual,
            "current_location": str(root if root.is_dir() else retained)}


def _write_restore_journal(recovery, journal, phase):
    value = {key: journal[key] for key in _RESTORE_JOURNAL_KEYS}
    value["phase"] = phase
    _json(recovery / "restore-journal.json", value, unique=True)
    journal["phase"] = phase


@_exclusive
def restore(install_root, recovery_point, *, confirm=False, progress=None):
    if not confirm:
        raise UpdateError("Explicit ConfirmPointInTimeRecovery is required")
    root, recovery = _path(install_root, existing=False), _path(recovery_point)
    _separate(root, recovery)
    pending = _pending_restore(root, recovery)
    receipt, receipt_digest = _verified_restore_receipt(root, recovery)
    snapshot = recovery / "installation"
    if pending is None or pending["actual_phase"] == "complete":
        _access_gate(snapshot, check_copy_semantics=True)
        _path(root)
        _access_gate(root)
        fallback = snapshot / "app/.env" if not (root / "app").exists() else None
        _, cfg = _config(root, verified_application_config=fallback)
        _stopped(root, cfg)
        if shutil.disk_usage(root.parent).free < sum(row.get("bytes", 0) for row in receipt["files"]) + 64 * 1024 * 1024:
            raise UpdateError("Insufficient free space to stage complete recovery")
        token, stage, retained = _restore_paths(root)
        _preflight_rows(stage, receipt["files"])
        _preflight_rows(root, receipt["files"])
        _preflight_copy(root, retained)
        result_path = recovery / ("restore-result-" + token + ".json")
        _preflight_json(result_path, unique=True)
        _preflight_json(recovery / "restore-journal.json", unique=True)
        try:
            if progress:
                progress("restore_stage")
            _copy_tree(snapshot, stage)
            if _inventory(stage) != receipt["files"]:
                raise UpdateError("Recovery staging verification failed")
            pending = {"schema": "saw.restore-journal/1", "install_root": str(root),
                       "receipt_sha256": receipt_digest, "token": token, "stage": str(stage),
                       "retained_installation": str(retained), "retained_files": _inventory(root),
                       "phase": "staged", "actual_phase": "staged", "current_location": str(root)}
            _write_restore_journal(recovery, pending, "staged")
        except Exception:
            raise UpdateError("Recovery staging could not finish; installation was not replaced",
                              code="restore_interrupted", diagnostics={"recovery_point": str(recovery),
                              "stage": str(stage), "retained_installation": str(retained)}) from None
    else:
        stage, retained = Path(pending["stage"]), Path(pending["retained_installation"])
        fallback = snapshot / "app/.env" if root.exists() and not (root / "app").exists() else None
        _, cfg = _config(root, verified_application_config=fallback,
                         verified_installation=snapshot if not root.exists() else None)
        result_path = recovery / ("restore-result-" + pending["token"] + ".json")
    try:
        _stopped(root, cfg)
        if pending["actual_phase"] == "staged":
            if _inventory(root) != pending["retained_files"] or _inventory(stage) != receipt["files"]:
                raise UpdateError("Recovery transaction changed before replacement")
            _preflight_copy(root, retained)
            if progress:
                progress("restore_swap")
            os.rename(root, retained)
            _write_restore_journal(recovery, pending, "root_retained")
            pending["actual_phase"] = "root_retained"
        if pending["actual_phase"] == "root_retained":
            _stopped(retained, cfg)
            _stopped(stage, cfg)
            try:
                os.rename(stage, root)
            except BaseException:
                # If replacement never happened, restore the previous name when possible.
                # The durable journal also supports retry when this rollback fails.
                if not root.exists() and stage.is_dir() and retained.is_dir():
                    try:
                        os.rename(retained, root)
                    except BaseException:
                        pass
                raise
        result = {"status": "restored_stopped", "install_root": str(root),
                  "retained_installation": str(retained), "recovery_point": str(recovery),
                  "newer_records": "Preserved in retained installation; reconciliation is explicit."}
        _json(result_path, result, unique=True)
        _write_restore_journal(recovery, pending, "complete")
        return result
    except Exception:
        raise UpdateError("Recovery was interrupted; preserve the recovery and retained directories",
                          code="restore_interrupted", diagnostics={"recovery_point": str(recovery),
                          "stage": str(stage), "retained_installation": str(retained)}) from None


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("plan", "apply", "restore", "backup"))
    parser.add_argument("--install-root", required=True, type=Path)
    parser.add_argument("--bundle-dir", type=Path)
    parser.add_argument("--baseline-bundle-dir", type=Path)
    parser.add_argument("--recovery-point", type=Path)
    parser.add_argument("--confirm-point-in-time-recovery", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.action == "backup":
            if not args.recovery_point:
                raise UpdateError("A fresh RecoveryPoint is required")
            result = backup(args.install_root, args.recovery_point)
        elif args.action == "restore":
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
