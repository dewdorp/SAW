"""Cold updates must preserve private state and refuse unsafe transitions."""
from __future__ import annotations
import importlib
import json
import shutil
import socket
import zipfile
from pathlib import Path
import pytest
from saw.devtools.release_manifest import REQUIRED, seal

def updater():
    try:
        return importlib.import_module("saw.devtools.offline_update")
    except ModuleNotFoundError:
        pytest.fail("The cold update implementation is missing")

def write(root, rel, data):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode() if isinstance(data, str) else data)

def media(root, version):
    root.mkdir()
    for rel in REQUIRED.values():
        write(root, rel, "synthetic runtime")
    for archive, entry in (
        ("python/python-3.12.10-embed-amd64.zip", "python.exe"),
        ("postgresql/postgresql-16.15-1-windows-x64-binaries.zip", "pgsql/bin/postgres.exe"),
        ("opensearch/opensearch-2.19.6-windows-x64.zip", "opensearch-2.19.6/jdk/bin/java.exe"),
        ("bootstrap/pip-25.1.1-py3-none-any.whl", "pip/__init__.py"),
        ("opensearch/analysis-nori-2.19.6.zip", "analysis-nori-2.19.6.jar"),
    ):
        with zipfile.ZipFile(root / archive, "w") as stream:
            stream.writestr(zipfile.ZipInfo(entry, (2026, 1, 1, 0, 0, 0)), "synthetic pinned binary")
            if entry == "pgsql/bin/postgres.exe":
                stream.writestr(zipfile.ZipInfo("pgsql/bin/pg_ctl.exe", (2026, 1, 1, 0, 0, 0)), "synthetic preserved state")
    write(root, "app/saw/storage/migrations/versions/0001_initial.py", "revision = '0001'\ndown_revision = None\n")
    write(root, "app/saw/main.py", version)
    write(root, "app/deploy/windows/saw-ctl.ps1", version)
    seal(root, {"python": "3.12.10", "postgresql": "16.15-1", "opensearch": "2.19.6"})
    return root

@pytest.fixture
def installation(tmp_path):
    baseline = media(tmp_path / "old-media", "old app")
    bundle = media(tmp_path / "new-media", "new app")
    root = tmp_path / "installed"
    updater()._private_directory(root)
    shutil.copytree(baseline / "app", root / "app")
    cfg = {"port": 58101, "postgresPort": 58102, "opensearchPort": 58103}
    write(root, "saw-ctl.json", json.dumps(cfg))
    write(root, "saw-ctl.ps1", "old app")
    write(root, "app/.env", "\n".join([
        "SAW_ENV=prod", "SAW_SCHEMA_MODE=migrate", "SAW_EVENT_STORE=opensearch",
        "SAW_DATABASE_URL=postgresql+psycopg://saw:synthetic@127.0.0.1:58102/saw",
        "SAW_OPENSEARCH_URL=http://127.0.0.1:58103", "SAW_OBJECT_STORE=local",
        f"SAW_DATA_DIR={root / 'data/saw'}", f"SAW_OBJECT_STORE_ROOT={root / 'data/objects'}",
        f"SAW_LLM_MODELS_ROOT={root / 'models'}", f"SAW_LLM_RUNTIME_ROOT={root / 'llm-runtime'}",
    ]))
    for rel in ("app/var/secret.key", "data/saw/audit-anchors.jsonl", "data/objects/evidence",
                "data/postgresql/PG_VERSION", "data/postgresql/table", "data/opensearch/index",
                "models/model.gguf", "tls/saw.key", "secrets/postgres-superuser.pw",
                "venv/Scripts/python.exe", "pgsql/bin/pg_ctl.exe"):
        write(root, rel, "16" if rel.endswith("PG_VERSION") else "synthetic preserved state")
    write(root, "data/postgresql/postgresql.conf", "# standard cluster\n")
    write(root, "opensearch-2.19.6/config/opensearch.yml", '\n'.join([
        f'path.data: "{(root / "data/opensearch").as_posix()}"',
        f'path.logs: "{(root / "logs/opensearch").as_posix()}"',
        f'path.repo: ["{(root / "backup/opensearch").as_posix()}"]', "transport.port: 58104",
    ]))
    shutil.copytree(baseline / "llm-runtime", root / "llm-runtime")
    for rel in ("venv/Scripts/python.exe", "pgsql/bin/postgres.exe", "opensearch-2.19.6/jdk/bin/java.exe"):
        write(root, rel, "synthetic pinned binary")
    write(root, "venv/Scripts/python312._pth", "python312.zip\n.\n../Lib/site-packages\n../../app\nimport site\n")
    write(root, "venv/Lib/site-packages/pip/__init__.py", "synthetic pinned binary")
    write(root, "opensearch-2.19.6/plugins/analysis-nori/analysis-nori-2.19.6.jar", "synthetic pinned binary")
    return root, bundle, baseline, tmp_path / "recovery"

def test_apply_and_whole_restore_preserve_private_state_and_new_records(installation):
    mod = updater()
    root, bundle, baseline, recovery = installation
    private = {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob('*') if p.is_file()}
    result = mod.apply(root, bundle, recovery, baseline)
    assert result["status"] == "applied_stopped_schema_pending"
    assert (root / "app/saw/main.py").read_text() == "new app"
    for rel in ("app/.env", "app/var/secret.key", "data/saw/audit-anchors.jsonl", "models/model.gguf"):
        assert (root / rel).read_bytes() == private[rel]
    write(root, "data/objects/after-update", "new evidence")
    restored = mod.restore(root, recovery, confirm=True)
    assert (root / "app/saw/main.py").read_text() == "old app"
    assert not (root / "data/objects/after-update").exists()
    assert (Path(restored["retained_installation"]) / "data/objects/after-update").read_text() == "new evidence"
    assert {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob('*') if p.is_file()} == private

@pytest.mark.parametrize("case", ["active_port", "modified_app", "runtime_drift", "external_data", "nested_recovery"])
def test_refusals_leave_original_untouched(installation, case):
    mod = updater()
    root, bundle, baseline, recovery = installation
    listener = None
    if case == "active_port":
        listener = socket.socket(); listener.bind(('127.0.0.1', 58101)); listener.listen()
    elif case == "modified_app":
        write(root, "app/saw/main.py", "locally changed")
    elif case == "runtime_drift":
        write(bundle, "wheels/drift.whl", "different dependency"); seal(bundle, {})
    elif case == "external_data":
        env = root / 'app/.env'
        env.write_text(env.read_text().replace(str(root / 'data/saw'), str(root.parent / 'outside')))
    else:
        recovery = root / "recovery"
    before = {p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()}
    try:
        with pytest.raises(mod.UpdateError):
            mod.apply(root, bundle, recovery, baseline)
        assert {p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()} == before
        assert not recovery.exists()
    finally:
        if listener: listener.close()

def test_corrupt_snapshot_and_unconfirmed_restore_never_replace_current_installation(installation):
    mod = updater()
    root, bundle, baseline, recovery = installation
    mod.apply(root, bundle, recovery, baseline)
    with pytest.raises(mod.UpdateError): mod.restore(root, recovery, confirm=False)
    write(recovery, "installation/data/postgresql/table", "corrupt recovery")
    with pytest.raises(mod.UpdateError): mod.restore(root, recovery, confirm=True)
    assert (root / "app/saw/main.py").read_text() == "new app"

def test_snapshot_copy_failure_does_not_switch_application(installation, monkeypatch):
    mod = updater()
    root, bundle, baseline, recovery = installation
    original = mod._copy_tree
    def fail(source, destination):
        original(source, destination)
        raise OSError("synthetic disk error")
    monkeypatch.setattr(mod, '_copy_tree', fail)
    with pytest.raises(OSError): mod.apply(root, bundle, recovery, baseline)
    assert (root / "app/saw/main.py").read_text() == "old app"
    assert not (recovery / 'recovery-point.json').exists()

@pytest.mark.skipif(__import__("os").name != "nt", reason="PowerShell wrapper")
def test_wrapper_rejects_changed_media_before_creating_recovery(installation):
    import subprocess
    mod = updater()
    root, bundle, baseline, recovery = installation
    wrapper = Path(__file__).resolve().parents[2] / "deploy/windows/update.ps1"
    assert wrapper.is_file(), "The verified-media wrapper is missing"
    verifier = wrapper.with_name("verify-bundle.ps1")
    shutil.copyfile(verifier, bundle / "verify-bundle.ps1")
    seal(bundle, {"python": "3.12.10", "postgresql": "16.15-1", "opensearch": "2.19.6"})
    write(bundle, "app/saw/main.py", "changed after sealing")
    result = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "RemoteSigned", "-File",
                             str(wrapper), "-Action", "apply", "-InstallRoot", str(root),
                             "-BundleDir", str(bundle), "-BaselineBundleDir", str(baseline),
                             "-RecoveryPoint", str(recovery)], capture_output=True, timeout=40)
    assert result.returncode != 0
    assert not recovery.exists()
    assert (root / "app/saw/main.py").read_text() == "old app"

def test_tracked_live_process_and_pg_lock_refuse_copy(installation):
    import os
    mod = updater()
    root, bundle, baseline, recovery = installation
    write(root, "run/saw.pid", str(os.getpid()))
    with pytest.raises(mod.UpdateError): mod.apply(root, bundle, recovery, baseline)
    assert not recovery.exists()

@pytest.mark.parametrize("case", ["inside_app", "postgres_auto", "runtime_binary"])
def test_unmanaged_mutable_paths_and_runtime_drift_refuse_mutation(installation, case):
    mod = updater()
    root, bundle, baseline, recovery = installation
    if case == "inside_app":
        env = root / "app/.env"
        env.write_text(env.read_text().replace(str(root / "data/saw"), str(root / "app/private-data")))
    elif case == "postgres_auto":
        write(root, "data/postgresql/postgresql.auto.conf", "data_directory = 'C:/external'\n")
    else:
        write(root, "venv/Scripts/python.exe", "unapproved runtime")
    with pytest.raises(mod.UpdateError):
        mod.apply(root, bundle, recovery, baseline)
    assert not recovery.exists()
    assert (root / "app/saw/main.py").read_text() == "old app"

def test_plan_rejects_insufficient_space_without_creating_recovery(installation, monkeypatch):
    from types import SimpleNamespace
    mod = updater()
    root, bundle, baseline, recovery = installation
    monkeypatch.setattr(mod.shutil, "disk_usage", lambda _path: SimpleNamespace(free=0))
    with pytest.raises(mod.UpdateError):
        mod.plan(root, bundle, baseline)
    assert not recovery.exists()

@pytest.mark.skipif(__import__("os").name != "nt", reason="Windows directory junction")
def test_junction_is_refused_without_reading_or_mutating_external_tree(installation):
    import subprocess
    mod = updater()
    root, bundle, baseline, recovery = installation
    external = root.parent / "external"
    write(external, "sentinel", "external synthetic content")
    junction = root / "app/var/junction"
    command = "New-Item -ItemType Junction -Path '" + str(junction) + "' -Target '" + str(external) + "' | Out-Null"
    created = subprocess.run(["powershell.exe", "-NoProfile", "-Command", command], capture_output=True)
    assert created.returncode == 0
    with pytest.raises(mod.UpdateError):
        mod.apply(root, bundle, recovery, baseline)
    assert (external / "sentinel").read_text() == "external synthetic content"
    assert not recovery.exists()

@pytest.mark.parametrize("case", ["python_dll", "installed_dependency", "schema_downgrade"])
def test_native_and_dependency_drift_and_migration_regression_are_refused(installation, case):
    mod = updater()
    root, bundle, baseline, recovery = installation
    if case == "python_dll":
        for media_root in (baseline, bundle):
            with zipfile.ZipFile(media_root / "python/python-3.12.10-embed-amd64.zip", "a") as stream:
                stream.writestr(zipfile.ZipInfo("python312.dll", (2026, 1, 1, 0, 0, 0)), "approved library")
            seal(media_root, {"python": "3.12.10", "postgresql": "16.15-1", "opensearch": "2.19.6"})
        write(root, "venv/Scripts/python312.dll", "changed library")
    elif case == "installed_dependency":
        write(root, "venv/Lib/site-packages/pip/__init__.py", "upgraded dependency")
    else:
        rel = "app/saw/storage/migrations/versions/0002_later.py"
        write(baseline, rel, "revision = '0002'\ndown_revision = '0001'\n")
        write(root, rel, "revision = '0002'\ndown_revision = '0001'\n")
        seal(baseline, {"python": "3.12.10", "postgresql": "16.15-1", "opensearch": "2.19.6"})
    with pytest.raises(mod.UpdateError):
        mod.plan(root, bundle, baseline)
    assert (root / "app/saw/main.py").read_text() == "old app"
    assert not recovery.exists()

def test_concurrent_update_and_restore_are_refused_before_mutation(installation):
    mod = updater()
    root, bundle, baseline, recovery = installation
    assert hasattr(mod, "_maintenance"), "The installation maintenance lock is missing"
    with mod._maintenance(root):
        with pytest.raises(mod.UpdateError, match="maintenance"):
            mod.apply(root, bundle, recovery, baseline)
        with pytest.raises(mod.UpdateError, match="maintenance"):
            mod.restore(root, recovery, confirm=True)
    assert not recovery.exists()
    assert (root / "app/saw/main.py").read_text() == "old app"


@pytest.mark.skipif(__import__("os").name != "nt", reason="Windows OpenProcess boundary")
@pytest.mark.parametrize("error", [5, 6, 0])
def test_inaccessible_tracked_pid_refuses_unbound_installation(installation, monkeypatch, error):
    from types import SimpleNamespace
    mod = updater()
    root, _bundle, _baseline, _recovery = installation
    write(root, "run/saw.pid", "424242")
    _, cfg = mod._config(root)
    # CIM can omit executable paths for processes the caller cannot inspect.
    monkeypatch.setattr(mod, "_ps", lambda _script: '{"processes":0,"services":0}')
    def inaccessible(*_args):
        mod.ctypes.set_last_error(error)
        return None
    kernel = SimpleNamespace(OpenProcess=inaccessible, CloseHandle=lambda _handle: None)
    monkeypatch.setattr(mod.ctypes, "WinDLL", lambda *_args, **_kwargs: kernel)
    with pytest.raises(mod.UpdateError, match="tracked process"):
        mod._stopped(root, cfg)

@pytest.mark.skipif(__import__("os").name != "nt", reason="Windows OpenProcess boundary")
def test_definitely_absent_tracked_pid_allows_stopped_installation(installation, monkeypatch):
    from types import SimpleNamespace
    mod = updater()
    root, _bundle, _baseline, _recovery = installation
    write(root, "run/saw.pid", "424242")
    _, cfg = mod._config(root)
    monkeypatch.setattr(mod, "_ps", lambda _script: '{"processes":0,"services":0}')
    def absent(*_args):
        mod.ctypes.set_last_error(87)  # ERROR_INVALID_PARAMETER: no such process ID.
        return None
    kernel = SimpleNamespace(OpenProcess=absent, CloseHandle=lambda _handle: None)
    monkeypatch.setattr(mod.ctypes, "WinDLL", lambda *_args, **_kwargs: kernel)
    mod._stopped(root, cfg)

@pytest.mark.parametrize("case", ["saw_missing", "postgresql_missing", "saw_changed", "postgresql_changed", "unexpected"])
def test_service_wrapper_drift_is_refused_before_update(installation, case):
    mod = updater()
    root, bundle, _baseline, recovery = installation
    approved = (bundle / "winsw/WinSW-x64.exe").read_bytes()
    for name, label in (("saw-service", "saw"), ("saw-postgresql", "postgresql")):
        write(root, "service/" + name + ".xml", "<service />")
        if case != label + "_missing":
            payload = b"!" * len(approved) if case == label + "_changed" else approved
            write(root, "service/" + name + ".exe", payload)
    if case == "unexpected":
        write(root, "service/unknown.exe", approved)
    with pytest.raises(mod.UpdateError, match="service"):
        mod._installed_runtime(root, bundle)
    assert not recovery.exists()
    assert (root / "app/saw/main.py").read_text() == "old app"

def test_pinned_service_wrappers_and_user_mode_without_wrappers_are_supported(installation):
    mod = updater()
    root, bundle, _baseline, _recovery = installation
    # -NoAdmin creates no WinSW executables.
    mod._installed_runtime(root, bundle)
    approved = (bundle / "winsw/WinSW-x64.exe").read_bytes()
    for name in ("saw-service", "saw-postgresql"):
        write(root, "service/" + name + ".xml", "<service />")
        write(root, "service/" + name + ".exe", approved)
    mod._installed_runtime(root, bundle)


@pytest.mark.skipif(__import__("os").name != "nt", reason="Windows DACL inheritance")
@pytest.mark.parametrize("root_policy", ["protected_ai", "inherited_ai", "legacy"])
def test_copy_preserves_exact_windows_acl_before_private_bytes(tmp_path, monkeypatch, root_policy):
    mod = updater()
    sid = mod._ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value")
    # Different parent policies exercise inherited ACEs without borrowing the
    # destination parent's permissions. A harmless Guests deny tests ACE order.
    policy = ("D:P(D;OICI;FW;;;BG)(A;OICI;FA;;;SY)(A;OICI;FA;;;" + sid
              + ")(A;OICI;FR;;;LS)")
    def modern_acl(path, value):
        mod._ps("$ErrorActionPreference='Stop'; "
                "$acl=Get-Acl -LiteralPath " + mod._literal(path) + "; "
                "$acl.SetSecurityDescriptorSddlForm(" + mod._literal(value)
                + ",[Security.AccessControl.AccessControlSections]::Access); "
                "Set-Acl -LiteralPath " + mod._literal(path) + " -AclObject $acl")
    parent = tmp_path / "source-parent"
    parent.mkdir()
    modern_acl(parent, policy)
    source = parent / "source"
    source.mkdir()
    if root_policy == "protected_ai":
        modern_acl(source, policy)
    elif root_policy == "legacy":
        mod._set_acl(source, policy)
    source_policy = mod._acl(source)
    assert source_policy.startswith({"protected_ai": "D:PAI(",
                                     "inherited_ai": "D:AI(",
                                     "legacy": "D:P("}[root_policy])
    write(source, "nested/deep/evidence", "synthetic private evidence")
    write(source, "private/key", "synthetic private key")
    modern_acl(source / "private", "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + sid + ")")
    modern_acl(source / "private/key", "D:P(A;;FA;;;SY)(A;;FA;;;" + sid + ")")
    assert mod._acl(source / "private").startswith("D:PAI(")
    assert mod._acl(source / "private/key").startswith("D:PAI(")
    before = mod._inventory(source)
    copy_parent = tmp_path / "recovery"
    mod._private_directory(copy_parent)
    assert mod._acl(parent) != mod._acl(copy_parent)
    original_copyfile = mod.shutil.copyfile
    copied = []
    def verify_access_before_write(original, destination):
        assert mod._acl(original) == mod._acl(destination), "ACL changed before private content write"
        copied.append(str(destination))
        return original_copyfile(original, destination)
    monkeypatch.setattr(mod.shutil, "copyfile", verify_access_before_write)
    snapshot = copy_parent / "installation"
    mod._copy_tree(source, snapshot)
    assert mod._inventory(source) == before
    assert mod._inventory(snapshot) == before
    restored = tmp_path / "restored"
    mod._copy_tree(snapshot, restored)
    assert mod._inventory(restored) == before
    assert len(copied) == 4


@pytest.mark.skipif(__import__("os").name != "nt", reason="Windows access policy gate")
@pytest.mark.parametrize("case", ["users_read", "everyone_read", "unknown_allow", "ns_secret",
                                  "ns_runtime_without_service", "ns_runtime_write", "null_dacl"])
def test_untrusted_access_is_refused_before_installation_content_reads(installation, monkeypatch, case):
    mod = updater()
    root, bundle, baseline, recovery = installation
    target = root / "app/var/secret.key"
    ace = {"users_read": "(A;;FR;;;BU)", "everyone_read": "(A;;FR;;;WD)",
           "unknown_allow": "(A;;FR;;;S-1-5-21-100-200-300-400)",
           "ns_secret": "(A;;FR;;;NS)", "ns_runtime_without_service": "(A;;FR;;;NS)",
           "ns_runtime_write": "(A;;FW;;;NS)"}.get(case)
    if case.startswith("ns_runtime"):
        target = root / "pgsql/bin/postgres.exe"
    if case == "ns_runtime_write":
        for name in ("saw-service", "saw-postgresql"):
            write(root, "service/" + name + ".exe", (bundle / "winsw/WinSW-x64.exe").read_bytes())
    original = mod._acl(target)
    mod._set_acl(target, "D:NO_ACCESS_CONTROL" if case == "null_dacl" else original + ace)
    changed = mod._acl(target)
    def forbidden(*args, **kwargs):
        raise AssertionError("Installation content read before access policy validation")
    for name in ("_baseline", "_installed_source", "_installed_runtime", "_config", "_inventory"):
        monkeypatch.setattr(mod, name, forbidden)
    with pytest.raises(mod.UpdateError, match="access policy"):
        mod.plan(root, bundle, baseline)
    assert mod._acl(target) == changed
    assert not recovery.exists()

@pytest.mark.skipif(__import__("os").name != "nt", reason="Windows access policy gate")
def test_update_uses_installed_acls_and_safe_parent_for_new_public_files(installation):
    mod = updater()
    root, bundle, baseline, recovery = installation
    sid = mod._ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value")
    original = {rel: mod._acl(root / rel) for rel in
                ("app", "app/saw/main.py", "app/.env", "app/var/secret.key")}
    public_policy = "D:P(A;;FA;;;SY)(A;;FA;;;" + sid + ")(A;;FR;;;BU)"
    mod._set_acl(bundle / "app/saw/main.py", public_policy)
    write(bundle, "app/new-feature/deep/new.py", "new public file")
    mod._set_acl(bundle / "app/new-feature/deep/new.py", public_policy)
    seal(bundle, {"python": "3.12.10", "postgresql": "16.15-1", "opensearch": "2.19.6"})
    mod.apply(root, bundle, recovery, baseline)
    for rel, policy in original.items():
        assert mod._acl(root / rel) == policy
    assert ";;;BU)" not in mod._acl(root / "app/new-feature/deep/new.py")
    assert (root / "app/new-feature/deep/new.py").read_text() == "new public file"


def service_markers(root, bundle):
    for name in ("saw-service", "saw-postgresql"):
        write(root, "service/" + name + ".exe", (bundle / "winsw/WinSW-x64.exe").read_bytes())

@pytest.mark.skipif(__import__("os").name != "nt", reason="Windows access policy gate")
def test_precise_service_access_profile_and_unknown_deny_are_accepted(installation):
    mod = updater()
    root, bundle, baseline, recovery = installation
    service_markers(root, bundle)
    for rel in (".", "data", "logs", "venv", "opensearch-2.19.6", "opensearch-2.19.6/jdk"):
        path = root / rel
        path.mkdir(exist_ok=True)
        mod._set_acl(path, mod._acl(path) + "(A;;0x100020;;;NS)")
    for rel, rights in (("pgsql", "0x1200a9"), ("service", "0x1200a9"),
                        ("venv/Scripts", "0x1200a9"),
                        ("opensearch-2.19.6/jdk/bin", "0x1200a9"),
                        ("data/postgresql", "FA"), ("logs/postgresql", "0x1301bf")):
        path = root / rel
        path.mkdir(exist_ok=True)
        mod._set_acl(path, mod._acl(path) + "(A;OICI;" + rights + ";;;NS)")
    key = root / "app/var/secret.key"
    mod._set_acl(key, mod._acl(key) + "(D;;FW;;;S-1-5-21-100-200-300-400)")
    before = {path: mod._acl(path) for path in mod._tree_paths(root)}
    mod._access_gate(root)
    assert {path: mod._acl(path) for path in mod._tree_paths(root)} == before

@pytest.mark.skipif(__import__("os").name != "nt", reason="Windows access policy gate")
@pytest.mark.parametrize("case", ["root_inheritance", "service_write", "object_allow"])
def test_unrecognized_or_excessive_service_access_is_refused(installation, case):
    mod = updater()
    root, bundle, baseline, recovery = installation
    service_markers(root, bundle)
    path = root if case == "root_inheritance" else root / "service"
    ace = {"root_inheritance": "(A;OICI;0x100020;;;NS)", "service_write": "(A;;FW;;;NS)",
           "object_allow": "(OA;;FR;11111111-1111-1111-1111-111111111111;;BU)"}[case]
    mod._set_acl(path, mod._acl(path) + ace)
    with pytest.raises(mod.UpdateError, match="access policy"):
        mod._access_gate(root)

@pytest.mark.skipif(__import__("os").name != "nt", reason="Windows access policy owner")
@pytest.mark.parametrize("case", ["database_service_owner", "runtime_service_owner", "unknown_owner"])
def test_only_trusted_owners_and_postgresql_mutable_service_owners_are_accepted(installation, monkeypatch, case):
    mod = updater()
    root, bundle, baseline, recovery = installation
    service_markers(root, bundle)
    target = root / ("data/postgresql/table" if case == "database_service_owner" else "pgsql/bin/postgres.exe")
    read_metadata = mod._access_metadata
    def metadata(path):
        owner, entries = read_metadata(path)
        if path == target:
            owner = "S-1-5-21-100-200-300-400" if case == "unknown_owner" else "S-1-5-20"
        return owner, entries
    monkeypatch.setattr(mod, "_access_metadata", metadata)
    if case == "database_service_owner":
        mod._access_gate(root)
    else:
        with pytest.raises(mod.UpdateError, match="access policy"):
            mod._access_gate(root)

@pytest.mark.skipif(__import__("os").name != "nt", reason="Windows recovery ACL gate")
def test_restore_refuses_untrusted_snapshot_before_reading_snapshot_contents(installation, monkeypatch):
    mod = updater()
    root, bundle, baseline, recovery = installation
    mod.apply(root, bundle, recovery, baseline)
    key = recovery / "installation/app/var/secret.key"
    mod._set_acl(key, mod._acl(key) + "(A;;FR;;;BU)")
    def forbidden(*args, **kwargs):
        raise AssertionError("Snapshot contents read before permission gate")
    monkeypatch.setattr(mod, "_inventory", forbidden)
    with pytest.raises(mod.UpdateError, match="access policy"):
        mod.restore(root, recovery, confirm=True)
    assert (root / "app/saw/main.py").read_text() == "new app"


def test_directory_enumeration_error_never_becomes_an_incomplete_inventory(tmp_path, monkeypatch):
    mod = updater()
    def inaccessible(path, *, followlinks=False, onerror=None):
        if onerror is not None:
            onerror(PermissionError("synthetic private filename"))
        yield str(path), [], []
    monkeypatch.setattr(mod.os, "walk", inaccessible)
    with pytest.raises(mod.UpdateError, match="enumerat") as error:
        mod._inventory(tmp_path)
    assert "synthetic private filename" not in str(error.value)

@pytest.mark.skipif(__import__("os").name != "nt", reason="Windows directory-list denial")
def test_native_directory_list_denial_refuses_inventory_and_copy(tmp_path):
    mod = updater()
    source = tmp_path / "source"
    mod._private_directory(source)
    write(source, "objects/evidence", "synthetic private evidence")
    blocked = source / "objects"
    original = mod._acl(blocked)
    sid = mod._ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value")
    index = original.index("(")
    denied = original[:index] + "(D;;CC;;;" + sid + ")" + original[index:]
    mod._set_acl(blocked, denied)  # FILE_LIST_DIRECTORY only; direct child bytes remain readable.
    try:
        with pytest.raises(PermissionError):
            list(blocked.iterdir())
        assert (blocked / "evidence").read_text() == "synthetic private evidence"
        with pytest.raises(mod.UpdateError, match="enumerat"):
            mod._inventory(source)
        with pytest.raises(mod.UpdateError, match="enumerat"):
            mod._copy_tree(source, tmp_path / "snapshot")
        assert not (tmp_path / "snapshot").exists()
    finally:
        mod._set_acl(blocked, original)


@pytest.mark.skipif(__import__("os").name != "nt", reason="Native Windows path limits")
def test_restore_uses_short_siblings_for_a_valid_deep_installation(installation):
    mod = updater()
    old_root, bundle, baseline, recovery = installation
    root = old_root.with_name("installation-" + "x" * 30)
    old_root.rename(root)
    for relative in ("app/.env", "opensearch-2.19.6/config/opensearch.yml"):
        path = root / relative
        path.write_text(path.read_text().replace(str(old_root), str(root))
                        .replace(old_root.as_posix(), root.as_posix()), encoding="utf-8")
    parent = root / "data/objects"
    deep = parent / ("d" * (225 - len(str(parent)) - 1))
    assert len(str(deep)) == 225
    assert len(str(root.with_name(root.name + ".restore-" + "0" * 32) / deep.relative_to(root))) > 247
    write(root, str(deep.relative_to(root) / "evidence"), "preserved evidence")
    mod.apply(root, bundle, recovery, baseline)
    write(root, "data/objects/new-evidence", "new evidence")
    restored = mod.restore(root, recovery, confirm=True)
    retained = Path(restored["retained_installation"])
    assert len(retained.name) <= 19
    assert deep.joinpath("evidence").read_text() == "preserved evidence"
    assert (retained / "data/objects/new-evidence").read_text() == "new evidence"
    assert (root / "app/saw/main.py").read_text() == "old app"

@pytest.mark.skipif(__import__("os").name != "nt", reason="Native Windows path limits")
def test_copy_rejects_overlong_descendant_before_creating_destination(tmp_path):
    mod = updater()
    source = tmp_path / "s"
    source.mkdir()
    deep = source / ("d" * (225 - len(str(source)) - 1))
    deep.mkdir()
    (deep / "evidence").write_text("synthetic evidence")
    destination = tmp_path / ("destination-" + "x" * 35)
    with pytest.raises(mod.UpdateError, match="path length"):
        mod._copy_tree(source, destination)
    assert not destination.exists()
    assert (deep / "evidence").read_text() == "synthetic evidence"

@pytest.mark.skipif(__import__("os").name != "nt", reason="Native Windows path limits")
def test_apply_preflights_every_recovery_destination_before_creation(installation):
    mod = updater()
    root, bundle, baseline, _recovery = installation
    recovery = root.parent / ("r" * (235 - len(str(root.parent)) - 1))
    assert len(str(recovery)) == 235
    with pytest.raises(mod.UpdateError, match="path length"):
        mod.apply(root, bundle, recovery, baseline)
    assert not recovery.exists()
    assert (root / "app/saw/main.py").read_text() == "old app"

@pytest.mark.skipif(__import__("os").name != "nt", reason="Windows UTF-16 path limits")
def test_copy_path_limits_count_utf16_units_not_python_characters(tmp_path):
    mod = updater()
    source = tmp_path / "source"
    source.mkdir()
    (source / "evidence").write_text("synthetic evidence")
    count = (249 - len(str(tmp_path)) - 1 + 1) // 2
    destination = tmp_path / ("\U0001f4c1" * count)
    assert len(str(destination)) < 247
    assert len(str(destination).encode("utf-16-le")) // 2 >= 249
    with pytest.raises(mod.UpdateError, match="path length"):
        mod._copy_tree(source, destination)
    assert not destination.exists()


@pytest.mark.skipif(__import__("os").name != "nt", reason="Native Windows path boundaries")
def test_native_copy_accepts_directory_247_and_file_259_units(tmp_path):
    mod = updater()
    source = tmp_path / "s"
    source.mkdir()
    (source / "record0.bin").write_text("boundary evidence")
    destination = tmp_path / ("d" * (247 - len(str(tmp_path)) - 1))
    assert len(str(destination)) == 247
    assert len(str(destination / "record0.bin")) == 259
    mod._copy_tree(source, destination)
    assert (destination / "record0.bin").read_text() == "boundary evidence"

@pytest.mark.skipif(__import__("os").name != "nt", reason="Windows retained-tree path limits")
def test_restore_preflights_newer_retained_records_before_staging(installation):
    mod = updater()
    root, bundle, baseline, recovery = installation
    mod.apply(root, bundle, recovery, baseline)
    parent = root / "data/objects"
    deep = parent / ("d" * (245 - len(str(parent)) - 1))
    deep.mkdir()
    (deep / "evidence").write_text("new evidence remains accessible")
    before = set(root.parent.iterdir())
    with pytest.raises(mod.UpdateError, match="path length"):
        mod.restore(root, recovery, confirm=True)
    assert set(root.parent.iterdir()) == before
    assert (deep / "evidence").read_text() == "new evidence remains accessible"
    assert (root / "app/saw/main.py").read_text() == "new app"


def test_whole_restore_recovers_interrupted_application_directory_move(installation):
    mod = updater()
    root, bundle, baseline, recovery = installation
    mod.apply(root, bundle, recovery, baseline)
    stranded = root.parent / 'stranded-app'
    (root / 'app').rename(stranded)
    result = mod.restore(root, recovery, confirm=True)
    assert result['status'] == 'restored_stopped'
    assert (root / 'app/saw/main.py').read_text() == 'old app'
    assert (stranded / 'saw/main.py').read_text() == 'new app'
    assert Path(result['retained_installation']).is_dir()


def test_missing_application_does_not_bypass_corrupt_snapshot(installation):
    mod = updater()
    root, bundle, baseline, recovery = installation
    mod.apply(root, bundle, recovery, baseline)
    (root / 'app').rename(root.parent / 'stranded-app')
    write(recovery, 'installation/app/.env', 'SAW_DATABASE_URL=postgresql+psycopg://synthetic@external/saw')
    with pytest.raises(mod.UpdateError):
        mod.restore(root, recovery, confirm=True)
    assert not (root / 'app').exists()
    assert root.is_dir()
