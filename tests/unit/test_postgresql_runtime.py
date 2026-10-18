"""Verified PostgreSQL archive recovery may add missing owned files only."""
from pathlib import Path
import zipfile
import pytest


def fixture(tmp_path):
    archive=tmp_path/"postgresql.zip"
    with zipfile.ZipFile(archive,"w") as z:
        z.writestr("pgsql/bin/postgres.exe",b"postgres synthetic")
        z.writestr("pgsql/bin/initdb.exe",b"initdb synthetic")
        z.writestr("pgsql/share/sample.txt",b"config synthetic")
    root=tmp_path/"install";root.mkdir()
    return archive,root


def run(archive,root):
    from saw.devtools.postgresql_runtime import prepare
    return prepare(archive,root)


def test_fresh_archive_and_missing_owned_binary_recovery(tmp_path):
    archive,root=fixture(tmp_path)
    assert run(archive,root)["written"]==3
    original=(root/"pgsql/bin/postgres.exe").read_bytes()
    (root/"pgsql/bin/initdb.exe").unlink()
    assert run(archive,root)["written"]==1
    assert (root/"pgsql/bin/postgres.exe").read_bytes()==original
    assert run(archive,root)["written"]==0


@pytest.mark.parametrize("case",["partial_without_marker","modified_binary","unknown_file"])
def test_unknown_or_modified_runtime_is_never_overwritten(tmp_path,case):
    archive,root=fixture(tmp_path)
    if case=="partial_without_marker":
        (root/"pgsql/bin").mkdir(parents=True)
        (root/"pgsql/bin/postgres.exe").write_bytes(b"postgres synthetic")
    else:
        run(archive,root)
        if case=="modified_binary": (root/"pgsql/bin/postgres.exe").write_bytes(b"user modification")
        else: (root/"pgsql/customer.txt").write_bytes(b"user data")
    before={p.relative_to(root):p.read_bytes() for p in root.rglob("*") if p.is_file()}
    with pytest.raises(ValueError): run(archive,root)
    assert {p.relative_to(root):p.read_bytes() for p in root.rglob("*") if p.is_file()}==before


def test_unreadable_inventory_aborts_without_partial_repair(tmp_path,monkeypatch):
    from saw.devtools import postgresql_runtime as m
    archive,root=fixture(tmp_path)
    run(archive,root)
    (root/"pgsql/bin/initdb.exe").unlink()
    before={p.relative_to(root):p.read_bytes() for p in root.rglob("*") if p.is_file()}
    def denied(path, *, followlinks, onerror):
        onerror(PermissionError("synthetic inaccessible directory"))
        return iter(())
    monkeypatch.setattr(m.os,"walk",denied)
    with pytest.raises(PermissionError): run(archive,root)
    assert {p.relative_to(root):p.read_bytes() for p in root.rglob("*") if p.is_file()}==before


def test_runtime_reparse_entry_refused_before_repair(tmp_path,monkeypatch):
    from saw.devtools import postgresql_runtime as m
    from types import SimpleNamespace
    import stat
    archive,root=fixture(tmp_path)
    run(archive,root)
    (root/"pgsql/bin/initdb.exe").unlink()
    target=root/"pgsql/bin"
    original=Path.lstat
    def reparse(path, *args, **kwargs):
        if path==target:
            return SimpleNamespace(st_mode=stat.S_IFDIR,st_file_attributes=0x400)
        return original(path,*args,**kwargs)
    monkeypatch.setattr(Path,"lstat",reparse)
    with pytest.raises(ValueError,match="reparse"): run(archive,root)
    assert not (root/"pgsql/bin/initdb.exe").exists()
