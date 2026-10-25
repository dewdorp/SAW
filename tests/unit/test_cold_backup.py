"""Complete stopped-installation backups share the verified restore contract."""
from __future__ import annotations

import json
import socket

import pytest

from saw.devtools import offline_update as mod
from tests.unit import test_offline_update as fixtures

installation = fixtures.installation


def test_standalone_backup_covers_generations_and_restores_later_data(installation):
    root, _, _, recovery = installation
    extra = {
        "data/saw/event-generations/g-synthetic.sqlite3": b"synthetic retained generation",
        "data/saw/event-generations/cursor.key": b"synthetic cursor secret",
        "data/opensearch/generation-index": b"synthetic staged and current index",
        "data/objects/saw-artifacts/generations/synthetic/1/http.log": b"synthetic raw",
    }
    for relative, content in extra.items():
        fixtures.write(root, relative, content)
    before = {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    result = mod.backup(root, recovery)
    assert result["status"] == "backup_complete_stopped"
    assert {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()} == before
    receipt = json.loads((recovery / "recovery-point.json").read_text(encoding="utf-8"))
    assert receipt["schema"] == "saw.cold-recovery/1"
    assert set(extra) <= {row["path"] for row in receipt["files"]}
    fixtures.write(root, "data/objects/later-evidence", b"later")
    restored = mod.restore(root, recovery, confirm=True)
    assert {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()} == before
    assert (mod.Path(restored["retained_installation"]) / "data/objects/later-evidence").read_bytes() == b"later"


def test_backup_rejects_active_process_without_creating_snapshot(installation):
    root, _, _, recovery = installation
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 58101))
        listener.listen()
        with pytest.raises(mod.UpdateError):
            mod.backup(root, recovery)
    assert not recovery.exists()


def test_backup_detects_state_change_during_copy(installation, monkeypatch):
    root, _, _, recovery = installation
    copy = mod._copy_tree

    def changed(source, destination):
        copy(source, destination)
        fixtures.write(root, "data/objects/concurrent", b"synthetic changed")
    monkeypatch.setattr(mod, "_copy_tree", changed)
    with pytest.raises(mod.UpdateError, match="changed"):
        mod.backup(root, recovery)
    assert not (recovery / "recovery-point.json").exists()
    assert (root / "data/objects/concurrent").read_bytes() == b"synthetic changed"


def test_backup_refuses_nested_destination_and_existing_point(installation):
    root, _, _, recovery = installation
    with pytest.raises(mod.UpdateError):
        mod.backup(root, root / "backup" / "nested")
    recovery.mkdir()
    fixtures.write(recovery, "keep.txt", b"synthetic prior recovery")
    with pytest.raises(mod.UpdateError):
        mod.backup(root, recovery)
    assert (recovery / "keep.txt").read_bytes() == b"synthetic prior recovery"


def test_backup_cli_needs_no_new_media(installation, capsys):
    root, _, _, recovery = installation
    assert mod.main(["backup", "--install-root", str(root), "--recovery-point", str(recovery)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "backup_complete_stopped"
