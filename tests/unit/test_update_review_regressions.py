"""Review regressions for restore preflight; synthetic metadata and mocks only."""
from contextlib import nullcontext
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from saw.devtools import desktop_update as desktop


class MemoryState:
    """Keep the controller result channel in memory for ordering assertions."""

    def __init__(self, directory, action, root, recovery):
        self.directory = directory
        self.value = {
            "schema": "saw.desktop-update/1",
            "action": action,
            "phase": "validate",
            "status": "working",
            "code": "working",
            "install_root": str(root),
            "requires_admin": False,
            "recovery_point": str(recovery),
        }

    def write(self, phase, status="working", code="working", **fields):
        self.value.update(phase=phase, status=status, code=code, **fields)
        return dict(self.value)


@pytest.fixture
def review_case(tmp_path, monkeypatch):
    """Avoid real runtime, ACL, lock, process, port, and service operations."""
    backend = desktop.backend
    root, bundle, recovery, state = [
        tmp_path / name for name in ("installed", "media", "recovery", "state")
    ]
    for path in (root, bundle, recovery, state):
        path.mkdir()
    candidate = {
        "metadata": dict(backend.PINS),
        "files": [{"path": "app/saw/main.py", "bytes": 16}],
    }
    (bundle / "release-manifest.json").write_text(
        json.dumps(candidate), encoding="utf-8"
    )
    snapshot_bytes = 1024 * 1024 * 1024
    receipt = {
        "schema": "saw.cold-recovery/1",
        "install_root": str(root),
        "files": [{"path": "synthetic-large-store", "bytes": snapshot_bytes}],
    }
    monkeypatch.setattr(desktop, "State", MemoryState)
    monkeypatch.setattr(desktop, "_state_directory", lambda value, paths: Path(value))
    monkeypatch.setattr(backend, "_maintenance", lambda *args, **kwargs: nullcontext())
    monkeypatch.setattr(backend, "_json", lambda *args, **kwargs: None)
    monkeypatch.setattr(backend._manifest, "verify", lambda path: {"verified": True})
    monkeypatch.setattr(desktop, "_verify_snapshot", lambda *args: receipt)
    monkeypatch.setattr(backend, "_access_gate", lambda *args, **kwargs: {"checked": 1})
    monkeypatch.setattr(backend, "_tree_paths", lambda path: [path])
    for name in ("_preflight_rows", "_preflight_copy", "_preflight_json",
                 "_windows_path_limit", "_installed_runtime"):
        monkeypatch.setattr(backend, name, lambda *args, **kwargs: None)
    cfg = {
        "port": 58443,
        "postgresPort": 58444,
        "opensearchPort": 58445,
        "transportPort": 58446,
    }
    monkeypatch.setattr(backend, "_config", lambda *args, **kwargs: ({}, cfg))
    pending = Mock(return_value=None)
    monkeypatch.setattr(backend, "_pending_restore", pending)
    writable, access, remove = Mock(), Mock(), Mock()
    monkeypatch.setattr(desktop, "_require_directory_write", writable)
    monkeypatch.setattr(desktop, "_require_path_access", access, raising=False)
    monkeypatch.setattr(desktop, "_require_remove_access", remove, raising=False)
    monkeypatch.setattr(
        backend.shutil, "disk_usage",
        lambda path: SimpleNamespace(free=64 * 1024 * 1024),
    )
    restore = Mock()
    monkeypatch.setattr(backend.restore, "__wrapped__", restore)
    control = SimpleNamespace(
        identity=Mock(return_value={"admin": False, "services": []}),
        claim=Mock(side_effect=lambda *args, **kwargs: nullcontext()),
        stop=Mock(),
        start=Mock(),
        healthy=Mock(return_value=True),
    )
    return SimpleNamespace(
        root=root, bundle=bundle, recovery=recovery, state=state,
        snapshot_bytes=snapshot_bytes, pending=pending, writable=writable, access=access, remove=remove,
        restore=restore, control=control,
    )


@pytest.mark.parametrize("phase", ["staged", "restored"])
def test_restore_retry_does_not_budget_an_already_allocated_copy(review_case, phase):
    case = review_case
    case.pending.return_value = {"actual_phase": phase, "token": "c" * 12,
                                 "stage": str(case.root.with_name(".saw-r-" + "c" * 12))}
    report = desktop.diagnostics.Inspection()

    result = desktop._recovery_preflight(
        case.root, case.bundle, case.recovery, "restore", report
    )

    assert result["required_with_restore_headroom_bytes"] == 0
    assert result["free_bytes"] < case.snapshot_bytes
    assert report.rows["recovery"]["status"] == "pass"
    case.pending.assert_called_once_with(case.root, case.recovery)
    case.access.assert_any_call(case.recovery, 0x2)


@pytest.mark.parametrize("phase", [None, "complete"])
def test_new_restore_still_requires_space_for_another_copy(review_case, phase):
    case = review_case
    case.pending.return_value = {"actual_phase": phase, "token": "c" * 12,
                                 "stage": str(case.root.with_name(".saw-r-" + "c" * 12))} if phase else None

    with pytest.raises(desktop.DesktopError) as caught:
        desktop._recovery_preflight(
            case.root, case.bundle, case.recovery,
            "restore", desktop.diagnostics.Inspection(),
        )

    assert caught.value.code == "recovery_headroom_insufficient"
    assert caught.value.diagnostics["expected"] == (
        str(case.snapshot_bytes + 64 * 1024 * 1024) + " bytes"
    )


def test_resumed_missing_root_swap_does_not_budget_a_second_copy(review_case):
    case = review_case
    case.pending.return_value = {"actual_phase": "complete"}

    result = desktop._recovery_preflight(
        case.root, case.bundle, case.recovery,
        "restore", desktop.diagnostics.Inspection(), already_restored=True,
    )

    assert result["required_with_restore_headroom_bytes"] == 0
    assert result["free_bytes"] < case.snapshot_bytes


def test_missing_root_service_restore_requires_admin_before_restore(review_case):
    case = review_case
    case.root.rmdir()
    snapshot = case.recovery / "installation"
    snapshot.mkdir()
    (snapshot / ".saw-install-state.json").write_text(
        json.dumps({
            "schema": "saw.install-state/1",
            "root": str(case.root),
            "status": "complete",
            "options": {
                "noAdmin": False, "noServices": False, "hostName": "localhost",
            },
        }),
        encoding="utf-8",
    )
    services = []
    for name, relative in desktop.SERVICE_PATHS.items():
        command = '"' + str(case.root / relative) + '"'
        if name == "saw-opensearch":
            command += " //RS//saw-opensearch"
        services.append({"Name": name, "PathName": command})
    case.control.identity.return_value = {"admin": False, "services": services}

    result = desktop.run(
        "restore", case.root, case.bundle, case.state,
        recovery_point=case.recovery, maintenance_confirmed=True, confirm=True,
        controller=case.control,
    )

    assert result["status"] == "failed"
    assert result["code"] == "administrator_required"
    assert result["requires_admin"] is True
    assert not case.root.exists()
    case.restore.assert_not_called()
    case.control.stop.assert_not_called()
    case.control.start.assert_not_called()


@pytest.mark.parametrize("phase", [None, "staged"])
def test_existing_recovery_create_denial_is_reported_before_stop(review_case, phase):
    case = review_case
    case.pending.return_value = {"actual_phase": phase, "token": "c" * 12,
                                 "stage": str(case.root.with_name(".saw-r-" + "c" * 12))} if phase else None
    marker = case.root / "synthetic-evidence.txt"
    marker.write_text("Synthetic evidence for this regression only.", encoding="utf-8")

    def create_access(path, rights):
        if path == case.recovery:
            raise desktop.DesktopError("recovery_parent_access")

    case.access.side_effect = create_access

    result = desktop.run(
        "restore", case.root, case.bundle, case.state,
        recovery_point=case.recovery, maintenance_confirmed=True, confirm=True,
        controller=case.control,
    )

    assert result["status"] == "failed"
    assert result["code"] == "recovery_parent_access"
    recovery_row = result["diagnostic_summary"]["rows"][7]
    assert recovery_row["id"] == "recovery"
    assert recovery_row["status"] == "fail"
    assert recovery_row["code"] == "recovery_parent_access"
    case.access.assert_called_once_with(case.recovery, 0x2)
    case.restore.assert_not_called()
    case.control.stop.assert_not_called()
    case.control.start.assert_not_called()
    assert marker.read_text(encoding="utf-8") == (
        "Synthetic evidence for this regression only."
    )


@pytest.mark.parametrize("selected", ["none", "existing", "missing_parent"])
def test_start_does_not_require_backup_space_or_recovery_write_access(review_case, monkeypatch, selected):
    case = review_case
    recovery = {"none": None, "existing": case.recovery,
                "missing_parent": case.root.parent / "missing" / "recovery"}[selected]
    disk = Mock(return_value=SimpleNamespace(free=1))
    monkeypatch.setattr(desktop.backend.shutil, "disk_usage", disk)
    case.writable.side_effect = desktop.DesktopError("recovery_parent_access")
    snapshot = Mock(side_effect=AssertionError("Start must not claim snapshot verification"))
    monkeypatch.setattr(desktop, "_verify_snapshot", snapshot)
    report = desktop.diagnostics.Inspection()

    result = desktop._recovery_preflight(case.root, case.bundle, recovery, "start", report)

    assert result["required_with_restore_headroom_bytes"] == 0
    assert result["snapshot_required"] is False
    row = report.rows["recovery"]
    assert row["status"] == "pass"
    assert row["code"] == "recovery_not_required"
    assert "시작" in row["reason"] and "검증하지" in row["reason"]
    assert not row["location"]
    snapshot.assert_not_called()
    disk.assert_not_called()
    case.writable.assert_not_called()
    case.access.assert_not_called()
    case.remove.assert_not_called()
    case.pending.assert_not_called()


@pytest.mark.parametrize("action", ["inspect", "apply"])
def test_non_start_actions_preserve_full_new_snapshot_budget(review_case, monkeypatch, action):
    case = review_case
    recovery = case.root.parent / "fresh-recovery"
    disk = Mock(return_value=SimpleNamespace(free=1))
    monkeypatch.setattr(desktop.backend.shutil, "disk_usage", disk)

    with pytest.raises(desktop.DesktopError) as caught:
        desktop._recovery_preflight(
            case.root, case.bundle, recovery, action, desktop.diagnostics.Inspection(),
        )

    assert caught.value.code == "recovery_headroom_insufficient"
    assert caught.value.diagnostics["expected"] == str(128 * 1024 * 1024 + 16) + " bytes"
    disk.assert_called_once_with(case.root.parent)
    case.access.assert_any_call(recovery.parent, 0x4)


def test_start_still_rejects_overlapping_recovery_path_before_control(review_case):
    case = review_case

    with pytest.raises(desktop.DesktopError) as caught:
        desktop.run(
            "start", case.root, case.bundle, case.state,
            recovery_point=case.root, controller=case.control,
        )

    assert caught.value.code == "unsafe_paths"
    case.control.identity.assert_not_called()
    case.control.start.assert_not_called()


@pytest.mark.parametrize("action", ["inspect", "apply"])
@pytest.mark.parametrize("denied", ["root_create", "app_remove", "control_remove", "manifest_remove", "control_write", "manifest_write"])
def test_update_destination_rights_are_required_before_copy(review_case, monkeypatch, action, denied):
    case = review_case
    (case.root / "app").mkdir()
    control = case.root / "saw-ctl.ps1"
    manifest = case.root / "installed-release-manifest.json"
    control.write_text("synthetic control", encoding="utf-8")
    manifest.write_text("synthetic manifest", encoding="utf-8")
    monkeypatch.setattr(desktop.backend.shutil, "disk_usage",
                        lambda path: SimpleNamespace(free=8 * 1024 * 1024 * 1024))
    target = {"root_create": case.root, "app_remove": case.root / "app",
              "control_remove": control, "manifest_remove": manifest,
              "control_write": control, "manifest_write": manifest}[denied]
    def reject(path, *args):
        if path == target:
            raise desktop.DesktopError("recovery_parent_access")
    if denied == "root_create":
        case.writable.side_effect = reject
    elif denied.endswith("_write"):
        case.access.side_effect = reject
    else:
        case.remove.side_effect = reject

    with pytest.raises(desktop.DesktopError) as caught:
        desktop._recovery_preflight(
            case.root, case.bundle, case.root.parent / "fresh-recovery",
            action, desktop.diagnostics.Inspection(),
        )

    assert caught.value.code == "recovery_parent_access"
    case.control.stop.assert_not_called()
    assert control.read_text(encoding="utf-8") == "synthetic control"


@pytest.mark.parametrize("phase", ["staged", "restored"])
def test_restore_retry_checks_only_remaining_publication_and_rename_rights(review_case, phase):
    case = review_case
    token = "a" * 12
    stage = case.root.with_name(".saw-r-" + token)
    if phase == "staged":
        stage.mkdir()
    journal = case.recovery / "restore-journal.json"
    journal.write_text("synthetic journal", encoding="utf-8")
    result_path = case.recovery / ("restore-result-" + token + ".json")
    result_path.write_text("synthetic result", encoding="utf-8")
    case.pending.return_value = {"actual_phase": phase, "token": token, "stage": str(stage)}

    desktop._recovery_preflight(
        case.root, case.bundle, case.recovery, "restore", desktop.diagnostics.Inspection(),
    )

    case.access.assert_any_call(case.recovery, 0x2)
    case.remove.assert_any_call(journal)
    case.remove.assert_any_call(result_path)
    if phase == "staged":
        case.access.assert_any_call(case.root.parent, 0x4)
        case.remove.assert_any_call(case.root)
        case.remove.assert_any_call(stage)
    else:
        assert [entry.args for entry in case.access.call_args_list] == [(case.recovery, 0x2)]
        assert [entry.args for entry in case.remove.call_args_list] == [(journal,), (result_path,)]
        case.writable.assert_not_called()


@pytest.mark.parametrize("denied", ["parent_create", "stage_remove", "recovery_write", "journal_remove"])
def test_missing_root_resume_requires_remaining_rights_before_restore(review_case, monkeypatch, denied):
    case = review_case
    case.root.rmdir()
    token = "b" * 12
    stage = case.root.with_name(".saw-r-" + token)
    retained = case.root.with_name(".saw-k-" + token)
    stage.mkdir()
    retained.mkdir()
    journal = case.recovery / "restore-journal.json"
    journal.write_text("synthetic journal", encoding="utf-8")
    case.pending.return_value = {
        "actual_phase": "root_retained", "stage": str(stage),
        "retained_installation": str(retained), "token": token,
    }
    monkeypatch.setattr(desktop, "_mode", lambda *args, **kwargs: ("noadmin", "localhost"))
    target = {"parent_create": case.root.parent, "stage_remove": stage,
              "recovery_write": case.recovery, "journal_remove": journal}[denied]
    def reject(path, *args):
        if path == target:
            raise desktop.DesktopError("recovery_parent_access")
    if denied.endswith("_remove"):
        case.remove.side_effect = reject
    else:
        case.access.side_effect = reject

    result = desktop.run(
        "restore", case.root, case.bundle, case.state,
        recovery_point=case.recovery, maintenance_confirmed=True, confirm=True,
        controller=case.control,
    )

    assert result["status"] == "failed"
    assert result["code"] == "recovery_parent_access"
    case.restore.assert_not_called()
    case.control.stop.assert_not_called()
    case.control.start.assert_not_called()
    assert not case.root.exists() and stage.is_dir() and retained.is_dir()

@pytest.mark.parametrize("action", ["inspect", "apply", "restore", "start"])
def test_live_inspection_requests_complete_transient_acl_recheck(review_case, monkeypatch, action):
    case = review_case
    gate = Mock(return_value={"checked": 12, "violations": 0, "attempts": 2})
    monkeypatch.setattr(desktop.backend, "_access_gate", gate)
    state = MemoryState(case.state, action, case.root, case.recovery)

    report, _, _, _ = desktop._inspect_all(
        state, case.root, case.bundle, None, case.recovery, action,
        case.control, case.control.identity(),
    )

    first = gate.call_args_list[0]
    assert first.args == (case.root,)
    assert first.kwargs == {
        "check_copy_semantics": action in ("inspect", "apply"), "retry_transient": True,
    }
    assert all(not call.kwargs.get("retry_transient", False) for call in gate.call_args_list[1:])
    assert report.rows["access"]["status"] == "pass"
    assert "전체 검사 시도 2회" in report.rows["access"]["actual"]
    case.control.stop.assert_not_called()
    case.control.start.assert_not_called()


def test_failed_live_acl_recheck_still_prevents_service_mutation(review_case, monkeypatch):
    case = review_case
    error = desktop.backend.UpdateError(
        "Synthetic metadata failure", code="unsafe_access", diagnostics={
            "scope": "installation", "checked": 12, "violations": 1, "attempts": 3,
            "items": [{"path": "<private-data>", "reason": "access_metadata_file_missing"}],
            "truncated": False,
        },
    )
    gate = Mock(side_effect=error)
    monkeypatch.setattr(desktop.backend, "_access_gate", gate)

    result = desktop.run(
        "restore", case.root, case.bundle, case.state,
        recovery_point=case.recovery, maintenance_confirmed=True, confirm=True,
        controller=case.control,
    )

    assert result["status"] == "failed" and result["current_step"] == "validate"
    assert result["code"] == "unsafe_access"
    assert gate.call_args.kwargs["retry_transient"] is True
    case.control.stop.assert_not_called()
    case.control.start.assert_not_called()
    case.restore.assert_not_called()
