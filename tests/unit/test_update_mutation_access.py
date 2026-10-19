"""Read-only native permission probes for the updater's actual mutations."""
from __future__ import annotations
import json
import os
from pathlib import Path
from types import SimpleNamespace
import pytest
from saw.devtools import desktop_update as desktop
from saw.devtools import offline_update as backend

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Native Windows access checks")
FULL = 0x1F01FF
DELETE = 0x10000
DELETE_CHILD = 0x40


@pytest.fixture
def access_tree(tmp_path):
    root = tmp_path / "installation"
    backend._private_directory(root)
    app = root / "app"
    app.mkdir()
    (app / "record.txt").write_text("Synthetic record only.", encoding="utf-8")
    target = root / "saw-ctl.ps1"
    target.write_text("Synthetic control only.", encoding="utf-8")
    sid, _ = backend._access_metadata(root)
    policies = {path: backend._acl(path) for path in (root, app, target)}
    def policy(path, allow=FULL, deny=0):
        denied = f"(D;;0x{deny:x};;;{sid})" if deny else ""
        try:
            backend._set_acl(path, f"D:P{denied}(A;;0x{allow:x};;;{sid})(A;;FA;;;SY)")
        except backend.UpdateError:
            # Windows canonicalizes numeric SDDL masks to aliases. Assert the
            # complete native ACE list rather than its equivalent spelling.
            expected = ([(1, 0, deny, sid)] if deny else []) + [(0, 0, allow, sid), (0, 0, FULL, "S-1-5-18")]
            assert backend._access_metadata(path) == (sid, expected)
    try:
        yield SimpleNamespace(root=root, app=app, target=target, policy=policy, temporary=tmp_path)
    finally:
        for path, original in policies.items():
            if path.exists():
                backend._set_acl(path, original)


def test_native_path_probe_requests_only_specific_create_right(access_tree):
    case = access_tree
    case.policy(case.root, 0x1200A9 | 0x2)
    before = backend._inventory(case.root)
    desktop._require_path_access(case.root, 0x2)
    with pytest.raises(desktop.DesktopError) as caught:
        desktop._require_path_access(case.root, 0x4)
    assert caught.value.code == "recovery_parent_access"
    assert backend._inventory(case.root) == before


def test_native_create_probe_does_not_require_full_control_or_delete(access_tree):
    case = access_tree
    case.policy(case.root, 0x1200A9 | 0x6, DELETE | DELETE_CHILD)
    before = backend._inventory(case.root)
    desktop._require_directory_write(case.root)
    assert backend._inventory(case.root) == before


@pytest.mark.parametrize("object_delete,parent_delete_child,accepted", [
    (True, False, True), (False, True, True), (False, False, False),
])
def test_native_remove_probe_accepts_either_valid_permission_without_mutation(
        access_tree, object_delete, parent_delete_child, accepted):
    case = access_tree
    case.policy(case.root, FULL, 0 if parent_delete_child else DELETE_CHILD)
    case.policy(case.app, FULL, 0 if object_delete else DELETE)
    before = backend._inventory(case.root)
    if accepted:
        desktop._require_remove_access(case.app)
    else:
        with pytest.raises(desktop.DesktopError) as caught:
            desktop._require_remove_access(case.app)
        assert caught.value.code == "recovery_parent_access"
    assert backend._inventory(case.root) == before


def test_native_existing_file_remove_probe_keeps_bytes_and_acl(access_tree):
    case = access_tree
    case.policy(case.root, FULL, DELETE_CHILD)
    case.policy(case.target, 0x120089 | DELETE)
    before = backend._inventory(case.root)
    desktop._require_remove_access(case.target)
    assert backend._inventory(case.root) == before


@pytest.fixture
def preflight_media(access_tree):
    case = access_tree
    bundle = case.temporary / "media"
    (bundle / "app").mkdir(parents=True)
    (bundle / "app/record.txt").write_text("Synthetic public media.", encoding="utf-8")
    (bundle / "release-manifest.json").write_text(json.dumps({
        "files": [{"path": "app/record.txt", "bytes": 23}]}), encoding="utf-8")
    return case, bundle, case.temporary / "recovery"


@pytest.mark.parametrize("denied", [0x2, 0x4])
def test_apply_preflight_refuses_installation_create_denial_read_only(preflight_media, denied):
    case, bundle, recovery = preflight_media
    case.policy(case.root, FULL, denied)
    before = backend._inventory(case.root)
    with pytest.raises(desktop.DesktopError) as caught:
        desktop._recovery_preflight(case.root, bundle, recovery, "apply", desktop.diagnostics.Inspection())
    assert caught.value.code == "recovery_parent_access"
    assert not recovery.exists()
    assert backend._inventory(case.root) == before


def test_apply_preflight_refuses_app_rename_without_either_delete_permission(preflight_media):
    case, bundle, recovery = preflight_media
    case.policy(case.root, FULL, DELETE_CHILD)
    case.policy(case.app, FULL, DELETE)
    before = backend._inventory(case.root)
    with pytest.raises(desktop.DesktopError) as caught:
        desktop._recovery_preflight(case.root, bundle, recovery, "apply", desktop.diagnostics.Inspection())
    assert caught.value.code == "recovery_parent_access"
    assert not recovery.exists()
    assert backend._inventory(case.root) == before


@pytest.mark.parametrize("object_delete,parent_delete_child", [(True, False), (False, True)])
def test_apply_preflight_preserves_both_valid_rename_permission_alternatives(
        preflight_media, object_delete, parent_delete_child):
    case, bundle, recovery = preflight_media
    case.policy(case.root, FULL, 0 if parent_delete_child else DELETE_CHILD)
    case.policy(case.app, FULL, 0 if object_delete else DELETE)
    before = backend._inventory(case.root)
    report = desktop.diagnostics.Inspection()
    result = desktop._recovery_preflight(case.root, bundle, recovery, "apply", report)
    assert result["required_with_restore_headroom_bytes"] > 0
    assert report.rows["recovery"]["status"] == "pass"
    assert not recovery.exists()
    assert backend._inventory(case.root) == before
