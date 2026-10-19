"""Updater ACL regressions use only synthetic paths and security descriptors."""
from __future__ import annotations
import importlib.util
import json
import os
from pathlib import Path
import pytest

from saw.devtools import offline_update as backend
from saw.devtools import desktop_update as desktop

_spec = importlib.util.spec_from_file_location('_acl_cold_fixture', Path(__file__).with_name('test_offline_update.py'))
_fixture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fixture)
installation = _fixture.installation
write = _fixture.write
pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Native Windows ACL policy')


def test_owner_rights_native_dacl_is_accepted_without_repair(tmp_path):
    root = tmp_path / 'synthetic'
    backend._private_directory(root)
    write(root, 'app/runtime.py', 'synthetic')
    for path in backend._tree_paths(root):
        backend._set_acl(path, backend._acl(path) + '(A;;FA;;;OW)')
    before = {str(path): backend._acl(path) for path in backend._tree_paths(root)}
    report = backend._access_gate(root)
    desktop._static_access(root)
    assert report['checked'] == len(before)
    assert report['violations'] == 0
    assert {str(path): backend._acl(path) for path in backend._tree_paths(root)} == before


@pytest.mark.parametrize('owner,relative,rights,service,accepted', [
    ('current', '.', 0x1F01FF, False, True),
    ('S-1-5-18', '.', 0x1F01FF, False, True),
    ('S-1-5-32-544', '.', 0x1F01FF, False, True),
    ('S-1-5-21-100-200-300-400', '.', 0x1F01FF, False, False),
    ('S-1-5-20', 'data/postgresql', 0x1F01FF, True, True),
    ('S-1-5-20', 'logs/postgresql', 0x1301BF, True, True),
    ('S-1-5-20', 'logs/postgresql', 0x1F01FF, True, False),
    ('S-1-5-20', 'pgsql', 0x1200A9, True, False),
    ('S-1-5-20', 'data/postgresql', 0x1F01FF, False, False),
])
def test_owner_rights_resolves_owner_before_scope_limits(tmp_path, monkeypatch, owner, relative, rights, service, accepted):
    current = desktop._current_sid()
    owner = current if owner == 'current' else owner
    monkeypatch.setattr(backend, '_access_metadata', lambda _: (owner, [(0, 0, rights, 'S-1-3-4')]))
    if accepted:
        desktop._check_access(tmp_path, current, Path(relative), service)
    else:
        with pytest.raises(desktop.DesktopError):
            desktop._check_access(tmp_path, current, Path(relative), service)


@pytest.mark.parametrize('sid', ['S-1-1-0', 'S-1-5-11', 'S-1-5-32-545'])
def test_owner_rights_never_masks_foreign_write(tmp_path, monkeypatch, sid):
    current = desktop._current_sid()
    monkeypatch.setattr(backend, '_access_metadata',
                        lambda _: (current, [(0, 0, 0x1F01FF, 'S-1-3-4'), (0, 0, 0x2, sid)]))
    with pytest.raises(desktop.DesktopError, match='unsafe_access'):
        desktop._check_access(tmp_path, current)


def test_deny_owner_rights_and_precise_service_inheritance_remain_valid(tmp_path, monkeypatch):
    current = desktop._current_sid()
    monkeypatch.setattr(backend, '_access_metadata',
                        lambda _: (current, [(1, 0, 0x40000, 'S-1-3-4'), (0, 3, 0x1200A9, 'S-1-5-20')]))
    desktop._check_access(tmp_path, current, Path('pgsql'), True)
    with pytest.raises(desktop.DesktopError):
        desktop._check_access(tmp_path, current, Path('.'), True)


def test_access_report_aggregates_and_redacts_private_names(tmp_path):
    root = tmp_path / 'synthetic'
    backend._private_directory(root)
    for number in range(35):
        write(root, 'data/objects/SYNTHETIC_PRIVATE_NAME_' + str(number), 'private')
    for path in (root / 'data/objects').iterdir():
        backend._set_acl(path, backend._acl(path) + '(A;;FW;;;AU)')
    with pytest.raises(backend.UpdateError) as error:
        backend._access_gate(root)
    report = error.value.diagnostics
    assert report['checked'] == 38
    assert report['violations'] == 35
    assert len(report['items']) == 30 and report['truncated']
    assert all(item['reason'] == 'untrusted_allow' for item in report['items'])
    assert 'SYNTHETIC_PRIVATE_NAME_' not in json.dumps(report)
    assert str(tmp_path) not in json.dumps(report)
    assert error.value.code == 'unsafe_access'


def test_private_json_and_directory_have_explicit_owner_and_protected_acl(tmp_path):
    directory = tmp_path / 'private'
    backend._private_directory(directory)
    backend._json(directory / 'receipt.json', {'synthetic': True})
    current = desktop._current_sid()
    for path in (directory, directory / 'receipt.json'):
        owner, entries = backend._access_metadata(path)
        assert owner == current
        assert backend._acl(path).startswith('D:P')
        assert {entry[3] for entry in entries if entry[0] == 0} == {current, 'S-1-5-18'}
    with pytest.raises(FileExistsError):
        backend._private_directory(directory)
    assert json.loads((directory / 'receipt.json').read_text()) == {'synthetic': True}


def test_service_snapshot_uses_snapshot_relative_permissions(installation):
    root, bundle, baseline, recovery = installation
    _fixture.service_markers(root, bundle)
    for relative, rights in [('pgsql', '0x1200a9'), ('data/postgresql', 'FA')]:
        target = root / relative
        backend._set_acl(target, backend._acl(target) + '(A;OICI;' + rights + ';;;NS)')
    backend._private_directory(recovery)
    backend._copy_tree(root, recovery / 'installation')
    receipt = {'schema': 'saw.cold-recovery/1', 'install_root': str(root),
               'files': backend._inventory(recovery / 'installation')}
    backend._json(recovery / 'recovery-point.json', receipt)
    assert desktop._verify_snapshot(root, recovery) == receipt
    backend._set_acl(recovery, backend._acl(recovery) + '(A;;FR;;;NS)')
    with pytest.raises(backend.UpdateError):
        desktop._verify_snapshot(root, recovery)


def test_copy_keeps_owner_rights_bound_to_a_trusted_created_owner(tmp_path):
    source, parent = tmp_path / 'source', tmp_path / 'recovery'
    backend._private_directory(source)
    backend._private_directory(parent)
    write(source, 'runtime.py', 'synthetic')
    backend._set_acl(source / 'runtime.py', backend._acl(source / 'runtime.py') + '(A;;FA;;;OW)')
    before = backend._inventory(source)
    backend._copy_tree(source, parent / 'installation')
    assert backend._inventory(parent / 'installation') == before
    report = backend._access_gate(parent / 'installation')
    assert report['violations'] == 0


def test_metadata_access_failure_reports_only_safe_reason(tmp_path, monkeypatch):
    root = tmp_path / 'synthetic'
    backend._private_directory(root)
    write(root, 'app/runtime.py', 'synthetic')
    original = backend._access_metadata
    def denied(path):
        if path.name == 'runtime.py':
            raise PermissionError('SYNTHETIC_SECRET_MUST_NOT_ESCAPE')
        return original(path)
    monkeypatch.setattr(backend, '_access_metadata', denied)
    with pytest.raises(backend.UpdateError) as error:
        backend._access_gate(root)
    assert error.value.diagnostics['checked'] == 3
    assert error.value.diagnostics['items'] == [
        {'path': '<private-data>', 'reason': 'access_metadata_unreadable'}]
    assert 'SYNTHETIC_SECRET_MUST_NOT_ESCAPE' not in str(error.value)
    assert 'SYNTHETIC_SECRET_MUST_NOT_ESCAPE' not in json.dumps(error.value.diagnostics)


def test_failed_receipt_publish_keeps_previous_and_private_pending(tmp_path, monkeypatch):
    directory = tmp_path / 'recovery'
    backend._private_directory(directory)
    target = directory / 'recovery-point.json'
    backend._json(target, {'sequence': 1})
    before = target.read_bytes()
    def refuse(*args):
        raise PermissionError('synthetic publish refusal')
    monkeypatch.setattr(backend.os, 'replace', refuse)
    with pytest.raises(PermissionError):
        backend._json(target, {'sequence': 2})
    pending = target.with_name(target.name + '.writing')
    assert target.read_bytes() == before
    owner, entries = backend._access_metadata(pending)
    assert owner == desktop._current_sid()
    assert backend._acl(pending).startswith('D:P')
    assert {entry[3] for entry in entries if entry[0] == 0} == {owner, 'S-1-5-18'}


@pytest.mark.parametrize('source_owner,target_owner,entries,changed', [
    ('S-1-5-20', 'current', [(0, 0, 0x1F01FF, 'S-1-3-4')], True),
    ('S-1-5-20', 'current', [(0, 0, 0x1F01FF, 'S-1-5-20'), (0, 0, 0x1F01FF, 'S-1-3-4')], False),
    ('S-1-5-20', 'current', [(1, 0, 0x2, 'S-1-3-4'), (0, 0, 0x1F01FF, 'S-1-5-20')], True),
    ('S-1-5-20', 'current', [(1, 0, 0x2, 'S-1-5-20'), (1, 0, 0x2, 'S-1-3-4'), (0, 0, 0x1F01FF, 'S-1-5-20')], False),
    ('S-1-5-20', 'current', [(1, 0, 0x40000000, 'S-1-3-4'), (0, 0, 0x1F01FF, 'S-1-5-20')], True),
    ('S-1-5-20', 'current', [(1, 0, 0x120116, 'S-1-5-20'), (1, 0, 0x40000000, 'S-1-3-4'), (0, 0, 0x1F01FF, 'S-1-5-20')], False),
    ('S-1-5-20', 'current', [(0, 8, 0x1F01FF, 'S-1-3-4')], False),
    ('current', 'S-1-5-20', [(0, 0, 0x1F01FF, 'S-1-3-4')], True),
    ('S-1-5-20', 'S-1-5-20', [(0, 0, 0x1F01FF, 'S-1-3-4')], False),
    ('current', 'S-1-5-32-544', [(0, 0, 0x1F01FF, 'S-1-3-4')], False),
])
def test_owner_rights_service_semantics_consider_explicit_grants_and_denies(source_owner, target_owner, entries, changed):
    result = backend._owner_rights_service_change(source_owner, target_owner, entries)
    assert bool(result) is changed


def test_copy_refuses_service_owner_rights_change_before_private_bytes(tmp_path, monkeypatch):
    root = tmp_path / 'private'
    backend._private_directory(root)
    source, target = root / 'source', root / 'copy'
    source.write_text('synthetic private bytes')
    backend._set_acl(source, backend._acl(source) + '(A;;FA;;;OW)')
    metadata = backend._access_metadata
    def source_service_owner(path):
        owner, entries = metadata(path)
        return ('S-1-5-20' if path == source else owner), entries
    monkeypatch.setattr(backend, '_access_metadata', source_service_owner)
    with pytest.raises(backend.UpdateError) as error:
        backend._copy_file(source, target)
    assert error.value.code == 'owner_semantics_unpreserved'
    assert source.read_text() == 'synthetic private bytes'
    assert target.read_bytes() == b''


def test_copy_semantics_preflight_is_read_only_and_reports_specific_reason(tmp_path, monkeypatch):
    root = tmp_path / 'synthetic'
    backend._private_directory(root)
    backend._set_acl(root, backend._acl(root) + '(A;;FA;;;OW)')
    metadata = backend._access_metadata
    def source_service_owner(path):
        _, entries = metadata(path)
        return 'S-1-5-20', entries
    monkeypatch.setattr(backend, '_access_metadata', source_service_owner)
    before = backend._acl(root)
    with pytest.raises(backend.UpdateError) as error:
        backend._access_gate(root, relative_base=Path('data/postgresql'), service_mode=True,
                             check_copy_semantics=True)
    assert error.value.code == 'owner_semantics_unpreserved'
    assert error.value.diagnostics['items'][0]['reason'] == 'owner_rights_service_change'
    assert backend._acl(root) == before


def test_copy_tree_refuses_service_owner_rights_before_descendant_bytes(tmp_path, monkeypatch):
    source, target = tmp_path / 'source', tmp_path / 'copy'
    backend._private_directory(source)
    (source / 'record').write_text('synthetic private bytes')
    backend._set_acl(source, backend._acl(source) + '(A;;FA;;;OW)')
    metadata = backend._access_metadata
    def source_service_owner(path):
        owner, entries = metadata(path)
        return ('S-1-5-20' if path == source else owner), entries
    monkeypatch.setattr(backend, '_access_metadata', source_service_owner)
    with pytest.raises(backend.UpdateError) as error:
        backend._copy_tree(source, target)
    assert error.value.code == 'owner_semantics_unpreserved'
    assert list(target.iterdir()) == []
    assert (source / 'record').read_text() == 'synthetic private bytes'


def test_owner_rights_service_does_not_assume_mutable_users_membership():
    entries = [(1, 0, 0x1F01FF, 'S-1-5-32-545'),
               (0, 0, 0x1F01FF, 'S-1-3-4')]
    violation = backend._owner_rights_service_change('S-1-5-20', 'current', entries)
    assert violation is not None
    assert violation['source_rights'] == 0x1F01FF
    assert violation['copied_rights'] == 0


def test_owner_rights_service_checks_optional_deny_after_owner_allow():
    entries = [(0, 0, 0x2, 'S-1-3-4'),
               (1, 0, 0x2, 'S-1-5-32-545'),
               (0, 0, 0x2, 'S-1-5-20')]
    violation = backend._owner_rights_service_change('S-1-5-20', 'current', entries)
    assert violation is not None
    assert violation['source_rights'] == 0x2
    assert violation['copied_rights'] == 0


def test_owner_rights_service_accepts_equivalent_canonical_optional_denies():
    entries = [(1, 0, 0x2, 'S-1-5-32-545'),
               (1, 0, 0x4, 'S-1-5-21-123-456-789-1007'),
               (0, 0, 0x1F01FF, 'S-1-5-20'),
               (0, 0, 0x1F01FF, 'S-1-3-4')]
    assert backend._owner_rights_service_change('S-1-5-20', 'current', entries) is None


def test_owner_rights_service_bounds_ambiguous_membership_comparisons():
    entries = [(1, 0, 0x2, f'S-1-5-21-123-456-789-{1000 + number}') for number in range(33)]
    entries += [(0, 0, 0x1F01FF, 'S-1-5-20'), (0, 0, 0x1F01FF, 'S-1-3-4')]
    violation = backend._owner_rights_service_change('S-1-5-20', 'current', entries)
    assert violation is not None
    assert violation['comparison'] == 'unproven_group_membership'


@pytest.mark.parametrize('winerror,reason', [
    (2, 'access_metadata_file_missing'),
    (3, 'access_metadata_path_missing'),
    (32, 'access_metadata_sharing_violation'),
    (33, 'access_metadata_lock_violation'),
    (5, 'access_metadata_denied'),
    (87, 'access_metadata_unreadable'),
])
@pytest.mark.parametrize('failure_stage', ['size', 'read'])
def test_security_lookup_failure_captures_only_fixed_reason(tmp_path, monkeypatch, winerror, reason, failure_stage):
    import ctypes
    from ctypes import wintypes
    from types import SimpleNamespace
    calls = []
    def get_security(path, information, buffer, length, needed):
        calls.append(buffer is not None)
        if failure_stage == 'read' and buffer is None:
            ctypes.cast(needed, ctypes.POINTER(wintypes.DWORD)).contents.value = 64
            ctypes.set_last_error(122)
        else:
            ctypes.set_last_error(winerror)
        return 0
    monkeypatch.setattr(backend.ctypes, 'WinDLL',
                        lambda *args, **kwargs: SimpleNamespace(GetFileSecurityW=get_security))
    create_buffer = ctypes.create_string_buffer
    def unrelated_allocation(*args):
        ctypes.set_last_error(999)
        return create_buffer(*args)
    monkeypatch.setattr(backend.ctypes, 'create_string_buffer', unrelated_allocation)
    target = tmp_path / 'SYNTHETIC_PRIVATE_NAME'
    with pytest.raises(backend.UpdateError) as error:
        backend._access_metadata(target)
    assert error.value.code == reason
    assert calls == ([False] if failure_stage == 'size' else [False, True])
    assert 'SYNTHETIC_PRIVATE_NAME' not in str(error.value)
    assert str(tmp_path) not in str(error.value)


@pytest.fixture
def transient_acl_tree(tmp_path, monkeypatch):
    root = tmp_path / 'synthetic'
    backend._private_directory(root)
    write(root, 'data/objects/a-stable', 'synthetic')
    write(root, 'data/objects/z-transient', 'synthetic')
    current = backend._access_metadata(root)[0]
    monkeypatch.setattr(backend, '_ps', lambda _: current)
    return root


@pytest.mark.parametrize('changed', ['removed_only', 'new_untrusted_file', 'changed_checked_acl'])
def test_live_acl_retry_reenumerates_and_rechecks_every_object(transient_acl_tree, monkeypatch, changed):
    root = transient_acl_tree
    transient = root / 'data/objects/z-transient'
    stable = root / 'data/objects/a-stable'
    original = backend._access_metadata
    seen = []
    def metadata(path):
        seen.append(path)
        if path == transient and transient.exists():
            transient.unlink()
            if changed == 'new_untrusted_file':
                unsafe = root / 'data/objects/SYNTHETIC_PRIVATE_NAME'
                unsafe.write_text('synthetic')
                backend._set_acl(unsafe, backend._acl(unsafe) + '(A;;FW;;;AU)')
            elif changed == 'changed_checked_acl':
                backend._set_acl(stable, backend._acl(stable) + '(A;;FW;;;AU)')
        return original(path)
    monkeypatch.setattr(backend, '_access_metadata', metadata)
    if changed == 'removed_only':
        report = backend._access_gate(root, retry_transient=True)
        assert report['checked'] == 4 and report['violations'] == 0
    else:
        with pytest.raises(backend.UpdateError) as error:
            backend._access_gate(root, retry_transient=True)
        report = error.value.diagnostics
        assert error.value.code == 'unsafe_access'
        assert report['violations'] == 1
        assert report['items'] == [{'path': '<private-data>', 'reason': 'untrusted_allow',
                                   'sid': 'S-1-5-11', 'effective_sid': 'S-1-5-11',
                                   'rights': 0x120116, 'flags': 0}]
        assert 'SYNTHETIC_PRIVATE_NAME' not in json.dumps(report)
    assert report['attempts'] == 2
    assert seen.count(root) == 2 and seen.count(stable) == 2


@pytest.mark.parametrize('reason,retry,attempts', [
    ('access_metadata_file_missing', True, 3),
    ('access_metadata_path_missing', True, 3),
    ('access_metadata_sharing_violation', True, 3),
    ('access_metadata_lock_violation', True, 3),
    ('access_metadata_denied', True, 1),
    ('access_metadata_unreadable', True, 1),
    ('unsupported_access_ace', True, 1),
    ('UNTRUSTED_PRIVATE_EXCEPTION_CODE', True, 1),
    ('access_metadata_file_missing', False, 1),
])
def test_acl_retry_is_bounded_and_strict_by_default(transient_acl_tree, monkeypatch, reason, retry, attempts):
    root = transient_acl_tree
    transient = root / 'data/objects/z-transient'
    original = backend._access_metadata
    scans = []
    def metadata(path):
        if path == root:
            scans.append(path)
        if path == transient:
            raise backend.UpdateError('SYNTHETIC_SECRET_MUST_NOT_ESCAPE', code=reason)
        return original(path)
    monkeypatch.setattr(backend, '_access_metadata', metadata)
    with pytest.raises(backend.UpdateError) as error:
        if retry:
            backend._access_gate(root, retry_transient=True)
        else:
            backend._access_gate(root)
    report = error.value.diagnostics
    assert report['attempts'] == len(scans) == attempts
    assert report['checked'] == 5 and report['violations'] == 1
    assert error.value.code == 'unsafe_access'
    rendered = str(error.value) + json.dumps(report)
    assert 'SYNTHETIC_SECRET_MUST_NOT_ESCAPE' not in rendered
    assert 'UNTRUSTED_PRIVATE_EXCEPTION_CODE' not in rendered
    assert str(root) not in rendered


def test_acl_retry_never_retries_cold_snapshot(transient_acl_tree, monkeypatch):
    root = transient_acl_tree
    scans = []
    def metadata(path):
        scans.append(path)
        raise backend.UpdateError('synthetic missing', code='access_metadata_file_missing')
    monkeypatch.setattr(backend, '_access_metadata', metadata)
    with pytest.raises(backend.UpdateError) as error:
        backend._access_gate(root, snapshot_root=root / 'installation', retry_transient=True)
    assert error.value.diagnostics['attempts'] == 1
    assert len(scans) == 5


@pytest.mark.parametrize('other_failure', ['untrusted_allow', 'denied'])
def test_acl_retry_does_not_hide_real_violation_beyond_report_limit(tmp_path, monkeypatch, other_failure):
    root = tmp_path / 'synthetic'
    backend._private_directory(root)
    for number in range(31):
        (root / f'a-{number:02d}').write_text('synthetic')
    unsafe = root / 'z-unsafe'
    unsafe.write_text('synthetic')
    current, _ = backend._access_metadata(root)
    monkeypatch.setattr(backend, '_ps', lambda _: current)
    if other_failure == 'untrusted_allow':
        backend._set_acl(unsafe, backend._acl(unsafe) + '(A;;FW;;;AU)')
    original = backend._access_metadata
    scans = []
    def metadata(path):
        if path == root:
            scans.append(path)
        if path.name.startswith('a-'):
            raise backend.UpdateError('synthetic missing', code='access_metadata_file_missing')
        if path == unsafe and other_failure == 'denied':
            raise backend.UpdateError('synthetic denied', code='access_metadata_denied')
        return original(path)
    monkeypatch.setattr(backend, '_access_metadata', metadata)
    with pytest.raises(backend.UpdateError) as error:
        backend._access_gate(root, retry_transient=True)
    report = error.value.diagnostics
    assert report['attempts'] == len(scans) == 1
    assert report['checked'] == 33 and report['violations'] == 32
    assert len(report['items']) == 30 and report['truncated']
    assert all(item['reason'] == 'access_metadata_file_missing' for item in report['items'])


@pytest.mark.parametrize('kind', ['lstat', 'walk_onerror'])
def test_live_acl_retry_restarts_after_enumeration_disappearance(transient_acl_tree, monkeypatch, kind):
    root = transient_acl_tree
    transient = root / 'data/objects/z-transient'
    walk = backend.os.walk
    calls = []
    def disappearing_walk(top, **kwargs):
        calls.append(top)
        if kind == 'walk_onerror' and len(calls) == 1:
            kwargs['onerror'](FileNotFoundError(2, 'SYNTHETIC_PRIVATE_NAME'))
        for parent, directories, files in walk(top, **kwargs):
            if kind == 'lstat' and transient.name in files and len(calls) == 1:
                transient.unlink()
            yield parent, directories, files
    monkeypatch.setattr(backend.os, 'walk', disappearing_walk)
    report = backend._access_gate(root, retry_transient=True)
    assert report['attempts'] == len(calls) == 2
    assert report['checked'] == (4 if kind == 'lstat' else 5)
    assert report['violations'] == 0


@pytest.mark.parametrize('failure', ['token_missing', 'root_missing', 'reparse', 'hardlink', 'enumeration_denied'])
def test_live_acl_retry_never_retries_nontransient_enumeration_or_token(transient_acl_tree, monkeypatch, failure):
    root = transient_acl_tree
    original = backend._tree_paths
    attempts = []
    def tree(path):
        attempts.append(path)
        if failure in ('reparse', 'hardlink'):
            raise backend.UpdateError('SYNTHETIC_PRIVATE_NAME: ' + failure)
        if failure == 'enumeration_denied':
            raise PermissionError(13, 'SYNTHETIC_PRIVATE_NAME')
        return original(path)
    monkeypatch.setattr(backend, '_tree_paths', tree)
    if failure == 'token_missing':
        def missing_token(_):
            raise FileNotFoundError(2, 'SYNTHETIC_PRIVATE_NAME')
        monkeypatch.setattr(backend, '_ps', missing_token)
    elif failure == 'root_missing':
        root = root / 'SYNTHETIC_PRIVATE_NAME'
    with pytest.raises(backend.UpdateError) as error:
        backend._access_gate(root, retry_transient=True)
    report = error.value.diagnostics
    assert report['attempts'] == len(attempts) == 1
    assert report['checked'] == 0 and report['violations'] == 1
    assert 'SYNTHETIC_PRIVATE_NAME' not in str(error.value) + json.dumps(report)


def test_native_read_control_denial_is_strict_and_acl_is_not_repaired(transient_acl_tree):
    root = transient_acl_tree
    target = root / 'data/objects/z-transient'
    policy = backend._acl(target)
    owner, _ = backend._access_metadata(target)
    denied = f'D:P(D;;RC;;;OW)(A;;FA;;;{owner})(A;;FA;;;SY)'
    try:
        # The shared setter verifies by reading back; this fixture intentionally denies that read.
        with pytest.raises(backend.UpdateError, match='Cannot read a file access policy'):
            backend._set_acl(target, denied)
        with pytest.raises(backend.UpdateError) as error:
            backend._access_gate(root, retry_transient=True)
        report = error.value.diagnostics
        assert report['attempts'] == 1 and report['violations'] == 1
        assert report['items'] == [{'path': '<private-data>', 'reason': 'access_metadata_denied'}]
        with pytest.raises(backend.UpdateError) as still_denied:
            backend._access_metadata(target)
        assert still_denied.value.code == 'access_metadata_denied'
    finally:
        backend._set_acl(target, policy)
    assert backend._acl(target) == policy
