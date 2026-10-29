"""Cold restore interruption journals preserve both versions and require consent."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import pytest
from saw.devtools import offline_update as backend

_spec = importlib.util.spec_from_file_location('_restore_cold_fixture', Path(__file__).with_name('test_offline_update.py'))
_fixture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fixture)
installation = _fixture.installation
write = _fixture.write


@pytest.fixture
def recoverable(installation):
    root, bundle, baseline, recovery = installation
    backend._private_directory(recovery)
    backend._copy_tree(root, recovery / 'installation')
    receipt = {'schema': 'saw.cold-recovery/1', 'install_root': str(root),
               'files': backend._inventory(recovery / 'installation')}
    backend._json(recovery / 'recovery-point.json', receipt)
    write(root, 'app/saw/main.py', 'new app')
    write(root, 'data/objects/new-record', 'preserved new record')
    return root, recovery, receipt


@pytest.mark.parametrize('boundary', ['before_first', 'after_first', 'before_second', 'after_second', 'rollback_failure'])
def test_restore_interruption_can_resume_without_losing_either_version(recoverable, monkeypatch, boundary):
    root, recovery, receipt = recoverable
    original_rename = backend.os.rename
    calls = []
    def fail(source, target):
        source, target = Path(source), Path(target)
        calls.append((source, target))
        first = source == root and target.name.startswith('.saw-k-')
        second = source.name.startswith('.saw-r-') and target == root
        rollback = source.name.startswith('.saw-k-') and target == root
        if ((boundary == 'before_first' and first) or
            (boundary in ('before_second', 'rollback_failure') and second) or
            (boundary == 'rollback_failure' and rollback)):
            raise OSError('synthetic rename refusal')
        original_rename(source, target)
        if (boundary == 'after_first' and first) or (boundary == 'after_second' and second):
            raise OSError('synthetic interruption after rename')
    monkeypatch.setattr(backend.os, 'rename', fail)
    with pytest.raises(backend.UpdateError) as error:
        backend.restore(root, recovery, confirm=True)
    assert error.value.code == 'restore_interrupted'
    pending = backend._pending_restore(root, recovery)
    assert pending['actual_phase'] in {'staged', 'root_retained', 'restored'}
    newer = Path(pending['current_location'])
    if pending['actual_phase'] == 'restored':
        newer = Path(pending['retained_installation'])
    assert (newer / 'data/objects/new-record').read_text() == 'preserved new record'
    monkeypatch.setattr(backend.os, 'rename', original_rename)
    result = backend.restore(root, recovery, confirm=True)
    assert result['status'] == 'restored_stopped'
    assert backend._inventory(root) == receipt['files']
    assert (Path(result['retained_installation']) / 'data/objects/new-record').read_text() == 'preserved new record'
    assert backend._pending_restore(root, recovery)['actual_phase'] == 'complete'


def test_missing_root_retry_requires_explicit_confirmation(recoverable, monkeypatch):
    root, recovery, receipt = recoverable
    original = backend.os.rename
    def interrupt(source, target):
        original(source, target)
        if Path(source) == root:
            raise OSError('synthetic interruption')
    monkeypatch.setattr(backend.os, 'rename', interrupt)
    with pytest.raises(backend.UpdateError):
        backend.restore(root, recovery, confirm=True)
    assert not root.exists()
    before = backend._inventory(recovery)
    monkeypatch.setattr(backend.os, 'rename', original)
    with pytest.raises(backend.UpdateError, match='ConfirmPointInTimeRecovery'):
        backend.restore(root, recovery, confirm=False)
    assert not root.exists() and backend._inventory(recovery) == before


def test_result_write_failure_finishes_same_swap_on_retry(recoverable, monkeypatch):
    root, recovery, receipt = recoverable
    original_json = backend._json
    def refuse(path, data, **kwargs):
        if path.name.startswith('restore-result-'):
            raise PermissionError('synthetic write refusal')
        return original_json(path, data, **kwargs)
    monkeypatch.setattr(backend, '_json', refuse)
    with pytest.raises(backend.UpdateError):
        backend.restore(root, recovery, confirm=True)
    pending = backend._pending_restore(root, recovery)
    assert pending['actual_phase'] == 'restored'
    retained = pending['retained_installation']
    monkeypatch.setattr(backend, '_json', original_json)
    def never_rename(*_):
        raise AssertionError('Already restored installation must not be swapped again')
    monkeypatch.setattr(backend.os, 'rename', never_rename)
    result = backend.restore(root, recovery, confirm=True)
    assert result['retained_installation'] == retained
    assert backend._inventory(root) == receipt['files']


@pytest.mark.parametrize('part', ['journal_path', 'receipt', 'snapshot', 'retained'])
def test_tampered_restore_state_is_rejected_read_only(recoverable, monkeypatch, part):
    root, recovery, receipt = recoverable
    original = backend.os.rename
    def interrupt(source, target):
        original(source, target)
        if Path(source) == root:
            raise OSError('synthetic interruption')
    monkeypatch.setattr(backend.os, 'rename', interrupt)
    with pytest.raises(backend.UpdateError):
        backend.restore(root, recovery, confirm=True)
    pending = backend._pending_restore(root, recovery)
    monkeypatch.setattr(backend.os, 'rename', original)
    if part == 'journal_path':
        path = recovery / 'restore-journal.json'
        journal = json.loads(path.read_text())
        journal['retained_installation'] = str(root.parent / 'unrelated')
        backend._json(path, journal)
    elif part == 'receipt':
        path = recovery / 'recovery-point.json'
        value = json.loads(path.read_text())
        value['extra'] = 'tamper'
        backend._json(path, value)
    elif part == 'snapshot':
        write(recovery / 'installation', 'data/objects/evidence', 'tamper')
    else:
        write(Path(pending['retained_installation']), 'data/objects/new-record', 'tamper')
    before = backend._inventory(recovery)
    with pytest.raises(backend.UpdateError):
        backend._pending_restore(root, recovery)
    assert not root.exists()
    assert backend._inventory(recovery) == before
    with pytest.raises(backend.UpdateError):
        backend.restore(root, recovery, confirm=True)


def test_complete_journal_allows_new_explicit_restore_with_new_retained_point(recoverable):
    root, recovery, receipt = recoverable
    first = backend.restore(root, recovery, confirm=True)
    write(root, 'data/objects/later-record', 'later record')
    second = backend.restore(root, recovery, confirm=True)
    assert first['retained_installation'] != second['retained_installation']
    assert (Path(first['retained_installation']) / 'data/objects/new-record').is_file()
    assert (Path(second['retained_installation']) / 'data/objects/later-record').read_text() == 'later record'
    assert backend._inventory(root) == receipt['files']


def test_missing_root_resume_rechecks_logical_installation_stopped(recoverable, monkeypatch):
    root, recovery, receipt = recoverable
    original = backend.os.rename
    def interrupt(source, target):
        original(source, target)
        if Path(source) == root:
            raise OSError('synthetic interruption')
    monkeypatch.setattr(backend.os, 'rename', interrupt)
    with pytest.raises(backend.UpdateError):
        backend.restore(root, recovery, confirm=True)
    pending = backend._pending_restore(root, recovery)
    monkeypatch.setattr(backend.os, 'rename', original)
    checks = []
    def active(path, cfg):
        checks.append(path)
        raise backend.UpdateError('Installed processes or services are still active')
    monkeypatch.setattr(backend, '_stopped', active)
    with pytest.raises(backend.UpdateError):
        backend.restore(root, recovery, confirm=True)
    assert checks == [root]
    assert not root.exists()
    assert backend._pending_restore(root, recovery)['token'] == pending['token']


@pytest.mark.parametrize('phase', ['staged', 'root_retained', 'complete'])
def test_journal_publication_failure_preserves_retryable_state(recoverable, monkeypatch, phase):
    root, recovery, receipt = recoverable
    original = backend._json
    def refuse(path, value, **kwargs):
        if path.name == 'restore-journal.json' and value['phase'] == phase:
            raise PermissionError('synthetic journal publish refusal')
        return original(path, value, **kwargs)
    monkeypatch.setattr(backend, '_json', refuse)
    with pytest.raises(backend.UpdateError) as error:
        backend.restore(root, recovery, confirm=True)
    assert error.value.code == 'restore_interrupted'
    if phase == 'staged':
        assert (root / 'data/objects/new-record').read_text() == 'preserved new record'
        assert backend._pending_restore(root, recovery) is None
    else:
        pending = backend._pending_restore(root, recovery)
        assert pending['actual_phase'] == ('root_retained' if phase == 'root_retained' else 'restored')
    monkeypatch.setattr(backend, '_json', original)
    result = backend.restore(root, recovery, confirm=True)
    assert backend._inventory(root) == receipt['files']
    assert (Path(result['retained_installation']) / 'data/objects/new-record').is_file()


def test_pending_restore_refuses_file_at_missing_root_read_only(recoverable, monkeypatch):
    root, recovery, receipt = recoverable
    original = backend.os.rename
    def interrupt(source, target):
        original(source, target)
        if Path(source) == root:
            raise OSError('synthetic interruption')
    monkeypatch.setattr(backend.os, 'rename', interrupt)
    with pytest.raises(backend.UpdateError):
        backend.restore(root, recovery, confirm=True)
    root.write_text('unrelated synthetic file')
    before = backend._inventory(recovery)
    with pytest.raises(backend.UpdateError) as error:
        backend._pending_restore(root, recovery)
    assert error.value.code == 'restore_journal_invalid'
    assert root.read_text() == 'unrelated synthetic file'
    assert backend._inventory(recovery) == before
