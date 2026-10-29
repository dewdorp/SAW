"""Published and pending controller state must retain the private-file contract."""
from __future__ import annotations

import json
import os
from types import SimpleNamespace

import pytest

from saw.devtools import offline_update as backend
from saw.devtools import desktop_update as desktop


@pytest.fixture
def private_state(tmp_path):
    directory = tmp_path / 'private-state'
    backend._private_directory(directory)
    return directory


def assert_private(path):
    current = desktop._current_sid() if os.name == 'nt' else ''
    desktop._check_access(path, current, private=True)
    assert path.stat().st_nlink == 1
    if os.name == 'nt':
        owner, entries = backend._access_metadata(path)
        assert owner == current
        assert {sid for kind, _, _, sid in entries if kind == 0} == {current, 'S-1-5-18'}


@pytest.mark.parametrize('writes', [1, 3])
def test_each_published_state_can_pass_the_next_private_validation(private_state, writes):
    writer = desktop.State(private_state, 'inspect', private_state.parent / 'synthetic-install', None)
    previous_umask = os.umask(0o022)
    try:
        for sequence in range(writes):
            value = writer.write('ready', 'ready', sequence=sequence)
            assert_private(private_state / 'state.json')
            assert desktop._state_directory(private_state, []) == private_state
            assert json.loads((private_state / 'state.json').read_text(encoding='utf-8')) == value
    finally:
        os.umask(previous_umask)
    assert not list(private_state.glob('state-*.writing'))


def test_pending_filename_collision_preserves_both_existing_files(private_state, monkeypatch):
    writer = desktop.State(private_state, 'inspect', private_state.parent / 'synthetic-install', None)
    writer.write('ready', 'ready')
    previous = (private_state / 'state.json').read_bytes()
    pending = private_state / ('state-' + 'a' * 32 + '.writing')
    pending.write_bytes(b'synthetic previous pending file')
    monkeypatch.setattr(desktop.uuid, 'uuid4', lambda: SimpleNamespace(hex='a' * 32))
    with pytest.raises(OSError):
        writer.write('validate')
    assert pending.read_bytes() == b'synthetic previous pending file'
    assert (private_state / 'state.json').read_bytes() == previous


def test_failed_publish_keeps_previous_state_and_private_pending_file(private_state, monkeypatch):
    writer = desktop.State(private_state, 'inspect', private_state.parent / 'synthetic-install', None)
    writer.write('ready', 'ready')
    previous = (private_state / 'state.json').read_bytes()

    def refuse_replace(*_args):
        raise PermissionError('synthetic publish refusal')

    monkeypatch.setattr(desktop.os, 'replace', refuse_replace)
    with pytest.raises(PermissionError):
        writer.write('validate')
    assert (private_state / 'state.json').read_bytes() == previous
    pending, = private_state.glob('state-*.writing')
    assert_private(pending)


@pytest.mark.skipif(os.name == 'nt', reason='POSIX access-bit rejection; native ACL cases use the handoff test')
def test_untrusted_existing_state_is_still_rejected(private_state):
    target = private_state / 'state.json'
    target.write_text('{}', encoding='utf-8')
    target.chmod(0o666)
    with pytest.raises(desktop.DesktopError, match='unsafe_state_directory'):
        desktop._state_directory(private_state, [])
    assert target.read_text(encoding='utf-8') == '{}'
