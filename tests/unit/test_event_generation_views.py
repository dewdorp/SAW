from dataclasses import replace

import pytest

from saw.core.schemas.query import AggRequest
from tests.unit.test_event_generation_writers import env as env  # noqa: PLC0414 (pytest fixture export)
from tests.unit.test_event_generation_writers import event


def test_all_eight_reads_pin_one_generation(env):
    store, _, _, _, _, _, written = env
    old, _, _ = written([event(), event(1)])
    view = store.open_view('inv')
    written([event(payload='new generation')], 'g2')
    written([event(inv='other')], 'g3', 'other')
    assert view.ref == old
    assert view.get('inv', event()['event_id']) == event()
    assert len(view.search('inv', [])['events']) == 2
    assert len(list(view.iterate('inv', [], batch=1))) == 2
    assert view.count('inv') == 2
    assert view.aggregate('inv', [], AggRequest(type='count')) == {'value': 2}
    assert view.group_by('inv', [], ['data_source'], [])[0]['count'] == 2
    assert view.histogram_metrics('inv', [], None, [])['buckets'][0]['count'] == 2
    assert view.time_bounds('inv') == ('2026-01-01T00:00:00Z',) * 2
    assert store.open_view('inv').count('inv') == 1
    assert not hasattr(view, 'index')
    assert view.search('inv', [], fields=['event_id'])['events'] == [
        {'event_id': 'e000000'}, {'event_id': 'e000001'}]
    for call in [lambda: view.get('', 'e'), lambda: view.search('other', []),
                 lambda: list(view.iterate('other', [])), lambda: view.count('other'),
                 lambda: view.aggregate('other', [], AggRequest(type='count')),
                 lambda: view.group_by('other', [], ['data_source'], []),
                 lambda: view.histogram_metrics('other', [], None, []), lambda: view.time_bounds('other')]:
        with pytest.raises(ValueError): call()


def test_no_legacy_fallback_for_broken_head(env):
    from saw.storage.generations import GenerationUnavailable
    store, legacy, heads, _, _, allocated, _ = env
    legacy.index([event()])
    heads['inv'] = replace(allocated(), output_sha256='a' * 64)
    with pytest.raises(GenerationUnavailable): store.open_view('inv')
    assert store.open_view('other').ref.legacy


def test_retained_cursor_after_head_change_and_binding(env):
    from saw.storage.generations import InvalidGenerationCursor
    store, _, _, _, _, _, written = env
    written([event(n) for n in range(4)])
    view = store.open_view('inv')
    cursor = view.search('inv', [], limit=2)['next_cursor']
    written([event(9)], 'g2')
    resumed = store.resume_view('inv', cursor, filters=[], limit=2)
    assert [e['event_id'] for e in resumed.search('inv', [], limit=2, cursor=cursor)['events']] == ['e000002', 'e000003']
    for bad in [cursor[:-4] + 'aaaa', 'not-json']:
        with pytest.raises(InvalidGenerationCursor): store.resume_view('inv', bad, filters=[], limit=2)
    with pytest.raises(InvalidGenerationCursor): store.resume_view('inv', cursor, filters=[], limit=3)
    with pytest.raises(InvalidGenerationCursor): store.open_view('inv').search('inv', [], limit=2, cursor=cursor)


def test_legacy_snapshot_transition(env):
    store, legacy, _, _, _, _, written = env
    legacy.index([event(n) for n in range(3)])
    view = store.open_view('inv')
    cursor = view.search('inv', [], limit=1)['next_cursor']
    legacy.index([event(8)])
    written([event(9)])
    assert view.count('inv') == 3
    view.close()
    resumed = store.resume_view('inv', cursor, filters=[], limit=1)
    assert resumed.search('inv', [], limit=1, cursor=cursor)['events'][0]['event_id'] == 'e000001'


@pytest.mark.parametrize('sort', ['asc', 'desc'])
def test_tied_and_missing_timestamps_projection_and_acl(env, sort):
    store, _, _, _, _, _, written = env
    rows = [event(n) for n in range(6)]
    rows[0]['timestamp'] = None
    rows[1].pop('timestamp')
    written(rows)
    view = store.open_view('inv')
    out, cursor = [], None
    while True:
        page = view.search('inv', [], sort=sort, limit=2, cursor=cursor, fields=['event_id'])
        out.extend(e['event_id'] for e in page['events'])
        cursor = page['next_cursor']
        if not cursor: break
    assert out == [f'e{n:06d}' for n in (range(6) if sort == 'asc' else reversed(range(6)))]
    iterator = view.iterate('inv', [], batch=1)
    next(iterator)
    def denied(ref): raise PermissionError('synthetic revoked source ACL')
    store.check_read = denied
    with pytest.raises(PermissionError): next(iterator)


def test_disappeared_target_never_recreated(env, tmp_path):
    from pathlib import Path

    from saw.storage.generations import GenerationUnavailable
    store, _, _, _, _, _, written = env
    ref, _, _ = written([event()])
    view = store.open_view('inv')
    view.close()
    path = Path(ref.storage_targets[0])
    path.rename(path.with_suffix('.retained'))
    with pytest.raises(GenerationUnavailable): store.open_view('inv')
    assert not path.exists()


def test_legacy_close_releases_snapshot_without_cursor(env):
    store, _, _, _, _, _, _ = env
    # A long-lived service must not exhaust the finite snapshot quota on one-shot reads.
    for _ in range(140):
        with store.open_view('inv') as view:
            assert view.count('inv') == 0
    assert len(store._snapshots) == 0


def test_malformed_head_metadata_is_unavailable(env):
    import sqlite3

    from saw.storage.generations import GenerationUnavailable
    store, _, _, _, _, _, written = env
    ref, _, _ = written([event()])
    with sqlite3.connect(ref.storage_targets[0]) as db:
        db.execute("UPDATE generation_metadata SET doc=json_set(doc,'$.owner',null)")
    with pytest.raises(GenerationUnavailable): store.open_view('inv')


@pytest.mark.parametrize('corrupt_json', ['null', '[]', '42', '"scalar"', 'true'])
def test_non_object_sqlite_metadata_is_unavailable(env, corrupt_json):
    import sqlite3

    from saw.storage.generations import GenerationUnavailable
    store, _, _, _, _, _, written = env
    ref, _, _ = written([event()])
    with sqlite3.connect(ref.storage_targets[0]) as db:
        # Simulate external corruption beyond the adapter's ordinary durable seal guard.
        db.execute('DROP TRIGGER no_unseal')
        db.execute('UPDATE generation_metadata SET doc=?', (corrupt_json,))
    with pytest.raises(GenerationUnavailable) as error:
        store.open_view('inv')
    assert error.value.__cause__ is not None
