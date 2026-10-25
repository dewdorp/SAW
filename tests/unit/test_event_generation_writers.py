"""Synthetic contracts: expected digests are formed independently of stored readback."""
import hashlib
import io
import json
import sqlite3
from dataclasses import replace

import pytest

from saw.storage.eventstore import SQLiteEventStore


def digest(events):
    h = hashlib.sha256()
    for event in sorted(events, key=lambda x: x['event_id']):
        data = json.dumps(event, sort_keys=True, ensure_ascii=False, allow_nan=False,
                          separators=(',', ':')).encode()
        h.update(len(data).to_bytes(8, 'big'))
        h.update(data)
    return h.hexdigest()


def event(n=0, inv='inv', **extra):
    return dict(event_id=f'e{n:06d}', investigation_id=inv, evidence_id='ev', data_source='web',
                timestamp='2026-01-01T00:00:00Z', raw_ref={'object_key': 'evidence/raw', 'offset': 0, 'length': 3}, **extra)


def expected(events, **extra):
    return [dict(evidence_id='ev', file_id='file', replacement=False, unique_count=len(events),
                 events_sha256=digest(events), source_closure={'data_source': ['web']},
                 parse_status='ok', quality={'status': 'partial'}, coverage={'status': 'partial'},
                 raw_objects=[{'bucket': 'evidence', 'key': 'raw', 'byte_length': 3,
                                   'sha256': hashlib.sha256(b'raw').hexdigest(), 'owner_generation_id': None,
                                   'owner_attempt': None, 'retained': True}], **extra)]


@pytest.fixture
def env(tmp_path):
    from saw.storage.generations import GenerationRef, GenerationStore
    heads, history, checks = {}, {}, []
    legacy = SQLiteEventStore(tmp_path / 'legacy.db')
    def resolve(inv, *, generation_id=None):
        return heads.get(inv) if generation_id is None else history[(inv, generation_id)]
    store = GenerationStore(legacy, resolve=resolve, check_read=lambda ref: checks.append(ref),
                            open_raw=lambda bucket, key: io.BytesIO(b'raw'), cursor_key=b'x' * 32)
    def allocated(gen='g1', inv='inv'):
        return GenerationRef(inv, gen, 0, '', store.plan_targets(inv, gen), False)
    def written(events, gen='g1', inv='inv'):
        ref = allocated(gen, inv)
        kw = {'job_id': 'job', 'attempt': 1, 'input_sha256': 'a' * 64, 'check': lambda: None}
        store.create_target(ref, **kw)
        writer = store.begin_write(ref, **kw)
        writer.index(events)
        writer.seal()
        receipt = writer.verify(expected_files=expected(events), check=lambda: None)
        ref = replace(ref, output_sha256=receipt['output_sha256'], head_revision=1)
        history[(inv, gen)] = heads[inv] = ref
        return ref, writer, receipt
    return store, legacy, heads, history, checks, allocated, written


def test_full_canonical_manifest(env):
    store, _, _, _, _, _, written = env
    events = [event(n, payload={'z': [None, '한글', 3.5], 'a': True}) for n in range(5003)]
    ref, _writer, receipt = written(list(reversed(events)))
    assert receipt['output_sha256'] == digest(events)
    assert receipt['unique_count'] == 5003
    assert receipt['sealed'] and receipt['complete'] and receipt['rejected'] == 0
    assert receipt['files'][0]['quality'] == {'status': 'partial'}
    assert store.verify(ref, expected_files=expected(events), check=lambda: None) == receipt


def test_target_ownership_and_durable_seal(env):
    from saw.storage.generations import GenerationConflict, GenerationSealed, GenerationUnavailable
    store, _, _, _, _, allocated, written = env
    ref = allocated()
    kw = {'job_id': 'job', 'attempt': 1, 'input_sha256': 'a' * 64, 'check': lambda: None}
    with pytest.raises(GenerationUnavailable):
        store.begin_write(ref, **kw)
    store.create_target(ref, **kw)
    store.create_target(ref, **kw)
    with pytest.raises(GenerationConflict):
        store.begin_write(ref, **{**kw, 'attempt': 2})
    ref, writer, _ = written([event()])
    writer.seal()
    with pytest.raises(GenerationSealed):
        store.begin_write(ref, **kw)
    with pytest.raises(GenerationSealed):
        writer.index([event(1)])
    with sqlite3.connect(ref.storage_targets[0]) as db, pytest.raises(sqlite3.IntegrityError):
        db.execute('DELETE FROM events')


def test_same_id_replay_and_persistent_rejection(env):
    from saw.storage.generations import GenerationConflict, GenerationUnavailable, GenerationVerificationError
    store, _, _, _, _, allocated, _ = env
    ref = allocated()
    kw = {'job_id': 'job', 'attempt': 1, 'input_sha256': 'a' * 64, 'check': lambda: None}
    store.create_target(ref, **kw)
    writer = store.begin_write(ref, **kw)
    assert writer.index([event(), event()]) == 2
    with pytest.raises(GenerationConflict):
        writer.index([event(payload='changed')])
    assert writer.rejected == 1
    with pytest.raises(GenerationUnavailable):
        store.begin_write(ref, **kw)
    writer.seal()
    with pytest.raises(GenerationVerificationError):
        store.verify(ref, expected_files=expected([event()]), check=lambda: None)


@pytest.mark.parametrize('mutation', ['payload', 'source', 'raw', 'count', 'replacement', 'ambiguous'])
def test_verification_rejects_incomplete_or_changed_expectations(env, mutation):
    from saw.storage.generations import GenerationVerificationError
    store, _, _, _, _, _, written = env
    ref, _, _ = written([event()])
    files = expected([event()])
    if mutation == 'payload': files = expected([event(payload='different')])
    if mutation == 'source': files[0]['source_closure'] = {'data_source': ['firewall']}
    if mutation == 'raw': files[0]['raw_objects'][0]['sha256'] = '0' * 64
    if mutation == 'count': files[0]['unique_count'] = 2
    if mutation == 'replacement': files[0].update(replacement=True, parse_status='failed')
    if mutation == 'ambiguous': files.append({**files[0], 'file_id': 'another'})
    with pytest.raises(GenerationVerificationError):
        store.verify(ref, expected_files=files, check=lambda: None)


def test_bounded_batches_and_foreign_oversized_rows(env):
    from saw.storage.generations import GenerationVerificationError
    store, _, _, _, _, allocated, _ = env
    for gen, row in [('foreign', event(inv='foreign')), ('large', event(payload='x' * (10 * 1024 * 1024)))]:
        ref = allocated(gen)
        kw = {'job_id': 'job', 'attempt': 1, 'input_sha256': 'a' * 64, 'check': lambda: None}
        store.create_target(ref, **kw)
        writer = store.begin_write(ref, **kw)
        with pytest.raises((ValueError, GenerationVerificationError)):
            writer.index(iter([row]))
        writer.seal()
        with pytest.raises(GenerationVerificationError):
            writer.verify(expected_files=[], check=lambda: None)


def test_raw_coverage_and_verify_after_restart(env):
    from saw.storage.generations import GenerationStore, GenerationVerificationError
    store, legacy, heads, _history, _, allocated, _ = env
    ref = allocated()
    kw = {'job_id': 'job', 'attempt': 1, 'input_sha256': 'a' * 64, 'check': lambda: None}
    store.create_target(ref, **kw)
    writer = store.begin_write(ref, **kw)
    row = event()
    row['raw_ref']['object_key'] = 'evidence/raw'
    writer.index([row])
    writer.seal()
    reopened = GenerationStore(legacy, resolve=lambda inv, generation_id=None: heads.get(inv),
        check_read=lambda ref: None, open_raw=lambda b, k: io.BytesIO(b'raw'), cursor_key=b'x' * 32)
    receipt = reopened.verify(ref, expected_files=expected([row]), check=lambda: None)
    assert receipt['output_sha256'] == digest([row])
    reopened.open_raw = lambda b, k: io.BytesIO(b'ra')
    with pytest.raises(GenerationVerificationError):
        reopened.verify(ref, expected_files=expected([row]), check=lambda: None)


def test_replacement_pending_and_malformed_manifest_fail_closed(env):
    from saw.storage.generations import GenerationVerificationError
    store, _, _, _, _, _, written = env
    ref, _, _ = written([event()])
    for status in ['pending', 'waiting_input', 'skipped', 'parsing']:
        files = expected([event()])
        files[0].update(replacement=True, parse_status=status)
        with pytest.raises(GenerationVerificationError):
            store.verify(ref, expected_files=files, check=lambda: None)
    for missing in ['quality', 'coverage', 'source_closure', 'replacement']:
        files = expected([event()])
        del files[0][missing]
        with pytest.raises(GenerationVerificationError):
            store.verify(ref, expected_files=files, check=lambda: None)


def test_cancelled_batch_cannot_later_verify(env):
    from saw.storage.generations import GenerationVerificationError
    store, _, _, _, _, allocated, _ = env
    ref = allocated()
    calls = []
    def check():
        calls.append(1)
        if len(calls) == 6: raise PermissionError('synthetic lease revoked')
    kw = {'job_id': 'job', 'attempt': 1, 'input_sha256': 'a' * 64, 'check': lambda: None}
    store.create_target(ref, **kw)
    writer = store.begin_write(ref, **{**kw, 'check': check})
    with pytest.raises(PermissionError): writer.index(event(n) for n in range(5001))
    writer.check = lambda: None
    writer.seal()
    with pytest.raises(GenerationVerificationError):
        store.verify(ref, expected_files=expected([event(n) for n in range(5000)]), check=lambda: None)


def test_verification_callback_errors_propagate(env):
    store, _, _, _, _, _, written = env
    ref, _, _ = written([event()])
    calls = []
    def check():
        calls.append(1)
        if len(calls) == 3: raise PermissionError('synthetic revoked actor')
    with pytest.raises(PermissionError):
        store.verify(ref, expected_files=expected([event()]), check=check)


@pytest.mark.parametrize('offset,length', [(-1, 1), (0, -1), (2, 2), (True, 1), (0, 1.5)])
def test_raw_byte_range_validation(env, offset, length):
    from saw.storage.generations import GenerationVerificationError
    store, _, _, _, _, allocated, _ = env
    ref = allocated()
    kw = {'job_id': 'job', 'attempt': 1, 'input_sha256': 'a' * 64, 'check': lambda: None}
    store.create_target(ref, **kw)
    writer = store.begin_write(ref, **kw)
    row = event()
    row['raw_ref'].update(offset=offset, length=length)
    writer.index([row])
    writer.seal()
    with pytest.raises(GenerationVerificationError): writer.verify(expected_files=expected([row]), check=lambda: None)


def test_empty_generation_and_failed_replacement_cannot_use_parent_output(env):
    from saw.storage.generations import GenerationVerificationError
    store, _, _, _, _, allocated, written = env
    ref = allocated('empty')
    kw = {'job_id': 'job', 'attempt': 1, 'input_sha256': 'a' * 64, 'check': lambda: None}
    store.create_target(ref, **kw)
    writer = store.begin_write(ref, **kw)
    writer.seal()
    receipt = writer.verify(expected_files=[], check=lambda: None)
    assert receipt['unique_count'] == 0
    assert receipt['output_sha256'] == 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    ref, _, _ = written([event()])
    files = expected([event()])
    failed = expected([])[0]
    failed.update(file_id='replaced', evidence_id='replace-ev', raw_objects=[], replacement=True, parse_status='failed')
    with pytest.raises(GenerationVerificationError):
        store.verify(ref, expected_files=files + [failed], check=lambda: None)


def test_verification_pages_bound_bytes_as_well_as_rows(env):
    store, _, _, _, _, allocated, _ = env
    ref = allocated()
    kw = {'job_id': 'job', 'attempt': 1, 'input_sha256': 'a' * 64, 'check': lambda: None}
    store.create_target(ref, **kw)
    writer = store.begin_write(ref, **kw)
    writer.index(event(n, payload='x' * (2 * 1024 * 1024)) for n in range(7))
    writer.seal()
    pages = 0
    for page in store.adapter.pages(ref, lambda: None):
        pages += 1
        assert sum(len(json.dumps(row, separators=(',', ':')).encode()) for row in page) <= 10 * 1024 * 1024
    assert pages >= 2


def test_nested_source_context_closure_and_same_count_alteration(env):
    from saw.storage.generations import GenerationVerificationError
    store, _, _, _, _, allocated, _ = env
    ref = allocated()
    kw = {'job_id': 'job', 'attempt': 1, 'input_sha256': 'a' * 64, 'check': lambda: None}
    store.create_target(ref, **kw)
    writer = store.begin_write(ref, **kw)
    row = event(ext={'observation': {'context': {'affiliate_id': 'affiliate-a', 'profile_version': 2}},
                     'device_observation': {'device_id': 'device-a'}})
    writer.index([row])
    writer.seal()
    files = expected([row])
    files[0]['source_closure'].update({'ext.observation.context.affiliate_id': ['affiliate-a'],
                                     'ext.observation.context.profile_version': [2],
                                     'ext.device_observation.device_id': ['device-a']})
    assert writer.verify(expected_files=files, check=lambda: None)['unique_count'] == 1
    files[0]['source_closure']['ext.observation.context.affiliate_id'] = ['affiliate-b']
    with pytest.raises(GenerationVerificationError): writer.verify(expected_files=files, check=lambda: None)


@pytest.mark.parametrize('recovery', ['write', 'verify'])
def test_sqlite_interrupted_commit_remains_uncertain_after_reopen(env, monkeypatch, recovery):
    from saw.storage.generations import GenerationStore, GenerationUnavailable, GenerationVerificationError
    store, legacy, _, _, _, allocated, _ = env
    ref = allocated('interrupted-commit')
    kw = {'job_id': 'job', 'attempt': 1, 'input_sha256': 'a' * 64, 'check': lambda: None}
    store.create_target(ref, **kw)
    writer = store.begin_write(ref, **kw)
    real_connect = sqlite3.connect

    class InterruptedConnection(sqlite3.Connection):
        wrote_event = False

        def execute(self, sql, parameters=()):
            result = super().execute(sql, parameters)
            if sql.startswith('INSERT INTO events'):
                self.wrote_event = True
            return result

        def commit(self):
            super().commit()
            if self.wrote_event:
                raise KeyboardInterrupt('synthetic process loss after durable event commit')

    def connect(*args, **kwargs):
        return real_connect(*args, **kwargs, factory=InterruptedConnection)

    with monkeypatch.context() as patch:
        patch.setattr(sqlite3, 'connect', connect)
        with pytest.raises(KeyboardInterrupt):
            writer.index([event()])
    with real_connect(ref.storage_targets[0]) as db:
        assert db.execute('SELECT count(*) FROM events').fetchone()[0] == 1
    reopened = GenerationStore(legacy, resolve=lambda inv, generation_id=None: None,
        check_read=lambda ref: None, open_raw=lambda b, k: io.BytesIO(b'raw'), cursor_key=b'x' * 32)
    if recovery == 'write':
        with pytest.raises(GenerationUnavailable):
            reopened.begin_write(ref, **kw)
    else:
        writer.seal()
        with pytest.raises(GenerationVerificationError):
            reopened.verify(ref, expected_files=expected([event()]), check=lambda: None)


@pytest.mark.parametrize('count', [1, 3])
def test_buffered_event_identity_is_frozen_from_canonical_bytes(env, count):
    store, _, _, _, _, allocated, _ = env
    ref = allocated('mutable-buffer')
    kw = {'job_id': 'job', 'attempt': 1, 'input_sha256': 'a' * 64, 'check': lambda: None}
    store.create_target(ref, **kw)
    writer = store.begin_write(ref, **kw)
    rows = [event(n, payload={'number': n}) for n in range(count)]

    def reused_rows():
        row = event(payload={'number': 0})
        for n in range(count):
            row['event_id'] = f'e{n:06d}'
            row['payload']['number'] = n
            yield row
        row['event_id'] = 'changed-after-last-yield'
        row['payload']['number'] = -1

    assert writer.index(reused_rows()) == count
    writer.seal()
    manifest = writer.verify(expected_files=expected(rows), check=lambda: None)
    ref = replace(ref, output_sha256=manifest['output_sha256'], head_revision=1)
    with store.open_view('inv', ref=ref) as view:
        assert view.search('inv', [])['events'] == rows
        for row in rows:
            assert view.get('inv', row['event_id']) == row
