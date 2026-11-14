"""Real SQLite storage and lifecycle integration, synthetic inputs only."""
import hashlib
from copy import deepcopy
from datetime import UTC, datetime

import pytest

from saw.config import Settings
from saw.core.application.investigations import Forbidden
from saw.core.schemas.query import AggRequest
from saw.storage.eventstore import SQLiteEventStore
from saw.storage.generations import GenerationConflict, GenerationUnavailable, event_stream_sha256
from saw.storage.models import EvidenceFile, Job, User
from saw.storage.objectstore import LocalFSObjectStore
from tests.unit.test_event_generation_lifecycle import domain as domain  # noqa: PLC0414
from tests.unit.test_event_generation_lifecycle import request


@pytest.fixture
def reads(domain, tmp_path):
    from saw.event_generations.reads import EventFacade
    life, models, factory = domain
    settings = Settings(data_dir=tmp_path, event_store_path=str(tmp_path / 'events.db'),
                        database_url=str(factory.kw['bind'].url), object_store_root=str(tmp_path / 'objects'))
    objects = LocalFSObjectStore(str(tmp_path / 'objects'))
    raw = b'synthetic raw bytes line\n'
    objects.put_bytes('saw-evidence-original', 'raw/input', raw)
    with factory.begin() as s:
        f = s.get(EvidenceFile, 'file')
        f.size, f.sha256 = len(raw), hashlib.sha256(raw).hexdigest()
    facade = EventFacade(SQLiteEventStore(settings.event_store_path), objects=objects,
                         session_factory=factory, settings=settings)

    def publish(count=2, payload='old'):
        jid = request(domain)
        with factory.begin() as s:
            job = s.get(Job, jid)
            job.attempt, job.state = 1, 'PARSING'
            s.flush()
            ref = life.allocate(s, job, attempt=1, store=facade.generations)
            g = s.get(models.EventGeneration, ref.generation_id)
            closure = life.expected_source_closure(g.input_manifest, 'ev', 'file')
            parser = g.input_manifest['replacements'][0]['parser']
            kw = {'job_id': jid, 'attempt': 1, 'input_sha256': g.input_sha256, 'check': lambda: None}
            raw_objects = deepcopy(g.raw_objects)
            input_file = deepcopy(g.input_manifest['source']['evidence'][0]['files'][0])
        rows = [{'event_id': f'e{i}', 'investigation_id': 'inv', 'evidence_id': 'ev', 'data_source': 'web',
                     'timestamp': '2026-01-01T00:00:00Z', 'payload': payload,
                     'raw_ref': {'object_key': 'saw-evidence-original/' + input_file['object_key'],
                                  'offset': 0, 'length': input_file['size'], 'line_no': 1}}
                for i in range(count)]
        for row in rows:
            for field, value in closure.items():
                if '.' not in field:
                    row[field] = value[0] if isinstance(value, list) else value
        expected = [{'evidence_id': 'ev', 'file_id': 'file', 'replacement': True, 'unique_count': count,
                         'events_sha256': event_stream_sha256(rows), 'source_closure': closure,
                         'parse_status': 'done', 'quality': {}, 'coverage': {}, 'raw_objects': raw_objects}]
        facade.generations.create_target(ref, **kw)
        writer = facade.generations.begin_write(ref, **kw)
        writer.index(rows)
        writer.seal()
        receipt = writer.verify(expected_files=expected, check=lambda: None)
        results = [{'evidence_id': 'ev', 'file_id': 'file', 'parser_id': parser['id'],
                        'parser_version': parser['version'], 'parser_digest': parser['digest'], 'settings': {},
                        'started_at': datetime.now(UTC).isoformat(), 'parse_status': 'done', 'coverage': {},
                        'events_parsed': count, 'events_failed': 0, 'first_ts': None, 'last_ts': None,
                        'error_samples': [], 'message': ''}]
        with factory.begin() as s:
            life.mark_ready(s, ref, receipt, file_results=results)
            ref = life.publish(s, ref, job_id=jid, attempt=1)
            s.get(Job, jid).state = 'COMPLETED'
        return ref, rows
    return facade, publish, factory


def test_all_eight_reads_and_nested_scopes(reads):
    from saw.event_generations.reads import actor_scope
    es, publish, _ = reads
    old, _rows = publish()
    with actor_scope('actor'), es.read_scope():
        assert es.count('inv') == 2
        publish(1, 'new')
        assert es.get('inv', 'e0')['payload'] == 'old'
        assert len(es.search('inv', [])['events']) == 2
        assert len(list(es.iterate('inv', [], batch=1))) == 2
        assert es.aggregate('inv', [], AggRequest(type='count'))['value'] == 2
        assert es.group_by('inv', [], ['data_source'], [])[0]['count'] == 2
        assert es.histogram_metrics('inv', [], None, [])['buckets'][0]['count'] == 2
        assert es.time_bounds('inv') == ('2026-01-01T00:00:00Z',) * 2
        with es.open_view('inv') as borrowed:
            assert borrowed.ref == old
        assert es.count('inv') == 2
        with es.read_scope():
            assert es.count('inv') == 1
        assert es.count('inv') == 2


def test_cursor_selects_retained_scope_and_rechecks_acl(reads):
    from saw.event_generations.reads import actor_scope
    es, publish, factory = reads
    publish(3)
    with actor_scope('actor'), es.read_scope():
        cursor = es.search('inv', [], limit=1)['next_cursor']
    publish(1, 'new')
    with actor_scope('actor'), es.read_scope():
        assert es.search('inv', [], limit=1, cursor=cursor)['events'][0]['payload'] == 'old'
        assert es.count('inv') == 3
        with factory.begin() as s:
            s.get(User, 'actor').status = 'disabled'
        with pytest.raises(Forbidden):
            es.count('inv')


def test_no_actor_or_admin_content_and_explicit_maintenance(reads):
    from saw.event_generations.reads import actor_scope, maintenance_scope
    es, publish, factory = reads
    publish()
    with pytest.raises(Forbidden):
        es.count('inv')
    with factory.begin() as s:
        s.add(User(id='norole', username='norole', password_hash='unused', roles=[]))
    with actor_scope('norole'), pytest.raises(Forbidden):
        es.count('inv')
    checked = []
    with maintenance_scope(checked.append, purpose='authorized-deletion'):
        assert es.count('inv') == 2
    assert checked and set(checked) == {'inv'}
    with pytest.raises(Forbidden):
        es.count('inv')


def test_key_persists_and_malformed_fails(tmp_path):
    from saw.event_generations.reads import load_cursor_key
    key = load_cursor_key(tmp_path)
    assert len(key) >= 32 and load_cursor_key(tmp_path) == key
    (tmp_path / 'event-generations' / 'cursor.key').write_bytes(b'bad')
    with pytest.raises(GenerationUnavailable):
        load_cursor_key(tmp_path)


def test_managed_write_refused_and_missing_target_explicit(reads):
    from pathlib import Path

    from saw.event_generations.reads import actor_scope
    es, publish, _ = reads
    ref, rows = publish()
    with pytest.raises(GenerationConflict):
        es.index(rows)
    with pytest.raises(GenerationConflict):
        es.delete_by_investigation('inv')
    path = Path(ref.storage_targets[0])
    path.rename(path.with_suffix('.missing'))
    with actor_scope('actor'), pytest.raises(GenerationUnavailable):
        es.count('inv')


def test_task_decorator_binds_job_requester_and_resets(reads, monkeypatch):
    import inspect
    from types import SimpleNamespace

    from saw import container
    from saw.event_generations.reads import actor_scope
    from saw.workers.runner import TASKS, task
    es, publish, factory = reads
    publish()
    monkeypatch.setattr(container, 'get', lambda: SimpleNamespace(events=es, session_factory=factory))
    @task('synthetic.r.scope')
    def work(job_id: str):
        return es.count('inv')
    try:
        assert list(inspect.signature(work).parameters) == ['job_id']
        with actor_scope('missing'):
            assert work('old') == 2
            with pytest.raises(Forbidden):
                es.count('inv')
        with pytest.raises(Forbidden):
            es.count('inv')
    finally:
        TASKS.pop('synthetic.r.scope', None)


def test_run_manifest_retains_ref_and_old_hash(reads):
    from saw.analysis_runs.models import AnalysisRun
    from saw.behavior.service import source_manifest
    from saw.core.application.provenance import digest
    from saw.event_generations.reads import actor_scope
    es, publish, factory = reads
    old, _ = publish()
    with actor_scope('actor'), es.read_scope(), factory.begin() as s:
        manifest = es.pin_manifest(s, 'inv', source_manifest(s, 'inv'))
        assert manifest['event_generation']['generation_id'] == old.generation_id
        assert 'storage_targets' not in str(manifest['event_generation'])
        initial = deepcopy(manifest)
        sha = digest(manifest)
        s.add(AnalysisRun(id='run-old', investigation_id='inv', version=1, created_by='actor',
                          input_manifest=manifest, input_sha256=sha))
    publish(1, 'new')
    with actor_scope('actor'), es.read_scope(), factory() as s:
        ref = es.bind_run(s, 'inv', 'run-old')
        assert ref == old and es.count('inv') == 2
        assert s.get(AnalysisRun, 'run-old').input_manifest == initial
        assert s.get(AnalysisRun, 'run-old').input_sha256 == sha
        files = es.file_state(s, 'inv')
        assert sum(f['events_parsed'] for f in files) == 2


def test_analysis_start_hash_includes_selected_generation(reads, monkeypatch):
    from types import SimpleNamespace

    from saw import container
    from saw.analysis_runs import service
    from saw.core.application.provenance import digest
    from saw.event_generations.reads import actor_scope
    es, publish, factory = reads
    ref, _ = publish()
    monkeypatch.setattr(container, 'get', lambda: SimpleNamespace(events=es, session_factory=factory))
    with actor_scope('actor'), es.read_scope(), factory.begin() as s:
        run = service.start(s, 'inv', job_id='old')
        assert run.input_manifest['event_generation']['generation_id'] == ref.generation_id
        assert run.input_sha256 == digest(run.input_manifest)


def test_cursor_survives_facade_restart_and_legacy_does_not(reads):
    from saw.event_generations.reads import EventFacade, actor_scope
    from saw.storage.generations import InvalidGenerationCursor
    es, publish, _ = reads
    with actor_scope('actor'):
        es.index([{'event_id': f'legacy{i}', 'investigation_id': 'inv'} for i in range(2)])
        cursor = es.search('inv', [], limit=1)['next_cursor']
        restarted = EventFacade(es.legacy, objects=es.objects, session_factory=es.session_factory, settings=es.settings)
        with pytest.raises(InvalidGenerationCursor):
            restarted.search('inv', [], limit=1, cursor=cursor)
        publish(3)
        cursor = es.search('inv', [], limit=1)['next_cursor']
        publish(1, 'new')
        assert restarted.search('inv', [], limit=1, cursor=cursor)['events'][0]['payload'] == 'old'
        with pytest.raises(InvalidGenerationCursor):
            restarted.search('inv', [], limit=2, cursor=cursor)


def test_key_atomic_create_race(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    from saw.event_generations.reads import load_cursor_key
    with ThreadPoolExecutor(max_workers=4) as pool:
        keys = list(pool.map(lambda _: load_cursor_key(tmp_path), range(12)))
    assert len(set(keys)) == 1
    assert sorted(p.name for p in (tmp_path / 'event-generations').iterdir()) == ['cursor.key']


def test_read_callback_never_updates_sql_under_metadata_lock(reads):
    from sqlalchemy import event

    from saw.core.application.data_deletion import lock_investigation
    from saw.event_generations.reads import actor_scope
    es, publish, factory = reads
    publish()
    statements = []
    def record(_conn, _cursor, statement, _params, _context, _many):
        statements.append(statement)
    with actor_scope('actor'), factory.begin() as s:
        lock_investigation(s, 'inv')
        event.listen(factory.kw['bind'], 'before_cursor_execute', record)
        try:
            assert es.count('inv') == 2
        finally:
            event.remove(factory.kw['bind'], 'before_cursor_execute', record)
    assert statements and all(not text.lstrip().upper().startswith(('UPDATE', 'INSERT', 'DELETE')) for text in statements)


def test_legacy_write_fences_first_allocation(reads, domain, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    es, _, factory = reads
    life, _, _ = domain
    jid = request(domain)
    entered, release, allocating = Event(), Event(), Event()
    original = es.legacy.index
    def delayed(rows):
        entered.set()
        assert release.wait(5)
        return original(rows)
    monkeypatch.setattr(es.legacy, 'index', delayed)
    def allocate():
        allocating.set()
        with factory.begin() as s:
            job = s.get(Job, jid)
            job.attempt, job.state = 1, 'PARSING'
            s.flush()
            return life.allocate(s, job, attempt=1, store=es.generations)
    with ThreadPoolExecutor(max_workers=2) as pool:
        writer = pool.submit(es.index, [{'event_id': 'legacy', 'investigation_id': 'inv'}])
        assert entered.wait(5)
        allocator = pool.submit(allocate)
        assert allocating.wait(5)
        assert not allocator.done()
        release.set()
        assert writer.result(timeout=5) == 1
        allocator.result(timeout=5)
    with pytest.raises(GenerationConflict):
        es.index([{'event_id': 'late', 'investigation_id': 'inv'}])


def test_iteration_selects_before_head_change_and_scope_conflicts(reads):
    from saw.event_generations.reads import actor_scope
    es, publish, _ = reads
    old, _ = publish()
    with actor_scope('actor'):
        rows = es.iterate('inv', [], batch=1)
        _new, _ = publish(1, 'new')
        assert [e['payload'] for e in rows] == ['old', 'old']
        with es.read_scope():
            assert es.count('inv') == 1
            with pytest.raises(GenerationConflict):
                es.open_view('inv', old)
            assert es.count('inv') == 1


def test_raw_reads_recheck_authorization_after_bytes(reads, monkeypatch):
    from saw.event_generations.reads import actor_scope
    es, publish, factory = reads
    publish()
    read = es.objects.read_range
    def revoked(*args):
        data = read(*args)
        with factory.begin() as s:
            s.get(User, 'actor').status = 'disabled'
        return data
    with actor_scope('actor'), es.read_scope():
        event = es.get('inv', 'e0')
        monkeypatch.setattr(es.objects, 'read_range', revoked)
        with pytest.raises(Forbidden):
            es.hydrate_raw(event)


def test_unstarted_iterator_close_releases_legacy_snapshot(reads):
    from saw.event_generations.reads import actor_scope
    es, _, _ = reads
    with actor_scope('actor'):
        rows = es.iterate('inv', [])
        assert len(es.generations._snapshots) == 1
        rows.close()
        assert len(es.generations._snapshots) == 0


def test_maintenance_capability_cannot_run_analysis(reads, monkeypatch):
    from types import SimpleNamespace

    from saw import container
    from saw.core.application.analysis import run_patterns
    from saw.event_generations.reads import maintenance_scope
    es, publish, factory = reads
    publish()
    monkeypatch.setattr(container, 'get', lambda: SimpleNamespace(events=es, session_factory=factory))
    with maintenance_scope(lambda _: None, purpose='authorized-deletion'), factory.begin() as s, pytest.raises(Forbidden):
        run_patterns(s, 'inv')


def test_run_dependency_revocation_and_missing_association_fail_closed(reads):
    from saw.analysis_runs.models import AnalysisRun
    from saw.behavior.service import source_manifest
    from saw.core.application.provenance import digest
    from saw.event_generations.reads import actor_scope
    from saw.storage.models import Investigation, InvestigationMember
    es, publish, factory = reads
    publish()
    with actor_scope('actor'), es.read_scope(), factory.begin() as s:
        s.add(Investigation(id='dependency', display_id='SYN-DEP', title='Synthetic dependency', owner_id='actor'))
        s.flush()
        s.add(InvestigationMember(investigation_id='dependency', user_id='actor', access='viewer'))
        manifest = es.pin_manifest(s, 'inv', source_manifest(s, 'inv'))
        manifest['runtime_pin'] = {'devices': [{'source_investigation_ids': ['dependency']}]}
        s.add(AnalysisRun(id='dep-run', investigation_id='inv', version=1, created_by='actor',
                          input_manifest=manifest, input_sha256=digest(manifest)))
        s.add(AnalysisRun(id='unbound', investigation_id='inv', version=2, created_by='actor',
                          input_manifest={}, input_sha256=digest({})))
    with actor_scope('actor'), es.read_scope():
        with factory() as s:
            with pytest.raises(GenerationUnavailable):
                es.bind_run(s, 'inv', 'unbound')
            es.bind_run(s, 'inv', 'dep-run')
        assert es.count('inv') == 2
        with factory.begin() as s:
            s.delete(s.get(InvestigationMember, ('dependency', 'actor')))
        with pytest.raises(Forbidden):
            es.count('inv')


@pytest.mark.parametrize('state', ['revoked', 'expired', 'idle', 'mfa'])
def test_long_lived_scope_checks_current_session(reads, state):
    from datetime import timedelta

    from saw.event_generations.reads import actor_scope
    from saw.storage.db import utcnow
    from saw.storage.models import UserSession
    es, publish, factory = reads
    publish()
    with factory.begin() as s:
        s.add(UserSession(id='session', user_id='actor', token_hash='synthetic-session', csrf_token='synthetic',
                          mfa_passed=True, expires_at=utcnow() + timedelta(hours=1)))
    with actor_scope('actor', 'session'), es.read_scope():
        assert es.count('inv') == 2
        with factory.begin() as s:
            session = s.get(UserSession, 'session')
            if state == 'revoked':
                session.revoked_at = utcnow()
            elif state == 'expired':
                session.expires_at = utcnow() - timedelta(seconds=1)
            elif state == 'idle':
                session.last_seen_at = utcnow() - timedelta(days=1)
            else:
                session.mfa_passed = False
        with pytest.raises(Forbidden):
            es.count('inv')


def test_same_event_id_two_investigations_keep_distinct_scoped_views(reads):
    from saw.event_generations.reads import actor_scope
    from saw.storage.models import Investigation, InvestigationMember
    es, publish, factory = reads
    publish()
    with factory.begin() as s:
        s.add(Investigation(id='other', display_id='SYN-OTHER', title='Other source', owner_id='actor'))
        s.flush()
        s.add(InvestigationMember(investigation_id='other', user_id='actor', access='owner'))
    es.index([{'event_id': 'e0', 'investigation_id': 'other', 'payload': 'other'}])
    with actor_scope('actor'), es.read_scope():
        assert es.get('inv', 'e0')['payload'] == 'old'
        assert es.get('other', 'e0')['payload'] == 'other'
        publish(1, 'new')
        assert es.count('inv') == 2 and es.count('other') == 1
        assert es.get('inv', 'e0')['payload'] == 'old'


def test_direct_start_accepts_explicit_session_principal(reads, monkeypatch):
    from types import SimpleNamespace

    from saw import container
    from saw.analysis_runs import service
    from saw.core.application.identity import principal_of
    es, publish, factory = reads
    publish()
    monkeypatch.setattr(container, 'get', lambda: SimpleNamespace(events=es, session_factory=factory))
    with factory.begin() as s:
        s.info['principal'] = principal_of(s.get(User, 'actor'))
        run = service.start(s, 'inv')
        assert run.created_by == 'actor'
        assert run.input_manifest['event_generation']['generation_id']


def test_completed_analysis_cannot_reseal_immutable_input(reads, monkeypatch):
    from types import SimpleNamespace

    from saw import container
    from saw.analysis_runs import service
    from saw.core.application.analysis import run_detectors
    from saw.event_generations.reads import actor_scope
    from saw.storage.db import Base, load_models
    es, publish, factory = reads
    publish()
    load_models()
    Base.metadata.create_all(factory.kw['bind'])
    monkeypatch.setattr(container, 'get', lambda: SimpleNamespace(events=es, session_factory=factory, settings=es.settings))
    with actor_scope('actor'), es.read_scope(), factory.begin() as s:
        run = service.start(s, 'inv')
        run.status = 'complete'
        s.flush()
        original, sha = deepcopy(run.input_manifest), run.input_sha256
        with pytest.raises(GenerationConflict):
            run_detectors(s, 'inv', analysis_run=run)
        assert run.input_manifest == original and run.input_sha256 == sha


def test_retained_cursor_valid_in_fresh_python_process(reads):
    import json
    import subprocess
    import sys

    from saw.event_generations.reads import actor_scope
    es, publish, _ = reads
    publish(3)
    with actor_scope('actor'):
        cursor = es.search('inv', [], limit=1)['next_cursor']
    publish(1, 'new')
    program = """
import json, os, sys
for name in list(os.environ):
    if name.upper().startswith('SAW_'):
        del os.environ[name]
from saw.config import Settings
Settings.model_config['env_file'] = None
from saw.event_generations.reads import EventFacade, actor_scope
from saw.storage.db import make_engine, load_models
from saw.storage.eventstore import SQLiteEventStore
from saw.storage.objectstore import LocalFSObjectStore
from sqlalchemy.orm import sessionmaker
value = json.load(sys.stdin)
settings = Settings(**value['settings'])
load_models()
factory = sessionmaker(make_engine(settings.database_url), expire_on_commit=False)
es = EventFacade(SQLiteEventStore(settings.event_store_path), objects=LocalFSObjectStore(settings.object_store_root),
                 session_factory=factory, settings=settings)
with actor_scope('actor'), es.read_scope():
    result = es.search('inv', [], limit=1, cursor=value['cursor'])
    print(json.dumps({'payload': result['events'][0]['payload'], 'count': es.count('inv')}))
"""
    payload = {'settings': {'data_dir': str(es.settings.data_dir), 'database_url': es.settings.database_url,
                           'event_store_path': es.settings.event_store_path,
                           'object_store_root': es.settings.object_store_root}, 'cursor': cursor}
    completed = subprocess.run([sys.executable, '-B', '-c', program], input=json.dumps(payload),
                               text=True, capture_output=True, timeout=20, check=True)
    assert json.loads(completed.stdout) == {'payload': 'old', 'count': 3}
