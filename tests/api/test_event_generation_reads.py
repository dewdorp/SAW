"""Actual FastAPI dependency/threadpool and authenticated generation read contracts."""
from typing import Annotated

from fastapi import Depends

from saw import container
from saw.apps.api.deps import AuthContext, auth
from saw.storage.models import UserSession


def event(inv, n=0):
    return {'event_id': f'e{n}', 'investigation_id': inv, 'evidence_id': 'synthetic',
                'timestamp': '2026-01-01T00:00:00Z', 'data_source': 'web', 'payload': 'synthetic'}


def test_authenticated_sync_handler_has_actor_and_one_snapshot(app, analyst):
    inv = analyst.post('/investigations', json={'title': 'Synthetic'}).json()['id']
    c = container.get()
    c.events.index([event(inv)])

    @app.get('/api/v1/read-scope-test')
    def check(ctx: Annotated[AuthContext, Depends(auth)]):
        before = c.events.count(inv)
        c.legacy_events.index([event(inv, 1)])
        return {'before': before, 'after': c.events.count(inv), 'actor': ctx.principal.user_id}

    app.router.routes.insert(0, app.router.routes.pop())
    result = analyst.get('/read-scope-test')
    assert result.status_code == 200, result.text
    assert result.json()['before'] == result.json()['after'] == 1
    result = analyst.post(f'/investigations/{inv}/query/events', json={})
    assert result.status_code == 200, result.text
    assert len(result.json()['events']) == 2


def test_actorless_route_denied_and_session_rechecked(app, analyst):
    inv = analyst.post('/investigations', json={'title': 'Synthetic'}).json()['id']
    c = container.get()
    c.events.index([event(inv)])

    @app.get('/api/v1/actorless-test')
    def actorless():
        return {'count': c.events.count(inv)}

    app.router.routes.insert(0, app.router.routes.pop())

    @app.get('/api/v1/revoke-test')
    def revoke(ctx: Annotated[AuthContext, Depends(auth)]):
        assert c.events.count(inv) == 1
        from sqlalchemy.orm import object_session
        object_session(ctx.session).commit()
        with c.session_factory.begin() as s:
            row = s.get(UserSession, ctx.session.id)
            row.mfa_passed = False
        return {'count': c.events.count(inv)}

    app.router.routes.insert(0, app.router.routes.pop())
    assert analyst.get('/actorless-test').status_code == 403
    result = analyst.get('/revoke-test')
    assert result.status_code == 403, result.text


def test_invalid_cursor_is_safe_problem(app, analyst):
    inv = analyst.post('/investigations', json={'title': 'Synthetic'}).json()['id']
    result = analyst.post(f'/investigations/{inv}/query/events', json={'cursor': 'not-a-cursor'})
    assert result.status_code == 400
    assert 'Traceback' not in result.text


from tests.unit.test_event_generation_facade import reads as reads  # noqa: PLC0414
from tests.unit.test_event_generation_lifecycle import domain as domain  # noqa: PLC0414


def test_retained_event_and_raw_use_authorized_run(reads):
    import hashlib

    import pyotp

    from saw.analysis_runs.models import AnalysisRun
    from saw.apps.api.main import create_app
    from saw.behavior.service import source_manifest
    from saw.core.application.identity import hash_password
    from saw.core.application.provenance import digest
    from saw.event_generations.reads import actor_scope
    from saw.storage.models import EvidenceFile, User
    from tests.conftest import PASSWORD, Api
    es, publish, factory = reads
    _old, _ = publish()
    with actor_scope('actor'), es.read_scope(), factory.begin() as s:
        manifest = es.pin_manifest(s, 'inv', source_manifest(s, 'inv'))
        s.add(AnalysisRun(id='run-old', investigation_id='inv', version=1, created_by='actor',
                          input_manifest=manifest, input_sha256=digest(manifest)))
        user = s.get(User, 'actor')
        user.password_hash, user.mfa_secret = hash_password(PASSWORD), pyotp.random_base32()
    newer = b'new replacement bytes\n'
    es.objects.put_bytes('saw-evidence-original', 'raw/replacement', newer)
    with factory.begin() as s:
        f = s.get(EvidenceFile, 'file')
        f.object_key, f.sha256, f.size = 'raw/replacement', hashlib.sha256(newer).hexdigest(), len(newer)
    publish(1, 'new')
    app = create_app(es.settings, synchronous_jobs=True)
    api = Api(app, 'synthetic')
    with factory.begin() as s:
        s.get(EvidenceFile, 'file').events_failed = 100
    overview = api.post('/investigations/inv/overview', json={})
    assert overview.status_code == 200, overview.text
    assert overview.json()['summary']['events'] == 1
    assert overview.json()['summary']['parse_error_rate'] == 0
    result = api.get('/investigations/inv/events/e0', params={'analysis_run_id': 'run-old'})
    assert result.status_code == 200, result.text
    assert result.json()['event']['payload'] == 'old'
    assert result.json()['event']['raw_event'] == 'synthetic raw bytes line'
    current = api.get('/investigations/inv/events/e0')
    assert current.json()['event']['payload'] == 'new'
    assert current.json()['event']['raw_event'] == 'new replacement bytes'
    missing = api.get('/investigations/inv/events/e0', params={'analysis_run_id': 'missing'})
    assert missing.status_code == 404
    es.objects.local_path('saw-evidence-original', 'raw/input').rename(
        es.objects.local_path('saw-evidence-original', 'raw/input').with_suffix('.unavailable'))
    missing_raw = api.get('/investigations/inv/events/e0', params={'analysis_run_id': 'run-old'})
    assert missing_raw.status_code == 503
    assert str(es.settings.data_dir) not in missing_raw.text


def test_generated_pcap_download_resolves_retained_object(analyst):
    from saw.devtools.sample_data import scenario_pcap_forensics
    from tests.api.test_phase5_bulk import upload
    inv = analyst.post('/investigations', json={'title': 'Synthetic PCAP raw'}).json()['id']
    uploaded = upload(analyst, inv, 'synthetic.pcap', scenario_pcap_forensics(), kind='pcap')
    job = analyst.post(f"/evidence/{uploaded['evidence_id']}/process").json()
    assert analyst.get(f"/jobs/{job['id']}").json()['state'] == 'COMPLETED'
    files = analyst.get(f'/investigations/{inv}/forensics/files').json()
    extracted = [f for f in files if f['extracted'] and f['sha256']]
    assert extracted
    response = analyst.get(f"/investigations/{inv}/forensics/files/{extracted[0]['sha256']}/download")
    assert response.status_code == 200, response.text
    assert response.headers['content-type'] == 'application/octet-stream'


def test_concurrent_request_actors_do_not_cross(app, analyst):
    from concurrent.futures import ThreadPoolExecutor

    from tests.conftest import Api, make_user
    make_user('outsider-read', ['analyst'])
    outsider = Api(app, 'outsider-read')
    inv = analyst.post('/investigations', json={'title': 'Actor isolation'}).json()['id']
    container.get().events.index([event(inv)])
    def read(api):
        return api.post(f'/investigations/{inv}/query/events', json={}).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        for _ in range(3):
            good, denied = pool.submit(read, analyst), pool.submit(read, outsider)
            assert good.result(timeout=10) == 200
            assert denied.result(timeout=10) == 403


def test_captured_app_read_survives_replacement(settings):
    from saw.apps.api.main import create_app
    from tests.conftest import Api, make_user
    first = create_app(settings, synchronous_jobs=True)
    make_user('first-reader', ['analyst'])
    a = Api(first, 'first-reader')
    inv_a = a.post('/investigations', json={'title': 'First'}).json()['id']
    container.get().events.index([event(inv_a)])
    directory = settings.data_dir / 'second'
    other = settings.model_copy(update={'data_dir': directory,
        'database_url': f"sqlite:///{directory / 'db.sqlite'}", 'event_store_path': str(directory / 'events.sqlite'),
        'object_store_root': str(directory / 'objects'),
        'opensearch_index_prefix': settings.opensearch_index_prefix + 'second'})
    second = create_app(other, synchronous_jobs=True)
    make_user('second-reader', ['analyst'])
    b = Api(second, 'second-reader')
    inv_b = b.post('/investigations', json={'title': 'Second'}).json()['id']
    container.get().events.index([event(inv_b), event(inv_b, 1)])
    for api, inv, count in [(a, inv_a, 1), (b, inv_b, 2), (a, inv_a, 1)]:
        response = api.post(f'/investigations/{inv}/query/events', json={})
        assert response.status_code == 200, response.text
        assert len(response.json()['events']) == count


def test_signed_cursor_projection_tamper_and_expiry(analyst):
    inv = analyst.post('/investigations', json={'title': 'Cursor source'}).json()['id']
    c = container.get()
    c.events.index([event(inv, n) for n in range(3)])
    response = analyst.post(f'/investigations/{inv}/query/events', json={'limit': 1, 'fields': ['event_id']})
    assert response.status_code == 200
    cursor = response.json()['next_cursor']
    assert cursor
    changed = analyst.post(f'/investigations/{inv}/query/events',
        json={'limit': 1, 'fields': ['payload'], 'cursor': cursor})
    assert changed.status_code == 400
    payload = c.generations._decode(cursor)
    payload['expires'] = 0
    expired = c.generations._encode(payload)
    result = analyst.post(f'/investigations/{inv}/query/events',
        json={'limit': 1, 'fields': ['event_id'], 'cursor': expired})
    assert result.status_code == 400


def test_finding_events_binds_requested_run_before_search(reads):
    import pyotp

    from saw.analysis_runs.models import AnalysisRun
    from saw.apps.api.main import create_app
    from saw.behavior.service import source_manifest
    from saw.core.application.identity import hash_password
    from saw.core.application.provenance import digest
    from saw.event_generations.reads import actor_scope
    from saw.storage.models import Finding, Investigation, User
    from tests.conftest import PASSWORD, Api

    es, publish, factory = reads
    publish(1, 'old')
    with actor_scope('actor'), es.read_scope(), factory.begin() as s:
        manifest = es.pin_manifest(s, 'inv', source_manifest(s, 'inv'))
        s.add(AnalysisRun(id='run-old', investigation_id='inv', version=1, created_by='actor',
                          input_manifest=manifest, input_sha256=digest(manifest)))
        s.add(Investigation(id='other', display_id='SYN-2', title='Unrelated', owner_id='actor'))
        s.flush()
        s.add(AnalysisRun(id='run-other', investigation_id='other', version=1, created_by='actor',
                          input_manifest=manifest, input_sha256=digest(manifest)))
        s.add(Finding(id='finding', display_id='F-1', investigation_id='inv', detector_id='synthetic',
                      detector_version='1', title='Synthetic', category='test', risk_level='low',
                      risk_score=1, confidence='low', dedup_key='synthetic', evidence_refs={'query': {}}))
        user = s.get(User, 'actor')
        user.password_hash, user.mfa_secret = hash_password(PASSWORD), pyotp.random_base32()
    publish(1, 'new')
    api = Api(create_app(es.settings, synchronous_jobs=True), 'synthetic')
    url = '/investigations/inv/findings/finding/events'
    current = api.post(url, json={})
    assert current.status_code == 200, current.text
    assert current.json()['events'][0]['payload'] == 'new'
    old = api.post(url, json={}, params={'analysis_run_id': 'run-old'})
    assert old.status_code == 200, old.text
    assert old.json()['events'][0]['payload'] == 'old'
    for run in ('missing', 'run-other'):
        result = api.post(url, json={}, params={'analysis_run_id': run})
        assert result.status_code == 404, result.text


import pytest


@pytest.mark.parametrize('endpoint', ['pcap', 'stream'])
@pytest.mark.parametrize('failure', ['during', 'after', 'missing', 'io_error'])
def test_pcap_extraction_rechecks_access_and_missing_source(analyst, monkeypatch, endpoint, failure):
    from sqlalchemy import select

    from saw.apps.api.routers import forensics, network
    from saw.devtools.sample_data import scenario_pcap_forensics
    from tests.api.test_phase5_bulk import upload

    inv = analyst.post('/investigations', json={'title': 'Guarded extraction'}).json()['id']
    uploaded = upload(analyst, inv, 'synthetic.pcap', scenario_pcap_forensics(), kind='pcap')
    job = analyst.post(f"/evidence/{uploaded['evidence_id']}/process").json()
    assert analyst.get(f"/jobs/{job['id']}").json()['state'] == 'COMPLETED'
    page = analyst.post(f'/investigations/{inv}/query/events',
                        json={'filters': [{'field': 'data_source', 'value': 'zeek_conn'}]}).json()
    event_id = next(e['event_id'] for e in page['events'] if e.get('dst_port') == 80)
    c = container.get()
    module = network if endpoint == 'pcap' else forensics
    resolver = module.resolve_session
    def resolve(s, *args):
        resolved = resolver(s, *args)
        # Release this synthetic request's auth timestamp write so the independent
        # committed revocation can land while extraction is in progress on SQLite.
        s.commit()
        if failure == 'missing':
            resolved[2].rename(resolved[2].with_suffix('.unavailable'))
        return resolved
    monkeypatch.setattr(module, 'resolve_session', resolve)
    method = 'extract_session' if endpoint == 'pcap' else 'session_streams'
    original = getattr(module, method)
    continued_after_revocation = []
    def extract(fh, *args, **kwargs):
        if failure == 'io_error':
            raise OSError('private storage path must not be exposed')
        result = original(fh, *args, **kwargs)
        if failure in ('during', 'after'):
            with c.session_factory.begin() as s:
                for session in s.scalars(select(UserSession)):
                    session.mfa_passed = False
            if failure == 'during':
                # Force one more extraction read after revocation, before return.
                fh.read(1)
                continued_after_revocation.append(True)
        return result
    monkeypatch.setattr(module, method, extract)
    prefix = 'network' if endpoint == 'pcap' else 'forensics'
    result = analyst.get(f'/investigations/{inv}/{prefix}/sessions/{event_id}/{endpoint}')
    assert result.status_code == (403 if failure in ('during', 'after') else 503), result.text
    assert 'private storage path' not in result.text and str(c.settings.data_dir) not in result.text
    assert list(c.settings.data_dir.glob('saw-sess-*.pcap')) == []
    assert not continued_after_revocation


@pytest.mark.parametrize('change', ['none', 'hash', 'regeneration', 'legacy'])
def test_behavior_golden_compares_same_generation_projection(reads, change):
    from types import SimpleNamespace

    from saw.apps.api.main import create_app
    from saw.behavior.models import BehaviorResult
    from saw.behavior.service import golden_capture, source_manifest
    from saw.core.application.provenance import digest
    from saw.event_generations.reads import actor_scope
    from saw.storage.models import EvidenceFile

    es, publish, factory = reads
    publish(1)
    create_app(es.settings, synchronous_jobs=True)
    c = container.get()
    with actor_scope('actor'), c.events.read_scope(), factory.begin() as s:
        source = source_manifest(s, 'inv')
        if change != 'legacy':
            source = c.events.pin_manifest(s, 'inv', source)
        data = {'source_manifest': source, 'captured_at': 'synthetic', 'methodology': {},
                'profile': {}, 'scope': {}, 'observations': {}, 'selected_evidence': []}
        original_hash = digest(data)
        s.add(BehaviorResult(id='behavior', investigation_id='inv', job_id='old', version=1,
                             created_by='actor', result=data, result_sha256=original_hash))
    if change == 'hash':
        with factory.begin() as s:
            s.get(EvidenceFile, 'file').sha256 = 'b' * 64
    elif change == 'regeneration':
        publish(1)
    check = SimpleNamespace(scope={'behavior': {'result_id': 'behavior', 'result_sha256': original_hash}})
    with actor_scope('actor'), c.events.read_scope(), factory.begin() as s:
        if change in ('none', 'legacy'):
            row, observation, _ = golden_capture(s, 'inv', check)
            assert observation['source_manifest'] == source
            assert row.result_sha256 == original_hash and digest(row.result) == original_hash
        else:
            with pytest.raises(ValueError, match='golden_source_evidence_changed'):
                golden_capture(s, 'inv', check)
        assert s.get(BehaviorResult, 'behavior').result == data
