from __future__ import annotations

import pytest
from sqlalchemy import select

from saw import container
from saw.event_generations.models import InvestigationHead
from saw.storage.db import session_scope
from saw.storage.models import Job
from tests.api.test_phase5_bulk import upload

DATA = b'127.0.0.1 - - [10/Oct/2026:13:55:36 +0000] "GET /first HTTP/1.1" 200 123 "-" "test"\n'


def prepared(api, title='generation'):
    inv = api.post('/investigations', json={'title': title}).json()['id']
    up = upload(api, inv, 'access.log', DATA, kind='auto')
    job = api.post(f"/evidence/{up['evidence_id']}/process").json()
    current = api.get(f"/jobs/{job['id']}").json()
    assert current['state'] == 'COMPLETED', current
    return inv, up, current


def test_ingest_publishes_generation_and_reprocess_uses_new_job(analyst):
    inv, up, old = prepared(analyst)
    with session_scope() as s:
        head = s.get(InvestigationHead, inv)
        assert head is not None, 'normal producer must publish a generation'
        before = head.generation_id
        old_stages = dict(s.get(Job, old['id']).stages)
    response = analyst.post(f"/evidence/{up['evidence_id']}/files/{old['files'][0]['id']}/parser",
                            json={'parser_id': old['files'][0]['parser_id']})
    assert response.status_code == 200, response.text
    newer = response.json()
    assert newer['job_id'] != old['id']
    current = analyst.get(f"/jobs/{newer['job_id']}").json()
    assert current['state'] == 'COMPLETED', current
    with session_scope() as s:
        assert s.get(InvestigationHead, inv).generation_id != before
        assert s.get(Job, old['id']).stages == old_stages
    assert 'generation_request' not in current['stages']
    from saw.event_generations.reads import task_read_scope
    with task_read_scope(old["id"]):
        assert container.get().events.count(inv, []) == 1


def test_public_job_output_hides_private_generation_details():
    from saw.apps.api.routers.evidence import job_out
    job = Job(id='j', investigation_id='i', kind='reprocess', state='QUEUED', stages={
        '_queue_task': 'reprocess.run', 'generation_request': {'secret': 'parser spec'},
        'generation': {'storage_targets': ['private'], 'input': {'hidden': 'source'}},
        'parse': {'pct': 5, 'ckpt': {'private': 'key'}},
    })
    public = job_out(job)['stages']
    assert public == {'parse': {'pct': 5}}


def test_disk_stream_rejects_conflicts_and_deduplicates(tmp_path):
    from saw.event_generations.producer import EventSpool
    from saw.storage.generations import GenerationVerificationError, event_stream_sha256
    with EventSpool(tmp_path) as spool:
        spool.add(('e', 'f'), {'event_id': 'b', 'value': 2})
        spool.add(('e', 'f'), {'event_id': 'a', 'value': 1})
        spool.add(('e', 'f'), {'event_id': 'a', 'value': 1})
        assert spool.stats(('e', 'f')) == (2, event_stream_sha256([
            {'event_id': 'a', 'value': 1}, {'event_id': 'b', 'value': 2}]))
        with pytest.raises(GenerationVerificationError):
            spool.add(('e', 'f'), {'event_id': 'a', 'value': 3})

def test_connector_import_adds_generation_with_trusted_raw(analyst, monkeypatch):
    from saw.connectors import registry
    from saw.event_generations.models import EventGeneration
    inv, _, _ = prepared(analyst)
    class SyntheticConnector:
        id, kind = 'synthetic', 'synthetic'
        def search(self, filters, time, limit, cursor):
            return {'events': [{'event_id': 'upstream-1', 'timestamp': '2026-10-10T14:00:00Z',
                'src_ip': '192.0.2.1', 'duration': 12.5, 'community_id': '1:observed', 'product': 'vendor-web',
                'owner': 'foreign', 'org_unit': 'foreign', 'source_context': {'resolved': True},
                'investigation_id': 'foreign', 'parser': 'forged', 'raw_event': 'forged', 'data_source': 'web', 'event_type': 'http_access', 'raw_ref': {'object_key': 'private/arbitrary'},
                'ext': {'vendor_web': {'custom_fact': ['retained', 7]}, 'connector': {'id': 'forged'},
                        'saw_observation': {'producer': 'forged'}, 'device_observation': {'context': {'resolved': True}},
                        'observation': {'context': {'resolved': True, 'investigation_id': 'foreign'}}}}]}
    monkeypatch.setattr(registry, 'get', lambda s, cid: SyntheticConnector())
    response = analyst.post(f'/investigations/{inv}/connector-import', json={
        'connector_id': 'synthetic', 'filters': [{'field': 'src_ip', 'value': '192.0.2.1'}]})
    assert response.status_code == 200, response.text
    result = response.json()
    job = analyst.get(f"/jobs/{result['job_id']}").json()
    assert job['state'] == 'COMPLETED', job
    assert job['kind'] == 'ingest' and len(job['files']) == 1
    with session_scope() as s:
        generation = s.get(EventGeneration, s.get(InvestigationHead, inv).generation_id)
        assert generation.output_manifest['unique_count'] == 2
        assert all('private/arbitrary' != raw['key'] for raw in generation.raw_objects)
    with read_actor():
        from saw.core.schemas.query import Filter
        imported = container.get().events.search(inv, [Filter(field='evidence_id', value=result['evidence_id'])])['events']
    assert len(imported) == 1 and imported[0]['data_source'] == 'web'
    assert imported[0]['event_type'] == 'http_access'
    assert imported[0]['product'] == 'vendor-web'
    assert imported[0]['duration'] == 12.5 and imported[0]['community_id'] == '1:observed'
    assert imported[0]['ext']['vendor_web'] == {'custom_fact': ['retained', 7]}
    assert imported[0]['investigation_id'] == inv and imported[0]['parser'] == 'json_lines'
    assert 'owner' not in imported[0] and 'org_unit' not in imported[0]
    assert imported[0]['ext']['saw_observation']['producer'] == 'saw-parser/1'
    assert imported[0]['ext']['connector']['id'] == 'synthetic'
    assert imported[0]['event_id'] != 'upstream-1'
    assert imported[0]['raw_ref']['object_key'].startswith('saw-evidence-original/' + inv + '/')
    assert imported[0]['ext']['observation']['context']['resolved'] is False
    assert imported[0]['ext']['connector']['source_event_id'] == 'upstream-1'


def _head(inv):
    from saw.event_generations.models import EventGeneration
    with session_scope() as s:
        head = s.get(InvestigationHead, inv)
        row = s.get(EventGeneration, head.generation_id)
        return row.id, row.output_sha256, dict(row.output_manifest)


@pytest.mark.parametrize('fault', ['write', 'cancel', 'lease', 'actor', 'raw', 'receipt', 'parser', 'source'])
def test_failed_private_generation_never_changes_current(analyst, monkeypatch, fault):
    from saw.storage.generations import GenerationWriter
    from saw.storage.models import EvidenceFile, User
    inv, up, old = prepared(analyst)
    before = _head(inv)
    old_file = dict(old['files'][0])
    original_index = GenerationWriter.index
    fired = False
    def broken(writer, events):
        nonlocal fired
        count = original_index(writer, events)
        if not fired:
            fired = True
            if fault == 'write':
                raise OSError('synthetic write boundary failure')
            with session_scope() as s:
                job = s.scalar(select(Job).where(Job.investigation_id == inv, Job.kind == 'reprocess'))
                if fault == 'cancel':
                    job.cancel_requested = True
                elif fault == 'lease':
                    job.attempt += 1
                elif fault == 'actor':
                    s.get(User, job.requested_by).status = 'disabled'
                elif fault == 'parser':
                    from saw.parsers.registry import get_parser
                    monkeypatch.setattr(type(get_parser(old_file['parser_id'])), 'version', '999-test')
                elif fault == 'source':
                    s.get(EvidenceFile, up['file_id']).message = 'external source mutation'
                elif fault == 'raw':
                    source = s.get(EvidenceFile, up['file_id'])
                    path = container.get().objects.local_path('saw-evidence-original', source.object_key)
                    path.write_bytes(DATA.replace(b'/first', b'/other'))
        return count
    monkeypatch.setattr(GenerationWriter, 'index', broken)
    if fault == 'receipt':
        verify = GenerationWriter.verify
        def mismatched(writer, **kw):
            receipt = verify(writer, **kw)
            return {**receipt, 'output_sha256': '0' * 64}
        monkeypatch.setattr(GenerationWriter, 'verify', mismatched)
    response = analyst.post(f"/evidence/{up['evidence_id']}/files/{up['file_id']}/parser",
                            json={'parser_id': old_file['parser_id']})
    assert response.status_code == 200, response.text
    assert fired
    assert _head(inv) == before
    with session_scope() as s:
        source = s.get(EvidenceFile, up['file_id'])
        assert source.events_parsed == old_file['events_parsed']
        assert source.parser_id == old_file['parser_id']
        assert source.parse_status == old_file['status']
        original = s.get(Job, old['id'])
        assert original.state == 'COMPLETED'


def test_zero_replacement_and_new_upload_preserve_other_files(analyst):
    inv, up, _ = prepared(analyst)
    second = upload(analyst, inv, 'second.log', DATA.replace(b'/first', b'/other'), kind='auto')
    second_job = analyst.post(f"/evidence/{second['evidence_id']}/process").json()
    assert analyst.get(f"/jobs/{second_job['id']}").json()['state'] == 'COMPLETED'
    other, _, _ = prepared(analyst, 'other investigation')
    before, other_before = _head(inv), _head(other)
    response = analyst.post(f"/evidence/{up['evidence_id']}/files/{up['file_id']}/parser", json={'parser_id': 'json_lines'})
    job = analyst.get(f"/jobs/{response.json()['job_id']}").json()
    assert job['state'] == 'FAILED', job
    assert _head(inv) == before and _head(other) == other_before
    assert before[2]['unique_count'] == 2


def test_ingest_retry_creates_new_requester_owned_job(analyst, monkeypatch):
    from saw.storage.generations import GenerationWriter
    original = GenerationWriter.index
    def fail(writer, events):
        raise OSError('synthetic boundary')
    monkeypatch.setattr(GenerationWriter, 'index', fail)
    inv = analyst.post('/investigations', json={'title': 'retry'}).json()['id']
    up = upload(analyst, inv, 'access.log', DATA, kind='auto')
    job = analyst.post(f"/evidence/{up['evidence_id']}/process").json()
    assert analyst.get(f"/jobs/{job['id']}").json()['state'] == 'FAILED'
    monkeypatch.setattr(GenerationWriter, 'index', original)
    retry = analyst.post(f"/jobs/{job['id']}/retry")
    assert retry.status_code == 200, retry.text
    assert retry.json()['id'] != job['id']
    assert analyst.get(f"/jobs/{retry.json()['id']}").json()['state'] == 'COMPLETED'
    assert analyst.get(f"/jobs/{job['id']}").json()['state'] == 'FAILED'

def test_fewer_more_output_only_replaces_selected_file_and_preserves_history(analyst):
    from copy import deepcopy

    from saw.analysis_runs.models import AnalysisRun
    inv = analyst.post('/investigations', json={'title': 'multi source'}).json()['id']
    data = DATA + DATA.replace(b'/first', b'/second') + DATA.replace(b'/first', b'/third')
    up = upload(analyst, inv, 'access.log', data, kind='auto')
    analyst.post(f"/evidence/{up['evidence_id']}/process")
    other = upload(analyst, inv, 'other.log', DATA, kind='auto')
    analyst.post(f"/evidence/{other['evidence_id']}/process")
    foreign, _, _ = prepared(analyst, 'foreign')
    foreign_before = _head(foreign)
    before = _head(inv)
    other_descriptor = next(x for x in before[2]['files'] if x['evidence_id'] == other['evidence_id'])
    with session_scope() as s:
        snapshots = {r.id: (r.input_sha256, deepcopy(r.input_manifest)) for r in s.scalars(
            select(AnalysisRun).where(AnalysisRun.investigation_id == inv))}
    for slug, pattern, count in [('one', '^.*"GET (?P<uri>/first) HTTP/1.1".*$', 1),
                                  ('all', '^.*"GET (?P<uri>[^ ]+) HTTP/1.1".*$', 3)]:
        response = analyst.post('/parser-library', json={'name': slug, 'slug': slug,
            'spec': {'format': 'regex', 'pattern': pattern, 'data_source': 'web'}})
        assert response.status_code == 201, response.text
        selected = response.json()['pinned_id']
        job = analyst.post(f"/evidence/{up['evidence_id']}/files/{up['file_id']}/parser", json={'parser_id': selected}).json()
        result = analyst.get(f"/jobs/{job['job_id']}").json()
        assert result['state'] == 'COMPLETED', result
        current = _head(inv)
        assert current[2]['unique_count'] == count + 1
        unchanged = next(x for x in current[2]['files'] if x['evidence_id'] == other['evidence_id'])
        assert unchanged == other_descriptor
        assert _head(foreign) == foreign_before
    with session_scope() as s:
        assert all((s.get(AnalysisRun, key).input_sha256, s.get(AnalysisRun, key).input_manifest) == value
                   for key, value in snapshots.items())


def test_published_analysis_failure_retry_does_not_reparse(analyst, monkeypatch):
    from saw.core.application import analysis
    original = analysis.run_all
    def fail(*a, **kw):
        raise RuntimeError('synthetic analysis boundary')
    monkeypatch.setattr(analysis, 'run_all', fail)
    inv = analyst.post('/investigations', json={'title': 'published analysis fail'}).json()['id']
    up = upload(analyst, inv, 'access.log', DATA, kind='auto')
    job = analyst.post(f"/evidence/{up['evidence_id']}/process").json()
    assert analyst.get(f"/jobs/{job['id']}").json()['state'] == 'FAILED'
    before = _head(inv)
    monkeypatch.setattr(analysis, 'run_all', original)
    retry = analyst.post(f"/jobs/{job['id']}/retry").json()
    assert retry['kind'] == 'reanalyze'
    assert analyst.get(f"/jobs/{retry['id']}").json()['state'] == 'COMPLETED'
    assert _head(inv) == before

def test_legacy_first_reprocess_retains_baseline_and_unchanged_ids(analyst):
    from saw.event_generations.models import EventGeneration
    from saw.event_generations.reads import task_read_scope
    from saw.parsers.registry import get_parser, iter_lines, to_ces
    from saw.storage.models import EvidenceFile
    inv = analyst.post('/investigations', json={'title': 'legacy baseline'}).json()['id']
    up = upload(analyst, inv, 'legacy.log', DATA, kind='auto')
    parser = get_parser('nginx_combined')
    with session_scope() as s:
        source = s.get(EvidenceFile, up['file_id'])
        source.type_detected, source.parser_id, source.parser_version = 'text', parser.id, parser.version
        source.parse_status, source.events_parsed = 'done', 1
        key = source.object_key
        s.get(Job, up['job_id']).state = 'COMPLETED'
    line = next(iter_lines([DATA]))
    event = to_ces(parser, line, parser.parse_line(line.text), investigation_id=inv, evidence_id=up['evidence_id'],
        file_id=up['file_id'], source_file='legacy.log', object_key='saw-evidence-original/' + key, assumed_tz='UTC')
    container.get().legacy_events.index([event])
    response = analyst.post(f"/evidence/{up['evidence_id']}/files/{up['file_id']}/parser", json={'parser_id': parser.id})
    result = analyst.get(f"/jobs/{response.json()['job_id']}").json()
    assert result['state'] == 'COMPLETED', result
    with session_scope() as s:
        rows = list(s.scalars(select(EventGeneration).where(EventGeneration.investigation_id == inv)))
        baseline = next(g for g in rows if g.purpose == 'baseline')
        assert baseline.status == 'retained'
        baseline_id = baseline.id
    from saw.event_generations.service import resolve
    with session_scope() as s:
        reference = resolve(s, inv, generation_id=baseline_id)
    with task_read_scope(result['id']), container.get().generations.open_view(inv, ref=reference) as retained:
        assert retained.get(inv, event['event_id']) == event

def test_new_upload_same_evidence_preserves_existing_published_result(analyst):
    import hashlib
    inv, up, old = prepared(analyst)
    before = _head(inv)
    file_before = old['files'][0]
    data = DATA.replace(b'/first', b'/new')
    session = analyst.post('/uploads', json={'evidence_id': up['evidence_id'], 'filename': 'new.log',
        'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}).json()
    analyst.put(f"/uploads/{session['id']}/parts/1", content=data)
    new_file = analyst.post(f"/uploads/{session['id']}/complete").json()['file_id']
    job = analyst.post(f"/evidence/{up['evidence_id']}/process").json()
    result = analyst.get(f"/jobs/{job['id']}").json()
    assert result['state'] == 'COMPLETED', result
    from saw.event_generations.models import EventGeneration
    with session_scope() as s:
        generation = s.get(EventGeneration, s.get(InvestigationHead, inv).generation_id)
        assert [r['file_id'] for r in generation.file_results] == [new_file]
    assert next(f for f in result['files'] if f['id'] == up['file_id']) == file_before
    assert _head(inv)[2]['unique_count'] == 2
    assert next(f for f in _head(inv)[2]['files'] if f['file_id'] == up['file_id']) == before[2]['files'][0]

def test_public_job_keeps_safe_result_links_only():
    from saw.apps.api.routers.evidence import job_out
    job = Job(id='j', investigation_id='i', kind='device_analysis', state='COMPLETED', stages={
        'analysis_run_id': 'run', 'behavior_result': {'id': 'result', 'result_sha256': 'a' * 64, 'private': 'hidden'},
        'device_analysis_request': {'input': 'private'}, 'retry_of': 'earlier'})
    assert job_out(job)['stages'] == {'analysis_run_id': 'run',
        'behavior_result': {'id': 'result', 'result_sha256': 'a' * 64}, 'retry_of': 'earlier'}
from contextlib import contextmanager


@contextmanager
def read_actor(username='analyst1'):
    from saw.event_generations.reads import actor_scope
    from saw.storage.models import User
    with session_scope() as s:
        uid = s.scalar(select(User.id).where(User.username == username))
    assert uid is not None
    with actor_scope(uid), container.get().events.read_scope():
        yield


class read_events:
    """Explicit synthetic actor for direct adapter assertions outside an HTTP request."""
    def __init__(self, username='analyst1'):
        self.username = username

    def __getattr__(self, name):
        assert name in {'get', 'search', 'iterate', 'count', 'aggregate', 'group_by', 'histogram_metrics', 'time_bounds'}
        def read(*args, **kwargs):
            with read_actor(self.username):
                return getattr(container.get().events, name)(*args, **kwargs)
        if name == 'iterate':
            def iterate(*args, **kwargs):
                with read_actor(self.username):
                    yield from container.get().events.iterate(*args, **kwargs)
            return iterate
        return read


def test_mock_connector_preserves_ces_facts(admin, analyst):
    from saw.core.schemas.query import Filter
    connector = admin.post('/admin/connectors', json={'name': 'preserve-facts', 'kind': 'mock_logpresso'}).json()
    inv = analyst.post('/investigations', json={'title': 'connector facts'}).json()['id']
    for source, product, vendor, fact, value in (
        ('firewall', 'fw-mock', 'fw', 'action', None),
        ('ips', 'ips-mock', 'ips', 'signature', 'Web Application Scan (mock)'),
        ('vpn', 'vpn-mock', 'vpn', 'outcome', 'success'),
    ):
        response = analyst.post(f'/investigations/{inv}/connector-import', json={
            'connector_id': connector['id'], 'filters': [{'field': 'data_source', 'value': source}], 'limit': 3})
        assert response.status_code == 200, response.text
        imported = response.json()
        job = analyst.get(f"/jobs/{imported['job_id']}").json()
        assert job['state'] == 'COMPLETED', job
        with read_actor():
            events = container.get().events.search(inv, [Filter(field='evidence_id', value=imported['evidence_id'])])['events']
        assert len(events) == 3
        for event in events:
            assert event['product'] == product
            assert event['data_source'] == source
            assert event['ext'][vendor][fact] == value if value else event['ext'][vendor][fact] in ('allow', 'deny')
            if source == 'firewall':
                assert event['enforcement_action'] == ('allowed' if event['ext']['fw']['action'] == 'allow' else 'blocked')
            if source == 'ips':
                assert event['severity'] == 'medium'
        retry = analyst.post(f"/evidence/{imported['evidence_id']}/files/{job['files'][0]['id']}/parser",
                             json={'parser_id': 'json_lines'}).json()
        assert analyst.get(f"/jobs/{retry['job_id']}").json()['state'] == 'COMPLETED'
        with read_actor():
            replay = container.get().events.search(inv, [Filter(field='evidence_id', value=imported['evidence_id'])])['events']
        assert sorted((e['event_id'], e['product'], e['ext'][vendor]) for e in events) == sorted(
            (e['event_id'], e['product'], e['ext'][vendor]) for e in replay)


@pytest.mark.parametrize('identity', [('e', 'f'), None])
def test_expected_hash_scan_cancels_before_all_rows(tmp_path, monkeypatch, identity):
    from saw.event_generations import producer
    from saw.storage.generations import event_stream_sha256
    from saw.workers.pipeline import Cancelled
    consumed, checks = 0, 0
    loads = producer.json.loads
    def counted_loads(payload):
        nonlocal consumed
        consumed += 1
        return loads(payload)
    def check():
        nonlocal checks
        checks += 1
        if checks == 3:
            raise Cancelled()
    with producer.EventSpool(tmp_path) as spool:
        for index in range(5500):
            spool.add(('e', 'f'), {'event_id': f'{index:08}', 'value': index})
        monkeypatch.setattr(producer.json, 'loads', counted_loads)
        with pytest.raises(Cancelled):
            if identity:
                spool.stats(identity, check=check)
            else:
                event_stream_sha256(spool.events(check=check))
        assert checks == 3 and 500 <= consumed <= 1000


@pytest.mark.parametrize('scan', [1, 3, 4])
def test_real_producer_hash_cancellation_keeps_previous_head(analyst, monkeypatch, scan):
    from saw.event_generations import producer
    inv, _, _ = prepared(analyst)
    before = _head(inv)
    source = upload(analyst, inv, 'many.log', DATA * 1500, kind='auto')
    original_hash = producer.event_stream_sha256
    calls, consumed = 0, 0
    def interrupted_hash(events):
        nonlocal calls, consumed
        calls += 1
        def counted():
            nonlocal consumed
            for event in events:
                consumed += 1
                if consumed == 500:
                    # A separate transaction proves the scan holds no lifecycle SQL lock.
                    with session_scope() as s:
                        job = s.scalar(select(Job).where(Job.evidence_id == source['evidence_id']))
                        job.cancel_requested = True
                yield event
        return original_hash(counted() if calls == scan else events)
    monkeypatch.setattr(producer, 'event_stream_sha256', interrupted_hash)
    response = analyst.post(f"/evidence/{source['evidence_id']}/process").json()
    job = analyst.get(f"/jobs/{response['id']}").json()
    assert job['state'] == 'CANCELLED', job
    assert 500 <= consumed <= 1000
    assert _head(inv) == before


def test_connector_queued_duplicate_and_overlap_are_fenced(analyst, monkeypatch):
    from saw.connectors import registry
    from saw.storage.models import Evidence
    docs = [{'event_id': 'source-1', 'timestamp': '2026-10-10T14:00:00Z', 'product': 'test', 'data_source': 'vpn'}]
    class SyntheticConnector:
        id, kind = 'synthetic', 'synthetic'
        def search(self, filters, time, limit, cursor):
            return {'events': docs}
    monkeypatch.setattr(registry, 'get', lambda s, cid: SyntheticConnector())
    monkeypatch.setattr(container.get().runner, 'submit', lambda *args, **kwargs: None)
    inv = analyst.post('/investigations', json={'title': 'queued import'}).json()['id']
    body = {'connector_id': 'synthetic', 'filters': [{'field': 'data_source', 'value': 'vpn'}]}
    first = analyst.post(f'/investigations/{inv}/connector-import', json=body)
    again = analyst.post(f'/investigations/{inv}/connector-import', json=body)
    assert first.status_code == again.status_code == 200
    assert first.json() == again.json()
    with session_scope() as s:
        assert len(list(s.scalars(select(Job).where(Job.investigation_id == inv)))) == 1
        assert len(list(s.scalars(select(Evidence).where(Evidence.investigation_id == inv)))) == 1
    docs.append({**docs[0], 'event_id': 'source-2'})
    assert analyst.post(f'/investigations/{inv}/connector-import', json=body).status_code == 409
    docs.pop()
    docs[0]['product'] = 'changed-source'
    assert analyst.post(f'/investigations/{inv}/connector-import', json=body).status_code == 409
    other = analyst.post('/investigations', json={'title': 'separate import'}).json()['id']
    separate = analyst.post(f'/investigations/{other}/connector-import', json=body)
    assert separate.status_code == 200 and separate.json()['job_id'] != first.json()['job_id']


def test_connector_simultaneous_duplicate_reserves_one_job(analyst, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from saw.connectors import registry
    class SyntheticConnector:
        id, kind = 'synthetic', 'synthetic'
        def search(self, filters, time, limit, cursor):
            return {'events': [{'event_id': 'one', 'timestamp': '2026-10-10T14:00:00Z'}]}
    monkeypatch.setattr(registry, 'get', lambda s, cid: SyntheticConnector())
    monkeypatch.setattr(container.get().runner, 'submit', lambda *args, **kwargs: None)
    barrier = Barrier(2)
    objects = container.get().objects
    put = objects.put_stream
    def synchronized_put(*args):
        barrier.wait(timeout=10)
        return put(*args)
    monkeypatch.setattr(objects, 'put_stream', synchronized_put)
    inv = analyst.post('/investigations', json={'title': 'simultaneous'}).json()['id']
    def request():
        return analyst.post(f'/investigations/{inv}/connector-import', json={
            'connector_id': 'synthetic', 'filters': [{'field': 'data_source', 'value': 'vpn'}]})
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(request) for _ in range(2)]
        responses = [future.result(timeout=20) for future in futures]
    assert [r.status_code for r in responses] == [200, 200]
    assert responses[0].json() == responses[1].json()
    with session_scope() as s:
        assert len(list(s.scalars(select(Job).where(Job.investigation_id == inv)))) == 1


@pytest.mark.parametrize('fault', ['reservation', 'old_unreserved'])
def test_connector_source_reservation_fences_publication(analyst, monkeypatch, fault):
    from saw.connectors import registry
    from saw.storage.generations import GenerationWriter
    class SyntheticConnector:
        id, kind = 'synthetic', 'synthetic'
        def search(self, filters, time, limit, cursor):
            return {'events': [{'event_id': 'one', 'timestamp': '2026-10-10T14:00:00Z'}]}
    monkeypatch.setattr(registry, 'get', lambda s, cid: SyntheticConnector())
    inv, _, _ = prepared(analyst)
    body = {'connector_id': 'synthetic', 'filters': [{'field': 'data_source', 'value': 'custom'}]}
    if fault == 'old_unreserved':
        first = analyst.post(f'/investigations/{inv}/connector-import', json=body).json()
        assert analyst.get(f"/jobs/{first['job_id']}").json()['state'] == 'COMPLETED'
        with session_scope() as s:
            job = s.get(Job, first['job_id'])
            job.stages = {k: v for k, v in job.stages.items() if k != '_connector_import'}
    else:
        index = GenerationWriter.index
        def mutate(writer, events):
            result = index(writer, events)
            with session_scope() as s:
                for job in s.scalars(select(Job).where(Job.investigation_id == inv)):
                    if '_connector_import' in (job.stages or {}):
                        job.stages = {**job.stages, '_connector_import': {'forged': True}}
            return result
        monkeypatch.setattr(GenerationWriter, 'index', mutate)
    before = _head(inv)
    imported = analyst.post(f'/investigations/{inv}/connector-import', json=body).json()
    assert analyst.get(f"/jobs/{imported['job_id']}").json()['state'] == 'FAILED'
    assert _head(inv) == before


def test_connector_generation_records_concrete_parser_digest(analyst, monkeypatch):
    import hashlib
    import inspect
    from pathlib import Path

    from saw.connectors import registry
    from saw.core.application.provenance import parser_digest
    from saw.event_generations.models import EventGeneration
    from saw.event_generations.producer import ConnectorEnvelopeParser
    from saw.parsers.registry import get_parser
    class SyntheticConnector:
        id, kind = 'concrete-parser', 'synthetic'
        def search(self, filters, time, limit, cursor):
            return {'events': [{'event_id': 'one', 'timestamp': '2026-10-10T14:00:00Z', 'product': 'retained'}]}
    monkeypatch.setattr(registry, 'get', lambda s, cid: SyntheticConnector())
    inv = analyst.post('/investigations', json={'title': 'concrete parser'}).json()['id']
    result = analyst.post(f'/investigations/{inv}/connector-import', json={
        'connector_id': 'concrete-parser', 'filters': [{'field': 'data_source', 'value': 'custom'}]}).json()
    assert analyst.get(f"/jobs/{result['job_id']}").json()['state'] == 'COMPLETED'
    concrete = hashlib.sha256(Path(inspect.getsourcefile(ConnectorEnvelopeParser)).read_bytes()).hexdigest()
    assert concrete != parser_digest(get_parser('json_lines'))
    with session_scope() as s:
        row = s.get(EventGeneration, s.get(InvestigationHead, inv).generation_id)
        pin = row.input_manifest['replacements'][0]['parser']
        assert pin['digest'] == concrete
        assert pin['implementation'] == 'saw.parsers.connector.ConnectorEnvelopeParser'
        assert row.file_results[0]['parser_digest'] == concrete
        assert row.input_manifest['source']['evidence'][0]['files'][0]['parser'] == pin
        file_id = row.file_results[0]['file_id']
    replay = analyst.post(f"/evidence/{result['evidence_id']}/files/{file_id}/parser",
                          json={'parser_id': 'json_lines'}).json()
    assert analyst.get(f"/jobs/{replay['job_id']}").json()['state'] == 'COMPLETED'
    with session_scope() as s:
        request = s.get(Job, replay['job_id']).stages['generation_request']['input']
        assert request['replacements'][0]['parser'] == pin


@pytest.mark.parametrize('change', ['code', 'version'])
def test_changed_connector_implementation_blocks_publication(analyst, monkeypatch, tmp_path, change):
    import importlib
    from pathlib import Path

    from saw.connectors import registry
    from saw.event_generations.producer import ConnectorEnvelopeParser
    from saw.storage.generations import GenerationWriter
    module = importlib.import_module(ConnectorEnvelopeParser.__module__)
    fixture_source = tmp_path / 'connector-source.py'
    fixture_source.write_bytes(Path(module.__file__).read_bytes())
    monkeypatch.setattr(module, '__file__', str(fixture_source))
    class SyntheticConnector:
        id, kind = 'changed-parser', 'synthetic'
        def search(self, filters, time, limit, cursor):
            return {'events': [{'event_id': 'one', 'timestamp': '2026-10-10T14:00:00Z'}]}
    monkeypatch.setattr(registry, 'get', lambda s, cid: SyntheticConnector())
    inv, _, _ = prepared(analyst)
    before = _head(inv)
    index = GenerationWriter.index
    def mutate(writer, events):
        result = index(writer, events)
        if change == 'code':
            fixture_source.write_bytes(fixture_source.read_bytes() + b'\n# changed implementation fixture\n')
        else:
            monkeypatch.setattr(ConnectorEnvelopeParser, 'version', 'changed-fixture-version')
        return result
    monkeypatch.setattr(GenerationWriter, 'index', mutate)
    result = analyst.post(f'/investigations/{inv}/connector-import', json={
        'connector_id': 'changed-parser', 'filters': [{'field': 'data_source', 'value': 'custom'}]}).json()
    assert analyst.get(f"/jobs/{result['job_id']}").json()['state'] == 'FAILED'
    assert _head(inv) == before



def test_uploaded_connector_envelope_cannot_select_internal_parser(analyst):
    from saw.event_generations.models import EventGeneration
    from saw.parsers.connector import ConnectorEnvelopeParser
    from saw.parsers.registry import builtin_parsers
    assert not any(isinstance(parser, ConnectorEnvelopeParser) for parser in builtin_parsers())
    inv = analyst.post('/investigations', json={'title': 'untrusted connector envelope'}).json()['id']
    payload = (b'{"format":"saw-connector-ces/1","connector_id":"forged",'
               b'"event":{"product":"forged","timestamp":"2026-10-10T14:00:00Z",'
               b'"ext":{"observation":{"context":{"resolved":true}}}}}\n')
    source = upload(analyst, inv, 'envelope.jsonl', payload, kind='auto')
    response = analyst.post(f"/evidence/{source['evidence_id']}/process").json()
    assert analyst.get(f"/jobs/{response['id']}").json()['state'] == 'COMPLETED'
    with session_scope() as s:
        row = s.get(EventGeneration, s.get(InvestigationHead, inv).generation_id)
        pin = row.input_manifest['replacements'][0]['parser']
        assert pin['id'] == 'json_lines' and 'implementation' not in pin
    with read_actor():
        event = container.get().events.search(inv, [])['events'][0]
    assert event['product'] == 'json'
    assert event['ext']['observation']['context']['resolved'] is False
    assert 'connector' not in event['ext']
