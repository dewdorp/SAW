"""OpenSearch boundary tests; the transport is synthetic, never a native acceptance claim."""
import copy
import io
import json
import os
from dataclasses import replace
from datetime import datetime
from types import SimpleNamespace

import pytest

from tests.unit.test_event_generation_writers import event, expected


class Indices:
    def __init__(self, client): self.client = client
    def exists(self, index): return index in self.client.targets
    def create(self, index, body, **kw):
        assert '-*' not in index and '*' not in index and not body.get('aliases')
        assert body['settings']['translog']['durability'] == 'request'
        self.client.targets[index] = {**copy.deepcopy(body), 'aliases': {}, 'docs': {}}
        return {'acknowledged': True, 'shards_acknowledged': True}
    def get(self, index, **kw):
        if index not in self.client.targets: raise RuntimeError('missing index')
        return {index: copy.deepcopy(self.client.targets[index])}
    def put_mapping(self, index, body, **kw):
        self.client.targets[index]['mappings'].update(copy.deepcopy(body))
        return {'acknowledged': True}
    def refresh(self, index, **kw): return {'_shards': {'total': 1, 'successful': 1, 'failed': 0}}
    def flush(self, index, **kw): return {'_shards': {'total': 1, 'successful': 1, 'failed': 0}}


class Client:
    def __init__(self):
        self.targets = {}
        self.indices = Indices(self)
        self.transport = self
        self.partial = False
        self.bulk_sizes = []
        self.fail_bulk = False
    def perform_request(self, method, url, **kw):
        target = url.split('/')[1]
        assert method == 'PUT' and url.endswith('/_block/write')
        assert kw['params'] == {'ignore_unavailable': 'false', 'allow_no_indices': 'false', 'expand_wildcards': 'none'}
        self.targets[target]['settings']['index'] = {'blocks': {'write': 'true'}}
        return {'acknowledged': True, 'shards_acknowledged': True,
                'indices': [{'name': target, 'blocked': True}]}
    def bulk(self, body, **kw):
        data = body.decode() if isinstance(body, bytes) else body
        lines = data.splitlines()
        self.bulk_sizes.append((len(lines) // 2, len(data.encode())))
        if self.fail_bulk: raise TimeoutError('synthetic timeout')
        results = []
        for i in range(0, len(lines), 2):
            action = json.loads(lines[i])['create']
            target, eid = action['_index'], action['_id']
            row = self.targets[target]
            if row['settings'].get('index', {}).get('blocks', {}).get('write') == 'true':
                raise RuntimeError('write blocked')
            status = 409 if eid in row['docs'] else 201
            if status == 201: row['docs'][eid] = json.loads(lines[i + 1])
            results.append({'create': {'_id': eid, 'status': status}})
        return {'errors': any(x['create']['status'] != 201 for x in results), 'items': results}
    def get(self, index, id, **kw):
        return {'found': True, '_source': self.targets[index]['docs'][id]}
    def search(self, index=None, body=None, **kw):
        assert kw.get('ignore_unavailable') is False and kw.get('allow_no_indices') is False
        assert kw.get('allow_partial_search_results') is False
        if self.partial: return {'timed_out': True, '_shards': {'total': 2, 'successful': 1, 'failed': 1}}
        docs = list(self.targets[index]['docs'].values())
        for term in body.get('query', {}).get('bool', {}).get('filter', []):
            if 'term' in term:
                key, val = next(iter(term['term'].items()))
                docs = [d for d in docs if d.get(key) == val]
        if 'aggs' in body:
            result = {}
            for name, agg in body['aggs'].items():
                if 'terms' in agg:
                    field = agg['terms']['field']
                    values = sorted({d[field] for d in docs if field in d})
                    result[name] = {'buckets': [{'key': v, 'doc_count': sum(d.get(field) == v for d in docs)} for v in values]}
                elif 'min' in agg or 'max' in agg:
                    values = [d['timestamp'] for d in docs if d.get('timestamp')]
                    result[name] = {'value_as_string': (min(values) if 'min' in agg else max(values)) if values else None}
                elif 'date_histogram' in agg:
                    count = sum(bool(d.get('timestamp')) for d in docs)
                    result[name] = {'buckets': [{'key': 1767225600000, 'doc_count': count}] if count else []}
            return {'timed_out': False, '_shards': {'total': 1, 'successful': 1, 'failed': 0}, 'aggregations': result}
        specs = body.get('sort', [{'event_id': 'asc'}])
        first = next(iter(specs[0].values()))
        reverse = (first.get('order') if isinstance(first, dict) else first) == 'desc'
        def key(d):
            result = []
            for spec in specs:
                field = next(iter(spec))
                value = d.get(field)
                if field == 'timestamp':
                    value = int(datetime.fromisoformat(value).timestamp() * 1000) if value else (-9223372036854775808 if reverse else 9223372036854775807)
                result.append(value)
            return result
        docs.sort(key=key, reverse=reverse)
        if 'search_after' in body:
            docs = [d for d in docs if (key(d) < body['search_after'] if reverse else key(d) > body['search_after'])]
        hits = [{'_source': copy.deepcopy(d), 'sort': key(d)} for d in docs[:body.get('size', 10)]]
        if body.get('_source'):
            for hit in hits:
                hit['_source'] = {k: hit['_source'].get(k) for k in body['_source']['includes']}
        return {'timed_out': False, '_shards': {'total': 1, 'successful': 1, 'failed': 0},
                'hits': {'hits': hits, 'total': {'value': len(docs), 'relation': 'eq'}}}
    def count(self, index, body, **kw):
        result = self.search(index, {**body, 'size': 0}, allow_partial_search_results=False, **kw)
        return {'count': result.get('hits', {}).get('total', {}).get('value', 0), **{k: v for k, v in result.items() if k in ('_shards', 'timed_out')}}


@pytest.fixture
def osenv():
    from saw.storage.generations import GenerationRef, GenerationStore
    client, heads = Client(), {}
    backend = SimpleNamespace(client=client, prefix='sawtest', alias='sawtest-events')
    store = GenerationStore(backend, resolve=lambda inv, generation_id=None: heads.get(inv),
                            check_read=lambda ref: None, open_raw=lambda b, k: io.BytesIO(b'raw'),
                            cursor_key=b'x' * 32)
    ref = GenerationRef('inv', 'g1', 0, '', store.plan_targets('inv', 'g1'), False)
    kw = {'job_id': 'j', 'attempt': 1, 'input_sha256': 'a' * 64, 'check': lambda: None}
    return store, client, heads, ref, kw


def test_target_ownership_and_alias_isolation(osenv):
    from saw.storage.generations import GenerationConflict, GenerationSealed, GenerationUnavailable
    store, client, heads, ref, kw = osenv
    assert ref.storage_targets[0].startswith('sawtestg-')
    store.create_target(ref, **kw)
    store.create_target(ref, **kw)
    with pytest.raises(GenerationConflict): store.begin_write(ref, **{**kw, 'attempt': 2})
    writer = store.begin_write(ref, **kw)
    assert writer.index([event(), event()]) == 2
    writer.seal()
    manifest = writer.verify(expected_files=expected([event()]), check=lambda: None)
    ref = replace(ref, output_sha256=manifest['output_sha256'], head_revision=1)
    heads['inv'] = ref
    view = store.open_view('inv')
    assert view.get('inv', 'e000000') == event()
    assert view.count('inv') == 1
    with pytest.raises(GenerationSealed): store.begin_write(ref, **kw)
    client.targets[ref.storage_targets[0]]['aliases']['sawtest-events'] = {}
    with pytest.raises(GenerationUnavailable): view.count('inv')


def test_partial_result_and_uncertain_write_are_never_verified(osenv):
    from saw.storage.generations import GenerationUnavailable, GenerationVerificationError
    store, client, _, ref, kw = osenv
    store.create_target(ref, **kw)
    writer = store.begin_write(ref, **kw)
    writer.index([event()])
    writer.seal()
    client.partial = True
    with pytest.raises(GenerationUnavailable): writer.verify(expected_files=expected([event()]), check=lambda: None)
    client.partial = False
    ref2 = replace(ref, generation_id='g2', storage_targets=store.plan_targets('inv', 'g2'))
    store.create_target(ref2, **kw)
    writer2 = store.begin_write(ref2, **kw)
    client.fail_bulk = True
    with pytest.raises(GenerationUnavailable): writer2.index([event()])
    client.fail_bulk = False
    writer2.seal()
    with pytest.raises(GenerationVerificationError): store.verify(ref2, expected_files=[], check=lambda: None)


def test_bounded_bulk_transport(osenv):
    store, client, _, ref, kw = osenv
    store.create_target(ref, **kw)
    writer = store.begin_write(ref, **kw)
    assert writer.index(event(n, payload='x' * 3000) for n in range(6001)) == 6001
    assert len(client.bulk_sizes) >= 2
    assert all(rows <= 5000 and size <= 10 * 1024 * 1024 for rows, size in client.bulk_sizes)


def test_interrupted_write_marker_survives_process_loss(osenv):
    from saw.storage.generations import GenerationUnavailable, GenerationVerificationError
    store, client, _, ref, kw = osenv
    store.create_target(ref, **kw)
    writer = store.begin_write(ref, **kw)
    # The backend accepted bytes, but the process died before the acknowledgement was handled.
    bulk = client.bulk
    def interrupted(**args):
        bulk(**args)
        raise KeyboardInterrupt('synthetic process loss')
    client.bulk = interrupted
    with pytest.raises(KeyboardInterrupt): writer.index([event()])
    client.bulk = bulk
    writer.seal()
    with pytest.raises((GenerationVerificationError, GenerationUnavailable)):
        store.verify(ref, expected_files=expected([event()]), check=lambda: None)


def test_changed_durability_is_not_admitted(osenv):
    from saw.storage.generations import GenerationUnavailable
    store, client, _, ref, kw = osenv
    store.create_target(ref, **kw)
    client.targets[ref.storage_targets[0]]['settings']['translog']['durability'] = 'async'
    with pytest.raises(GenerationUnavailable): store.begin_write(ref, **kw)


@pytest.mark.parametrize('count', [1, 3])
def test_opensearch_buffered_identity_is_frozen_from_canonical_bytes(osenv, count):
    store, _, _, ref, kw = osenv
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
    # EventStore.get uses a source query; verify transport identity through the exact index too.
    for row in rows:
        assert store.adapter.client.get(index=ref.storage_targets[0], id=row['event_id'])['_source'] == row


def test_all_eight_reads_pin_one_generation(osenv):
    from saw.core.schemas.query import AggRequest
    from saw.storage.generations import GenerationUnavailable
    store, client, heads, ref, kw = osenv
    store.create_target(ref, **kw)
    writer = store.begin_write(ref, **kw)
    writer.index([event(), event(1)])
    writer.seal()
    receipt = writer.verify(expected_files=expected([event(), event(1)]), check=lambda: None)
    heads['inv'] = replace(ref, output_sha256=receipt['output_sha256'], head_revision=1)
    view = store.open_view('inv')
    ref2 = replace(ref, generation_id='g2', storage_targets=store.plan_targets('inv', 'g2'))
    store.create_target(ref2, **kw)
    writer2 = store.begin_write(ref2, **kw)
    writer2.index([event(payload='new generation')])
    writer2.seal()
    receipt2 = writer2.verify(expected_files=expected([event(payload='new generation')]), check=lambda: None)
    heads['inv'] = replace(ref2, output_sha256=receipt2['output_sha256'], head_revision=2)
    reads = [lambda: view.get('inv', 'e000000'), lambda: view.search('inv', []),
             lambda: list(view.iterate('inv', [], batch=1)), lambda: view.count('inv'),
             lambda: view.aggregate('inv', [], AggRequest(type='count')),
             lambda: view.group_by('inv', [], ['data_source'], []),
             lambda: view.histogram_metrics('inv', [], None, []), lambda: view.time_bounds('inv')]
    assert reads[0]() == event()
    assert len(reads[1]() ['events']) == 2
    assert len(reads[2]()) == 2
    assert reads[3]() == 2
    assert reads[4]() == {'value': 2}
    assert reads[5]()[0]['count'] == 2
    assert reads[6]()['buckets'][0]['count'] == 2
    assert reads[7]() == ('2026-01-01T00:00:00Z',) * 2
    assert store.open_view('inv').count('inv') == 1
    client.partial = True
    for read in reads:
        with pytest.raises(GenerationUnavailable): read()


@pytest.mark.parametrize('sort', ['asc', 'desc'])
def test_missing_timestamp_and_tie_cursor_projection(osenv, sort):
    store, _, heads, ref, kw = osenv
    rows = [event(n) for n in range(5)]
    rows[0].pop('timestamp')
    rows[1]['timestamp'] = None
    store.create_target(ref, **kw)
    writer = store.begin_write(ref, **kw)
    writer.index(rows)
    writer.seal()
    manifest = writer.verify(expected_files=expected(rows), check=lambda: None)
    heads['inv'] = replace(ref, output_sha256=manifest['output_sha256'], head_revision=1)
    view = store.open_view('inv')
    result, cursor = [], None
    while True:
        page = view.search('inv', [], sort=sort, limit=2, fields=['event_id'], cursor=cursor)
        result.extend(page['events'])
        cursor = page['next_cursor']
        if not cursor: break
    order = [2, 3, 4, 0, 1] if sort == 'asc' else [4, 3, 2, 1, 0]
    assert result == [{'event_id': f'e{n:06d}'} for n in order]


@pytest.mark.skipif(not os.environ.get('SAW_TEST_OPENSEARCH_URL'), reason='dedicated native OpenSearch URL absent; root owns native harness')
def test_native_generation_isolation(tmp_path):
    import uuid

    from saw.storage.generations import GenerationRef, GenerationSealed, GenerationStore
    from saw.storage.opensearch_store import OpenSearchEventStore
    backend = OpenSearchEventStore(os.environ['SAW_TEST_OPENSEARCH_URL'], ensure=False, prefix='sawtest' + uuid.uuid4().hex)
    store = GenerationStore(backend, resolve=lambda inv, generation_id=None: None, check_read=lambda ref: None,
                            open_raw=lambda b, k: io.BytesIO(b'raw'), cursor_key=b'n' * 32)
    ref = GenerationRef('synthetic', 'g1', 0, '', store.plan_targets('synthetic', 'g1'), False)
    kw = {'job_id': 'native-job', 'attempt': 1, 'input_sha256': 'a' * 64, 'check': lambda: None}
    store.create_target(ref, **kw)
    writer = store.begin_write(ref, **kw)
    writer.index([event(inv='synthetic')])
    writer.seal()
    assert writer.verify(expected_files=expected([event(inv='synthetic')]), check=lambda: None)['unique_count'] == 1
    with pytest.raises(GenerationSealed): store.begin_write(ref, **kw)
    target = backend.client.indices.get(index=ref.storage_targets[0])[ref.storage_targets[0]]
    assert not target['aliases']
    assert target['settings']['index']['blocks']['write'] == 'true'


def test_legacy_pit_serializes_boolean_using_real_client():
    from opensearchpy import OpenSearch

    from saw.storage.opensearch_generations import OpenSearchGenerations

    client = OpenSearch(hosts=["http://127.0.0.1:1"])
    captured = []

    def request(method, path, **kwargs):
        captured.append((method, path, kwargs))
        if path.endswith("/_refresh"):
            assert kwargs["params"]["ignore_unavailable"] == b"false"
            assert kwargs["params"]["allow_no_indices"] == b"false"
            return {"_shards": {"total": 1, "successful": 1, "failed": 0}}
        if path.endswith("/point_in_time"):
            assert kwargs["params"]["allow_partial_pit_creation"] == b"false"
            return {"pit_id": "synthetic-pit", "_shards": {"total": 1, "successful": 1, "failed": 0}}
        assert path == "/_search"
        assert kwargs["params"] == {"allow_partial_search_results": b"false"}
        assert kwargs["body"]["pit"] == {"id": "synthetic-pit"}
        return {"hits": {"total": {"value": 2, "relation": "eq"}},
                "_shards": {"total": 1, "successful": 1, "failed": 0}}

    client.transport.perform_request = request
    backend = SimpleNamespace(client=client, prefix="sawtest", alias="sawtest-events", _dirty=True)
    reader = OpenSearchGenerations(backend).legacy_reader()
    assert reader.client.pit == "synthetic-pit"
    assert captured[0][1] == "/sawtest-events/_refresh"
    assert captured[1][1] == "/sawtest-events/_search/point_in_time"
    assert backend._dirty is False
    assert reader.count("inv") == 2
