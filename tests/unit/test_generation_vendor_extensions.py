"""Native vendor JSON compatibility with typed producer statistics and exact snapshots."""
import io
import os
import re
import uuid
from dataclasses import replace

import pytest

from saw.core.schemas.query import AggRequest, Filter, GroupMetric
from saw.parsers.registry import parse_text
from saw.storage.generations import (
    GenerationRef,
    GenerationStore,
    GenerationUnavailable,
    canonical_event_bytes,
)
from saw.storage.opensearch_store import OpenSearchEventStore, index_template
from tests.unit.test_event_generation_writers import digest, event, expected
from tests.unit.test_security_csv import NDR, document
from tests.unit.test_security_csv import row as security_row


def test_extension_template_preserves_known_typed_namespaces():
    from saw.parsers.registry import builtin_parsers
    mappings = index_template()['template']['mappings']
    known = {p.product for p in builtin_parsers()} | {
        'observation', 'saw_observation', 'device_observation', 'connector', 'fw', 'ips', 'vpn'}
    properties = mappings['properties'].get('ext', {}).get('properties', {})
    assert known <= properties.keys()
    assert all(properties[name]['type'] == 'object' for name in known)


def test_extension_template_only_flattens_unknown_namespace_objects():
    mappings = index_template()['template']['mappings']
    templates = [next(iter(t.values())) for t in mappings['dynamic_templates']]
    flat = next((t for t in templates if t['mapping']['type'] == 'flat_object'), None)
    assert flat is not None, 'unknown vendor objects need an explicit type, not mixed leaf inference'
    assert flat['match_mapping_type'] == 'object' and flat['match_pattern'] == 'regex'
    assert re.fullmatch(flat['path_match'], 'ext.vendor_web')
    assert not re.fullmatch(flat['path_match'], 'ext.observation.counters')
    assert not re.fullmatch(flat['path_match'], 'another.vendor_web')
    custom = next(t for t in templates if t['mapping']['type'] == 'object')
    assert re.fullmatch(custom['path_match'], 'ext.u_custom_parser')
    assert templates.index(custom) < templates.index(flat)


@pytest.mark.skipif(not os.environ.get('SAW_TEST_OPENSEARCH_URL'), reason='dedicated native OpenSearch URL absent')
@pytest.mark.parametrize("combined_first", [False, True])
def test_native_mixed_vendor_roundtrip_queries_and_typed_retained_statistics(combined_first):
    backend = OpenSearchEventStore(os.environ['SAW_TEST_OPENSEARCH_URL'], prefix='sawtest' + uuid.uuid4().hex)
    heads = {}
    store = GenerationStore(backend, resolve=lambda inv, generation_id=None: heads.get(inv),
                            check_read=lambda ref: None, open_raw=lambda bucket, key: io.BytesIO(b'raw'),
                            cursor_key=b'v' * 32)
    source_only = parse_text(document([*NDR, "source_columns"],
                                     security_row(source_columns="source-only")))["events"][0]["ext"]["security_csv"]
    combined = parse_text(document([*NDR, "source_columns", "csv_format"],
                                  security_row(source_columns="combined",
                                               csv_format="recorded-source-format")))["events"][0]["ext"]["security_csv"]
    security_extensions = [combined, source_only] if combined_first else [source_only, combined]
    rows = [event(n, ext={
        'security_csv': security_extensions[n],
        'vendor_web': {'custom_fact': ['retained' if n == 0 else 'other', 7 + n],
                       'nested': {'unchanged': [None, True, 1.25]}},
        'observation': {'context': {'network': 'corp', 'resolved': True}, 'duration_seconds': 10 + n},
        'device_observation': {'metrics': {'bytes': 100 + n}},
        'saw_observation': {'timestamp_precision': 'seconds'},
        'zeek': {'duration': 4000 + n}, 'u_custom_parser': {'counter': 20 + n},
    }) for n in range(2)]
    def publish(name, docs):
        ref = GenerationRef('inv', name, 0, '', store.plan_targets('inv', name), False)
        args = {'job_id': name, 'attempt': 1, 'input_sha256': 'a' * 64, 'check': lambda: None}
        store.create_target(ref, **args)
        writer = store.begin_write(ref, **args)
        assert writer.index(docs) == len(docs)
        writer.seal()
        receipt = writer.verify(expected_files=expected(docs), check=lambda: None)
        assert receipt['output_sha256'] == digest(docs)
        heads['inv'] = replace(ref, output_sha256=receipt['output_sha256'], head_revision=1)
        return ref
    old_ref = publish('vendor-old', rows)
    old = store.open_view('inv')
    assert [canonical_event_bytes(e) for e in old.iterate('inv', [])] == [canonical_event_bytes(e) for e in rows]
    for value in ('retained', 7):
        assert old.count('inv', [Filter(field='ext.vendor_web.custom_fact', value=value)]) == 1
    assert old.count('inv', [Filter(field='ext.vendor_web', value='retained')]) == 1
    assert old.count('inv', [Filter(field='ext.security_csv.csv_format', value='ndr')]) == 2
    assert old.aggregate('inv', [], AggRequest(type='terms', field='ext.security_csv.csv_format'))['buckets'] == [
        {'key': 'ndr', 'count': 2}]
    for n in range(2):
        original = old.get('inv', rows[n]['event_id'])['ext']['security_csv']
        assert original['그룹명'] == '가상그룹'
        assert original['장비IP'] == '192.0.2.10'
        assert original['source_columns'] == security_extensions[n]['source_columns']
    scoped = [Filter(field='ext.observation.context.network', value='corp')]
    assert old.aggregate('inv', scoped, AggRequest(type='stats', field='ext.observation.duration_seconds'))['avg'] == 10.5
    assert old.aggregate('inv', scoped, AggRequest(type='stats', field='ext.device_observation.metrics.bytes'))['sum'] == 201
    assert old.aggregate('inv', scoped, AggRequest(type='stats', field='ext.u_custom_parser.counter'))['sum'] == 41
    assert old.count('inv', [Filter(field='ext.zeek.duration', op='range', value={'gte': 4001})]) == 1
    grouped = old.group_by('inv', scoped, ['ext.observation.context.network'], [
        GroupMetric(type='sum', field='ext.device_observation.metrics.bytes', name='bytes'),
        GroupMetric(type='min_ts', name='first', preserve_timestamp=True)])
    assert grouped[0]['bytes'] == 201 and grouped[0]['first'] == rows[0]['timestamp']
    assert sum(b['count'] for b in old.histogram_metrics('inv', scoped, 3600, [])['buckets']) == 2
    mapping = backend.client.indices.get_mapping(index=old_ref.storage_targets[0])[old_ref.storage_targets[0]]['mappings']
    fields = mapping['properties']
    security_mapping = fields['ext']['properties']['security_csv']
    assert security_mapping.get('type', 'object') == 'object'
    assert isinstance(security_mapping.get('properties'), dict)
    assert security_mapping['properties']['csv_format']['type'] == 'keyword'
    source_mapping = security_mapping['properties']['source_columns']
    assert source_mapping.get('type', 'object') == 'object'
    assert isinstance(source_mapping.get('properties'), dict)
    assert security_mapping['properties']['장비IP']['type'] == 'keyword'
    assert fields['ext']['properties']['vendor_web']['type'] == 'flat_object'
    assert fields['timestamp']['type'] == 'date'
    assert fields['ext']['properties']['observation']['properties']['duration_seconds']['type'] == 'long'
    assert fields['ext']['properties']['device_observation']['properties']['metrics']['properties']['bytes']['type'] == 'long'
    replacement = [event(ext={'vendor_web': {'custom_fact': ['replacement', 9]}})]
    publish('vendor-new', replacement)
    with store.open_view('inv') as current:
        assert current.get('inv', rows[0]['event_id']) == replacement[0]
    assert old.get('inv', rows[0]['event_id']) == rows[0]
    assert backend.client.indices.get_mapping(index=old_ref.storage_targets[0])[old_ref.storage_targets[0]]['mappings'] == mapping
    with pytest.raises(GenerationUnavailable):
        publish('malformed-rejected', [event(bytes_out='not-a-number')])
    assert old.count('inv') == 2
    old.close()
