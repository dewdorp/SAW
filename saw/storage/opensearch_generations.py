"""Exact OpenSearch generation indices, durable block fencing and strict read responses."""
from __future__ import annotations

import copy
import hashlib
import re
import threading
import uuid
from weakref import WeakValueDictionary

from saw.storage.eventstore import decode_cursor, encode_cursor
from saw.storage.generations import (
    MAX_BYTES,
    MAX_EVENTS,
    GenerationConflict,
    GenerationSealed,
    GenerationUnavailable,
    canonical_event_bytes,
)
from saw.storage.opensearch_store import OpenSearchEventStore, filters_to_dsl, index_template

STRICT = {'ignore_unavailable': False, 'allow_no_indices': False, 'expand_wildcards': 'none'}
FAILURE_FIELD = '_saw_generation_failed'
_LOCKS = WeakValueDictionary()
_LOCKS_GUARD = threading.Lock()


def _lock(target):
    with _LOCKS_GUARD:
        lock = _LOCKS.get(target)
        if lock is None:
            lock = threading.RLock()
            _LOCKS[target] = lock
        return lock


def _complete(result):
    shards = result.get('_shards')
    if (result.get('timed_out') or result.get('terminated_early') or not shards
            or shards.get('failed', 0) or shards.get('successful', 0) + shards.get('skipped', 0) < shards.get('total', 0)):
        raise GenerationUnavailable('incomplete OpenSearch result')
    return result


def _ack(result):
    if result.get('acknowledged') is not True or result.get('shards_acknowledged', True) is not True:
        raise GenerationUnavailable('OpenSearch mutation not acknowledged')


class _StrictClient:
    def __init__(self, client, target=None, pit=None):
        self.client, self.target, self.pit = client, target, pit

    def search(self, *, index=None, body):
        body = copy.deepcopy(body)
        kwargs = {'allow_partial_search_results': False}
        if self.pit:
            # PIT binds its own exact shard closure; OpenSearch rejects index options here.
            body['pit'] = {'id': self.pit}
        else:
            kwargs.update(STRICT, index=self.target)
        try:
            return _complete(self.client.search(body=body, **kwargs))
        except GenerationUnavailable: raise
        except Exception as exc:
            raise GenerationUnavailable('OpenSearch target unavailable') from exc

    def count(self, *, index=None, body):
        if self.pit:
            result = self.search(body={**body, 'size': 0, 'track_total_hits': True})
            total = result['hits']['total']
            if total['relation'] != 'eq':
                raise GenerationUnavailable('inexact snapshot count')
            return {'count': total['value']}
        try:
            return _complete(self.client.count(index=self.target, body=body, **STRICT))
        except GenerationUnavailable: raise
        except Exception as exc:
            raise GenerationUnavailable('OpenSearch target unavailable') from exc


class _Reader(OpenSearchEventStore):
    def __init__(self, client, target=None, pit=None):
        self.client = _StrictClient(client, target, pit)
        self.alias = target

    def _fresh(self): pass

    def search(self, investigation_id, filters, time=None, sort='asc', limit=100, cursor=None, fields=None):
        body = {'query': filters_to_dsl(investigation_id, filters, time), 'size': limit,
                'sort': [{'timestamp': {'order': sort, 'missing': '_last'}}, {'event_id': sort}]}
        if fields: body['_source'] = {'includes': list(fields)}
        if cursor: body['search_after'] = decode_cursor(cursor)
        hits = self.client.search(body=body)['hits']['hits']
        return {'events': [hit['_source'] for hit in hits],
                'next_cursor': encode_cursor(hits[-1]['sort']) if len(hits) == limit else None}

    def close(self):
        if self.client.pit:
            self.client.client.delete_pit(body={'pit_id': [self.client.pit]})


class OpenSearchGenerations:
    def __init__(self, legacy, namespace=None):
        self.legacy, self.client = legacy, legacy.client
        self.prefix = namespace or legacy.prefix
        if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,100}', self.prefix):
            raise ValueError('invalid installation index namespace')

    def plan_targets(self, inv, generation):
        digest = hashlib.sha256(canonical_event_bytes({'namespace': self.prefix,
                                                          'investigation_id': inv, 'generation_id': generation})).hexdigest()
        return (f'{self.prefix}g-{digest}',)

    def _state(self, ref):
        target = ref.storage_targets[0]
        try:
            response = self.client.indices.get(index=target, **STRICT)
            if set(response) != {target} or response[target].get('aliases'):
                raise GenerationUnavailable('generation target closure or alias mismatch')
            state = response[target]
            settings = state['settings']
            index_settings = settings.get('index', settings)
            durability = index_settings.get('translog', settings.get('translog', {})).get('durability')
            if durability != 'request':
                raise GenerationUnavailable('generation requires request durability')
            metadata = copy.deepcopy(state['mappings']['_meta']['saw_generation'])
            if not isinstance(metadata.get('owner'), dict):
                raise GenerationUnavailable('generation has no owner')
            blocked = str(state['settings'].get('index', {}).get('blocks', {}).get('write', False)).lower() == 'true'
            metadata['blocked'] = blocked
            metadata['failed'] = FAILURE_FIELD in state['mappings'].get('properties', {}) or bool(metadata.get('pending'))
            if metadata.get('sealed') and not blocked:
                raise GenerationUnavailable('sealed generation lost write block')
            return metadata
        except GenerationUnavailable: raise
        except Exception as exc:
            raise GenerationUnavailable('missing or corrupt generation target') from exc

    def metadata(self, ref): return self._state(ref)

    def _owner(self, ref, owner, unsealed=False):
        metadata = self._state(ref)
        if metadata['owner'] != owner:
            raise GenerationConflict('generation target ownership conflict')
        if unsealed and (metadata.get('sealed') or metadata.get('blocked')):
            raise GenerationSealed('generation is fenced or sealed')
        if unsealed and metadata.get('pending'):
            raise GenerationUnavailable('prior write outcome is uncertain; allocate a new generation')
        return metadata

    def _save(self, ref, metadata):
        # The failure field is a permanent mapping addition, separate from replaceable _meta.
        metadata = {k: v for k, v in metadata.items() if k not in ('blocked', 'failed')}
        _ack(self.client.indices.put_mapping(index=ref.storage_targets[0],
                 body={'_meta': {'saw_generation': metadata}}))

    def create(self, ref, owner):
        target = ref.storage_targets[0]
        if self.client.indices.exists(index=target):
            self._owner(ref, owner)
            return
        template = copy.deepcopy(index_template(self.prefix, durability='request')['template'])
        template.pop('aliases', None)
        # Reject malformed mapped values rather than silently dropping fields from indexing.
        template['settings']['mapping']['ignore_malformed'] = False
        template['mappings']['_meta'] = {'saw_generation': {'owner': owner, 'sealed': False, 'manifest': None}}
        try:
            _ack(self.client.indices.create(index=target, body=template))
        except Exception:
            # Race-safe identical-owner retry, never adopt an unowned index.
            self._owner(ref, owner)
            raise
        self._owner(ref, owner)

    def admit(self, ref, owner): self._owner(ref, owner, True)

    def write(self, ref, owner, batch):
        with _lock(ref.storage_targets[0]):
            self._write(ref, owner, batch)

    def _write(self, ref, owner, batch):
        metadata = self._owner(ref, owner, True)
        token = uuid.uuid4().hex
        metadata['pending'] = token
        metadata['max_event_bytes'] = max(metadata.get('max_event_bytes', 1), max(len(data) for _, data in batch))
        self._save(ref, metadata)
        if self._state(ref).get('pending') != token:
            raise GenerationUnavailable('writer admission changed')
        target = ref.storage_targets[0]
        body = b''.join(canonical_event_bytes({'create': {'_index': target, '_id': event['event_id']}})
                        + b'\n' + data + b'\n' for event, data in batch)
        try:
            result = self.client.bulk(body=body, refresh=False, wait_for_active_shards='all')
            items = result.get('items', [])
            if len(items) != len(batch):
                raise GenerationUnavailable('incomplete bulk acknowledgement')
            for item, (event, data) in zip(items, batch, strict=True):
                outcome = item.get('create', {})
                if outcome.get('_id') != event['event_id']:
                    raise GenerationUnavailable('bulk identity mismatch')
                if outcome.get('status') == 409:
                    old = self.client.get(index=target, id=event['event_id'], realtime=True)
                    if not old.get('found') or canonical_event_bytes(old['_source']) != data:
                        raise GenerationConflict('same event ID has different canonical payload')
                elif outcome.get('status') not in (200, 201):
                    raise GenerationUnavailable('bulk write rejected')
            metadata = self._owner(ref, owner)
            if metadata.get('pending') != token or metadata.get('sealed') or metadata.get('blocked'):
                raise GenerationUnavailable('writer admission changed during bulk')
            metadata['pending'] = None
            self._save(ref, metadata)
        except (GenerationConflict, GenerationUnavailable): raise
        except Exception as exc:
            raise GenerationUnavailable('uncertain OpenSearch write') from exc

    def fail(self, ref, owner):
        self._owner(ref, owner)
        # Mapping fields cannot be removed by later mapping merges. A successful later write,
        # stale seal metadata update, or restarted process cannot erase this rejection marker.
        _ack(self.client.indices.put_mapping(index=ref.storage_targets[0],
             body={'properties': {FAILURE_FIELD: {'type': 'boolean', 'index': False}}}))

    def seal(self, ref, owner):
        with _lock(ref.storage_targets[0]):
            self._seal(ref, owner)

    def _seal(self, ref, owner):
        metadata = self._owner(ref, owner)
        target = ref.storage_targets[0]
        # Blocks API acknowledges shard fences after in-flight writes drain; put_settings alone
        # does not supply that barrier. Never clear a block after partial or crashed sealing.
        result = self.client.transport.perform_request('PUT', f'/{target}/_block/write', params={key: str(value).lower() if isinstance(value, bool) else value for key, value in STRICT.items()})
        _ack(result)
        rows = result.get('indices', [])
        if len(rows) != 1 or rows[0].get('name') != target or rows[0].get('blocked') is not True:
            raise GenerationUnavailable('write block closure not acknowledged')
        _complete(self.client.indices.refresh(index=target, **STRICT))
        _complete(self.client.indices.flush(index=target, force=True, wait_if_ongoing=True, **STRICT))
        metadata = self._owner(ref, owner)
        if not metadata.get('blocked'):
            raise GenerationUnavailable('durable write block missing')
        metadata['sealed'] = True
        self._save(ref, metadata)
        self._owner(ref, owner)

    def receipt(self, ref, manifest):
        metadata = self._state(ref)
        if not metadata.get('sealed') or metadata.get('failed'):
            raise GenerationUnavailable('generation changed during verification')
        if metadata.get('manifest') is not None and metadata['manifest'] != manifest:
            raise GenerationConflict('verified manifest is immutable')
        metadata['manifest'] = manifest
        self._save(ref, metadata)
        if self._state(ref).get('failed'):
            raise GenerationUnavailable('generation rejected during verification')

    def reader(self, ref): return _Reader(self.client, ref.storage_targets[0])

    def legacy_reader(self):
        try:
            if getattr(self.legacy, '_dirty', False):
                _complete(self.client.indices.refresh(index=self.legacy.alias, **STRICT))
                self.legacy._dirty = False
            result = _complete(self.client.create_pit(index=self.legacy.alias,
                keep_alive='15m', allow_partial_pit_creation=False, expand_wildcards='none'))
            return _Reader(self.client, pit=result['pit_id'])
        except GenerationUnavailable: raise
        except Exception as exc:
            raise GenerationUnavailable('legacy snapshot unavailable') from exc

    def pages(self, ref, check):
        client = _StrictClient(self.client, ref.storage_targets[0])
        maximum = self._state(ref).get('max_event_bytes', MAX_BYTES)
        page_size = max(1, min(MAX_EVENTS, MAX_BYTES // maximum))
        last = None
        while True:
            check()
            body = {'query': {'match_all': {}}, 'sort': [{'event_id': 'asc'}], 'size': page_size}
            if last is not None: body['search_after'] = last
            hits = client.search(body=body)['hits']['hits']
            check()
            if not hits: return
            yield [hit['_source'] for hit in hits]
            last = hits[-1]['sort']
