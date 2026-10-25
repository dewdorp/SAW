"""Immutable event snapshots. SQL-head resolution and authorization belong to the caller."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time as clock
import uuid
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from typing import BinaryIO, Protocol, TypedDict

from saw.core.schemas.query import AggRequest, Filter, GroupMetric, TimeRange

FORMAT = 'saw-event-generation/1'
MAX_EVENTS = 5000
MAX_BYTES = 10 * 1024 * 1024


class GenerationUnavailable(RuntimeError): pass
class GenerationConflict(RuntimeError): pass
class GenerationSealed(RuntimeError): pass
class GenerationVerificationError(RuntimeError): pass
class InvalidGenerationCursor(ValueError): pass


@dataclass(frozen=True)
class GenerationRef:
    investigation_id: str
    generation_id: str | None
    head_revision: int
    output_sha256: str
    storage_targets: tuple[str, ...]
    legacy: bool

    def __post_init__(self):
        if not self.investigation_id or type(self.storage_targets) is not tuple:
            raise ValueError('invalid generation reference')
        if self.legacy:
            if self.generation_id is not None:
                raise ValueError('invalid legacy reference')
        elif not self.generation_id or not self.storage_targets or not all(self.storage_targets):
            raise ValueError('generation requires exact targets')


class RawObject(TypedDict):
    bucket: str
    key: str
    byte_length: int
    sha256: str
    owner_generation_id: str | None
    owner_attempt: int | None
    retained: bool


class ExpectedFile(TypedDict):
    evidence_id: str
    file_id: str
    replacement: bool
    unique_count: int
    events_sha256: str
    source_closure: dict
    parse_status: str
    quality: dict
    coverage: dict
    raw_objects: list[RawObject]


class EventReadPort(Protocol):
    @property
    def ref(self) -> GenerationRef: ...
    def get(self, investigation_id: str, event_id: str) -> dict | None: ...
    def search(self, investigation_id: str, filters: list[Filter], time: TimeRange | None = None,
               sort: str = 'asc', limit: int = 100, cursor: str | None = None,
               fields: list[str] | None = None) -> dict: ...
    def iterate(self, investigation_id: str, filters: list[Filter], time: TimeRange | None = None,
                fields: list[str] | None = None, batch: int = 5000) -> Iterator[dict]: ...
    def count(self, investigation_id: str, filters: list[Filter] | None = None,
              time: TimeRange | None = None) -> int: ...
    def aggregate(self, investigation_id: str, filters: list[Filter], agg: AggRequest,
                  time: TimeRange | None = None) -> dict: ...
    def group_by(self, investigation_id: str, filters: list[Filter], fields: list[str],
                 metrics: list[GroupMetric], size: int = 100, time: TimeRange | None = None,
                 order_by: str | None = None) -> list[dict]: ...
    def histogram_metrics(self, investigation_id: str, filters: list[Filter], interval_sec: int | None,
                          metrics: list[GroupMetric], time: TimeRange | None = None,
                          split_field: str | None = None) -> dict: ...
    def time_bounds(self, investigation_id: str, filters: list[Filter] | None = None) -> tuple: ...
    def close(self) -> None: ...


def canonical_event_bytes(event: dict) -> bytes:
    def validate(value):
        if isinstance(value, dict):
            if not all(isinstance(k, str) for k in value):
                raise ValueError('canonical object keys must be strings')
            for v in value.values(): validate(v)
        elif isinstance(value, list):
            for v in value: validate(v)
        elif value is not None and type(value) not in (str, int, float, bool):
            raise ValueError('unsupported canonical value')
    if not isinstance(event, dict):
        raise TypeError('event must be an object')
    validate(event)
    return json.dumps(event, sort_keys=True, ensure_ascii=False, allow_nan=False,
                      separators=(',', ':')).encode('utf-8')


def _feed(hasher, payload):
    hasher.update(len(payload).to_bytes(8, 'big'))
    hasher.update(payload)


def _source_value(event, field):
    """CES dotted paths traverse dictionaries only; literal dotted keys cannot shadow context."""
    value = event
    if not isinstance(field, str) or not field:
        raise GenerationVerificationError('invalid source closure field')
    for part in field.split('.'):
        if not part or not isinstance(value, dict) or part not in value:
            raise GenerationVerificationError('missing source closure field')
        value = value[part]
    return value


def event_stream_sha256(events: Iterable[dict]) -> str:
    """Hash an ascending event_id stream; producers must sort independently, on disk if needed."""
    h, last = hashlib.sha256(), None
    for event in events:
        key = event['event_id']
        if not isinstance(key, str) or (last is not None and key <= last):
            raise ValueError('event stream must have unique ascending IDs')
        _feed(h, canonical_event_bytes(event))
        last = key
    return h.hexdigest()


class GenerationStore:
    def __init__(self, backend, *, resolve: Callable, check_read: Callable,
                 open_raw: Callable[[str, str], BinaryIO], cursor_key: bytes,
                 data_dir=None, namespace=None, cursor_ttl=900):
        from saw.storage.eventstore import SQLiteEventStore
        if not isinstance(cursor_key, bytes) or len(cursor_key) < 32:
            raise ValueError('installation cursor key must contain at least 32 bytes')
        if isinstance(backend, SQLiteEventStore):
            from saw.storage.sqlite_generations import SQLiteGenerations
            self.adapter = SQLiteGenerations(backend, data_dir, namespace)
        else:
            from saw.storage.opensearch_generations import OpenSearchGenerations
            self.adapter = OpenSearchGenerations(backend, namespace)
        self.resolve, self.check_read, self.open_raw = resolve, check_read, open_raw
        self._cursor_key, self.cursor_ttl = cursor_key, cursor_ttl
        self._snapshots = {}
        self._snapshot_cursors = set()

    def plan_targets(self, investigation_id, generation_id):
        if not investigation_id or not generation_id:
            raise ValueError('generation identity required')
        return self.adapter.plan_targets(investigation_id, generation_id)

    def _validate(self, ref):
        if not isinstance(ref, GenerationRef) or ref.legacy or ref.storage_targets != self.plan_targets(
                ref.investigation_id, ref.generation_id):
            raise GenerationUnavailable('invalid exact target closure')

    def _owner(self, ref, job_id, attempt, input_sha256):
        self._validate(ref)
        if not job_id or type(attempt) is not int or attempt < 1 or not input_sha256:
            raise GenerationConflict('invalid target ownership')
        return {'format': FORMAT, 'investigation_id': ref.investigation_id, 'generation_id': ref.generation_id,
                    'job_id': job_id, 'attempt': attempt, 'input_sha256': input_sha256}

    def create_target(self, ref, *, job_id, attempt, input_sha256, check):
        owner = self._owner(ref, job_id, attempt, input_sha256)
        check()
        self.adapter.create(ref, owner)
        check()

    def begin_write(self, ref, *, job_id, attempt, input_sha256, check):
        owner = self._owner(ref, job_id, attempt, input_sha256)
        check()
        self.adapter.admit(ref, owner)
        check()
        return GenerationWriter(self, ref, owner, check)

    def _readable(self, ref):
        self._validate(ref)
        metadata = self.adapter.metadata(ref)
        manifest = metadata.get('manifest') or {}
        if (not isinstance(manifest, dict) or not isinstance(metadata.get('owner'), dict)
                or metadata.get('sealed') is not True or metadata.get('failed') or not ref.output_sha256
                or manifest.get('output_sha256') != ref.output_sha256
                or manifest.get('storage_targets') != list(ref.storage_targets)
                or metadata['owner'].get('investigation_id') != ref.investigation_id
                or metadata['owner'].get('generation_id') != ref.generation_id):
            raise GenerationUnavailable('generation is not durably verified')

    def open_view(self, investigation_id, *, ref=None):
        if not investigation_id:
            raise ValueError('investigation_id is mandatory')
        if ref is None:
            ref = self.resolve(investigation_id, generation_id=None)
            if ref is None:
                ref = GenerationRef(investigation_id, None, 0, '', (), True)
                self.check_read(ref)
                self._expire_snapshots()
                if len(self._snapshots) >= 128:
                    raise GenerationUnavailable('legacy snapshot capacity exhausted')
                handle = uuid.uuid4().hex
                reader = self.adapter.legacy_reader()
                self._snapshots[handle] = (clock.time() + self.cursor_ttl, reader, ref)
                return _View(self, ref, reader, handle)
        if not isinstance(ref, GenerationRef) or ref.legacy or ref.investigation_id != investigation_id:
            raise GenerationUnavailable('invalid trusted generation reference')
        self.check_read(ref)
        self._readable(ref)
        return _View(self, ref, self.adapter.reader(ref))

    def _expire_snapshots(self):
        for handle, (expires, reader, _) in list(self._snapshots.items()):
            if expires <= clock.time():
                reader.close()
                del self._snapshots[handle]
                self._snapshot_cursors.discard(handle)

    def _query(self, filters, time, sort, limit, fields):
        if sort not in ('asc', 'desc') or type(limit) is not int or not 1 <= limit <= MAX_EVENTS:
            raise ValueError('invalid bounded search')
        q = {'filters': [f.model_dump(mode='json') for f in filters],
                 'time': time.model_dump(mode='json') if time else None, 'sort': sort, 'limit': limit, 'fields': fields}
        return hashlib.sha256(canonical_event_bytes(q)).hexdigest()

    def _encode(self, data):
        payload = canonical_event_bytes(data)
        return base64.urlsafe_b64encode(payload + hmac.digest(self._cursor_key, payload, 'sha256')).decode()

    def _decode(self, cursor):
        try:
            if not isinstance(cursor, str) or len(cursor) > 16384:
                raise ValueError()
            data = base64.b64decode(cursor, altchars=b'-_', validate=True)
            payload, sig = data[:-32], data[-32:]
            if not hmac.compare_digest(sig, hmac.digest(self._cursor_key, payload, 'sha256')):
                raise ValueError()
            value = json.loads(payload)
            if value['v'] != 1 or value['expires'] <= clock.time():
                raise ValueError()
            return value
        except (ValueError, KeyError, TypeError):
            raise InvalidGenerationCursor('invalid or expired generation cursor') from None

    def resume_view(self, investigation_id, cursor, *, filters, time=None, sort='asc', limit=100, fields=None):
        data = self._decode(cursor)
        if data['inv'] != investigation_id or data['query'] != self._query(filters, time, sort, limit, fields):
            raise InvalidGenerationCursor('cursor query mismatch')
        if data['legacy']:
            self._expire_snapshots()
            snapshot = self._snapshots.get(data['snapshot'])
            if snapshot is None:
                raise InvalidGenerationCursor('legacy snapshot is unavailable')
            _, reader, ref = snapshot
            self.check_read(ref)
            view = _View(self, ref, reader, data['snapshot'])
        else:
            try:
                ref = self.resolve(investigation_id, generation_id=data['generation'])
            except (KeyError, LookupError) as exc:
                raise InvalidGenerationCursor('retained generation unavailable') from exc
            if ref is None:
                raise InvalidGenerationCursor('retained generation unavailable')
            view = self.open_view(investigation_id, ref=ref)
        view._cursor(data, data['query'])
        return view

    def verify(self, ref, *, expected_files, check):
        self._validate(ref)
        check()
        metadata = self.adapter.metadata(ref)
        owner = metadata.get('owner')
        if (not isinstance(owner, dict) or owner.get('investigation_id') != ref.investigation_id
                or owner.get('generation_id') != ref.generation_id or owner.get('format') != FORMAT):
            raise GenerationUnavailable('generation owner identity mismatch')
        if not metadata.get('sealed') or metadata.get('failed'):
            raise GenerationVerificationError('target must be sealed without rejected or uncertain writes')
        checkpoint_error = None
        def checkpoint():
            nonlocal checkpoint_error
            try:
                check()
            except Exception as exc:
                checkpoint_error = exc
                raise
        try:
            manifest = self._verify(ref, expected_files, metadata, checkpoint)
        except (ValueError, KeyError, TypeError, OSError) as exc:
            if exc is checkpoint_error:
                raise
            raise GenerationVerificationError('generation verification failed') from exc
        check()
        self.adapter.receipt(ref, manifest)
        check()
        return manifest

    def _verify(self, ref, expected_files, metadata, check):
        files = json.loads(canonical_event_bytes({'files': expected_files}))['files']
        seen_files, objects, mapping, states = set(), {}, {}, []
        for f in files:
            if (set(f) != set(ExpectedFile.__annotations__) or not isinstance(f['quality'], dict)
                    or not isinstance(f['coverage'], dict) or not isinstance(f['source_closure'], dict)
                    or type(f['replacement']) is not bool or not isinstance(f['raw_objects'], list)
                    or not isinstance(f['parse_status'], str) or not f['evidence_id'] or not f['file_id']):
                raise GenerationVerificationError('invalid expected file descriptor')
            identity = (f['evidence_id'], f['file_id'])
            if identity in seen_files or type(f['unique_count']) is not int or f['unique_count'] < 0:
                raise GenerationVerificationError('invalid expected file closure')
            seen_files.add(identity)
            if f['replacement'] and (f['unique_count'] == 0 or f['parse_status'] not in ('done', 'degraded', 'partial')):
                raise GenerationVerificationError('replacement has no successful output')
            states.append([0, hashlib.sha256()])
            for raw in f['raw_objects']:
                if set(raw) != set(RawObject.__annotations__) or type(raw['retained']) is not bool:
                    raise GenerationVerificationError('invalid raw object descriptor')
                identity = (raw['bucket'], raw['key'])
                if (not all(isinstance(x, str) and x for x in identity) or type(raw['byte_length']) is not int
                        or raw['byte_length'] < 0 or (not raw['retained'] and
                        (raw['owner_generation_id'] != ref.generation_id or raw['owner_attempt'] != metadata['owner']['attempt']))):
                    raise GenerationVerificationError('invalid raw object ownership')
                if identity in objects and objects[identity] != raw:
                    raise GenerationVerificationError('conflicting raw descriptor')
                objects[identity] = raw
                key = (f['evidence_id'], raw['bucket'] + '/' + raw['key'])
                if key in mapping:
                    raise GenerationVerificationError('ambiguous file mapping')
                mapping[key] = (len(states) - 1, raw)
        raw_bytes = 0
        for raw in objects.values():
            check()
            length, h = 0, hashlib.sha256()
            with self.open_raw(raw['bucket'], raw['key']) as stream:
                while True:
                    check()
                    chunk = stream.read(1024 * 1024)
                    if not chunk: break
                    length += len(chunk)
                    h.update(chunk)
                    check()
            if length != raw['byte_length'] or h.hexdigest() != raw['sha256']:
                raise GenerationVerificationError('raw object byte closure mismatch')
            raw_bytes += length
            check()
        count, h, last = 0, hashlib.sha256(), None
        for page in self.adapter.pages(ref, check):
            check()
            for event in page:
                eid = event.get('event_id')
                if not isinstance(eid, str) or not eid or (last is not None and eid <= last):
                    raise GenerationVerificationError('duplicate or unordered event identity')
                if event.get('investigation_id') != ref.investigation_id:
                    raise GenerationVerificationError('foreign investigation')
                rawref = event.get('raw_ref')
                if not isinstance(rawref, dict):
                    raise GenerationVerificationError('missing raw reference')
                rawkey = rawref.get('object_key')
                if rawref.get('bucket') and isinstance(rawkey, str) and not rawkey.startswith(rawref['bucket'] + '/'):
                    rawkey = rawref['bucket'] + '/' + rawkey
                item = mapping.get((event.get('evidence_id'), rawkey))
                if item is None:
                    raise GenerationVerificationError('event outside expected file closure')
                index, raw = item
                offset, length = rawref.get('offset'), rawref.get('length')
                if (type(offset) is not int or type(length) is not int or offset < 0 or length < 0
                        or offset + length > raw['byte_length'] or
                        ('bucket' in rawref and rawref['bucket'] != raw['bucket'])):
                    raise GenerationVerificationError('invalid raw byte range')
                f = files[index]
                if event.get('file_id', f['file_id']) != f['file_id']:
                    raise GenerationVerificationError('foreign file')
                for field, allowed in f['source_closure'].items():
                    if _source_value(event, field) not in (allowed if isinstance(allowed, list) else [allowed]):
                        raise GenerationVerificationError('source closure mismatch')
                payload = canonical_event_bytes(event)
                _feed(h, payload)
                _feed(states[index][1], payload)
                states[index][0] += 1
                count += 1
                last = eid
            check()
        for f, (actual, fh) in zip(files, states, strict=True):
            if actual != f['unique_count'] or fh.hexdigest() != f['events_sha256']:
                raise GenerationVerificationError('per-file count or canonical hash mismatch')
        if sum(f['unique_count'] for f in files) != count:
            raise GenerationVerificationError('overall file closure mismatch')
        result = {'format': FORMAT, 'investigation_id': ref.investigation_id, 'generation_id': ref.generation_id,
                      'storage_targets': list(ref.storage_targets), 'input_sha256': metadata['owner']['input_sha256'],
                      'unique_count': count, 'output_sha256': h.hexdigest(), 'files': files,
                      'raw_objects': list(objects.values()), 'coverage_totals': {'events': count, 'objects': len(objects),
                                                                          'byte_length': raw_bytes},
                      'rejected': 0, 'sealed': True, 'complete': True}
        if ref.output_sha256 and ref.output_sha256 != result['output_sha256']:
            raise GenerationVerificationError('trusted digest mismatch')
        return result


class GenerationWriter:
    def __init__(self, store, ref, owner, check):
        self.store, self.ref, self.owner, self.check = store, ref, owner, check
        self.last_errors, self.rejected = [], 0

    def index(self, events):
        self.last_errors = []
        self.check()
        self.store.adapter.admit(self.ref, self.owner)
        total, batch, size = 0, [], 0
        try:
            for event in events:
                if event.get('investigation_id') != self.ref.investigation_id or not isinstance(
                        event.get('event_id'), str) or not event['event_id']:
                    raise ValueError('event requires matching investigation and nonempty ID')
                data = canonical_event_bytes(event)
                # Producers may reuse/mutate their dictionary when the iterator advances.
                # Derive both backend identity/columns and payload from this admitted value.
                event = json.loads(data)
                cost = len(data) + len(canonical_event_bytes({'create': {
                    '_index': self.ref.storage_targets[0], '_id': event['event_id']}})) + 2
                if cost > MAX_BYTES:
                    raise ValueError('event exceeds bounded write size')
                if batch and (len(batch) == MAX_EVENTS or size + cost > MAX_BYTES):
                    total += self._batch(batch)
                    batch, size = [], 0
                batch.append((event, data))
                size += cost
            if batch: total += self._batch(batch)
            self.check()
            return total
        except Exception as exc:
            self.rejected += 1
            self.last_errors = [{'reason': type(exc).__name__}]
            self.store.adapter.fail(self.ref, self.owner)
            raise

    def _batch(self, batch):
        self.check()
        self.store.adapter.write(self.ref, self.owner, batch)
        self.check()
        return len(batch)

    def seal(self):
        self.check()
        self.store.adapter.seal(self.ref, self.owner)
        self.check()

    def verify(self, *, expected_files, check):
        return self.store.verify(self.ref, expected_files=expected_files, check=check)


class _View:
    def __init__(self, store, ref, reader, snapshot=None):
        self._store, self._ref, self._reader, self._snapshot = store, ref, reader, snapshot
        self._closed = False

    @property
    def ref(self): return self._ref

    def _check(self, inv):
        if not inv or inv != self.ref.investigation_id:
            raise ValueError('view investigation mismatch')
        if self._closed:
            raise GenerationUnavailable('view is closed')
        self._store.check_read(self.ref)
        if self.ref.legacy:
            self._store._expire_snapshots()
            if self._snapshot not in self._store._snapshots:
                raise GenerationUnavailable('legacy snapshot expired')
        else:
            self._store._readable(self.ref)

    def _cursor(self, data, query):
        if (data['inv'] != self.ref.investigation_id or data['generation'] != self.ref.generation_id
                or data['revision'] != self.ref.head_revision or data['hash'] != self.ref.output_sha256
                or data['legacy'] != self.ref.legacy or data['snapshot'] != self._snapshot or data['query'] != query):
            raise InvalidGenerationCursor('cursor view mismatch')
        return data['last']

    def search(self, investigation_id, filters, time=None, sort='asc', limit=100, cursor=None, fields=None):
        self._check(investigation_id)
        query = self._store._query(filters, time, sort, limit, fields)
        last = self._cursor(self._store._decode(cursor), query) if cursor else None
        page = self._reader.search(investigation_id, filters, time, sort, limit, last, fields)
        if page['next_cursor']:
            if self.ref.legacy:
                self._store._snapshot_cursors.add(self._snapshot)
            expires = (self._store._snapshots[self._snapshot][0] if self.ref.legacy
                       else clock.time() + self._store.cursor_ttl)
            page['next_cursor'] = self._store._encode({'v': 1, 'inv': investigation_id,
                'generation': self.ref.generation_id, 'revision': self.ref.head_revision, 'hash': self.ref.output_sha256,
                'legacy': self.ref.legacy, 'snapshot': self._snapshot, 'query': query, 'last': page['next_cursor'], 'expires': expires})
        return page

    def iterate(self, investigation_id, filters, time=None, fields=None, batch=5000):
        cursor = None
        while True:
            page = self.search(investigation_id, filters, time, 'asc', batch, cursor, fields)
            yield from page['events']
            cursor = page['next_cursor']
            if not cursor: return

    def get(self, investigation_id, event_id):
        self._check(investigation_id)
        return self._reader.get(investigation_id, event_id)

    def count(self, investigation_id, filters=None, time=None):
        self._check(investigation_id)
        return self._reader.count(investigation_id, filters, time)

    def aggregate(self, investigation_id, filters, agg, time=None):
        self._check(investigation_id)
        return self._reader.aggregate(investigation_id, filters, agg, time)

    def group_by(self, investigation_id, filters, fields, metrics, size=100, time=None, order_by=None):
        self._check(investigation_id)
        return self._reader.group_by(investigation_id, filters, fields, metrics, size, time, order_by)

    def histogram_metrics(self, investigation_id, filters, interval_sec, metrics, time=None, split_field=None):
        self._check(investigation_id)
        return self._reader.histogram_metrics(investigation_id, filters, interval_sec, metrics, time, split_field)

    def time_bounds(self, investigation_id, filters=None):
        self._check(investigation_id)
        return self._reader.time_bounds(investigation_id, filters)

    def close(self):
        if not self._closed:
            if not self.ref.legacy:
                self._reader.close()
            elif self._snapshot not in self._store._snapshot_cursors:
                self._reader.close()
                self._store._snapshots.pop(self._snapshot, None)
        self._closed = True

    def __enter__(self): return self
    def __exit__(self, *args): self.close()
