"""Private SQLite generation files with transactional, persistent mutation guards."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from contextlib import contextmanager
from pathlib import Path

from saw.storage.eventstore import SQLiteEventStore, _FirstTimestamp, _LastTimestamp, ts_epoch
from saw.storage.generations import (
    MAX_BYTES,
    MAX_EVENTS,
    GenerationConflict,
    GenerationSealed,
    GenerationUnavailable,
    canonical_event_bytes,
)


class _Reader(SQLiteEventStore):
    def __init__(self, connection, path=None):
        self.connection, self.path = connection, path
        connection.create_aggregate('first_timestamp', 2, _FirstTimestamp)
        connection.create_aggregate('last_timestamp', 2, _LastTimestamp)

    def _conn(self):
        if self.path is not None and not self.path.is_file():
            raise GenerationUnavailable('generation target disappeared')
        return self.connection

    def search(self, investigation_id, filters, time=None, sort='asc', limit=100, cursor=None, fields=None):
        page = super().search(investigation_id, filters, time, sort, limit, cursor)
        if fields:
            page['events'] = [{k: e.get(k) for k in fields} for e in page['events']]
        return page

    def close(self): self.connection.close()


class SQLiteGenerations:
    def __init__(self, legacy, data_dir=None, namespace=None):
        self.legacy = legacy
        if data_dir is None:
            if legacy.path == ':memory:' or legacy.path.startswith('file:'):
                raise ValueError('in-memory legacy backend requires explicit generation data_dir')
            data_dir = Path(legacy.path).resolve().parent
        self.root = Path(data_dir).resolve() / 'event-generations'
        self.namespace = namespace or str(self.root)

    def plan_targets(self, inv, generation):
        digest = hashlib.sha256(canonical_event_bytes({'namespace': self.namespace,
                                                          'investigation_id': inv, 'generation_id': generation})).hexdigest()
        return (str(self.root / f'g-{digest}.sqlite3'),)

    @contextmanager
    def _connection(self, ref, write=False):
        path = Path(ref.storage_targets[0])
        try:
            c = sqlite3.connect(path.as_uri() + ('?mode=rw' if write else '?mode=ro'),
                                uri=True, timeout=60, check_same_thread=False)
        except sqlite3.Error as exc:
            raise GenerationUnavailable('generation target unavailable') from exc
        try:
            if write:
                c.execute('PRAGMA synchronous=FULL')
                c.execute('BEGIN IMMEDIATE')
            yield c
            if write: c.commit()
        except Exception:
            if write: c.rollback()
            raise
        finally:
            c.close()

    def _metadata(self, c):
        try:
            row = c.execute('SELECT doc FROM generation_metadata WHERE singleton=1').fetchone()
            if row is None: raise ValueError('missing owner')
            metadata = json.loads(row[0])
            if not isinstance(metadata, dict):
                raise TypeError('generation metadata must be an object')
            return metadata
        except (sqlite3.Error, ValueError, TypeError) as exc:
            raise GenerationUnavailable('missing or corrupt generation metadata') from exc

    def _save(self, c, metadata):
        c.execute('UPDATE generation_metadata SET doc=? WHERE singleton=1',
                  (canonical_event_bytes(metadata).decode(),))

    def metadata(self, ref):
        with self._connection(ref) as c:
            metadata = self._metadata(c)
            metadata['failed'] = bool(metadata.get('failed') or metadata.get('pending'))
            return metadata

    def _owner(self, c, owner, unsealed=False):
        metadata = self._metadata(c)
        if metadata.get('owner') != owner:
            raise GenerationConflict('target ownership conflict')
        if unsealed and metadata.get('sealed'):
            raise GenerationSealed('generation is sealed')
        if unsealed and metadata.get('pending'):
            raise GenerationUnavailable('prior write outcome is uncertain; allocate a new generation')
        return metadata

    def create(self, ref, owner):
        path = Path(ref.storage_targets[0])
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with path.open('xb'): pass
        except FileExistsError:
            with self._connection(ref) as c:
                self._owner(c, owner)
            return
        # A crash leaves an unowned file that cannot be silently adopted or truncated.
        with self._connection(ref, True) as c:
            c.execute('CREATE TABLE events(event_id TEXT PRIMARY KEY, investigation_id TEXT NOT NULL, '
                      'evidence_id TEXT, data_source TEXT, ts TEXT, ts_epoch REAL, doc TEXT NOT NULL)')
            c.execute('CREATE INDEX ix_ev_inv_ts ON events(investigation_id, ts_epoch, event_id)')
            c.execute('CREATE INDEX ix_ev_evidence ON events(investigation_id, evidence_id)')
            c.execute('CREATE TABLE generation_metadata(singleton INTEGER PRIMARY KEY CHECK(singleton=1), doc TEXT NOT NULL)')
            c.execute('INSERT INTO generation_metadata VALUES(1,?)',
                      (canonical_event_bytes({'owner': owner, 'sealed': False, 'failed': False, 'manifest': None}).decode(),))
            for operation in ('INSERT', 'UPDATE', 'DELETE'):
                c.execute(f"CREATE TRIGGER sealed_{operation.lower()} BEFORE {operation} ON events "
                          "WHEN COALESCE((SELECT json_extract(doc, '$.sealed') FROM generation_metadata WHERE singleton=1),1) "
                          "BEGIN SELECT RAISE(ABORT,'generation sealed'); END")
            c.execute("CREATE TRIGGER no_unseal BEFORE UPDATE ON generation_metadata "
                      "WHEN json_extract(OLD.doc,'$.sealed')=1 AND json_extract(NEW.doc,'$.sealed') IS NOT 1 "
                      "BEGIN SELECT RAISE(ABORT,'generation sealed'); END")
            c.execute("CREATE TRIGGER keep_owner BEFORE DELETE ON generation_metadata "
                      "BEGIN SELECT RAISE(ABORT,'generation owner immutable'); END")

    def admit(self, ref, owner):
        with self._connection(ref) as c:
            self._owner(c, owner, True)

    def write(self, ref, owner, batch):
        token = uuid.uuid4().hex
        with self._connection(ref, True) as c:
            metadata = self._owner(c, owner, True)
            metadata['pending'] = token
            self._save(c, metadata)
        # Persist uncertainty in a separate FULL synchronous transaction before any events.
        # Process loss after the event commit must leave the token for recovery to reject.
        with self._connection(ref, True) as c:
            metadata = self._owner(c, owner)
            if metadata.get('sealed'):
                raise GenerationSealed('generation is sealed')
            if metadata.get('pending') != token:
                raise GenerationUnavailable('writer admission changed')
            metadata['max_event_bytes'] = max(metadata.get('max_event_bytes', 1), max(len(data) for _, data in batch))
            self._save(c, metadata)
            for event, data in batch:
                old = c.execute('SELECT doc FROM events WHERE event_id=?', (event['event_id'],)).fetchone()
                if old:
                    if old[0].encode() != data:
                        raise GenerationConflict('same event ID has different canonical payload')
                    continue
                c.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?)',
                          (event['event_id'], event['investigation_id'], event.get('evidence_id'),
                           event.get('data_source'), event.get('timestamp'), ts_epoch(event.get('timestamp')), data.decode()))
        # The event transaction has returned its durable commit acknowledgement. Only this
        # token owner can clear uncertainty, and a concurrent seal cannot be undone.
        with self._connection(ref, True) as c:
            metadata = self._owner(c, owner)
            if metadata.get('sealed'):
                raise GenerationSealed('generation is sealed')
            if metadata.get('pending') != token:
                raise GenerationUnavailable('writer admission changed')
            metadata['pending'] = None
            self._save(c, metadata)

    def fail(self, ref, owner):
        with self._connection(ref, True) as c:
            metadata = self._owner(c, owner)
            metadata['failed'] = True
            self._save(c, metadata)

    def seal(self, ref, owner):
        with self._connection(ref, True) as c:
            metadata = self._owner(c, owner)
            metadata['sealed'] = True
            self._save(c, metadata)
        # FULL synchronous commits plus closed handles make a rollback-journal file durable.
        # Checkpoint existing WAL too, including a target recovered after an interrupted process.
        with self._connection(ref) as c:
            mode = c.execute('PRAGMA journal_mode').fetchone()[0]
        if mode == 'wal':
            path = Path(ref.storage_targets[0])
            c = sqlite3.connect(path.as_uri() + '?mode=rw', uri=True)
            try:
                if c.execute('PRAGMA wal_checkpoint(FULL)').fetchone()[0]:
                    raise GenerationUnavailable('generation WAL checkpoint incomplete')
            finally: c.close()

    def receipt(self, ref, manifest):
        with self._connection(ref, True) as c:
            metadata = self._metadata(c)
            if not metadata.get('sealed') or metadata.get('failed') or metadata.get('pending'):
                raise GenerationUnavailable('generation changed during verification')
            if metadata.get('manifest') is not None and metadata['manifest'] != manifest:
                raise GenerationConflict('verified manifest is immutable')
            metadata['manifest'] = manifest
            self._save(c, metadata)

    def reader(self, ref):
        path = Path(ref.storage_targets[0])
        try:
            c = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, check_same_thread=False)
        except sqlite3.Error as exc:
            raise GenerationUnavailable('generation target unavailable') from exc
        return _Reader(c, path)

    def legacy_reader(self):
        # Establish a read transaction before returning. Head publication and subsequent
        # legacy WAL writes cannot change this view; cursor expiry bounds snapshot retention.
        if self.legacy.path == ':memory:':
            c = sqlite3.connect('', check_same_thread=False)
            self.legacy._conn().backup(c, pages=128)
        else:
            uri = self.legacy.path if self.legacy._uri else Path(self.legacy.path).resolve().as_uri() + '?mode=ro'
            c = sqlite3.connect(uri, uri=True, check_same_thread=False)
        c.execute('PRAGMA query_only=ON')
        c.execute('BEGIN')
        c.execute('SELECT event_id FROM events LIMIT 1').fetchone()
        return _Reader(c)

    def pages(self, ref, check):
        with self._connection(ref) as c:
            maximum = self._metadata(c).get('max_event_bytes', MAX_BYTES)
            page_size = max(1, min(MAX_EVENTS, MAX_BYTES // maximum))
            last = ''
            while True:
                check()
                rows = c.execute('SELECT event_id,doc FROM events WHERE event_id>? ORDER BY event_id LIMIT ?',
                                 (last, page_size)).fetchall()
                check()
                if not rows: return
                yield [json.loads(row[1]) for row in rows]
                last = rows[-1][0]
