"""Bounded producer-side full snapshots; external I/O never holds a lifecycle SQL lock."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path

from sqlalchemy import select

from saw.event_generations import service
from saw.event_generations.models import EventGeneration
from saw.parsers.connector import ConnectorEnvelopeParser, connector_implementation_pin
from saw.storage.generations import (
    GenerationConflict,
    GenerationVerificationError,
    canonical_event_bytes,
    event_stream_sha256,
)
from saw.storage.models import Job


class EventSpool:
    """Disk-backed independent expected stream, sorted by ID, with conflict detection."""
    def __init__(self, root):
        self.directory = tempfile.TemporaryDirectory(prefix='saw-generation-', dir=str(root))
        self.db = sqlite3.connect(str(Path(self.directory.name) / 'expected.sqlite'))
        self.db.execute('PRAGMA cache_size=-2048')
        self.db.execute('CREATE TABLE events (id TEXT PRIMARY KEY, evidence TEXT, file TEXT, payload BLOB)')
        self.db.execute('CREATE INDEX file_stream ON events (evidence,file,id)')

    def add(self, identity, event):
        payload = canonical_event_bytes(event)
        if len(payload) > 10 * 1024 * 1024:
            raise GenerationVerificationError('producer_event_too_large')
        previous = self.db.execute('SELECT evidence,file,payload FROM events WHERE id=?', (event['event_id'],)).fetchone()
        if previous:
            if previous != (*identity, payload):
                raise GenerationVerificationError('producer_conflicting_event_id')
            return False
        self.db.execute('INSERT INTO events VALUES (?,?,?,?)', (event['event_id'], *identity, payload))
        return True

    def events(self, identity=None, *, check=None):
        query, params = 'SELECT payload FROM events', ()
        if identity is not None:
            query += ' WHERE evidence=? AND file=?'
            params = identity
        for index, (payload,) in enumerate(self.db.execute(query + ' ORDER BY id', params)):
            if check is not None and index % 500 == 0:
                check()
            yield json.loads(payload)
        if check is not None:
            check()

    def stats(self, identity, *, check=None):
        count = 0
        def counted():
            nonlocal count
            for event in self.events(identity, check=check):
                count += 1
                yield event
        return_hash = event_stream_sha256(counted())
        return count, return_hash

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.db.close()
        self.directory.cleanup()


class SpoolSink:
    def __init__(self, producer, identity):
        self.producer, self.identity = producer, identity
        self.last_errors = []

    def check(self):
        self.producer.check()

    def index(self, events):
        self.check()
        for event in events:
            self.producer.spool.add(self.identity, event)
        self.check()
        return len(events)


@contextmanager
def transaction(c):
    with c.session_factory() as s, s.begin():
        yield s


class Producer:
    def __init__(self, c, job_id, attempt, *, baseline=False):
        self.c, self.job_id, self.attempt, self.baseline = c, job_id, attempt, baseline
        with transaction(c) as s:
            job = s.get(Job, job_id)
            self.reprocess = job.kind == 'reprocess'
            self.connector_reservation = deepcopy((job.stages or {}).get('_connector_import'))
            self.ref = service.allocate(s, job, attempt=attempt, store=c.generations, baseline=baseline)
            row = s.get(EventGeneration, self.ref.generation_id)
            self.input = deepcopy(row.input_manifest)
            self.input_sha256 = row.input_sha256
            self.raw = deepcopy(row.raw_objects)
            self.parent = deepcopy(s.get(EventGeneration, row.parent_id).output_manifest) if row.parent_id else None
        self.files = {(ev['id'], f['id']): (ev, f) for ev in self.input['source']['evidence'] for f in ev['files']}
        self.replaced = {(r['evidence_id'], r['file_id']): r for r in self.input['replacements']}
        self.descriptors, self.results = {}, []
        self.legacy_transfers = set()
        self.spool = EventSpool(c.settings.data_dir)
        self.closed = False

    def check(self):
        from saw.workers.pipeline import Cancelled, StaleLease
        if self.input.get("runtime_pins") is not None:
            from saw.integrations.pcap import verify_runtime_pins
            verify_runtime_pins(self.input["runtime_pins"])
        with transaction(self.c) as s:
            job = s.get(Job, self.job_id)
            if job is None or job.attempt != self.attempt:
                raise StaleLease("generation lease superseded")
            if job.cancel_requested:
                raise Cancelled()
            if (job.stages or {}).get('_connector_import') != self.connector_reservation:
                raise GenerationConflict('producer_connector_reservation_changed')
            service.check_writer(s, self.ref, job_id=self.job_id, attempt=self.attempt)

    def progress(self, *, parsed=False):
        """Reprocess phase facts only; index completion belongs to publication."""
        if self.baseline or not self.reprocess:
            return
        self.check()
        with transaction(self.c) as s:
            job = s.get(Job, self.job_id)
            if job.kind != 'reprocess':
                return
            service.lock_investigation(s, self.ref.investigation_id)
            service.check_writer(s, self.ref, job_id=self.job_id, attempt=self.attempt)
            stages = dict(job.stages or {})
            stages['parse'] = {**stages.get('parse', {}), 'pct': 100 if parsed else 0, 'done': parsed}
            stages['index'] = {**stages.get('index', {}), 'pct': 0, 'done': False}
            job.stages = stages
            job.state = 'INDEXING' if parsed else 'PARSING'

    def original(self, f):
        return next(deepcopy(r) for r in self.raw if (r['bucket'], r['key']) == (f['object_bucket'], f['object_key']))

    def descriptor(self, identity, *, replacement=False):
        _, f = self.files[identity]
        closure = service.expected_source_closure(self.input, *identity, replacement=not self.baseline)
        if not self.baseline:
            from saw.observation.connection import connection_observation
            snapshot = ((self.replaced.get(identity) or {}).get('source_context') or {}).get('snapshot')
            context = connection_observation({}, context_snapshot=snapshot)['context']
            for key, value in context.items():
                closure['ext.observation.context.' + key] = value
        return {'evidence_id': identity[0], 'file_id': identity[1], 'replacement': replacement,
                'unique_count': 0, 'events_sha256': hashlib.sha256().hexdigest(),
                'source_closure': closure,
                'parse_status': f['parse_status'], 'quality': {},
                'coverage': next((deepcopy(x['coverage']) for x in f['error_samples'] or [] if 'coverage' in x), {}),
                'raw_objects': [self.original(f)]}

    def raw_object(self, identity, path, suffix):
        self.check()
        length, digest = 0, hashlib.sha256()
        with open(path, 'rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                self.check()
                length += len(chunk)
                digest.update(chunk)
        key = f'generations/{self.ref.generation_id}/{self.attempt}/{identity[0]}/{identity[1]}/{suffix}'
        raw = {'bucket': 'saw-artifacts', 'key': key, 'byte_length': length, 'sha256': digest.hexdigest(),
               'owner_generation_id': self.ref.generation_id, 'owner_attempt': self.attempt, 'retained': False}
        with transaction(self.c) as s:
            service.register_raw_objects(s, self.ref, [raw], job_id=self.job_id, attempt=self.attempt)
        self.check()
        with open(path, 'rb') as stream:
            actual = self.c.objects.put_stream(raw['bucket'], key, stream)
        if tuple(actual) != (length, raw['sha256']):
            raise GenerationVerificationError('producer_raw_write_mismatch')
        self.descriptors[identity]['raw_objects'].append(raw)
        self.raw.append(raw)
        self.check()
        return raw

    def legacy_transfer(self, identity, event):
        """Only a captured PCAP's normalized extracted-file event can nominate a content-addressed blob."""
        import re
        detail = (event.get('ext') or {}).get('zeek') or {}
        if event.get('data_source') != 'zeek_files' or detail.get('extracted') is not True:
            return
        sha = detail.get('sha256')
        if not isinstance(sha, str) or re.fullmatch('[0-9a-f]{64}', sha) is None:
            raise GenerationVerificationError('producer_legacy_transfer_unavailable')
        key = f'{self.ref.investigation_id}/extracted-files/{sha}'
        if (identity[0], key) in self.legacy_transfers:
            return
        length, digest = 0, hashlib.sha256()
        with self.c.objects.open('saw-artifacts', key) as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                self.check()
                length += len(chunk)
                digest.update(chunk)
        if digest.hexdigest() != sha:
            raise GenerationVerificationError('producer_legacy_transfer_fingerprint_mismatch')
        raw = {'bucket': 'saw-artifacts', 'key': key, 'byte_length': length, 'sha256': sha,
               'owner_generation_id': None, 'owner_attempt': None, 'retained': True}
        with transaction(self.c) as s:
            service.register_legacy_objects(s, self.ref, [raw], job_id=self.job_id, attempt=self.attempt,
                                            source_file=identity)
        self.descriptors[identity]['raw_objects'].append(raw)
        self.legacy_transfers.add((identity[0], key))

    def copy(self, view):
        mapping = {}
        reserved_sources = set((self.connector_reservation or {}).get('sources', []))
        reserved_connector = (self.connector_reservation or {}).get('connector_id')
        if self.parent:
            for value in self.parent['files']:
                identity = value['evidence_id'], value['file_id']
                if not self.baseline and identity in self.replaced:
                    continue
                descriptor = deepcopy(value)
                descriptor['replacement'] = False
                descriptor['raw_objects'] = [{**r, 'retained': True} for r in descriptor['raw_objects']]
                self.descriptors[identity] = descriptor
                for raw in descriptor['raw_objects']:
                    mapping[(identity[0], raw['bucket'] + '/' + raw['key'])] = identity
        else:
            for identity, (_, f) in self.files.items():
                if f['object_key'] and f['sha256']:
                    mapping[(identity[0], f['object_bucket'] + '/' + f['object_key'])] = identity
                if f['events_parsed'] > 0:
                    self.descriptors[identity] = self.descriptor(identity)
        for index, event in enumerate(view.iterate(self.ref.investigation_id, [], batch=5000)):
            if index % 500 == 0:
                self.check()
            connector = (event.get('ext') or {}).get('connector') or {}
            if reserved_sources and connector.get('id') == reserved_connector:
                source_key = hashlib.sha256(canonical_event_bytes({
                    'connector': reserved_connector, 'source': connector.get('source_event_id')})).hexdigest()
                if source_key in reserved_sources:
                    raise GenerationConflict('producer_connector_source_already_retained')
            rawkey = (event.get('raw_ref') or {}).get('object_key', '')
            identity = mapping.get((event.get('evidence_id'), rawkey))
            if identity is None and self.baseline and rawkey.startswith('saw-artifacts/'):
                key = rawkey.partition('/')[2]
                candidates = [ident for ident, (_, f) in self.files.items()
                              if f['type_detected'] in ('pcap', 'pcapng') and
                              key.startswith(f'{self.ref.investigation_id}/{ident[0]}/{ident[1]}/')]
                if len(candidates) == 1:
                    identity = candidates[0]
                    path = self.c.objects.local_path('saw-artifacts', key)
                    digest = hashlib.sha256()
                    length = 0
                    with open(path, 'rb') as stream:
                        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                            self.check()
                            digest.update(chunk)
                            length += len(chunk)
                    raw = {'bucket': 'saw-artifacts', 'key': key, 'byte_length': length,
                           'sha256': digest.hexdigest(), 'owner_generation_id': None,
                           'owner_attempt': None, 'retained': True}
                    with transaction(self.c) as s:
                        service.register_legacy_objects(s, self.ref, [raw], job_id=self.job_id, attempt=self.attempt)
                    self.descriptors.setdefault(identity, self.descriptor(identity))['raw_objects'].append(raw)
                    mapping[(identity[0], rawkey)] = identity
            if identity is None:
                # Replaced parent streams are deliberately excluded by their trusted raw mapping.
                if self.parent and any(event.get('evidence_id') == v['evidence_id'] and
                    any(rawkey == r['bucket'] + '/' + r['key'] for r in v['raw_objects'])
                    for v in self.parent['files'] if (v['evidence_id'], v['file_id']) in self.replaced):
                    continue
                raise GenerationVerificationError('producer_unknown_legacy_source')
            if not self.baseline and identity in self.replaced:
                continue
            self.descriptors.setdefault(identity, self.descriptor(identity))
            if self.baseline and self.files[identity][1]['type_detected'] in ('pcap', 'pcapng'):
                self.legacy_transfer(identity, event)
            self.spool.add(identity, event)
        self.check()

    def parse(self):
        import time

        from saw.parsers.registry import get_parser
        from saw.storage.db import utcnow
        from saw.workers.pipeline import FileJob, _parse_file
        for identity, selected in self.replaced.items():
            self.check()
            ev, f = self.files[identity]
            pinned = selected['parser']
            descriptor = self.descriptor(identity, replacement=self.input['job_kind'] == 'reprocess')
            self.descriptors[identity] = descriptor
            context = (selected.get('source_context') or {}).get('snapshot')
            raw = self.original(f)
            digest, length = hashlib.sha256(), 0
            with self.c.objects.open(raw['bucket'], raw['key']) as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    self.check()
                    length += len(chunk)
                    digest.update(chunk)
            if (length, digest.hexdigest()) != (raw['byte_length'], raw['sha256']):
                raise GenerationVerificationError('producer_input_fingerprint_mismatch')
            started = utcnow().isoformat()
            if pinned is None:
                status = f['parse_status'] if f['parse_status'] in ('waiting_input', 'skipped', 'failed') else 'failed'
                result = {'coverage': {}, 'samples': [], 'failed': f['events_failed'], 'first_ts': None,
                          'last_ts': None, 'settings': {}, 'message': f['message'], 'status': status}
            elif pinned['id'] == 'pcap':
                from saw.integrations.pcap import produce_generation
                result = produce_generation(self, identity, ev, f, context)
            else:
                if pinned['spec'] is not None:
                    from saw.parsers.custom import DefinedParser, ParserSpec
                    slug = pinned['id'][2:].split('@')[0]
                    parser = DefinedParser(slug, int(pinned['version']), ParserSpec.model_validate(pinned['spec']), pid=pinned['id'])
                else:
                    if ev['kind'] == 'connector' and pinned['id'] == 'json_lines':
                        concrete = connector_implementation_pin()
                        if not concrete['digest'] or any(pinned.get(key) != value for key, value in concrete.items()):
                            raise GenerationConflict('generation_connector_parser_changed')
                        parser = ConnectorEnvelopeParser()
                    else:
                        if pinned.get('implementation') is not None:
                            raise GenerationConflict('generation_parser_implementation_invalid')
                        parser = get_parser(pinned['id'])
                job = FileJob(self.job_id, f['id'], f['object_bucket'], f['object_key'], f['display_name'],
                              self.ref.investigation_id, ev['id'], ev['tz_assumed'], 0, 1, time.time())
                result = _parse_file(self.c, job, parser, self.c.objects.local_path(f['object_bucket'], f['object_key']),
                                     0, {}, sink=SpoolSink(self, identity), context_snapshot=context)
                ok, failed = result['ok'], result['failed']
                result['status'] = 'degraded' if ok and failed / max(1, ok + failed) > .05 else ('done' if ok else 'failed')
                result['message'] = ' · '.join(result['warnings'] if ok else ['no lines parsed'])[:1000]
                result['settings'] = {'encoding': result['encoding'], 'assumed_tz': ev['tz_assumed'],
                                      'source_context': context, 'raw_store': self.c.settings.raw_store}
            count, digest = self.spool.stats(identity, check=self.check)
            descriptor.update(unique_count=count, events_sha256=digest, parse_status=result['status'], coverage=result['coverage'])
            self.results.append({'evidence_id': identity[0], 'file_id': identity[1],
                'parser_id': pinned['id'] if pinned else None, 'parser_version': pinned['version'] if pinned else None,
                'parser_digest': pinned['digest'] if pinned else '', 'settings': result['settings'], 'started_at': started,
                'parse_status': result['status'], 'coverage': result['coverage'], 'events_parsed': count,
                'events_failed': result['failed'], 'first_ts': result['first_ts'], 'last_ts': result['last_ts'],
                'error_samples': result['samples'] + [{'coverage': result['coverage']}], 'message': result['message']})
            self.check()

    def publish(self):
        for identity, descriptor in self.descriptors.items():
            count, digest = self.spool.stats(identity, check=self.check)
            if self.parent and identity not in self.replaced and (count, digest) != (descriptor['unique_count'], descriptor['events_sha256']):
                raise GenerationVerificationError('producer_parent_copy_mismatch')
            descriptor.update(unique_count=count, events_sha256=digest)
        self.c.generations.create_target(self.ref, job_id=self.job_id, attempt=self.attempt,
                                         input_sha256=self.input_sha256, check=self.check)
        writer = self.c.generations.begin_write(self.ref, job_id=self.job_id, attempt=self.attempt,
                                                input_sha256=self.input_sha256, check=self.check)
        batch, size = [], 0
        expected_hash = event_stream_sha256(self.spool.events(check=self.check))
        for event in self.spool.events(check=self.check):
            length = len(canonical_event_bytes(event))
            if batch and (len(batch) >= 5000 or size + length > 10 * 1024 * 1024):
                if writer.index(batch) != len(batch):
                    raise GenerationVerificationError('producer_storage_rejected')
                batch, size = [], 0
            batch.append(event)
            size += length
        if batch and writer.index(batch) != len(batch):
            raise GenerationVerificationError('producer_storage_rejected')
        writer.seal()
        receipt = writer.verify(expected_files=list(self.descriptors.values()), check=self.check)
        if receipt['output_sha256'] != expected_hash:
            raise GenerationVerificationError('producer_hash_mismatch')
        with transaction(self.c) as s:
            service.mark_ready(s, self.ref, receipt, file_results=self.results)
        with transaction(self.c) as s:
            if self.baseline:
                result = service.retain_baseline(s, self.ref, job_id=self.job_id, attempt=self.attempt)
                from saw.analysis_runs.models import AnalysisRun
                from saw.event_generations.models import AnalysisRunGeneration
                for run in s.scalars(select(AnalysisRun).where(AnalysisRun.investigation_id == self.ref.investigation_id)):
                    if s.get(AnalysisRunGeneration, run.id) is None:
                        # Only source-equivalent old snapshots may acquire this baseline association.
                        try:
                            with s.begin_nested():
                                service.associate_analysis_run(s, run.id, result.generation_id)
                        except GenerationConflict as error:
                            if str(error) != "generation_history_mismatch":
                                raise
                return result
            result = service.publish(s, self.ref, job_id=self.job_id, attempt=self.attempt)
            job = s.get(Job, self.job_id)
            if job.kind == 'reprocess':
                stages = dict(job.stages or {})
                for phase in ('parse', 'index'):
                    stages[phase] = {**stages.get(phase, {}), 'pct': 100, 'done': True}
                job.stages = stages
            return result

    def close(self, *, failed=False):
        if self.closed:
            return
        self.closed = True
        try:
            if failed:
                with transaction(self.c) as s:
                    service.abandon(s, self.ref, job_id=self.job_id, attempt=self.attempt, reason='failed')
        finally:
            self.spool.__exit__(None, None, None)


def produce(c, job_id, attempt):
    """Capture legacy output once, then atomically replace only the prepared source files."""
    with transaction(c) as s:
        job = s.get(Job, job_id)
        is_ingest = job.kind == "ingest"
        manifest = None if (job.stages or {}).get("generation", {}).get("published") else service.capture_input(s, job)
    if is_ingest and manifest and any((r["parser"] or {}).get("id") == "pcap" for r in manifest["replacements"]):
        from saw.integrations.pcap import runtime_pins
        pins = runtime_pins()
        with transaction(c) as s:
            job = s.get(Job, job_id)
            job.stages = {**(job.stages or {}), "runtime_pins": pins}
    with transaction(c) as s:
        job = s.get(Job, job_id)
        inv_id = job.investigation_id
        stage = (job.stages or {}).get('generation') or {}
        if stage.get('published'):
            ref = service.resolve(s, inv_id)
            if ref is None or ref.generation_id != stage['id']:
                raise GenerationVerificationError('generation_published_superseded')
            return ref
        head = service.resolve(s, inv_id)
    if head is None:
        with c.generations.open_view(inv_id) as legacy:
            from saw.analysis_runs.models import AnalysisRun
            with transaction(c) as s:
                has_history = s.scalar(select(AnalysisRun.id).where(AnalysisRun.investigation_id == inv_id).limit(1)) is not None
            if legacy.count(inv_id, []) or has_history:
                baseline = Producer(c, job_id, attempt, baseline=True)
                try:
                    baseline.copy(legacy)
                    baseline.publish()
                except BaseException:
                    baseline.close(failed=True)
                    raise
                baseline.close()
    producer = Producer(c, job_id, attempt)
    try:
        with c.generations.open_view(inv_id) as parent:
            producer.copy(parent)
        producer.progress()
        producer.parse()
        producer.progress(parsed=True)
        return producer.publish()
    except BaseException:
        producer.close(failed=True)
        raise
    finally:
        producer.close()
