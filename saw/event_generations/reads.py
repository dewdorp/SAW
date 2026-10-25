"""Captured-instance event reads. Absence of an actor never grants content access."""
from __future__ import annotations

import os
import secrets
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import UTC, timedelta
from pathlib import Path

from sqlalchemy import select

from saw.core.application.identity import principal_of
from saw.core.application.investigations import Forbidden, NotFound
from saw.core.application.provenance import digest
from saw.core.security.authz import InvestigationAccess, can
from saw.storage.db import utcnow
from saw.storage.generations import (
    MAX_BYTES,
    MAX_EVENTS,
    GenerationConflict,
    GenerationStore,
    GenerationUnavailable,
    InvalidGenerationCursor,
    canonical_event_bytes,
)
from saw.storage.models import Investigation, InvestigationMember, Job, User, UserSession


@dataclass
class ReadActor:
    user_id: str | None = None
    session_id: str | None = None
    job_id: str | None = None
    maintenance: object = None


@dataclass
class ReadScope:
    views: dict = field(default_factory=dict)
    sources: dict = field(default_factory=dict)
    lock: object = field(default_factory=threading.RLock)


_actor = ContextVar('generation_read_actor', default=None)
_scope = ContextVar('generation_read_scope', default=None)


@contextmanager
def actor_scope(user_id=None, session_id=None, *, holder=None, job_id=None):
    actor = holder if holder is not None else ReadActor(user_id, session_id, job_id)
    token = _actor.set(actor)
    try:
        yield actor
    finally:
        _actor.reset(token)


@contextmanager
def read_scope():
    state = ReadScope()
    token = _scope.set(state)
    try:
        yield state
    finally:
        try:
            for view in state.views.values():
                view.close()
        finally:
            _scope.reset(token)


@contextmanager
def ensure_scope():
    if _scope.get() is not None:
        yield _scope.get()
    else:
        with read_scope() as state:
            yield state


@contextmanager
def maintenance_scope(check, *, purpose):
    """Internal capability: caller owns fresh receipt/barrier authorization, per read."""
    if not callable(check) or purpose not in {'generation-baseline', 'authorized-deletion', 'cold-backup'}:
        raise Forbidden('maintenance_scope_invalid')
    with actor_scope(holder=ReadActor(maintenance=check)), read_scope():
        yield


@contextmanager
def task_read_scope(job_id):
    from saw import container
    c = container.get()
    with c.session_factory() as s:
        job = s.get(Job, job_id) if job_id else None
        uid = job.requested_by if job is not None else None
    with actor_scope(uid, job_id=job_id), read_scope():
        yield


def bind_request_actor(user_id, session_id):
    actor = _actor.get()
    if actor is None:
        raise Forbidden('request_read_context_missing')
    actor.user_id, actor.session_id = user_id, session_id


def _private_file(path):
    if os.name != 'nt':
        os.chmod(path, 0o600)
        return
    # A protected DACL before secret bytes: current owner, SYSTEM and administrators.
    import ctypes
    from ctypes import wintypes
    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    descriptor = ctypes.c_void_p()
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    advapi.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            'D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)', 1, ctypes.byref(descriptor), None):
        raise GenerationUnavailable('cursor_key_permissions_unavailable')
    try:
        if not advapi.SetFileSecurityW(str(path), 4 | 0x80000000, descriptor):
            raise GenerationUnavailable('cursor_key_permissions_unavailable')
    finally:
        kernel.LocalFree(descriptor)


def load_cursor_key(data_dir):
    directory = Path(data_dir) / 'event-generations'
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / 'cursor.key'
    if not path.exists():
        temporary = directory / ('.cursor-' + secrets.token_hex(16))
        fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            with os.fdopen(fd, 'wb') as stream:
                _private_file(temporary)
                stream.write(secrets.token_bytes(32))
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, path)  # Atomic, no replacement; winner is fully written.
            except FileExistsError:
                pass
        finally:
            temporary.unlink(missing_ok=True)
    try:
        if path.is_symlink():
            raise OSError()
        with path.open('rb') as stream:
            value = stream.read(65)
        if len(value) != 32:
            raise ValueError()
        return value
    except (OSError, ValueError):
        raise GenerationUnavailable('cursor_key_unavailable') from None


def _aware(value):
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def public_generation(ref):
    return {name: getattr(ref, name) for name in (
        'investigation_id', 'generation_id', 'head_revision', 'output_sha256', 'legacy')}


class _Borrowed:
    def __init__(self, view):
        self._view = view

    def __getattr__(self, name):
        return getattr(self._view, name)

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class _PinnedIterator:
    def __init__(self, rows, view, owned):
        self.rows, self.view, self.owned, self.closed = rows, view, owned, False

    def __iter__(self):
        return self

    def __next__(self):
        if self.closed:
            raise StopIteration
        try:
            return next(self.rows)
        except BaseException:
            self.close()
            raise

    def close(self):
        if not self.closed:
            self.closed = True
            try:
                self.rows.close()
            finally:
                if self.owned:
                    self.view.close()


class EventFacade:
    def __init__(self, legacy, *, objects, session_factory, settings):
        self.legacy, self.objects = legacy, objects
        self.session_factory, self.settings = session_factory, settings
        self.generations = GenerationStore(
            legacy, resolve=self.resolve, check_read=self.check_read, open_raw=objects.open,
            cursor_key=load_cursor_key(settings.data_dir), data_dir=settings.data_dir)

    read_scope = staticmethod(read_scope)

    def resolve(self, investigation_id, *, generation_id=None):
        from saw.event_generations.service import resolve
        with self.session_factory() as s:
            return resolve(s, investigation_id, generation_id=generation_id)

    def authorize(self, s, inv_id):
        actor = _actor.get()
        if actor is None:
            raise Forbidden('event_read_actor_required')
        if actor.maintenance is not None:
            actor.maintenance(inv_id)
            return None
        user = s.get(User, actor.user_id, populate_existing=True) if actor.user_id else None
        if user is None or user.status != 'active':
            raise Forbidden('event_read_actor_unavailable')
        if actor.job_id:
            job = s.get(Job, actor.job_id, populate_existing=True)
            if job is None or job.requested_by != user.id:
                raise Forbidden('event_read_job_unavailable')
        if actor.session_id:
            session = s.get(UserSession, actor.session_id, populate_existing=True)
            now = utcnow()
            if (session is None or session.user_id != user.id or session.revoked_at is not None
                    or not session.mfa_passed or _aware(session.expires_at) <= now
                    or _aware(session.last_seen_at) + timedelta(minutes=self.settings.session_idle_minutes) <= now):
                raise Forbidden('event_read_session_unavailable')
        inv = s.get(Investigation, inv_id, populate_existing=True)
        if inv is None:
            raise NotFound('investigation not found')
        if (inv.settings or {}).get('data_deletion'):
            raise GenerationConflict('event_source_deleting')
        member = s.get(InvestigationMember, (inv_id, user.id), populate_existing=True)
        p = principal_of(user)
        if not can(p, 'investigation.read', InvestigationAccess(member.access if member else None)):
            raise Forbidden('investigation.read')
        return p

    def check_read(self, ref):
        with self.session_factory() as s:
            self.authorize(s, ref.investigation_id)
            state = _scope.get()
            for inv in state.sources.get((id(self), ref.investigation_id), ()) if state else ():
                self.authorize(s, inv)

    def _select(self, inv, ref=None, resume=None):
        state = _scope.get()
        def create():
            if resume:
                return self.generations.resume_view(inv, **resume)
            return self.generations.open_view(inv, ref=ref)
        if state is None:
            return create(), True
        with state.lock:
            key = (id(self), inv)
            previous = state.views.get(key)
            if resume:
                candidate = create()
                if previous is not None:
                    # Legacy refs alone cannot prove the same snapshot: let S validate the cursor.
                    try:
                        if previous.ref != candidate.ref:
                            raise InvalidGenerationCursor('cursor_scope_conflict')
                        if previous.ref.legacy:
                            previous.search(inv, **resume)
                    finally:
                        candidate.close()
                else:
                    previous = state.views[key] = candidate
            elif previous is None:
                previous = state.views[key] = create()
            elif ref is not None and previous.ref != ref:
                raise GenerationConflict('event_scope_conflict')
            return previous, False

    def open_view(self, investigation_id, ref=None):
        view, owned = self._select(investigation_id, ref)
        return view if owned else _Borrowed(view)

    def _call(self, name, inv, *args, **kwargs):
        view, owned = self._select(inv)
        try:
            return getattr(view, name)(inv, *args, **kwargs)
        finally:
            if owned:
                view.close()

    def get(self, investigation_id, event_id):
        return self._call('get', investigation_id, event_id)

    def search(self, investigation_id, filters, time=None, sort='asc', limit=100, cursor=None, fields=None):
        resume = {'cursor': cursor, 'filters': filters, 'time': time, 'sort': sort, 'limit': limit, 'fields': fields} if cursor else None
        view, owned = self._select(investigation_id, resume=resume)
        try:
            return view.search(investigation_id, filters, time, sort, limit, cursor, fields)
        finally:
            if owned:
                view.close()

    def iterate(self, investigation_id, filters, time=None, fields=None, batch=5000):
        # Select at iterator creation, not on a later first next() after publication.
        view, owned = self._select(investigation_id)
        return _PinnedIterator(view.iterate(investigation_id, filters, time, fields, batch), view, owned)

    def count(self, investigation_id, filters=None, time=None):
        return self._call('count', investigation_id, filters, time)

    def aggregate(self, investigation_id, filters, agg, time=None):
        return self._call('aggregate', investigation_id, filters, agg, time)

    def group_by(self, investigation_id, filters, fields, metrics, size=100, time=None, order_by=None):
        return self._call('group_by', investigation_id, filters, fields, metrics, size, time, order_by)

    def histogram_metrics(self, investigation_id, filters, interval_sec, metrics, time=None, split_field=None):
        return self._call('histogram_metrics', investigation_id, filters, interval_sec, metrics, time, split_field)

    def time_bounds(self, investigation_id, filters=None):
        return self._call('time_bounds', investigation_id, filters)

    @contextmanager
    def _legacy_write(self, inv):
        from saw.core.application.data_deletion import lock_investigation
        from saw.event_generations.models import InvestigationHead, WriterReservation
        with self.session_factory.begin() as s:
            lock_investigation(s, inv)
            if s.get(InvestigationHead, inv) is not None or s.get(WriterReservation, inv) is not None:
                raise GenerationConflict('managed_event_write_forbidden')
            yield

    def index(self, events):
        total, batch, size, inv = 0, [], 0, None
        def write():
            with self._legacy_write(inv):
                return self.legacy.index(batch)
        for event in events:
            length = len(canonical_event_bytes(event))
            identity = event.get('investigation_id')
            if not identity or length > MAX_BYTES:
                raise GenerationConflict('invalid_bounded_event_write')
            if batch and (identity != inv or len(batch) == MAX_EVENTS or size + length > MAX_BYTES):
                total += write()
                batch, size = [], 0
            inv = identity
            batch.append(event)
            size += length
        if batch:
            total += write()
        return total

    def delete_by_investigation(self, investigation_id):
        with self._legacy_write(investigation_id):
            return self.legacy.delete_by_investigation(investigation_id)

    def delete_by_evidence(self, investigation_id, evidence_id):
        with self._legacy_write(investigation_id):
            return self.legacy.delete_by_evidence(investigation_id, evidence_id)

    def pin_manifest(self, s, investigation_id, manifest):
        from saw.event_generations import service as life
        from saw.event_generations.models import EventGeneration
        with self.open_view(investigation_id) as view:
            ref = view.ref
            current = life.resolve(s, investigation_id)
            if (current is None) != ref.legacy or (current is not None and current != ref):
                raise GenerationConflict('analysis_source_generation_changed')
            if not ref.legacy:
                g = s.get(EventGeneration, ref.generation_id, populate_existing=True)
                expected_epoch = g.data_epoch + (0 if g.purpose == 'baseline' else 1)
                if manifest.get('data_epoch') != expected_epoch:
                    raise GenerationConflict('analysis_source_epoch_changed')
            result = deepcopy(manifest)
            result['event_generation'] = public_generation(ref)
            return result

    def bind_live_run(self, s, run):
        pin = run.input_manifest.get('event_generation')
        if isinstance(pin, dict) and pin.get('legacy'):
            # Only live computation may bind a genuine no-head snapshot. Historical HTTP
            # retrieval always calls bind_run and requires a retained association.
            with self.open_view(run.investigation_id) as view:
                if not view.ref.legacy or public_generation(view.ref) != pin:
                    raise GenerationConflict('analysis_source_generation_changed')
            return
        self.bind_run(s, run.investigation_id, run.id)

    def bind_run(self, s, investigation_id, analysis_run_id):
        from saw.analysis_runs.models import AnalysisRun
        from saw.analysis_runs.service import _derived_sources
        from saw.detection.runtime_capture import sources
        from saw.event_generations import service as life
        from saw.event_generations.models import AnalysisRunGeneration, EventGeneration
        self.authorize(s, investigation_id)
        run = s.get(AnalysisRun, analysis_run_id, populate_existing=True)
        if run is None or run.investigation_id != investigation_id:
            raise NotFound('analysis run not found')
        if digest(run.input_manifest) != run.input_sha256:
            raise GenerationUnavailable('analysis_manifest_unavailable')
        dependencies = set(_derived_sources(s, run))
        if run.input_manifest.get('runtime_pin'):
            dependencies.update(sources(run.input_manifest['runtime_pin']))
        for inv in dependencies:
            self.authorize(s, inv)
        pin = run.input_manifest.get('event_generation')
        if isinstance(pin, dict) and pin.get('generation_id') and not pin.get('legacy'):
            ref = life.resolve(s, investigation_id, generation_id=pin['generation_id'])
            if public_generation(ref) != pin:
                raise GenerationUnavailable('analysis_generation_mismatch')
        else:
            association = s.get(AnalysisRunGeneration, run.id)
            if association is None or association.input_sha256 != run.input_sha256:
                raise GenerationUnavailable('analysis_generation_unavailable')
            ref = life.resolve(s, investigation_id, generation_id=association.generation_id)
            g = s.get(EventGeneration, ref.generation_id)
            if digest(g.input_manifest['source']) != association.source_sha256:
                raise GenerationUnavailable('analysis_generation_mismatch')
        state = _scope.get()
        if state is None:
            raise GenerationConflict('analysis_read_scope_required')
        state.sources[(id(self), investigation_id)] = dependencies
        with self.open_view(investigation_id, ref=ref):
            pass
        return ref

    def file_state(self, s, investigation_id):
        from saw.event_generations.models import EventGeneration
        from saw.storage.models import Evidence, EvidenceFile
        with self.open_view(investigation_id) as view:
            if view.ref.legacy:
                return [{c.name: getattr(f, c.name) for c in EvidenceFile.__table__.columns}
                        for f in s.scalars(select(EvidenceFile).join(Evidence).where(
                            Evidence.investigation_id == investigation_id))]
            g = s.get(EventGeneration, view.ref.generation_id, populate_existing=True)
            if g is None or g.output_sha256 != view.ref.output_sha256:
                raise GenerationUnavailable('generation_files_unavailable')
            files = {f['id']: deepcopy(f) for ev in g.input_manifest['source']['evidence'] for f in ev['files']}
            for result in g.file_results:
                files[result['file_id']].update(deepcopy(result))
            for output in g.output_manifest['files']:
                files[output['file_id']]['raw_objects'] = deepcopy(output['raw_objects'])
            return list(files.values())

    def raw_descriptor(self, event):
        inv = event.get('investigation_id')
        raw = event.get('raw_ref') or {}
        bucket, _, key = str(raw.get('object_key', '')).partition('/')
        if raw.get('bucket'):
            bucket, key = raw['bucket'], raw['object_key']
            if key.startswith(bucket + '/'):
                key = key[len(bucket) + 1:]
        if not bucket or not key:
            raise NotFound('raw reference not available')
        with self.open_view(inv) as view:
            self.check_read(view.ref)
            if not view.ref.legacy:
                with self.session_factory() as s:
                    from saw.event_generations.models import EventGeneration
                    g = s.get(EventGeneration, view.ref.generation_id)
                    valid = any(x['bucket'] == bucket and x['key'] == key for x in g.raw_objects)
                if not valid:
                    raise GenerationUnavailable('generation_raw_unavailable')
        return bucket, key

    @contextmanager
    def open_local_raw(self, investigation_id, path):
        """Guard a trusted resolver's retained local source throughout extraction."""
        with ensure_scope(), self.open_view(investigation_id) as view:
            check = lambda: self.check_read(view.ref)
            check()
            try:
                with open(path, 'rb') as source:
                    class CheckedRaw:
                        def read(self, size=-1):
                            check()
                            data = source.read(size)
                            check()
                            return data

                        def seek(self, offset, whence=0):
                            check()
                            result = source.seek(offset, whence)
                            check()
                            return result

                    yield CheckedRaw()
                    check()
            except OSError:
                raise GenerationUnavailable('generation_raw_unavailable') from None

    def read_raw_range(self, event, offset, length):
        with ensure_scope(), self.open_view(event['investigation_id']) as view:
            bucket, key = self.raw_descriptor(event)
            try:
                data = self.objects.read_range(bucket, key, offset, length)
            except (OSError, KeyError, ValueError):
                raise GenerationUnavailable('generation_raw_unavailable') from None
            self.check_read(view.ref)
            return data

    def hydrate_raw(self, event):
        if event.get('raw_event') is not None or not (event.get('raw_ref') or {}).get('object_key'):
            return event
        from saw.core.application.rawref import RAW_MAX
        from saw.core.security.masking import mask_text
        raw = event['raw_ref']
        try:
            data = self.read_raw_range(event, int(raw['offset']), min(int(raw['length']), RAW_MAX))
            if len(data) != min(int(raw['length']), RAW_MAX):
                raise OSError()
        except (OSError, KeyError, ValueError):
            raise GenerationUnavailable('generation_raw_unavailable') from None
        text = data.decode(raw.get('enc') or 'utf-8', errors='replace').rstrip('\r\n').lstrip('\ufeff')
        if event.get('raw_redacted'):
            text = mask_text(text).text
        return {**event, 'raw_event': text}

    @property
    def last_errors(self):
        return getattr(self.legacy, 'last_errors', [])

    @property
    def rejected(self):
        return getattr(self.legacy, 'rejected', 0)


class ReadContextMiddleware:
    """ASGI lifetime includes response streaming and disconnect cleanup."""
    def __init__(self, app, *, captured):
        self.app, self.captured = app, captured

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        from saw import container
        with container.activate(self.captured, self.captured.session_factory), actor_scope(), read_scope():
            await self.app(scope, receive, send)


def analysis_scoped(fn):
    """Direct service callers must supply an authorized principal or a persisted Job."""
    import inspect
    from functools import wraps
    signature = inspect.signature(fn)
    @wraps(fn)
    def wrapped(*args, **kwargs):
        bound = signature.bind(*args, **kwargs).arguments
        s = bound['s']
        actor = _actor.get()
        if actor is not None and actor.maintenance is not None:
            raise Forbidden('maintenance_analysis_forbidden')
        if actor is not None and actor.user_id:
            with ensure_scope():
                return fn(*args, **kwargs)
        job_id = bound.get('job_id')
        if job_id:
            with task_read_scope(job_id):
                return fn(*args, **kwargs)
        principal = s.info.get('principal')
        if principal is None:
            raise Forbidden('analysis_actor_required')
        with actor_scope(principal.user_id), ensure_scope():
            return fn(*args, **kwargs)
    return wrapped


def hydrate_raw(event):
    from saw import container
    return container.get().events.hydrate_raw(event)


def current_actor_id():
    actor = _actor.get()
    if actor is None or not actor.user_id or actor.maintenance is not None:
        raise Forbidden('analysis_actor_required')
    return actor.user_id
