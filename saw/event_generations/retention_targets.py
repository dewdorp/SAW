"""Exact-target deletion for the authorized, single-server retention workflow."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

from saw.storage.generations import GenerationUnavailable
from saw.storage.sqlite_generations import SQLiteGenerations


def safe_path(path, *, root=None):
    path = Path(path).absolute()
    for item in (path, *path.parents):
        if item.is_symlink() or (hasattr(item, "is_junction") and item.is_junction()):
            raise ValueError("reparse path is not supported")
        if item.exists() and item.is_file() and item.stat().st_nlink != 1:
            raise ValueError("hardlink path is not supported")
    if root is not None and (not path.is_relative_to(Path(root).absolute()) or path == Path(root).absolute()):
        raise ValueError("target escapes root")
    if path.exists() and not path.is_file():
        raise ValueError("target is not a regular file")
    return path


def validate_target(store, ref):
    if ref.legacy or ref.storage_targets != store.plan_targets(ref.investigation_id, ref.generation_id):
        raise GenerationUnavailable("invalid exact target closure")
    if isinstance(store.adapter, SQLiteGenerations):
        path = safe_path(ref.storage_targets[0], root=store.adapter.root)
        for suffix in ("-wal", "-shm", "-journal"):
            safe_path(str(path) + suffix, root=store.adapter.root)


def remove_target(store, ref, *, owner, check):
    """Delete a registered target, never an alias or wildcard. Repeated absence is success."""
    check()
    validate_target(store, ref)
    adapter = store.adapter
    if isinstance(adapter, SQLiteGenerations):
        path = Path(ref.storage_targets[0])
        if path.exists() and path.stat().st_size:
            metadata = adapter.metadata(ref)
            if metadata.get("owner") != owner:
                raise GenerationUnavailable("target ownership changed")
            # Obtain the SQLite write lock to reject a still-active physical writer.
            # The SQL barrier has already fenced every conforming producer checkpoint.
            with closing(sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, timeout=0)) as connection:
                connection.execute("BEGIN EXCLUSIVE")
                connection.rollback()
        check()
        for suffix in ("-wal", "-shm", "-journal"):
            safe_path(str(path) + suffix, root=adapter.root).unlink(missing_ok=True)
        safe_path(path, root=adapter.root).unlink(missing_ok=True)
        if any(Path(str(path) + suffix).exists() for suffix in ("", "-wal", "-shm", "-journal")):
            raise GenerationUnavailable("generation target remains")
    else:
        from opensearchpy import NotFoundError

        from saw.storage.opensearch_generations import STRICT

        target = ref.storage_targets[0]
        try:
            state = adapter._state(ref)
        except NotFoundError:
            state = None
        except GenerationUnavailable:
            # _state intentionally wraps errors. Only an exact 404 can certify absence.
            try:
                adapter.client.indices.get(index=target, **STRICT)
            except NotFoundError:
                state = None
            else:
                raise
        if state is not None:
            if state.get("owner") != owner:
                raise GenerationUnavailable("target ownership changed")
            check()
            result = adapter.client.indices.delete(index=target, **STRICT)
            if result.get("acknowledged") is not True:
                raise GenerationUnavailable("target deletion not acknowledged")
        try:
            adapter.client.indices.get(index=target, **STRICT)
        except NotFoundError:
            pass
        else:
            raise GenerationUnavailable("generation target remains")
    check()
