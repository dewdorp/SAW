"""Append-only audit log with SHA-256 hash chain (docs/07 audit, docs/12 §7)."""
from __future__ import annotations

import hashlib
import json
import threading
from datetime import UTC
from pathlib import Path
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from saw.storage.db import utcnow
from saw.storage.models import AuditEvent, AuditHead

_lock = threading.Lock()
GENESIS = "0" * 64
ANCHOR_FILE = "audit-anchors.jsonl"


def _ts(dt) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(UTC).replace(tzinfo=None)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical(e: AuditEvent) -> str:
    return json.dumps(
        {
            "at": _ts(e.at),
            "actor_id": e.actor_id,
            "actor_name": e.actor_name,
            "actor_ip": e.actor_ip,
            "action": e.action,
            "target_type": e.target_type,
            "target_id": e.target_id,
            "investigation_id": e.investigation_id,
            "outcome": e.outcome,
            "detail": e.detail,
        },
        sort_keys=True,
        ensure_ascii=False,
        default=str,
    )


def _head(s: Session) -> AuditHead:
    """The end-of-chain row, held until the transaction ends: two requests must never extend the same entry (the
    thread lock alone covers neither other processes nor the time between flush and commit). The no-op UPDATE takes the
    row lock on PostgreSQL and the write lock on SQLite *before* the row is read, so the read is never stale."""
    hold = update(AuditHead).where(AuditHead.id == 1).values(id=1).execution_options(synchronize_session=False)
    if not s.execute(hold).rowcount:
        # Database without a head row (built before it existed, or by create_all): adopt the chain as it is now.
        # Two first writers may get here together: only one row is created, and both then queue on its lock.
        last = s.execute(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1)).scalar_one_or_none()
        row = {"id": 1, "last_id": last.id if last else 0, "last_hash": last.hash if last else GENESIS,
               "entries": s.execute(select(func.count()).select_from(AuditEvent)).scalar_one()}
        dialect = s.get_bind().dialect.name
        if dialect == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as pg_insert

            s.execute(pg_insert(AuditHead).values(**row).on_conflict_do_nothing())
        elif dialect == "sqlite":
            from sqlalchemy.dialects.sqlite import insert as sqlite_insert

            s.execute(sqlite_insert(AuditHead).values(**row).on_conflict_do_nothing())
        else:
            s.add(AuditHead(**row))
            s.flush()
        s.execute(hold)
    return s.execute(select(AuditHead).where(AuditHead.id == 1).execution_options(populate_existing=True)).scalar_one()


def record(
    s: Session,
    action: str,
    *,
    actor_id: str | None = None,
    actor_name: str = "",
    actor_ip: str = "",
    target_type: str = "",
    target_id: str = "",
    investigation_id: str | None = None,
    outcome: str = "success",
    detail: dict[str, Any] | None = None,
) -> AuditEvent:
    # Acquire the database lock before the process lock: callers may already own a SQLite writer lock.
    head = _head(s)
    with _lock:
        prev = head.last_hash or GENESIS
        e = AuditEvent(
            at=utcnow().replace(microsecond=0),
            actor_id=actor_id,
            actor_name=actor_name,
            actor_ip=actor_ip,
            action=action,
            target_type=target_type,
            target_id=str(target_id or ""),
            investigation_id=investigation_id,
            outcome=outcome,
            detail=detail or {},
            prev_hash=prev,
        )
        e.hash = hashlib.sha256((prev + _canonical(e)).encode()).hexdigest()
        s.add(e)
        s.flush()
        head.last_id, head.last_hash, head.entries = e.id, e.hash, (head.entries or 0) + 1
        s.flush()
        return e


def _anchor_path() -> Path | None:
    try:
        from saw import container

        return Path(container.get().settings.data_dir) / ANCHOR_FILE
    except Exception:  # noqa: BLE001 - no application context (bare scripts): anchors are simply not used
        return None


def _anchors(path: Path | None) -> list[dict]:
    if path is None or not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            a = json.loads(line)
            out.append({"id": int(a["id"]), "hash": str(a["hash"]), "entries": int(a["entries"])})
        except (ValueError, KeyError, TypeError):
            out.append({"id": -1, "hash": "", "entries": -1})  # an edited anchor file is itself a finding
    return out


def verify(s: Session, checkpoint: bool = True) -> dict:
    """Walk the chain and compare its end with what was recorded outside the entries themselves.

    reason: None | "chain" (an entry was changed or removed in the middle) | "tail" (the newest entries are missing:
    the chain is valid but ends before the recorded head) | "anchor" (an entry that existed at an earlier check is gone
    or different; anchors live in a file next to the data so that editing the database alone cannot hide it).
    """
    path = _anchor_path()
    anchors = _anchors(path)
    wanted = {a["id"]: a for a in anchors}
    prev, n, last_id, seen = GENESIS, 0, 0, {}
    for e in s.execute(select(AuditEvent).order_by(AuditEvent.id).execution_options(yield_per=2000)).scalars():
        if e.prev_hash != prev or hashlib.sha256((prev + _canonical(e)).encode()).hexdigest() != e.hash:
            return {"ok": False, "first_broken_id": e.id, "reason": "chain", "entries": n}
        prev, n, last_id = e.hash, n + 1, e.id
        if e.id in wanted:
            seen[e.id] = (e.hash, n)
    head = s.get(AuditHead, 1)
    if head is not None and (head.last_id != last_id or (head.last_hash or GENESIS) != prev or head.entries != n):
        return {"ok": False, "first_broken_id": last_id + 1, "reason": "tail", "entries": n,
                "expected_entries": head.entries}
    for a in anchors:
        if seen.get(a["id"]) != (a["hash"], a["entries"]):
            return {"ok": False, "first_broken_id": max(a["id"], 0) or None, "reason": "anchor", "entries": n,
                    "expected_entries": max((x["entries"] for x in anchors), default=n)}
    if checkpoint and path is not None and n and (not anchors or anchors[-1]["id"] != last_id):
        try:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"id": last_id, "hash": prev, "entries": n, "at": _ts(utcnow())}) + "\n")
        except OSError:
            pass
    return {"ok": True, "first_broken_id": None, "reason": None, "entries": n}


def verify_chain(s: Session) -> tuple[bool, int | None]:
    """Returns (ok, first_broken_id)."""
    r = verify(s)
    return r["ok"], r["first_broken_id"]
