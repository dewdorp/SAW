from __future__ import annotations

from sqlalchemy.orm import Session

from saw.storage.db import utcnow
from saw.storage.models import Counter


def next_display_id(s: Session, prefix: str, daily: bool = True, width: int = 3) -> str:
    """INV-20261005-013 style ids. Row-level increment inside the caller's transaction."""
    day = utcnow().strftime("%Y%m%d")
    name = f"{prefix}-{day}" if daily else prefix
    c = s.get(Counter, name, with_for_update=True)
    if c is None:
        c = Counter(name=name, value=0)
        s.add(c)
    c.value += 1
    s.flush()
    return f"{name}-{c.value:0{width}d}"
