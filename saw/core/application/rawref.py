"""Raw line on demand: structured events are stored without raw_event (slim index on small PCs); the original line
is read back from the evidence file by raw_ref when an analyst opens the event."""
from __future__ import annotations

from saw import container
from saw.core.security.masking import mask_text

RAW_MAX = 32 * 1024


def hydrate_raw(ev: dict) -> dict:
    if ev.get("raw_event") is not None:
        return ev
    ref = ev.get("raw_ref") or {}
    if not ref.get("object_key"):
        return ev
    bucket, _, key = ref["object_key"].partition("/")
    try:
        data = container.get().objects.read_range(bucket, key, int(ref["offset"]), min(int(ref["length"]), RAW_MAX))
    except (OSError, KeyError, ValueError):
        return ev
    text = data.decode(ref.get("enc") or "utf-8", errors="replace").rstrip("\r\n").lstrip("﻿")
    if ev.get("raw_redacted"):  # the parser redacted secrets at ingest (NDR cookies): keep that promise on read-back
        text = mask_text(text).text
    return {**ev, "raw_event": text}
