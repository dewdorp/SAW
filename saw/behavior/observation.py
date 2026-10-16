"""Trusted parser observations captured before normalization removes empty markers."""
from __future__ import annotations

import re


def timestamp_precision(raw):
    if raw is None:
        return "unknown"
    value = str(raw).strip().strip("[]")
    if re.fullmatch(r"\d{10}", value):
        return "seconds"
    if re.fullmatch(r"\d{13}|\d{16,19}|\d{10}\.\d+", value):
        return "subseconds"
    if re.search(r"\d{1,2}:\d{2}:\d{2}[.,]\d+", value):
        return "subseconds"
    if re.search(r"\d{1,2}:\d{2}:\d{2}", value) or re.fullmatch(r"\d{14}", value):
        return "seconds"
    return "unknown"


def observe_fields(fields):
    value = fields.get("user_agent")
    state = "not_collected" if value is None else (
        "recorded_empty" if str(value).strip() in ("", "-", "(empty)") else "present")
    return {"producer": "saw-parser/1", "user_agent": state,
            "timestamp_precision": timestamp_precision(fields.get("timestamp_raw"))}
