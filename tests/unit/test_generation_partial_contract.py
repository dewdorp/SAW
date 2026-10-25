"""Storage and lifecycle agree on replacement output quality semantics."""
import pytest

from saw.storage.generations import GenerationVerificationError
from tests.unit import test_event_generation_writers as fixtures

env = fixtures.env


@pytest.mark.parametrize("status", ["done", "degraded", "partial"])
def test_verified_nonempty_replacement_preserves_explicit_quality(env, status):
    store, _, _, _, _, allocated, _ = env
    ref = allocated()
    owner = {"job_id": "job", "attempt": 1, "input_sha256": "a" * 64, "check": lambda: None}
    store.create_target(ref, **owner)
    writer = store.begin_write(ref, **owner)
    rows = [fixtures.event()]
    writer.index(rows)
    writer.seal()
    files = fixtures.expected(rows)
    files[0].update(replacement=True, parse_status=status)
    receipt = writer.verify(expected_files=files, check=lambda: None)
    assert receipt["files"][0]["parse_status"] == status
    assert receipt["files"][0]["quality"] == {"status": "partial"}
    assert receipt["files"][0]["coverage"] == {"status": "partial"}


@pytest.mark.parametrize("status", ["failed", "waiting_input", "skipped", "ok"])
def test_non_successful_replacement_status_never_publishes(env, status):
    store, _, _, _, _, allocated, _ = env
    ref = allocated()
    owner = {"job_id": "job", "attempt": 1, "input_sha256": "a" * 64, "check": lambda: None}
    store.create_target(ref, **owner)
    writer = store.begin_write(ref, **owner)
    rows = [fixtures.event()]
    writer.index(rows)
    writer.seal()
    files = fixtures.expected(rows)
    files[0].update(replacement=True, parse_status=status)
    with pytest.raises(GenerationVerificationError):
        writer.verify(expected_files=files, check=lambda: None)
