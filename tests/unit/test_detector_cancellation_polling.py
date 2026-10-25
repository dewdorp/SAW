"""Bound only the detector hot callback; forced checks retain fresh cancellation semantics."""
from types import SimpleNamespace

import pytest

from saw.core.application import analysis
from saw.workers import pipeline


@pytest.fixture
def polling(monkeypatch):
    now = [0.0]
    calls = []
    outcomes = {}

    def fresh(job_id):
        calls.append(job_id)
        result = outcomes.get(job_id, False)
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(analysis, "time", SimpleNamespace(monotonic=lambda: now[0]))
    monkeypatch.setattr(pipeline, "_cancelled", fresh)
    return now, calls, outcomes


def test_first_callback_reads_even_at_monotonic_zero(polling):
    _, calls, outcomes = polling
    outcomes["job"] = True
    assert analysis._detector_cancellation("job")() is True
    assert calls == ["job"]


def test_many_hot_callbacks_are_bounded_and_refresh_at_elapsed_interval(polling):
    now, calls, outcomes = polling
    check = analysis._detector_cancellation("job")
    assert check() is False
    for _ in range(10000):
        now[0] = 0.199
        assert check() is False
    assert calls == ["job"]
    outcomes["job"] = True
    now[0] = 0.2
    assert check() is True
    assert calls == ["job", "job"]


def test_forced_callback_reads_inside_cached_window(polling):
    now, calls, outcomes = polling
    check = analysis._detector_cancellation("job")
    assert check() is False
    now[0] = 0.001
    outcomes["job"] = True
    assert check() is False
    assert check(force=True) is True
    assert calls == ["job", "job"]


def test_each_run_and_job_has_independent_first_read(polling):
    _, calls, outcomes = polling
    first = analysis._detector_cancellation("one")
    second = analysis._detector_cancellation("two")
    next_run = analysis._detector_cancellation("one")
    assert first() is False
    outcomes["one"] = outcomes["two"] = True
    assert second() is True
    assert next_run() is True
    assert first() is False
    assert calls == ["one", "two", "one"]


def test_cancellation_remains_true_after_later_false_read(polling):
    now, calls, outcomes = polling
    check = analysis._detector_cancellation("job")
    outcomes["job"] = True
    assert check() is True
    outcomes["job"] = False
    now[0] = 1.0
    assert check() is True
    assert check(force=True) is True
    assert calls[-1] == "job"


@pytest.mark.parametrize("error", [pipeline.StaleLease("superseded"), RuntimeError("SQL unavailable")])
@pytest.mark.parametrize("mode", ["first", "elapsed", "forced"])
def test_original_exception_propagates_without_becoming_cached_false(polling, error, mode):
    now, _, outcomes = polling
    check = analysis._detector_cancellation("job")
    if mode != "first":
        assert check() is False
    outcomes["job"] = error
    now[0] = 0.2 if mode == "elapsed" else 0.001
    with pytest.raises(type(error)) as caught:
        check(force=mode == "forced")
    assert caught.value is error
    outcomes["job"] = True
    assert check(force=True) is True


def test_absent_job_never_reads_sql(polling):
    _, calls, _ = polling
    check = analysis._detector_cancellation(None)
    assert check() is False
    assert check(force=True) is False
    assert calls == []
