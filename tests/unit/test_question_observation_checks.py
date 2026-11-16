"""Question cards anchor requests; they are not a human attestation about the matched rows."""
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from saw.core.application import checks
from saw.core.application.briefing import _check_line
from saw.storage.eventstore import SQLiteEventStore
from saw.storage.models import Check


@pytest.fixture
def observation(monkeypatch):
    es = SQLiteEventStore(":memory:")
    es.index([{"investigation_id": "inv", "event_id": "e1", "timestamp": "2026-10-01T04:00:00Z", "data_source": "firewall"},
              {"investigation_id": "inv", "event_id": "outside", "timestamp": "2026-10-01T04:00:00Z", "data_source": "web"}])
    monkeypatch.setattr(checks.container, "get", lambda: SimpleNamespace(events=es))
    filters = [{"field": "data_source", "op": "is", "value": "firewall"}]
    return {"target_type": "set", "target_label": "관측 1건", "questions": ["nature"], "evidence": ["e1"],
            "scope": {"coverage": "observation", "checked": 0, "event_ids": [], "query": {"filters": filters, "time": None},
                      "origin": {"kind": "question", "bundle": "spread", "scope": {"investigation_id": "inv"},
                                 "item": {"title": "관측 1건", "filters": filters}}}}


def test_observation_keeps_evidence_without_incrementing_manual_counts(observation, monkeypatch):
    data = checks._clean(observation, "inv")
    assert data["scope"]["total"] == 1 and data["scope"]["checked"] == 0 and data["evidence"] == ["e1"]
    # Updating a note revalidates the stored scope. Its query and matching origin must round-trip.
    assert checks._clean({**data, "note": "업무 수행 시간 추가 확인"}, "inv")["scope"] == data["scope"]
    engine = create_engine("sqlite://")
    Check.__table__.create(engine)
    with Session(engine) as s:
        s.add(Check(investigation_id="inv", author_id="u", author_name="A", **data))
        s.flush()
        empty = checks.summary(s, "inv")
        assert empty["direct"] == empty["cited"] == empty["by_question"]["nature"] == 0
        assert empty["observations"] == 1 and "직접 확인해 남긴 기록: 없음" in _check_line(empty)
        assert "자동 관측 근거 1건" in _check_line(empty)
        manual = {**data, "scope": {**data["scope"], "coverage": "one"}}
        # Even a legacy question origin is not a new automatic observation without the explicit coverage.
        s.add(Check(investigation_id="inv", author_id="u", author_name="A", **manual))
        s.add(Check(investigation_id="inv", author_id="u", author_name="A", **{**manual,"kind":"cited"}))
        s.flush()
        monkeypatch.setattr(checks, "_visible_check", lambda *_: True)
        result = checks.summary(s, "inv", principal=object())
        assert (result["total"], result["direct"], result["observations"], result["cited"]) == (3, 1, 1, 1)
        assert result["by_question"]["nature"] == 1 and result["by_judgement"] == {"none": 1}


@pytest.mark.parametrize("change", ["no_origin", "wrong_investigation", "wrong_window", "manual", "judgement", "not_in_search"])
def test_observation_refuses_inconsistent_or_out_of_scope_claims(observation, change):
    scope = observation["scope"]
    if change == "no_origin":
        scope.pop("origin")
    elif change == "wrong_investigation":
        scope["origin"]["scope"]["investigation_id"] = "other"
    elif change == "manual":
        scope["checked"] = 1
    elif change == "wrong_window":
        scope["origin"]["item"]["evidence_time"] = {"start": "2026-10-02T00:00:00Z"}
    elif change == "judgement":
        observation.update(judgement="normal", note="담당자")
    else:
        observation["evidence"] = ["outside"]
    with pytest.raises(ValueError):
        checks._clean(observation, "inv")
