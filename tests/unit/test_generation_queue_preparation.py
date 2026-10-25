"""Durable queue admission preserves committed generations and abandons private attempts."""
from __future__ import annotations

import pytest

from saw.storage.models import Job, User
from saw.workers.preparation import prepare_job
from tests.unit import test_event_generation_lifecycle as fixtures
from tests.unit.test_event_generation_lifecycle import allocated, ready

domain = fixtures.domain


@pytest.mark.parametrize("reason", ["cancel", "revoked", "restart"])
def test_unpublished_generation_releases_reservation_on_settlement(domain, reason):
    life, models, factory = domain
    jid, ref = allocated(domain)
    with factory.begin() as s:
        job = s.get(Job, jid)
        if reason == "cancel":
            job.cancel_requested = True
        elif reason == "revoked":
            s.get(User, "actor").status = "disabled"
        s.flush()
        route = prepare_job(s, job, recovering=True)
        assert route == ("reprocess.run" if reason == "restart" else None)
    with factory() as s:
        gen = s.get(models.EventGeneration, ref.generation_id)
        assert gen.status == "abandoned"
        assert gen.storage_targets == list(ref.storage_targets)
        assert s.get(models.WriterReservation, "inv") is None
        assert life.resolve(s, "inv") is None
        assert s.get(Job, jid).state == {
            "cancel": "CANCELLED", "revoked": "FAILED", "restart": "QUEUED"
        }[reason]


def test_published_ingest_recovers_analysis_only(domain):
    life, models, factory = domain
    jid, ref = ready(domain)
    with factory.begin() as s:
        life.publish(s, ref, job_id=jid, attempt=1)
        # Recreate the durable ingestion route after a crash before terminal state.
        job = s.get(Job, jid)
        job.kind = "ingest"
        job.stages = {**job.stages, "_queue_task": "ingest.run"}
        s.flush()
        assert prepare_job(s, job, recovering=True) == "analyze.run"
    with factory() as s:
        assert life.resolve(s, "inv").generation_id == ref.generation_id
        assert s.get(models.EventGeneration, ref.generation_id).status == "published"
        assert s.get(Job, jid).stages["_queue_task"] == "analyze.run"


def test_superseded_published_job_never_analyzes_new_head(domain):
    life, models, factory = domain
    first_job, first_ref = ready(domain)
    with factory.begin() as s:
        life.publish(s, first_ref, job_id=first_job, attempt=1)
        s.get(Job, first_job).state = "COMPLETED"
    second_job, second_ref = ready(domain)
    with factory.begin() as s:
        life.publish(s, second_ref, job_id=second_job, attempt=1)
        s.get(Job, second_job).state = "COMPLETED"
        stale = s.get(Job, first_job)
        stale.state = "ANALYZING"
        s.flush()
        assert prepare_job(s, stale, recovering=True) is None
    with factory() as s:
        stale = s.get(Job, first_job)
        assert stale.state == "FAILED"
        assert stale.error["code"] == "generation_published_superseded"
        assert life.resolve(s, "inv").generation_id == second_ref.generation_id
        assert s.get(models.EventGeneration, first_ref.generation_id).status == "retained"


def test_cancelled_committed_generation_keeps_current_head(domain):
    life, models, factory = domain
    jid, ref = ready(domain)
    with factory.begin() as s:
        life.publish(s, ref, job_id=jid, attempt=1)
        job = s.get(Job, jid)
        job.cancel_requested = True
        s.flush()
        assert prepare_job(s, job, recovering=True) is None
    with factory() as s:
        assert s.get(Job, jid).state == "CANCELLED"
        assert life.resolve(s, "inv").generation_id == ref.generation_id
        assert s.get(models.WriterReservation, "inv") is None
