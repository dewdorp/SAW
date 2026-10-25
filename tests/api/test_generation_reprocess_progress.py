"""Reprocessing progress follows actual parsing and verified publication boundaries."""
from __future__ import annotations

import pytest

from saw.event_generations import producer
from saw.event_generations.models import InvestigationHead
from saw.storage.db import session_scope
from saw.storage.generations import GenerationWriter
from saw.storage.models import Job
from saw.workers import pipeline
from tests.api.test_generation_reprocessing import prepared


@pytest.mark.parametrize('outcome', ['success', 'write', 'cancel', 'analysis'])
def test_reprocess_progress_tracks_publication_boundary(analyst, monkeypatch, outcome):
    inv, up, old = prepared(analyst)
    with session_scope() as session:
        old_head = session.get(InvestigationHead, inv).generation_id
        old_stages = dict(session.get(Job, old['id']).stages)
    observed = []
    parse = producer.Producer.parse
    index = GenerationWriter.index
    verify = GenerationWriter.verify

    def public_phase(own, phase):
        with session_scope() as session:
            job = session.get(Job, own.job_id)
            observed.append(phase)
            if phase == 'parse':
                assert job.state == 'PARSING'
                assert job.stages['parse'] == {'pct': 0, 'done': False}
            else:
                assert job.state == 'INDEXING'
                assert job.stages['parse']['done'] is True
                assert job.stages['parse']['pct'] == 100
                assert job.stages['index']['done'] is False

    def parsing(own):
        public_phase(own, 'parse')
        return parse(own)

    def indexing(writer, events):
        # Publication has not occurred merely because parsing produced a spool.
        with session_scope() as session:
            job = session.query(Job).filter_by(investigation_id=inv, kind='reprocess').one()
            public_phase(type('Owner', (), {'job_id': job.id})(), 'index')
        if outcome == 'write':
            raise OSError('synthetic staging write failure')
        return index(writer, events)

    def verifying(writer, **kwargs):
        if outcome == 'cancel':
            with session_scope() as session:
                session.query(Job).filter_by(investigation_id=inv, kind='reprocess').one().cancel_requested = True
        return verify(writer, **kwargs)

    def analysis(*args):
        raise RuntimeError('synthetic analysis failure after publication')

    monkeypatch.setattr(producer.Producer, 'parse', parsing)
    monkeypatch.setattr(GenerationWriter, 'index', indexing)
    monkeypatch.setattr(GenerationWriter, 'verify', verifying)
    if outcome == 'analysis':
        monkeypatch.setattr(pipeline, 'analyze_job', analysis)
    response = analyst.post(f"/evidence/{up['evidence_id']}/files/{old['files'][0]['id']}/parser",
                            json={'parser_id': old['files'][0]['parser_id']})
    assert response.status_code == 200, response.text
    current = analyst.get(f"/jobs/{response.json()['job_id']}").json()
    assert observed == ['parse', 'index']
    assert current['stages']['parse']['done'] is True
    assert current['stages']['parse']['pct'] == 100
    published = outcome in ('success', 'analysis')
    assert current['stages']['index'] == {'pct': 100 if published else 0, 'done': published}
    assert not {'upload', 'extract', 'generation', 'generation_request'} & current['stages'].keys()
    assert current['state'] == ('COMPLETED' if outcome == 'success' else 'CANCELLED' if outcome == 'cancel' else 'FAILED')
    with session_scope() as session:
        assert (session.get(InvestigationHead, inv).generation_id != old_head) is published
        assert session.get(Job, old['id']).stages == old_stages
