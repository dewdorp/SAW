from __future__ import annotations

import hashlib

import pytest

from saw import container
from saw.devtools.sample_data import scenario_pcap_forensics
from saw.storage.generations import GenerationVerificationError
from tests.api.test_phase5_bulk import upload


def test_runtime_pin_detects_changed_tool_bytes(tmp_path, monkeypatch):
    import subprocess

    from saw.integrations.pcap import runtime_pins, verify_runtime_pins
    monkeypatch.setattr(subprocess, 'run', lambda *a, **kw: subprocess.CompletedProcess(a[0], 0, b'fixture/1', b''))
    (tmp_path / 'bin').mkdir()
    scripts = tmp_path / 'share' / 'zeek'
    scripts.mkdir(parents=True)
    (scripts / 'local.zeek').write_text('# synthetic runtime fixture')
    tool = tmp_path / 'bin' / 'synthetic-tool.exe'
    tool.write_bytes(b'first synthetic executable fixture, never executed')
    pins = runtime_pins(tools={'zeek': str(tool), 'suricata': None}, settings=type('Config', (), {
        'suricata_config': '', 'suricata_rules': ''})())
    tool.write_bytes(b'changed synthetic executable fixture, never executed')
    with pytest.raises(GenerationVerificationError):
        verify_runtime_pins(pins)


def test_pcap_reprocessing_retains_original_derived_bytes(analyst):
    from saw.event_generations.models import EventGeneration, InvestigationHead
    from saw.event_generations.reads import actor_scope
    from saw.storage.db import session_scope
    from saw.storage.models import Job
    inv = analyst.post('/investigations', json={'title': 'pcap generations'}).json()['id']
    up = upload(analyst, inv, 'incident.pcap', scenario_pcap_forensics(), kind='pcap')
    job = analyst.post(f"/evidence/{up['evidence_id']}/process").json()
    result = analyst.get(f"/jobs/{job['id']}").json()
    assert result['state'] == 'COMPLETED', result
    c = container.get()
    with session_scope() as s:
        old = s.get(EventGeneration, s.get(InvestigationHead, inv).generation_id)
        old_id = old.id
        owned = [dict(r) for r in old.raw_objects if r['owner_generation_id'] == old.id]
        uid = s.get(Job, job['id']).requested_by
    assert owned
    before = {r['key']: hashlib.sha256(c.objects.local_path(r['bucket'], r['key']).read_bytes()).hexdigest() for r in owned}
    response = analyst.post(f"/evidence/{up['evidence_id']}/files/{up['file_id']}/parser", json={'parser_id': 'pcap'})
    assert response.status_code == 200, response.text
    result = analyst.get(f"/jobs/{response.json()['job_id']}").json()
    assert result['state'] == 'COMPLETED', result
    with session_scope() as s:
        assert s.get(InvestigationHead, inv).generation_id != old_id
        assert s.get(EventGeneration, old_id).status == 'retained'
    assert before == {r['key']: hashlib.sha256(c.objects.local_path(r['bucket'], r['key']).read_bytes()).hexdigest() for r in owned}
    with actor_scope(uid), c.events.read_scope():
        assert c.events.count(inv, []) > 0

def test_mixed_archive_text_and_pcap_publishes_one_full_generation(analyst):
    import io
    import zipfile

    from saw.event_generations.models import EventGeneration, InvestigationHead
    from saw.storage.db import session_scope
    from tests.api.test_generation_reprocessing import DATA
    packed = io.BytesIO()
    with zipfile.ZipFile(packed, 'w') as archive:
        archive.writestr('access.log', DATA)
        archive.writestr('incident.pcap', scenario_pcap_forensics())
    inv = analyst.post('/investigations', json={'title': 'mixed'}).json()['id']
    up = upload(analyst, inv, 'mixed.zip', packed.getvalue(), kind='auto')
    job = analyst.post(f"/evidence/{up['evidence_id']}/process").json()
    result = analyst.get(f"/jobs/{job['id']}").json()
    assert result['state'] == 'COMPLETED', result
    with session_scope() as s:
        current = s.get(EventGeneration, s.get(InvestigationHead, inv).generation_id)
        assert len(current.file_results) == 2
        assert {r['parser_id'] for r in current.file_results} == {'nginx_combined', 'pcap'}
        assert current.output_manifest['unique_count'] > 1


def test_legacy_pcap_baseline_fingerprints_existing_logs(analyst, admin, tmp_path):
    from sqlalchemy import select

    from saw.event_generations.models import EventGeneration
    from saw.integrations.pcapkit import PRODUCER, analyze_pcap
    from saw.parsers.base import Parsed
    from saw.parsers.network import ZeekJsonParser
    from saw.parsers.registry import iter_lines, to_ces
    from saw.storage.db import session_scope
    from saw.storage.models import EvidenceFile, Job
    inv = analyst.post('/investigations', json={'title': 'legacy pcap'}).json()['id']
    up = upload(analyst, inv, 'legacy.pcap', scenario_pcap_forensics(), kind='pcap')
    c = container.get()
    with session_scope() as s:
        source = s.get(EvidenceFile, up['file_id'])
        key = source.object_key
    work = tmp_path / 'old-logs'
    analyze_pcap(c.objects.local_path('saw-evidence-original', key), work)
    events, raw_bytes = [], {}
    for path in sorted(work.glob('*.log')):
        parser = ZeekJsonParser()
        old_key = f"{inv}/{up['evidence_id']}/{up['file_id']}/builtin/{path.name}"
        raw_bytes[old_key] = path.read_bytes()
        with path.open('rb') as stream:
            c.objects.put_stream('saw-artifacts', old_key, stream)
        for line in iter_lines([raw_bytes[old_key]]):
            parsed = parser.parse_line(line.text)
            if isinstance(parsed, Parsed):
                events.append(to_ces(parser, line, parsed, investigation_id=inv, evidence_id=up['evidence_id'],
                    file_id=up['file_id'] + ':' + path.name, source_file='legacy.pcap:' + path.name,
                    object_key='saw-artifacts/' + old_key, assumed_tz='UTC'))
    transfers = {}
    for path in sorted((work / 'files').glob('*')):
        old_key = f'{inv}/extracted-files/{path.name}'
        transfers[old_key] = path.read_bytes()
        with path.open('rb') as stream:
            c.objects.put_stream('saw-artifacts', old_key, stream)
    assert events and transfers
    c.legacy_events.index(events)
    with session_scope() as s:
        source = s.get(EvidenceFile, up['file_id'])
        source.type_detected, source.parser_id, source.parser_version = 'pcap', 'pcap(builtin)', PRODUCER.rpartition('/')[2]
        source.events_parsed, source.parse_status = len(events), 'done'
        s.get(Job, up['job_id']).state = 'COMPLETED'
    response = analyst.post(f"/evidence/{up['evidence_id']}/files/{up['file_id']}/parser", json={'parser_id': 'pcap'})
    result = analyst.get(f"/jobs/{response.json()['job_id']}").json()
    assert result['state'] == 'COMPLETED', result
    with session_scope() as s:
        baseline = s.scalar(select(EventGeneration).where(EventGeneration.investigation_id == inv,
                                                         EventGeneration.purpose == 'baseline'))
        assert baseline.status == 'retained'
        known = {r['key']: r for r in baseline.raw_objects}
        assert all(known[key]['sha256'] == hashlib.sha256(data).hexdigest() for key, data in raw_bytes.items() if data)
        assert all(known[key]['sha256'] == hashlib.sha256(data).hexdigest() for key, data in transfers.items())
        assert all(any(r['key'] == key for f in baseline.output_manifest['files'] for r in f['raw_objects']) for key in transfers)
    assert all(c.objects.local_path('saw-artifacts', key).read_bytes() == data for key, data in raw_bytes.items())
    from saw.core.application import data_deletion as deletion
    from saw.core.application.identity import principal_of
    from saw.storage.models import User
    other = analyst.post('/investigations', json={'title': 'preserved synthetic pcap'}).json()['id']
    other_up = upload(analyst, other, 'other.pcap', scenario_pcap_forensics(), kind='pcap')
    other_job = analyst.post(f"/evidence/{other_up['evidence_id']}/process").json()
    assert analyst.get(f"/jobs/{other_job['id']}").json()['state'] == 'COMPLETED'
    with session_scope() as s:
        other_key = s.get(EvidenceFile, other_up['file_id']).object_key
        generations = list(s.scalars(select(EventGeneration).where(EventGeneration.investigation_id == inv)))
        targets = [target for g in generations for target in g.storage_targets]
        owned = {(r['bucket'], r['key']) for g in generations for r in g.raw_objects}
        other_generations = list(s.scalars(select(EventGeneration).where(EventGeneration.investigation_id == other)))
        other_owned = {(r['bucket'], r['key']) for g in other_generations for r in g.raw_objects}
        from saw.event_generations import retention
        retention.closure(s, c, inv, {up['evidence_id']}, False)
        partial = deletion.preview(s, 'evidence', up['evidence_id'])
        assert 'shared_pcap_artifact' in partial['blockers']
        preview = deletion.preview(s, 'investigation', inv)
        assert not preview['blockers'], preview['blockers']
        actor = principal_of(s.scalar(select(User).where(User.username == 'admin1')))
        result = deletion.start(s, actor, 'investigation', inv, preview['confirmation'], preview['fingerprint'],
                                'Synthetic legacy PCAP retention regression')
        assert result.state == 'COMPLETED'
    from pathlib import Path
    assert all(not Path(target).exists() for target in targets)
    assert all(not c.objects.exists(bucket, object_key) for bucket, object_key in owned)
    assert not c.objects.exists('saw-evidence-original', key)
    assert all(c.objects.exists(bucket, object_key) for bucket, object_key in other_owned)
    assert c.objects.exists('saw-evidence-original', other_key)


def test_builtin_capture_checks_cancel_before_finishing(tmp_path, monkeypatch):
    from saw.integrations import pcap
    from saw.integrations.pcapkit.analyzer import PcapAnalyzer
    from saw.workers.pipeline import Cancelled
    source = tmp_path / 'capture.pcap'
    source.write_bytes(scenario_pcap_forensics())
    cancelled = False
    feed = PcapAnalyzer.feed
    def cancel_after_packet(analyzer, *args):
        nonlocal cancelled
        result = feed(analyzer, *args)
        cancelled = True
        return result
    monkeypatch.setattr(PcapAnalyzer, 'feed', cancel_after_packet)
    def check():
        if cancelled:
            raise Cancelled()
    with pytest.raises(Cancelled):
        pcap.analyze_generation_pcap(source, tmp_path / 'out', check)


def test_actual_pcap_expected_hash_observes_cancel_within_batch(analyst, monkeypatch):
    from sqlalchemy import select

    from saw.devtools.pcap_writer import PcapWriter, dns_query
    from saw.event_generations import producer
    from saw.storage.db import session_scope
    from saw.storage.models import Job
    from tests.api.test_generation_reprocessing import _head, prepared
    inv, _, _ = prepared(analyst)
    before = _head(inv)
    capture = PcapWriter()
    for index in range(700):
        capture.udp(1791249000.0 + index, '10.20.1.5', 40000 + index, '192.0.2.53', 53,
                    dns_query(index, f'host{index}.example.test'))
    source = upload(analyst, inv, 'many.pcap', capture.to_bytes(), kind='pcap')
    original_hash = producer.event_stream_sha256
    calls, consumed = 0, 0
    def cancel_in_first_hash(events):
        nonlocal calls, consumed
        calls += 1
        def counted():
            nonlocal consumed
            for event in events:
                consumed += 1
                if consumed == 500:
                    with session_scope() as s:
                        job = s.scalar(select(Job).where(Job.evidence_id == source['evidence_id']))
                        job.cancel_requested = True
                yield event
        return original_hash(counted() if calls == 1 else events)
    monkeypatch.setattr(producer, 'event_stream_sha256', cancel_in_first_hash)
    response = analyst.post(f"/evidence/{source['evidence_id']}/process").json()
    job = analyst.get(f"/jobs/{response['id']}").json()
    assert job['state'] == 'CANCELLED', job
    assert consumed == 500, 'the first PCAP stats pass must stop at its next bounded checkpoint'
    assert _head(inv) == before


@pytest.mark.parametrize("invalid", ["foreign_investigation", "foreign_file", "non_pcap", "sha_mismatch",
                                    "invalid_sha", "extra_suffix", "owned", "not_retained", "wrong_bucket"])
def test_legacy_transfer_requires_exact_captured_pcap_ownership(invalid):
    from copy import deepcopy
    from saw.event_generations.service import legacy_transfer_owned
    sha = "a" * 64
    manifest = {"source": {"evidence": [{"id": "evidence", "files": [{"id": "capture", "parser_id": "pcap(builtin)"}]}]}}
    obj = {"bucket": "saw-artifacts", "key": "synthetic/extracted-files/" + sha, "sha256": sha,
           "byte_length": 5, "retained": True, "owner_generation_id": None, "owner_attempt": None}
    assert legacy_transfer_owned("synthetic", manifest, obj, ("evidence", "capture"))
    source = ("evidence", "capture")
    if invalid == "foreign_investigation":
        obj["key"] = "foreign/extracted-files/" + sha
    elif invalid == "foreign_file":
        source = ("evidence", "foreign")
    elif invalid == "non_pcap":
        manifest = deepcopy(manifest)
        manifest["source"]["evidence"][0]["files"][0]["parser_id"] = "nginx_combined"
    elif invalid == "sha_mismatch":
        obj["sha256"] = "b" * 64
    elif invalid == "invalid_sha":
        obj["sha256"] = "invalid"
        obj["key"] = "synthetic/extracted-files/invalid"
    elif invalid == "extra_suffix":
        obj["key"] += "/nested"
    elif invalid == "owned":
        obj["owner_generation_id"], obj["owner_attempt"] = "generation", 1
    elif invalid == "not_retained":
        obj["retained"] = False
    elif invalid == "wrong_bucket":
        obj["bucket"] = "saw-evidence-original"
    assert not legacy_transfer_owned("synthetic", manifest, obj, source)
