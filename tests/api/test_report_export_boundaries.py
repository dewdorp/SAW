"""Cancellation, source revocation and integrity must fence actual artifact publication."""
import io
import zipfile

from sqlalchemy import select

from saw import container
from saw.reports import export_jobs
from saw.storage.db import session_scope
from saw.storage.models import Investigation, InvestigationMember, Job
from tests.api.test_report_exports import finished, request_job, scope
from tests.conftest import Api, make_user


def queued(analyst, monkeypatch, *, selection=None, key="queued"):
    monkeypatch.setattr(container.get().runner, "submit", lambda *a, **kw: None)
    result = request_job(analyst, selection or scope(finished(analyst)), key=key)
    assert result.status_code == 202, result.text
    assert result.json()["state"] == "QUEUED"
    return result.json()


def test_cancel_queued_report_preserves_snapshot_and_publishes_nothing(analyst, monkeypatch):
    job = queued(analyst, monkeypatch)
    cancelled = analyst.post(f"/jobs/{job['id']}/cancel")
    assert cancelled.json()["state"] == "CANCELLED"
    export_jobs.run(job["id"])
    result = analyst.get(f"/jobs/{job['id']}").json()
    assert result["state"] == "CANCELLED"
    assert result["stages"]["report_export"]["artifact"] is None
    assert analyst.get(f"/report-export-jobs/{job['id']}/download").status_code == 409


def test_revocation_before_worker_prevents_file_publication(app, analyst, monkeypatch):
    a, b = finished(analyst), finished(analyst)
    uid = make_user("report-revoked-worker", ["analyst"])
    with session_scope() as s:
        for inv, _ in (a, b):
            s.add(InvestigationMember(investigation_id=inv, user_id=uid, access="editor"))
    actor = Api(app, "report-revoked-worker")
    job = queued(actor, monkeypatch, selection=scope(a, b))
    with session_scope() as s:
        s.delete(s.get(InvestigationMember, (b[0], uid)))
    export_jobs.run(job["id"])
    with session_scope() as s:
        saved = s.get(Job, job["id"])
        assert saved.state == "FAILED"
        assert saved.stages["report_export"]["artifact"] is None
    assert actor.get(f"/report-export-jobs/{job['id']}/download").status_code == 403


def test_cancel_during_writer_seals_cancelled_without_artifact(analyst, monkeypatch):
    job = queued(analyst, monkeypatch)
    original = export_jobs.render_artifact
    def cancel(content, path, fmt, **kw):
        with session_scope() as s:
            s.get(Job, job["id"]).cancel_requested = True
        return original(content, path, fmt, **kw)
    monkeypatch.setattr(export_jobs, "render_artifact", cancel)
    export_jobs.run(job["id"])
    saved = analyst.get(f"/jobs/{job['id']}").json()
    assert saved["state"] == "CANCELLED"
    assert saved["stages"]["report_export"]["artifact"] is None


def test_stale_worker_does_not_publish_or_overwrite_current_attempt(analyst, monkeypatch):
    job = queued(analyst, monkeypatch)
    original = export_jobs.render_artifact
    def supersede(content, path, fmt, **kw):
        with session_scope() as s:
            s.get(Job, job["id"]).attempt += 1
        return original(content, path, fmt, **kw)
    monkeypatch.setattr(export_jobs, "render_artifact", supersede)
    export_jobs.run(job["id"])
    saved = analyst.get(f"/jobs/{job['id']}").json()
    assert saved["state"] == "ANALYZING"
    assert saved["stages"]["report_export"]["artifact"] is None
    monkeypatch.setattr(export_jobs, "render_artifact", original)
    export_jobs.run(job["id"])
    assert analyst.get(f"/jobs/{job['id']}").json()["state"] == "COMPLETED"


def test_revocation_after_upload_still_prevents_publication(app, analyst, monkeypatch):
    pair = finished(analyst)
    uid = make_user("report-revoked-publication", ["analyst"])
    with session_scope() as s:
        s.add(InvestigationMember(investigation_id=pair[0], user_id=uid, access="editor"))
    actor = Api(app, "report-revoked-publication")
    job = queued(actor, monkeypatch, selection=scope(pair))
    original = container.get().objects.put_stream
    def revoke(bucket, key, stream):
        stored = original(bucket, key, stream)
        with session_scope() as s:
            s.delete(s.get(InvestigationMember, (pair[0], uid)))
        return stored
    monkeypatch.setattr(container.get().objects, "put_stream", revoke)
    export_jobs.run(job["id"])
    with session_scope() as s:
        row = s.get(Job, job["id"])
        assert row.state == "FAILED" and row.stages["report_export"]["artifact"] is None
        assert "report_object_key" not in row.stages


def test_actual_xlsx_has_eight_sheets_and_no_private_object_key(analyst):
    job = request_job(analyst, scope(finished(analyst)), fmt="xlsx").json()
    assert job["state"] == "COMPLETED"
    assert set(job["stages"]) == {"report_export", "retry_of"}
    artifact = job["stages"]["report_export"]["artifact"]
    download = analyst.get(f"/report-export-jobs/{job['id']}/download")
    assert download.status_code == 200
    import hashlib
    assert len(download.content) == artifact["bytes"]
    assert hashlib.sha256(download.content).hexdigest() == artifact["sha256"]
    with zipfile.ZipFile(io.BytesIO(download.content)) as archive:
        from xml.etree import ElementTree as ET
        workbook = ET.fromstring(archive.read("xl/workbook.xml"))
        ns = {"m":"http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
        assert [x.attrib["name"] for x in workbook.findall("m:sheets/m:sheet",ns)] == [
            "요약","상세","확인 필요","통계","시간 추이","근거","적용 기준","범위·한계"]
        assert not any("externalLinks" in x or "vbaProject" in x for x in archive.namelist())


def test_changed_artifact_is_never_downloaded(analyst):
    job = request_job(analyst, scope(finished(analyst))).json()
    with session_scope() as s:
        key = s.get(Job, job["id"]).stages["report_object_key"]
    container.get().objects.put_bytes("saw-exports", key, b"changed synthetic artifact")
    response = analyst.get(f"/report-export-jobs/{job['id']}/download")
    assert response.status_code == 400
    assert b"changed synthetic artifact" not in response.content


def test_duplicate_key_at_admission_limit_returns_existing_job(analyst, monkeypatch):
    chosen = scope(finished(analyst))
    first = queued(analyst, monkeypatch, selection=chosen, key="limited-0")
    for number in range(1, 8):
        out = request_job(analyst, chosen, key=f"limited-{number}")
        assert out.status_code == 202
    duplicate = request_job(analyst, chosen, key="limited-0")
    assert duplicate.status_code == 202 and duplicate.json()["id"] == first["id"]
    assert request_job(analyst, chosen, key="limited-9").status_code == 429


def test_source_cleanup_blocks_external_report_but_own_report_can_be_removed(analyst, admin):
    from tests.api.test_admin_data import preview, execute
    a, b = finished(analyst), finished(analyst)
    job = request_job(analyst, scope(a, b)).json()
    blocked = preview(admin, "investigation", b[0])
    assert "report_reference" in blocked["blockers"]
    own_preview = preview(admin, "investigation", a[0])
    assert not own_preview["blockers"], own_preview["blockers"]
    own = execute(admin, own_preview)
    assert own.status_code == 200, own.text
    assert own.json()["state"] == "COMPLETED", own.text
    with session_scope() as s:
        assert s.get(Job, job["id"]) is None


def test_cancel_flag_before_claim_seals_cancelled(analyst, monkeypatch):
    job = queued(analyst, monkeypatch)
    with session_scope() as s:
        s.get(Job, job["id"]).cancel_requested = True
    export_jobs.run(job["id"])
    with session_scope() as s:
        row = s.get(Job, job["id"])
        assert row.state == "CANCELLED"
        assert row.finished_at is not None
        assert row.stages["report_export"]["artifact"] is None


def test_html_writer_receives_cooperative_cancel_callback(tmp_path, monkeypatch):
    from saw.reports import projection_html
    seen = []
    def render(content, *, cancelled=None):
        assert callable(cancelled)
        seen.append(cancelled())
        return "<html>synthetic</html>"
    monkeypatch.setattr(projection_html, "render", render)
    output = tmp_path / "synthetic.html"
    export_jobs.render_artifact({"schema_version": "synthetic"}, output, "html", cancelled=lambda: False)
    assert seen == [False]
    assert output.read_text() == "<html>synthetic</html>"

def test_exact_history_xlsx_download_enforces_writer_deadline(analyst, monkeypatch):
    inv, run = finished(analyst)
    saved = analyst.post(f"/investigations/{inv}/report-versions", json={"analysis_run_id": run}).json()
    monkeypatch.setattr(export_jobs, "MAX_SECONDS", -1)
    response = analyst.get(f"/investigations/{inv}/report-versions/{saved['id']}/xlsx")
    assert response.status_code == 400
    assert "report_export_time_limit" in response.text
