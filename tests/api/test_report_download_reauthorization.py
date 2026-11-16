"""Report bytes remain private when authority changes during expensive I/O."""
from contextlib import contextmanager

import pytest
from sqlalchemy import delete, select, update

from saw import container
from saw.reports import export_jobs
from saw.storage.db import session_scope, utcnow
from saw.storage.models import InvestigationMember, Job, User, UserSession
from tests.api.test_report_exports import finished, request_job, scope


def _change_authority(uid, inv, change):
    with session_scope() as s:
        # A held download writer lock should fail this test quickly, not hide revocation.
        if s.bind.dialect.name == "sqlite":
            s.connection().exec_driver_sql("PRAGMA busy_timeout=200")
        if change == "disabled":
            s.get(User, uid).status = "disabled"
        elif change == "role":
            s.get(User, uid).roles = []
        elif change == "membership":
            s.execute(delete(InvestigationMember).where(
                InvestigationMember.investigation_id == inv,
                InvestigationMember.user_id == uid))
        elif change == "session":
            s.execute(update(UserSession).where(UserSession.user_id == uid)
                      .values(revoked_at=utcnow()))
        else:
            raise AssertionError(change)


def _spools(monkeypatch):
    streams = []
    original = export_jobs.tempfile.SpooledTemporaryFile
    def capture(*args, **kwargs):
        stream = original(*args, **kwargs)
        streams.append(stream)
        return stream
    monkeypatch.setattr(export_jobs.tempfile, "SpooledTemporaryFile", capture)
    return streams


@pytest.mark.parametrize("change", ["disabled", "role", "membership", "session"])
@pytest.mark.parametrize("mode", ["history", "stored", "html"])
def test_download_rechecks_current_authority_and_closes_private_spool(
        analyst, monkeypatch, change, mode):
    inv, run = finished(analyst)
    with session_scope() as s:
        uid = s.scalar(select(User.id).where(User.username == "analyst1"))
    if mode in {"history", "html"}:
        saved = analyst.post(f"/investigations/{inv}/report-versions",
                             json={"analysis_run_id": run}).json()
        suffix = "html" if mode == "html" else "xlsx"
        url = f"/investigations/{inv}/report-versions/{saved['id']}/{suffix}"
        from saw.reports import projection_html
        owner, attr = (projection_html, "render") if mode == "html" else (export_jobs, "render_artifact")
        original = getattr(owner, attr)
        def mutate_after_render(*args, **kwargs):
            result = original(*args, **kwargs)
            _change_authority(uid, inv, change)
            return result
        monkeypatch.setattr(owner, attr, mutate_after_render)
    else:
        job = request_job(analyst, scope((inv, run))).json()
        url = f"/report-export-jobs/{job['id']}/download"
        original = container.get().objects.open
        @contextmanager
        def mutate_after_read(*args, **kwargs):
            with original(*args, **kwargs) as source:
                yield source
            _change_authority(uid, inv, change)
        monkeypatch.setattr(container.get().objects, "open", mutate_after_read)
    streams = _spools(monkeypatch)
    response = analyst.get(url)
    assert response.status_code in {401, 403}, response.status_code
    assert "attachment" not in response.headers.get("content-disposition", "")
    assert (mode == "html" or streams) and all(stream.closed for stream in streams)


def test_stored_download_rechecks_cancellation_after_verifying_bytes(analyst, monkeypatch):
    job = request_job(analyst, scope(finished(analyst))).json()
    original = container.get().objects.open
    @contextmanager
    def cancel_after_read(*args, **kwargs):
        with original(*args, **kwargs) as source:
            yield source
        with session_scope() as s:
            if s.bind.dialect.name == "sqlite":
                s.connection().exec_driver_sql("PRAGMA busy_timeout=200")
            s.get(Job, job["id"]).cancel_requested = True
    monkeypatch.setattr(container.get().objects, "open", cancel_after_read)
    streams = _spools(monkeypatch)
    response = analyst.get(f"/report-export-jobs/{job['id']}/download")
    assert response.status_code == 409
    assert streams and all(stream.closed for stream in streams)

def test_history_html_enforces_shared_render_deadline(analyst, monkeypatch):
    inv, run = finished(analyst)
    report = analyst.post(f"/investigations/{inv}/report-versions",
                          json={"analysis_run_id": run}).json()
    monkeypatch.setattr(export_jobs, "MAX_SECONDS", -1)
    response = analyst.get(f"/investigations/{inv}/report-versions/{report['id']}/html")
    assert response.status_code == 400
    assert "report_export_time_limit" in response.text
