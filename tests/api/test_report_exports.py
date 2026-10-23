"""Synthetic contracts for frozen reports and exact source-scoped export jobs."""
from sqlalchemy import select
from saw import container
from saw.analysis_runs import service as runs
from saw.core.application import identity
from saw.storage.db import session_scope
from saw.storage.models import Investigation, InvestigationMember, Job, User
from tests.conftest import Api, make_user


def finished(analyst, title="가상 관계사 보고"):
    inv = analyst.post("/investigations", json={"title": title}).json()["id"]
    with session_scope() as s:
        row = runs.start(s, inv)
        row.created_by = s.get(Investigation, inv).owner_id
        runs.record(s, row, "fw.observation", "1", "insufficient_data",
                    detail={"reason": "no_synthetic_input"}, input_count=0, match_count=None)
        runs.finish(s, row, status="insufficient_data")
        run_id = row.id
    return inv, run_id


def scope(*pairs):
    return {"kind": "investigations" if len(pairs) > 1 else "investigation",
            "selections": [{"investigation_id": inv, "analysis_run_id": run,
                            "followup_version_ids": None} for inv, run in pairs]}


def request_job(analyst, selections, key="synthetic-export", fmt="html"):
    return analyst.post("/report-export-jobs", json={"scope": selections,
                        "format": fmt, "idempotency_key": key})


def test_single_report_v2_freezes_exact_finished_run(analyst):
    inv, run = finished(analyst)
    out = analyst.post(f"/investigations/{inv}/report-versions", json={"analysis_run_id": run})
    assert out.status_code == 201, out.text
    content = out.json()["content"]
    assert content["schema_version"] == "saw.report.v2"
    assert content["scope"] == scope((inv, run))
    assert content["items"][0]["analysis"]["id"] == run
    assert content["items"][0]["analysis"]["status"] == "insufficient_data"
    analyst.patch(f"/investigations/{inv}", json={"title": "나중에 수정한 이름"})
    again = analyst.get(f"/investigations/{inv}/report-versions/{out.json()['id']}")
    assert again.json()["content"] == content


def test_multi_report_job_exact_selection_and_idempotency(analyst):
    a, b = finished(analyst, "가상 A"), finished(analyst, "가상 B")
    chosen = scope(a, b)
    first = request_job(analyst, chosen)
    assert first.status_code == 202, first.text
    job = first.json()
    assert job["kind"] == "report_export" and job["state"] == "COMPLETED"
    stage = job["stages"]["report_export"]
    assert stage["scope"] == chosen and stage["artifact"]["bytes"] > 0
    duplicate = request_job(analyst, chosen)
    assert duplicate.status_code == 202 and duplicate.json()["id"] == job["id"]
    conflict = request_job(analyst, scope(a))
    assert conflict.status_code == 409
    download = analyst.get(f"/report-export-jobs/{job['id']}/download")
    assert download.status_code == 200 and "가상 A" in download.text and "가상 B" in download.text


def test_multi_report_requires_every_target_writer(app, analyst):
    a, b = finished(analyst), finished(analyst)
    uid = make_user("report-target-reader", ["analyst"])
    with session_scope() as s:
        s.add_all([InvestigationMember(investigation_id=a[0], user_id=uid, access="editor"),
                   InvestigationMember(investigation_id=b[0], user_id=uid, access="viewer")])
    reader = Api(app, "report-target-reader")
    out = request_job(reader, scope(a, b))
    assert out.status_code == 403
    with session_scope() as s:
        assert s.scalar(select(Job).where(Job.requested_by == uid, Job.kind == "report_export")) is None


def test_multi_report_revoked_source_hides_job_and_download(app, analyst):
    a, b = finished(analyst), finished(analyst)
    uid = make_user("report-both-editor", ["analyst"])
    with session_scope() as s:
        for inv, _ in (a, b):
            s.add(InvestigationMember(investigation_id=inv, user_id=uid, access="editor"))
    other = Api(app, "report-both-editor")
    out = request_job(other, scope(a, b))
    assert out.status_code == 202, out.text
    jid = out.json()["id"]
    with session_scope() as s:
        s.delete(s.get(InvestigationMember, (b[0], uid)))
    assert other.get(f"/jobs/{jid}").status_code == 403
    assert other.get(f"/report-export-jobs/{jid}/download").status_code == 403
    assert jid not in {j["id"] for j in other.get("/jobs").json()}


def test_export_failure_retry_new_job_same_frozen_snapshot(analyst, monkeypatch):
    from saw.reports import export_jobs
    inv, run = finished(analyst)
    original = export_jobs.render_artifact
    def fail(*args, **kwargs):
        raise RuntimeError("synthetic writer failure")
    monkeypatch.setattr(export_jobs, "render_artifact", fail)
    first = request_job(analyst, scope((inv, run)))
    assert first.status_code == 202, first.text
    job = first.json()
    assert job["state"] == "FAILED" and not job["stages"]["report_export"]["artifact"]
    monkeypatch.setattr(export_jobs, "render_artifact", original)
    retried = analyst.post(f"/jobs/{job['id']}/retry")
    assert retried.status_code == 200, retried.text
    newer = retried.json()
    assert newer["id"] != job["id"] and newer["state"] == "COMPLETED"
    assert newer["stages"]["report_export"]["report_id"] == job["stages"]["report_export"]["report_id"]
    assert analyst.get(f"/jobs/{job['id']}").json()["state"] == "FAILED"


def test_export_validates_explicit_scope_no_silent_duplicate_or_empty(analyst):
    pair = finished(analyst)
    duplicate = scope(pair, pair)
    assert request_job(analyst, duplicate).status_code in {400, 422}
    assert request_job(analyst, {"kind": "investigations", "selections": []}).status_code in {400, 422}
    wrong = scope(pair)
    wrong["selections"][0]["analysis_run_id"] = "missing"
    assert request_job(analyst, wrong).status_code == 404


def test_legacy_v1_report_content_and_html_remain_readable(analyst):
    from saw.reports.models import ReportVersion, ReportSourceInvestigation
    from saw.core.application.provenance import digest
    inv, run = finished(analyst, "legacy synthetic report")
    created = analyst.post(f"/investigations/{inv}/report-versions",
                            json={"analysis_run_id": run}).json()
    item = created["content"]["items"][0]
    legacy = {"schema_version": "saw.report.v1", "investigation": item["investigation"],
              "analysis": item["analysis"], "checks": [], "limits": ["legacy scope"],
              "masking_policy": "authenticated-source-acl-v1"}
    with session_scope() as s:
        row = ReportVersion(investigation_id=inv, version=2,
                            created_by=s.get(Investigation, inv).owner_id,
                            source_investigation_ids=[inv], content=legacy,
                            content_sha256=digest(legacy))
        s.add(row); s.flush(); report_id = row.id
        s.add(ReportSourceInvestigation(report_id=row.id, investigation_id=inv))
    analyst.patch(f"/investigations/{inv}", json={"title": "changed afterwards"})
    out = analyst.get(f"/investigations/{inv}/report-versions/{report_id}")
    assert out.status_code == 200 and out.json()["content"] == legacy
    assert out.json()["content_sha256"] == digest(legacy)
    html = analyst.get(f"/investigations/{inv}/report-versions/{report_id}/html")
    assert html.status_code == 200 and "legacy synthetic report" in html.text
    assert "changed afterwards" not in html.text
