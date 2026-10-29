"""Golden jobs never expose private inputs and cannot mutate source manifests."""
from saw.analysis_runs.scoped import _manifest
from saw.apps.api.routers.evidence import job_out
from saw.event_generations.reads import actor_scope
from saw.storage.db import session_scope
from saw.storage.models import Job


def test_golden_job_output_excludes_private_input_mapping_and_object_keys():
    job = Job(id="synthetic-job", kind="golden_export", state="QUEUED",
              investigation_id="synthetic-inv", requested_by="synthetic-user",
              stages={"golden_export": {"release_id": "synthetic-release",
                  "version_id": None, "artifact": None, "state": "building"},
                  "input_ref": {"key": "PRIVATE_OBJECT_PATH"},
                  "private_context": {"mapping_seed": "PRIVATE_MAPPING_SEED"},
                  "frozen_inputs": {"answers": "PRIVATE_EVALUATOR_ANSWER"},
                  "request_sha256": "a" * 64})
    output = job_out(job)
    assert "PRIVATE_" not in str(output)
    assert output["stages"]["golden_export"]["release_id"] == "synthetic-release"


def test_readonly_golden_job_does_not_change_analysis_source_manifest(analyst):
    inv = analyst.post("/investigations", json={"title": "Synthetic Golden job scope"}).json()["id"]
    with actor_scope(analyst.get("/auth/me").json()["id"]), session_scope() as s:
        before = _manifest(s, inv)
        s.add(Job(investigation_id=inv, kind="golden_export", requested_by="synthetic",
                  state="QUEUED", stages={"golden_export": {"release_id": "synthetic-release"}}))
    with actor_scope(analyst.get("/auth/me").json()["id"]), session_scope() as s:
        assert _manifest(s, inv) == before


def test_secondary_source_revocation_hides_golden_job_list_and_detail(app, analyst):
    from saw.reports.models import JobSourceInvestigation
    from saw.storage.models import InvestigationMember
    from tests.conftest import Api, make_user
    first = analyst.post("/investigations", json={"title":"Synthetic first"}).json()["id"]
    second = analyst.post("/investigations", json={"title":"Synthetic second"}).json()["id"]
    uid = make_user("golden-source-reader", ["analyst"])
    with session_scope() as s:
        s.add(InvestigationMember(investigation_id=first,user_id=uid,access="viewer"))
        job = Job(investigation_id=first,kind="golden_export",requested_by=uid,state="QUEUED",
                  stages={"golden_export":{"release_id":"synthetic-release"},
                          "source_ids":[first,second]})
        s.add(job); s.flush(); jid=job.id
        s.add_all(JobSourceInvestigation(job_id=jid,investigation_id=i) for i in (first,second))
    reader = Api(app,"golden-source-reader")
    assert reader.get(f"/jobs/{jid}").status_code == 403
    assert jid not in {j["id"] for j in reader.get("/jobs").json()}


def test_real_release_submission_stores_verified_private_zip_and_idempotent_job(analyst,manager):
    import hashlib
    import zipfile
    from saw import container
    from saw.knowledge.golden_governance_models import GoldenReleaseVersion
    from tests.api.test_golden_governance import adopted_candidate,release_request
    _, _, g = adopted_candidate(analyst,manager)
    request = release_request(analyst,g)
    response = analyst.post("/knowledge/golden/releases",json=request)
    assert response.status_code == 202, response.text
    result = response.json()
    assert result["job"]["state"] == "COMPLETED", result
    duplicate = analyst.post("/knowledge/golden/releases",json=request)
    assert duplicate.status_code == 202 and duplicate.json()["job_id"] == result["job_id"]
    job = analyst.get(f"/jobs/{result['job_id']}").json()
    assert "PRIVATE_" not in str(job) and "input_ref" not in str(job)
    assert "mapping_seed" not in str(job) and "object_key" not in str(job)
    with session_scope() as s:
        version = s.get(GoldenReleaseVersion,result["current_version_id"])
        assert version and version.size_bytes > 0
        reference = version.private_objects["artifact"]
        with container.get().objects.open(reference["bucket"],reference["key"]) as stream:
            data = stream.read()
        assert len(data) == version.size_bytes
        assert hashlib.sha256(data).hexdigest() == version.artifact_sha256
    import io
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        assert "manifest.json" in z.namelist() and z.testzip() is None
    assert analyst.get(f"/knowledge/golden/releases/{result['release_id']}/versions/{result['current_version_id']}/download").status_code in (403,409)
