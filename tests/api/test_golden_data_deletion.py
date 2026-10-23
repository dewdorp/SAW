"""Cleanup preserves immutable release sources and removes only owned failed artifacts."""
import io

from saw import container
from saw.storage.db import session_scope
from saw.storage.models import Job
from tests.api.test_admin_data import preview, execute
from tests.api.test_golden_governance import adopted_candidate, release_request


def test_published_release_explicitly_blocks_source_deletion(analyst, manager, admin):
    inv, _, golden = adopted_candidate(analyst, manager)
    built = analyst.post("/knowledge/golden/releases", json=release_request(analyst, golden))
    assert built.status_code == 202 and built.json()["job"]["state"] == "COMPLETED"
    plan = preview(admin, "investigation", inv["id"])
    assert "golden_reference" in plan["blockers"]
    assert execute(admin, plan).status_code == 409


def test_failed_single_source_job_cleanup_is_bounded_to_exact_owned_prefix(analyst, admin):
    inv = analyst.post("/investigations", json={"title": "Synthetic cleanup source"}).json()
    with session_scope() as s:
        job = Job(investigation_id=inv["id"], kind="golden_export", state="FAILED",
                  requested_by="synthetic", stages={"source_ids": [inv["id"]]})
        s.add(job); s.flush(); jid = job.id
    objects = container.get().objects
    own = f"golden/{jid}/1/artifact/synthetic.zip"
    other = f"golden/{jid}-other/1/artifact/synthetic.zip"
    for key in (own, other):
        objects.put_stream("saw-exports", key, io.BytesIO(b"Synthetic private artifact"))
    plan = preview(admin, "investigation", inv["id"])
    assert not plan["blockers"], plan
    result = execute(admin, plan)
    assert result.status_code == 200 and result.json()["state"] == "COMPLETED", result.text
    assert not objects.exists("saw-exports", own)
    assert objects.exists("saw-exports", other)
