"""Independent synthetic probes for the final derived-source ACL integration."""
from sqlalchemy import select

from saw.storage.db import session_scope, utcnow
from saw.storage.models import Check, InvestigationMember, User
from tests.api.test_derived_finding_access import generated
from tests.conftest import Api, make_user


def test_story_edit_retains_original_private_source_closure(analyst, manager, app):
    uid = make_user("story-projection-reader", ["analyst"])
    with session_scope() as s:
        source, target, finding, _ = generated(s)
        for iid in (source.id, target.id):
            s.add(InvestigationMember(investigation_id=iid, user_id=uid, access="read"))
        source_id, target_id = source.id, target.id
    reader = Api(app, "story-projection-reader")
    before = analyst.get(f"/investigations/{target_id}/story")
    assert before.status_code == 200, before.text
    graph = before.json()["story"]["graph"]
    assert graph.pop("_source_investigation_ids", None), graph
    edited = analyst.put(f"/investigations/{target_id}/story", json={"graph": graph})
    assert edited.status_code == 200, edited.text
    with session_scope() as s:
        s.delete(s.get(InvestigationMember, (source_id, uid)))
    after = reader.get(f"/investigations/{target_id}/story")
    assert after.status_code in {403,404}, after.text


def test_golden_list_hides_private_derived_metadata_after_source_revocation(analyst, manager, senior):
    with session_scope() as s:
        source, target, finding, _ = generated(s)
        reviewer = s.scalar(select(User).where(User.username == "senior1"))
        uid, source_id, target_id = reviewer.id, source.id, target.id
        for iid in (source_id, target_id):
            s.add(InvestigationMember(investigation_id=iid, user_id=uid, access="read"))
        author = s.get(User, target.owner_id)
        now = utcnow().isoformat()
        scope = {"target_type":"entity", "target_key":"ip:198.51.100.8", "role":"src", "filters":[],
                 "time":None, "effective_time":None, "as_of":now, "scope_key":"peer-probe", "evidence_manifest":[]}
        capture = {"schema_version":1, "captured_at":now, "known_at":now, "as_of":now,
                   "temporally_valid":True, "methodology":{"id":"soc-guidance","version":"1.0","digest":"a"*64},
                   "scope":scope, "input":{"request":scope,"facts":[],"unknowns":[],"queries":[],"limits":[]},
                   "evidence_refs":[],"selected_events":[]}
        s.add(Check(investigation_id=target_id,target_type="entity",target_key="ip:198.51.100.8",
                    questions=["success"],judgement="undetermined",note="synthetic retained capture",
                    scope={"coverage":"all","guidance":{"follow_up":"verify synthetic source"}},
                    context={"guidance":capture},author_id=author.id,author_name=author.username,evidence=[]))
    closed = analyst.post(f"/investigations/{target_id}/close", json={"verdict":"unknown","reason":"synthetic",
                         "save_experience":True,"limits":"synthetic missing confirmation"})
    assert closed.status_code == 200, closed.text
    eid = closed.json()["experience_id"]
    prepared = analyst.post(f"/knowledge/golden/experience/{eid}/prepare",json={"expected_experience_rev":1})
    assert prepared.status_code == 201, prepared.text
    vid = prepared.json()["id"]
    assert senior.get(f"/knowledge/golden/experience/{eid}").status_code == 200
    with session_scope() as s:
        s.delete(s.get(InvestigationMember,(source_id,uid)))
    assert senior.get(f"/knowledge/golden/experience/{eid}").status_code in {403,404}
    listing = senior.get("/knowledge/golden")
    assert listing.status_code == 200, listing.text
    assert vid not in listing.text, listing.text
