"""Permanent regressions from independent governance review; synthetic sources only."""
import pytest
from sqlalchemy import select
from saw.core.application import identity, investigations
from saw.detection import governance as g, service
from saw.detection.policy_models import PolicyVersion
from saw.source_context.models import Device, OrgUnit
from saw.storage.db import session_scope
from saw.storage.models import User
from tests.api.test_sigma_auto import setup_rule



def test_device_policy_scope_never_crosses_affiliate_for_same_device(analyst):
    with session_scope() as s:
        user=s.scalar(select(User).where(User.username=="analyst1"))
        p=identity.principal_of(user)
        inv=investigations.create(s,p,"Synthetic review scope")
        a=OrgUnit(display_name="Synthetic same label",created_by=p.user_id)
        b=OrgUnit(display_name="Synthetic same label",created_by=p.user_id)
        s.add_all([a,b])
        s.flush()
        dev=Device(investigation_id=inv.id,display_name="Synthetic shared sensor",created_by=p.user_id)
        s.add(dev)
        s.flush()
        binding=g.draft_policy(s,p,{"detector_id":"fw.observation",
            "scope":{"kind":"device","org_unit_id":a.id,"device_id":dev.id},
            "expected_draft_version_id":None,"changes":{"set":{"scan_min_targets":9},"inherit":[]},
            "reason":"Synthetic exact-scope review"})
        version=s.get(PolicyVersion,binding.draft_version_id)
        scope_a={"kind":"device","org_unit_id":a.id,"device_id":dev.id}
        scope_b={"kind":"device","org_unit_id":b.id,"device_id":dev.id}
        assert g.resolve_effective(s,"fw.observation",scope_a,p=p,candidate=version)["values"]["scan_min_targets"]==9
        with pytest.raises(g.Conflict):
            g.resolve_effective(s,"fw.observation",scope_b,p=p,candidate=version)
        assert g.resolve_effective(s,"fw.observation",scope_b,p=p)["values"]["scan_min_targets"]==5
        other=g.draft_policy(s,p,{"detector_id":"fw.observation","scope":scope_b,
            "expected_draft_version_id":None,"changes":{"set":{"scan_min_targets":17},"inherit":[]},
            "reason":"Synthetic distinct affiliated policy"})
        assert other.id != binding.id and other.scope_key != binding.scope_key
        other_version=s.get(PolicyVersion,other.draft_version_id)
        assert g.resolve_effective(s,"fw.observation",scope_b,p=p,candidate=other_version)["values"]["scan_min_targets"]==17
        assert g.resolve_effective(s,"fw.observation",scope_a,p=p,candidate=version)["values"]["scan_min_targets"]==9



def test_source_rule_pin_never_crosses_investigation_even_when_actor_reads_both(analyst,manager):
    with session_scope() as s:
        source,det,_,_=setup_rule(s)
        p=identity.principal_of(s.get(User,det.created_by))
        det.source={"investigation_id":source.id}
        target=investigations.create(s,p,"Synthetic second readable investigation")
        pin=g.pin_runtime(s,p,target.id,[{"kind":"group"}])
        assert not any(row["rule"]["id"]==det.id for row in pin["rules"])


def test_actual_runtime_uses_captured_rule_while_later_draft_is_unapproved(analyst,manager):
    from saw.detection.auto import run_approved
    with session_scope() as s:
        inv,det,version,ctx=setup_rule(s)
        p=identity.principal_of(s.get(User,det.created_by))
        ctx.params["runtime_pin"]=g.pin_runtime(s,p,inv.id,[{"kind":"group"}])
        service.update(s,p,det.id,{"logic":version.logic.replace("/selected","/different")})
        drafts,_=run_approved(s,ctx)
        assert len(drafts)==1 and drafts[0].total_events==2
        assert drafts[0].detector_version=="1"


def test_runtime_pin_keeps_selected_proof_sources_and_rechecks_revoked_source_acl(analyst,manager):
    from saw.detection import runtime_capture
    from saw.core.application.investigations import Forbidden
    from saw.storage.models import InvestigationMember
    with session_scope() as s:
        source,det,_,_=setup_rule(s)
        p=identity.principal_of(s.get(User,det.created_by))
        target=investigations.create(s,p,"Synthetic other target")
        pin=g.pin_runtime(s,p,target.id,[{"kind":"group"}])
        rule=next(row for row in pin["rules"] if row["rule"]["id"]==det.id)
        assert source.id in rule["source_investigation_ids"]
        assert source.id in runtime_capture.sources(pin)
        s.delete(s.get(InvestigationMember,(source.id,p.user_id)))
        s.flush()
        with pytest.raises(Forbidden):
            runtime_capture.authorize(s,p,target.id,pin,writing=True)


def test_revoked_selected_proof_source_blocks_publication_even_with_readable_target(analyst,manager):
    from saw.detection import runtime_capture
    from saw.core.application.investigations import Forbidden
    from saw.storage.models import InvestigationMember
    with session_scope() as s:
        source,det,_,_=setup_rule(s)
        p=identity.principal_of(s.get(User,det.created_by))
        target=investigations.create(s,p,"Synthetic publication target")
        pin=g.pin_runtime(s,p,target.id,[{"kind":"group"}])
        s.delete(s.get(InvestigationMember,(source.id,p.user_id)))
        s.flush()
        with pytest.raises(Forbidden):
            runtime_capture.authorize(s,p,target.id,pin,writing=True)


def test_active_parent_policy_keeps_approval_proof_sources_in_effective_runtime(analyst,senior):
    from tests.api.test_selected_policy_truth import test_signature_disable_uses_actual_examples_and_explicit_apply
    from saw.detection.policy_models import Approval,PolicyBinding
    from saw.detection import runtime_capture
    from saw.storage.models import InvestigationMember
    from saw.core.application.investigations import Forbidden
    test_signature_disable_uses_actual_examples_and_explicit_apply(analyst,senior)
    with session_scope() as s:
        binding=s.scalar(select(PolicyBinding))
        approval=s.get(Approval,binding.active_approval_id)
        source=approval.source_investigation_ids[0]
        user=s.scalar(select(User).where(User.username=="analyst1"))
        p=identity.principal_of(user)
        effective=g.resolve_effective(s,binding.detector_id,{"kind":"group"},p=p)
        assert source in effective["source_investigation_ids"]
        assert set(approval.contributor_ids).issubset(effective["contributors"]["ids"])
        target=investigations.create(s,p,"Synthetic policy runtime target")
        pin=g.pin_runtime(s,p,target.id,[{"kind":"group"}])
        assert source in runtime_capture.sources(pin)
        s.delete(s.get(InvestigationMember,(source,p.user_id)))
        s.flush()
        with pytest.raises(Forbidden):
            runtime_capture.authorize(s,p,target.id,pin,writing=True)
