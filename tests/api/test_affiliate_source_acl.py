"""Synthetic regressions for source ACL and affiliate-scoped asset context."""
from __future__ import annotations

import pytest
from sqlalchemy import select

from saw.core.application import checks
from saw.core.application.investigations import Forbidden
from saw.core.domain.enums import Role
from saw.core.security.authz import Principal
from saw.knowledge import asset
from saw.knowledge.models import Asset
from saw.source_context.models import OrgUnit
from saw.storage.db import session_scope
from saw.storage.models import AuditEvent, Check, InvestigationMember
from tests.api import test_checks as check_tests

two = check_tests.two


def _revoke_source(two):
    with session_scope() as s:
        member = s.execute(select(InvestigationMember).where(
            InvestigationMember.investigation_id == two["a"]["id"],
            InvestigationMember.user_id != two["shared"]["author_id"])).scalar_one()
        reader_id = member.user_id
        s.delete(member)
    return Principal(reader_id, "a2", frozenset({Role.ANALYST}))


def test_unreadable_source_has_no_team_metadata(two):
    _revoke_source(two)
    response = two["other"].post(f"/investigations/{two['b']['id']}/checks/team",
                                  json={"keys": [f"ip:{two['ip']}"]})
    assert response.status_code == 200
    assert response.json() == {"items": []}


@pytest.mark.parametrize("action", ["evidence", "cite", "recheck"])
def test_known_shared_id_does_not_bypass_source_acl(two, action):
    _revoke_source(two)
    other, source = two["other"], two["shared"]["id"]
    if action == "evidence":
        response = other.get(f"/team-checks/{source}/evidence")
    elif action == "cite":
        response = other.post(f"/investigations/{two['b']['id']}/checks/cite", json={"source_id": source})
    else:
        response = other.post(f"/team-checks/{source}/recheck", json={"note": "synthetic recheck"})
    assert response.status_code in (403, 404)
    assert two["a"]["id"] not in response.text
    assert two["a"]["title"] not in response.text
    with session_scope() as s:
        assert s.scalar(select(Check).where(Check.investigation_id == two["b"]["id"])) is None
        assert s.get(Check, source).share_status == "unreviewed"
        assert s.scalar(select(AuditEvent).where(AuditEvent.action == "check.evidence_view")) is None


def test_revoked_source_is_hidden_from_local_citations_and_inbox(two):
    other, inv_id = two["other"], two["b"]["id"]
    cited = other.post(f"/investigations/{inv_id}/checks/cite", json={"source_id": two["shared"]["id"]}).json()
    with session_scope() as s:
        s.get(Check, cited["id"]).source_state = "changed"
    principal = _revoke_source(two)
    with session_scope() as s:
        assert checks.list_checks(s, inv_id) == []
        assert checks.list_checks(s, inv_id, principal=principal) == []
        assert checks.summary(s, inv_id, principal=principal)["total"] == 0
        assert checks.marks(s, inv_id, principal=principal) == {"events": {}, "entities": {}, "findings": {}}
        assert checks.lookup(s, inv_id, [], [f"ip:{two['ip']}"], principal=principal) == {"events": {}, "entities": {}}
    assert other.get("/team-checks/inbox").json() == {"recheck": [], "source_changed": []}
    assert other.put(f"/investigations/{inv_id}/checks/{cited['id']}", json={"note": "x"}).status_code in (403, 404)
    assert other.post(f"/investigations/{inv_id}/checks/{cited['id']}/cancel", json={"note": "x"}).status_code in (403, 404)


def test_team_citation_counts_exclude_unreadable_investigations(two, analyst):
    two["other"].post(f"/investigations/{two['b']['id']}/checks/cite", json={"source_id": two["shared"]["id"]}).raise_for_status()
    own = analyst.post("/investigations", json={"title": "readable target"}).json()
    result = analyst.post(f"/investigations/{own['id']}/checks/team", json={"keys": [f"ip:{two['ip']}"]}).json()
    assert len(result["items"]) == 1
    assert result["items"][0]["citations"] == 0


@pytest.fixture
def scoped_assets(app):
    with session_scope() as s:
        s.add_all([OrgUnit(id="acl-org-a", display_name="Affiliate A", created_by="fixture"),
                   OrgUnit(id="acl-org-b", display_name="Affiliate B", created_by="fixture")])
        for key, company, org_id in [("AS-A", "Affiliate A", "acl-org-a"), ("AS-B", "Affiliate B", "acl-org-b"), ("AS-LEGACY", "", None)]:
            s.add(Asset(asset_id=key, service=key, criticality="high", data={
                "org_unit_id": org_id, "company": company, "ip": ["10.0.0.7"], "hostname": "shared-host",
                "expected_uri": ["/shared"], "expected_request_rate": {"per_min": {"max": 10}},
                "known_exception": [{"reason": "synthetic", "expires_at": "2099-01-01"}]}))


def test_same_ip_asset_context_only_uses_investigation_affiliate(scoped_assets):
    with session_scope() as s:
        result = asset.context_for(s, None, {"dst_ips": ["10.0.0.7"]}, org_unit_id="acl-org-b")
        scoped = [item for item in result if not item["reference_only"]]
        assert [item["asset_id"] for item in scoped] == ["AS-B"]
        assert "AS-A" not in str(result)
        legacy = next(item for item in result if item["asset_id"] == "AS-LEGACY")
        assert legacy["reference_only"] is True and legacy["comparisons"] == []


def test_unknown_affiliate_context_cannot_guess_from_ip(scoped_assets):
    with session_scope() as s:
        result = asset.context_for(s, None, {"dst_ips": ["10.0.0.7"]})
        assert [item["asset_id"] for item in result] == ["AS-LEGACY"]
        assert result[0]["reference_only"] is True


def test_detector_asset_port_never_uses_foreign_or_unscoped_policy(scoped_assets):
    with session_scope() as s:
        port = asset.AssetPortImpl(s, org_unit_id="acl-org-b")
        assert port.match_path("/shared/customer")["asset_id"] == "AS-B"
        with pytest.raises(ImportError):
            asset.AssetPortImpl(s)
        with pytest.raises(ImportError):
            asset.AssetPortImpl(s, org_unit_id="missing-org")


def test_report_source_ledger_validates_transitive_citation_acl(two, analyst):
    target = two["b"]["id"]
    two["other"].post(f"/investigations/{target}/checks/cite", json={"source_id": two["shared"]["id"]}).raise_for_status()
    with session_scope() as s:
        reader = s.execute(select(InvestigationMember).where(
            InvestigationMember.investigation_id == two["a"]["id"],
            InvestigationMember.user_id != two["shared"]["author_id"])).scalar_one()
        principal = Principal(reader.user_id, "a2", frozenset({Role.ANALYST}))
        assert checks.source_investigation_ids(s, principal, target) == {target, two["a"]["id"]}
    third = analyst.post("/investigations", json={"title": "transitive source"}).json()
    ancestor = analyst.post(f"/investigations/{third['id']}/checks", json={
        "target_type": "entity", "target_key": "ip:192.0.2.123", "questions": ["nature"]}).json()
    with session_scope() as s:
        # A pre-existing cited chain must not grant access through its readable intermediate source.
        source = s.get(Check, two["shared"]["id"])
        source.kind, source.source_check_id = "cited", ancestor["id"]
    with session_scope() as s:
        with pytest.raises(Forbidden):
            checks.source_investigation_ids(s, principal, target)
        assert checks.list_checks(s, target, principal=principal) == []
    analyst.post(f"/investigations/{third['id']}/members", json={"user_id": principal.user_id, "access": "viewer"}).raise_for_status()
    with session_scope() as s:
        assert checks.source_investigation_ids(s, principal, target) == {target, two["a"]["id"], third["id"]}
