"""Stable identity and network isolation for synthetic asset baselines."""
from __future__ import annotations

import pytest

from saw.knowledge import asset
from saw.knowledge.models import Asset
from saw.source_context.models import OrgUnit
from saw.storage.db import session_scope


@pytest.fixture
def stable_assets(app):
    with session_scope() as s:
        s.add_all([OrgUnit(id="org-a", display_name="Synthetic Shared Name", created_by="fixture"),
                   OrgUnit(id="org-b", display_name="Synthetic Shared Name", created_by="fixture")])
        for key, org, network, company in [
            ("A-PROD", "org-a", "prod", "Synthetic Shared Name"),
            ("B-PROD", "org-b", "prod", "Synthetic Shared Name"),
            ("B-TEST", "org-b", "test", "Synthetic Shared Name"),
            ("LEGACY-NAME", None, "", "Synthetic Shared Name"),
            ("LEGACY-GLOBAL", None, "", ""),
        ]:
            s.add(Asset(asset_id=key, service=key, criticality="critical", data={
                "org_unit_id": org, "network": network, "company": company,
                "ip": ["10.0.0.7"], "expected_uri": ["/shared"],
                "expected_request_rate": {"per_min": {"min": 1, "max": 10}},
                "batch_schedule": [{"name": "synthetic batch", "uri": "/shared"}],
            }))


def test_upsert_preserves_stable_identity_network_and_legacy_fields(senior):
    org = senior.post("/source-context/org-units", json={"display_name": "Synthetic A"}).json()
    response = senior.post("/assets", json={"asset_id": "stable", "service": "synthetic API", "data": {
        "org_unit_id": org["id"], "network": "isolated-prod", "company": "old label", "notes": "preserve me"}})
    assert response.status_code == 201
    assert response.json()["org_unit_id"] == org["id"]
    assert response.json()["network"] == "isolated-prod"
    updated = senior.post("/assets", json={"asset_id": "stable", "service": "synthetic API", "data": {"notes": "new note"}}).json()
    assert updated["org_unit_id"] == org["id"] and updated["network"] == "isolated-prod"
    assert updated["company"] == "old label" and updated["notes"] == "new note"


@pytest.mark.parametrize("data", [{"org_unit_id": "missing-org"}, {"org_unit_id": []}, {"network": []}, {"network": "x" * 129}])
def test_upsert_rejects_invalid_registry_identity_or_network(senior, data):
    response = senior.post("/assets", json={"asset_id": "invalid", "service": "synthetic", "data": data})
    assert response.status_code == 400
    assert senior.get("/assets").json() == []


def test_upsert_rejects_inactive_organization(stable_assets, senior):
    with session_scope() as s:
        s.get(OrgUnit, "org-b").state = "inactive"
    response = senior.post("/assets", json={"asset_id": "inactive", "service": "synthetic", "data": {"org_unit_id": "org-b"}})
    assert response.status_code == 400


def test_same_name_and_ip_do_not_cross_stable_identity_or_network(stable_assets):
    finding = {"entities": ["ip:10.0.0.7"], "metrics": [{"name": "request_rate_per_min", "observed": 30}]}
    with session_scope() as s:
        result = asset.context_for(s, finding, {}, org_unit_id="org-b", network="prod")
        scoped = [item for item in result if not item["reference_only"]]
        assert [item["asset_id"] for item in scoped] == ["B-PROD"]
        assert scoped[0]["comparisons"][0]["deviates"] is True
        assert not {"A-PROD", "B-TEST"} & {item["asset_id"] for item in result}
        legacy = next(item for item in result if item["asset_id"] == "LEGACY-NAME")
        assert legacy["reference_only"] is True and legacy["comparisons"] == []
        assert all(not batch["matches"] for batch in legacy["batch_schedule"])
        assert asset.AssetPortImpl(s, org_unit_id="org-b", network="prod").match_path("/shared/1")["asset_id"] == "B-PROD"
        assert asset.AssetPortImpl(s, org_unit_id="org-b", network="test").match_path("/shared/1")["asset_id"] == "B-TEST"


def test_network_specific_assets_are_only_references_when_network_unknown(stable_assets):
    with session_scope() as s:
        result = asset.context_for(s, None, {"dst_ips": ["10.0.0.7"]}, org_unit_id="org-b")
        assert result and all(item["reference_only"] for item in result)
        assert all(item["comparisons"] == [] for item in result)
        assert "A-PROD" not in str(result)
        with pytest.raises(ImportError):
            asset.AssetPortImpl(s, org_unit_id="org-b")


def test_company_only_assets_never_become_detector_baselines(stable_assets):
    with session_scope() as s:
        with pytest.raises(ImportError):
            asset.AssetPortImpl(s, org_unit_id="Synthetic Shared Name", network="prod")
        result = asset.context_for(s, None, {"dst_ips": ["10.0.0.7"]})
        assert [item["asset_id"] for item in result] == ["LEGACY-GLOBAL"]
        assert result[0]["scope_status"] == "legacy_unscoped"


def test_active_registry_is_rechecked_before_using_persisted_asset_scope(stable_assets):
    with session_scope() as s:
        s.get(OrgUnit, "org-b").state = "inactive"
        s.flush()
        with pytest.raises(ImportError):
            asset.AssetPortImpl(s, org_unit_id="org-b", network="prod")
        result = asset.context_for(s, None, {"dst_ips": ["10.0.0.7"]}, org_unit_id="org-b", network="prod")
        assert not any(not item["reference_only"] for item in result)


def test_organization_wide_assets_remain_explicitly_scoped_without_a_network(stable_assets):
    with session_scope() as s:
        s.add(Asset(asset_id="B-ALL", service="org-wide synthetic", data={"org_unit_id": "org-b", "expected_uri": ["/shared"]}))
        s.flush()
        port = asset.AssetPortImpl(s, org_unit_id="org-b")
        assert port.match_path("/shared/1")["asset_id"] == "B-ALL"
        # Explicit network policy wins over organization-wide policy for a known network.
        assert asset.AssetPortImpl(s, org_unit_id="org-b", network="prod").match_path("/shared/1")["asset_id"] == "B-PROD"
