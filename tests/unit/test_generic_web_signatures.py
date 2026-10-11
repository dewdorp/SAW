"""Synthetic regressions for precise web signatures and endpoint-only evidence."""
from __future__ import annotations

import pytest

from saw.detectors import signatures as sg


CASES = [
    ("webext.teamcity_rpc2", "POST", "/app/rest/users/id:7/tokens/RPC2"),
    ("webext.ivanti_epmm_users", "GET", "/mifs/aad/api/v2/authorized/users?rows=10"),
    ("apiuse.teamcity_process", "POST", "/app/rest/debug/processes?exePath=echo"),
    ("apiuse.docker_create", "POST", "/v1.45/containers/create?name=lab"),
    ("apiuse.docker_exec", "POST", "/v1.45/containers/lab/exec"),
    ("apiuse.docker_archive_read", "GET", "/v1.45/containers/lab/archive?path=/etc/shadow"),
    ("apiuse.docker_archive_write", "PUT", "/v1.45/containers/lab/archive?path=/tmp"),
    ("apiuse.etcd_range", "POST", "/v3/kv/range"),
    ("apiuse.etcd_auth_disable", "POST", "/v3/auth/disable"),
    ("apiuse.consul_service_register", "PUT", "/v1/agent/service/register"),
    ("apiuse.consul_acl_bootstrap", "PUT", "/v1/acl/bootstrap"),
    ("apiuse.nomad_exec", "GET", '/v1/client/allocation/00000000-1111-2222-3333-444444444444/exec?task=lab&command=["echo","test"]'),
    ("apiuse.vault_raw_read", "GET", "/v1/sys/raw/secret/lab"),
    ("apiuse.vault_root_generate", "POST", "/v1/sys/generate-root/attempt"),
    ("apiuse.webhdfs_privileged_read", "GET", "/webhdfs/v1/user/lab/report.csv?user.name=hdfs&op=OPEN"),
    ("apiuse.yarn_submit", "POST", "/ws/v1/cluster/apps"),
    ("wrapper.php_filter", "GET", "/view.php?file=php://filter/convert.base64-encode/resource=index.php"),
    ("wrapper.php_expect", "GET", "/view.php?file=expect://id"),
]


@pytest.mark.parametrize("sid,method,uri", CASES, ids=[c[0] for c in CASES])
def test_generic_web_content_recognises_specific_requests(sid, method, uri):
    assert sid in sg.sig_ids({"method": method, "uri": uri})


@pytest.mark.parametrize("sid,method,uri", CASES[:16], ids=[c[0] for c in CASES[:16]])
def test_management_request_method_and_path_boundaries(sid, method, uri):
    assert sid not in sg.sig_ids({"method": "HEAD", "uri": uri})
    path, sep, query = uri.partition("?")
    if sid not in ("apiuse.vault_raw_read", "apiuse.webhdfs_privileged_read"):
        assert sid not in sg.sig_ids({"method": method, "uri": path + "-guide" + sep + query})
    assert sid not in sg.sig_ids({"method": method, "uri": "/docs" + uri})


@pytest.mark.parametrize("sid", [c[0] for c in CASES])
def test_each_new_rule_has_counterexamples_and_cautious_guidance(sid):
    s = sg.by_id()[sid]
    assert len(s.examples) >= 2 and len(s.benign) >= 3
    assert "가능성" in s.title and "Possible" in s.title
    assert s.explain and s.checks
    if sid.startswith("apiuse."):
        assert not s.cve and s.confidence in ("low", "medium")
        assert "정상" in s.explain and "2xx" in s.explain


ENDPOINTS = [
    ("rce.spring_cloud_function", "/functionRouter"),
    ("rce.f5_icontrol", "/mgmt/tm/util/bash"),
    ("rce.fortinet_auth_bypass", "/api/v2/cmdb/system/admin"),
    ("rce.panos_2024_3400", "/ssl-vpn/hipreport.esp"),
]


@pytest.mark.parametrize("sid,path", ENDPOINTS)
def test_endpoint_alone_keeps_id_but_does_not_claim_a_cve_or_execution(sid, path):
    s = sg.by_id()[sid]
    assert sid in sg.sig_ids({"uri": path})
    assert s.cve == ""
    assert s.stage == "DISCOVERY" and s.confidence == "low" and s.severity <= 0.45
    assert "가능성" in s.title and "정상" in s.explain and "확정" in s.explain
    assert sid not in sg.sig_ids({"uri": path + ".bak"})
    assert sid not in sg.sig_ids({"uri": "/docs" + path})


def test_ordinary_parameter_names_and_documentation_stay_clear_of_new_rules():
    requests = [
        "/admin/login?data=1&id=2",
        "/api/v1/items?sort=id&data=archive&command=echo",
        "/docs/php-filter?example=php://filter/convert.base64-encode/resource=index.php",
        "/search?q=expect://id",
        "/api/search?file=php://memory",
        "/download?file=report.csv",
        "/webhdfs/v1/user/lab/report.csv?user.name=analyst&op=OPEN",
        "/webhdfs/v1/user/lab/report.csv?user.name=hdfs&op=GETFILESTATUS",
        "/v1.45/containers/lab/archive?path=/docs/readme.txt",
    ]
    for uri in requests:
        hits = sg.sig_ids({"uri": uri, "method": "GET"})
        assert not any(s.startswith(("webext.", "apiuse.", "wrapper.")) for s in hits), (uri, hits)
