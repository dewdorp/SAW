"""Local development seed: test users (TOTP pre-enrolled) + demo investigation.

Credentials are written to var/dev-credentials.json (git-ignored) — never use in production.
Usage: python -m saw.devtools.seed  |  python -m saw.devtools.seed totp <username>
"""
from __future__ import annotations

import json
import secrets
import string
import sys
from pathlib import Path

import pyotp
from sqlalchemy import select

from saw import container
from saw.core.application import identity
from saw.core.application import investigations as inv_svc
from saw.storage.db import session_scope
from saw.storage.models import Investigation, User

from saw.config import VAR

CRED = VAR / "dev-credentials.json"
USERS = [("analyst", ["analyst"], "분석가 (dev)"), ("senior", ["senior_analyst"], "선임 분석가 (dev)"),
         ("manager", ["soc_manager"], "관제 매니저 (dev)"), ("admin", ["admin"], "관리자 (dev)")]


def _pw() -> str:
    a = string.ascii_letters + string.digits
    return "Dev!" + "".join(secrets.choice(a) for _ in range(14)) + "9a"


def seed_users() -> dict:
    creds = json.loads(CRED.read_text(encoding="utf-8")) if CRED.exists() else {}
    with session_scope() as s:
        for name, roles, disp in USERS:
            u = s.execute(select(User).where(User.username == name)).scalar_one_or_none()
            if u is None:
                pw = _pw()
                identity.create_user(s, name, pw, roles, disp)
                # MFA is NOT pre-enrolled: the first login shows the QR enrollment screen for the user's authenticator app
                creds[name] = {"password": pw, "roles": roles}
    CRED.parent.mkdir(parents=True, exist_ok=True)
    CRED.write_text(json.dumps(creds, indent=2), encoding="utf-8")
    return creds


def seed_demo() -> str | None:
    from saw.core.application import evidence as ev_svc
    from saw.devtools.sample_data import gz_bytes, scenario_waf_jsonl, scenario_weblog
    from saw.workers.pipeline import ingest_run

    with session_scope() as s:
        if s.execute(select(Investigation).where(Investigation.title == "Customer API 대량 조회 의심 (demo)")).first():
            return None
        u = s.execute(select(User).where(User.username == "analyst")).scalar_one()
        p = identity.principal_of(u)
        inv = inv_svc.create(s, p, "Customer API 대량 조회 의심 (demo)")
        jobs = []
        for kind, name, data in (("web_log", "access.log.gz", gz_bytes(scenario_weblog())),
                                 ("waf_log", "waf_events.jsonl", ("\n".join(scenario_waf_jsonl()) + "\n").encode())):
            e = ev_svc.create_evidence(s, p, inv.id, kind, name)
            sess = ev_svc.start_upload(s, p, e.id, name, len(data))
            ev_svc.put_part(s, p, sess.id, 1, data)
            ev_svc.complete_upload(s, p, sess.id)
            jobs.append(ev_svc.start_processing(s, p, e.id)[0].id)
        inv_id = inv.id
    for j in jobs:
        ingest_run(j)
    return inv_id


def seed_network() -> str | None:
    """Add Zeek/Suricata logs (PCAP-derived) to the demo investigation → unified investigation (Phase 6/7)."""
    import io
    import zipfile

    from saw.core.application import evidence as ev_svc
    from saw.devtools.sample_data import scenario_zeek
    from saw.storage.models import Evidence
    from saw.workers.pipeline import ingest_run

    with session_scope() as s:
        inv = s.execute(select(Investigation).where(Investigation.title == "Customer API 대량 조회 의심 (demo)")).scalar_one_or_none()
        if inv is None or s.execute(select(Evidence).where(Evidence.investigation_id == inv.id, Evidence.kind == "pcap")).first():
            return None
        u = s.execute(select(User).where(User.username == "analyst")).scalar_one()
        p = identity.principal_of(u)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for name, lines in scenario_zeek().items():
                z.writestr(name, "\n".join(lines) + "\n")
        data = buf.getvalue()
        e = ev_svc.create_evidence(s, p, inv.id, "pcap", "capture-0105 (zeek+suricata logs)")
        sess = ev_svc.start_upload(s, p, e.id, "capture-0105_zeek.zip", len(data))
        ev_svc.put_part(s, p, sess.id, 1, data)
        ev_svc.complete_upload(s, p, sess.id)
        job = ev_svc.start_processing(s, p, e.id)[0].id
        inv_id = inv.id
    ingest_run(job)
    return inv_id


def seed_pcap_forensics() -> str | None:
    """Raw PCAP (built-in forensic analyzer) + an IOC list in the demo investigation (ADR-0016)."""
    import hashlib

    from saw.core.application import evidence as ev_svc
    from saw.devtools.sample_data import PE_SAMPLE, scenario_pcap_forensics
    from saw.storage.models import Evidence
    from saw.workers.pipeline import ingest_run

    jobs = []
    with session_scope() as s:
        inv = s.execute(select(Investigation).where(Investigation.title == "Customer API 대량 조회 의심 (demo)")).scalar_one_or_none()
        if inv is None or s.execute(select(Evidence).where(Evidence.investigation_id == inv.id,
                                                           Evidence.title == "incident-0106.pcap (raw capture)")).first():
            return None
        p = identity.principal_of(s.execute(select(User).where(User.username == "analyst")).scalar_one())
        iocs = "\n".join(["# 공유 IOC (합성)", "203[.]0[.]113[.]66", hashlib.sha256(PE_SAMPLE).hexdigest(), ""]).encode()
        for kind, title, name, data in (("ioc_list", "공유 IOC 목록", "iocs.txt", iocs),
                                        ("pcap", "incident-0106.pcap (raw capture)", "incident-0106.pcap", scenario_pcap_forensics())):
            e = ev_svc.create_evidence(s, p, inv.id, kind, title)
            sess = ev_svc.start_upload(s, p, e.id, name, len(data))
            ev_svc.put_part(s, p, sess.id, 1, data)
            ev_svc.complete_upload(s, p, sess.id)
            jobs.append(ev_svc.start_processing(s, p, e.id)[0].id)
        inv_id = inv.id
    for j in jobs:
        ingest_run(j)
    return inv_id


def seed_knowledge() -> str | None:
    """Asset + a prior closed investigation with an approved SOC Experience (4-eyes: analyst writes, manager approves)."""
    from saw.core.application import analysis
    from saw.core.application import evidence as ev_svc
    from saw.devtools.sample_data import gz_bytes, scenario_weblog
    from saw.knowledge import asset as asset_svc
    from saw.knowledge import experience as exp_svc
    from saw.knowledge.models import Asset
    from saw.knowledge.similar import index_investigation
    from saw.workers.pipeline import ingest_run

    with session_scope() as s:
        if s.execute(select(Asset).where(Asset.asset_id == "AST-API-0012")).first():
            return None
        senior = identity.principal_of(s.execute(select(User).where(User.username == "senior")).scalar_one())
        asset_svc.upsert(s, senior, "AST-API-0012", "Customer Lookup API", "high", {
            "domain": ["service.example.com"], "ip": ["10.10.1.21"], "expected_uri": ["/api/customer"],
            "expected_request_rate": {"per_min": {"min": 18, "max": 32}}, "expected_access_time": {"weekday": "07:00-23:00"},
            "expected_country": ["KR"], "data_classification": "개인정보", "internet_exposed": True, "owner": "홍길동",
            "department": "디지털채널개발부",
            "batch_schedule": [{"name": "Customer Sync", "cron": "0 3 * * *", "src": "10.20.3.5", "uri": "/internal/sync"}]})
        analyst = identity.principal_of(s.execute(select(User).where(User.username == "analyst")).scalar_one())
        prior = inv_svc.create(s, analyst, "2026-10-02 API 순차 조회 (prior case)")
        data = gz_bytes(scenario_weblog(seed=3, normal=600, enum_count=500))
        e = ev_svc.create_evidence(s, analyst, prior.id, "web_log", "access_1002.log.gz")
        sess = ev_svc.start_upload(s, analyst, e.id, "access_1002.log.gz", len(data))
        ev_svc.put_part(s, analyst, sess.id, 1, data)
        ev_svc.complete_upload(s, analyst, sess.id)
        job = ev_svc.start_processing(s, analyst, e.id)[0].id
        prior_id = prior.id
    ingest_run(job)
    with session_scope() as s:
        analyst = identity.principal_of(s.execute(select(User).where(User.username == "analyst")).scalar_one())
        manager = identity.principal_of(s.execute(select(User).where(User.username == "manager")).scalar_one())
        inv = inv_svc.close(s, analyst, prior_id, "attack", "동일 UA·클라우드 분산 IP로 고객 ID 순차 열거 확인",
                            {"checks": ["배치 스케줄 확인", "동일 지문(JA4/UA) 확장 검색"], "response": "WAF rate-limit 적용 요청, 개발팀 IDOR 점검 요청",
                             "detection_idea": "uri_template 별 10분 500회 이상 + 순차 파라미터"})
        index_investigation(s, inv)
        exp = exp_svc.draft_from_investigation(s, analyst, inv)
        exp_svc.submit(s, analyst, exp.id)
        exp_svc.approve(s, manager, exp.id, "근거 충분 — 승인")
        demo = s.execute(select(Investigation).where(Investigation.title == "Customer API 대량 조회 의심 (demo)")).scalar_one_or_none()
        if demo:
            analysis.run_all(s, demo.id)  # re-run detectors so the asset baseline applies
    return prior_id


def seed_connector() -> None:
    from saw.connectors import registry as creg

    with session_scope() as s:
        if not s.execute(select(creg.ConnectorConfig).where(creg.ConnectorConfig.name == "siem-mock")).first():
            creg.upsert(s, "siem-mock", "mock_logpresso", {"seed": 11}, None)


def main() -> None:
    container.build(synchronous_jobs=True)
    if len(sys.argv) >= 3 and sys.argv[1] == "totp":  # dev automation only: reads the enrolled secret from the DB
        with session_scope() as s:
            secret = s.execute(select(User.mfa_secret).where(User.username == sys.argv[2])).scalar_one_or_none()
        print(pyotp.TOTP(secret).now() if secret else "not enrolled yet (log in once to see the QR enrollment)")
        return
    creds = seed_users()
    inv = seed_demo()
    net = seed_network()
    kn = seed_knowledge()
    pf = seed_pcap_forensics()
    print(f"pcap forensics evidence: {pf or 'already present'}")
    seed_connector()
    print(f"knowledge seeded: {kn or 'already present'}")
    print(f"network evidence added: {net or 'already present'}")
    print(f"users: {', '.join(creds)} (credentials in {CRED})")
    print(f"demo investigation: {inv or 'already present'}")


if __name__ == "__main__":
    main()
