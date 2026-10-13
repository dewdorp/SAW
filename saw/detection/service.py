"""Detection Engineering (docs/31): candidate → test → approved (4-eyes, tested) → deployed (recorded only) → deprecated.

SAW never deploys rules. Versions are immutable once approved; edits create a new version.
"""
from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from time import monotonic

import yaml
from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, func, select, update as sql_update
from sqlalchemy.orm import Mapped, Session, mapped_column

from saw import container
from saw.attack.catalog import TECHNIQUES
from saw.core.application import audit
from saw.core.application.ids import next_display_id
from saw.core.application.investigations import Forbidden, NotFound, list_for, require
from saw.core.schemas.query import Filter
from saw.core.security.authz import Principal, can
from saw.detection.sigma_eval import (
    SigmaError,
    apply_threshold,
    attack_tags,
    compile_rule,
    evaluate,
    to_opensearch_lucene,
    validate_threshold,
    validate_with_pysigma,
)
from saw.storage.db import Base, new_id, utcnow
from saw.storage.models import Finding, Investigation

FORMATS = {"sigma", "suricata", "regex", "generic_query"}
STATUSES = ["draft", "test", "approved", "deployed", "deprecated"]


class Detection(Base):
    __tablename__ = "det_detection"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    display_id: Mapped[str] = mapped_column(String(32), unique=True)
    status: Mapped[str] = mapped_column(String(16), default="draft")
    current_version: Mapped[int] = mapped_column(Integer, default=1)
    created_by: Mapped[str] = mapped_column(String(36))
    created_by_name: Mapped[str] = mapped_column(String(64), default="")
    deployments: Mapped[list] = mapped_column(JSON, default=list)
    source: Mapped[dict] = mapped_column(JSON, default=dict)  # {finding_id, investigation_id, experience_id}
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DetectionVersion(Base):
    __tablename__ = "det_version"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    detection_id: Mapped[str] = mapped_column(ForeignKey("det_detection.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(256))
    description: Mapped[str] = mapped_column(Text, default="")
    data_source: Mapped[str] = mapped_column(String(32), default="web")
    format: Mapped[str] = mapped_column(String(16), default="sigma")
    logic: Mapped[str] = mapped_column(Text)
    threshold: Mapped[dict] = mapped_column(JSON, default=dict)  # {group_by:[..], timespan_sec, count_gte, distinct_field}
    exceptions: Mapped[list] = mapped_column(JSON, default=list)  # SAW Query Model filters excluded
    false_positive: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    confidence: Mapped[str] = mapped_column(String(16), default="medium")
    test_events: Mapped[list] = mapped_column(JSON, default=list)  # [{expected: match|no_match, event: {...}}]
    attack: Mapped[list] = mapped_column(JSON, default=list)
    created_by: Mapped[str] = mapped_column(String(64))
    reviewed_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status_at_version: Mapped[str] = mapped_column(String(16), default="draft")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TestRun(Base):
    __tablename__ = "det_test_run"
    __test__ = False  # not a pytest class
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    detection_id: Mapped[str] = mapped_column(String(36), index=True)
    version: Mapped[int] = mapped_column(Integer)
    scope: Mapped[dict] = mapped_column(JSON, default=dict)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    passed: Mapped[bool] = mapped_column(default=False)
    ran_by: Mapped[str] = mapped_column(String(64))
    ran_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ------------------------------------------------------------------ candidate templates (Finding → Sigma)
def _sigma(title: str, desc: str, category: str, selection: dict, tags: list[str], level: str, fps: list[str],
           extra_cond: str = "selection") -> str:
    d = {"title": title, "status": "experimental", "description": desc, "logsource": {"category": category},
         "detection": {"selection": selection, "condition": extra_cond}, "falsepositives": fps or ["Unknown"],
         "level": level, "tags": tags}
    return yaml.safe_dump(d, allow_unicode=True, sort_keys=False)


def candidate_from_finding(f: Finding) -> dict:
    ents = {e.split(":", 1)[0]: e.split(":", 1)[1] for e in f.entities}
    tags = [f"attack.{a['technique_id'].lower()}" for a in (f.attack or []) if a.get("confidence") != "candidate"]
    cat = f.category
    th: dict = {}
    if cat == "web.api_enumeration":
        tpl = ents.get("uri_template", "/api/x?id=<NUM>")
        path = tpl.split("?")[0].split("<")[0].rstrip("/")
        sel = {"cs-uri-stem|startswith": path or "/", "sc-status": 200}
        th = {"group_by": ["uri_template"], "timespan_sec": 600, "count_gte": 300, "distinct_field": "params"}  # distributed sources
        title, desc, fps = f"Possible Sequential Object Enumeration on {path}", "다수 객체를 짧은 시간에 순차 조회", ["Batch jobs (Asset batch_schedule)"]
    elif cat == "web.sensitive_file_probe":
        sel = {"cs-uri-stem|contains": ["/.env", "/.git", "/config", "/backup", ".sql", "/.aws", "/phpinfo"]}
        title, desc, fps = "Possible Sensitive File Probing", "민감 파일 경로 탐색", ["Vulnerability scanners run by the security team"]
    elif cat == "web.credential_attack":
        sel = {"cs-method": "POST", "cs-uri-stem|contains": ["login", "signin", "auth"], "sc-status": [401, 403]}
        th = {"group_by": ["src_ip"], "timespan_sec": 600, "count_gte": 30}
        title, desc, fps = "Possible Credential Attack on Login Endpoint", "로그인 실패 반복", ["Misconfigured clients"]
    elif cat == "web.injection_like":
        sel = {"cs-uri|re": r"(?i)(union(\s|%20|\+)+select|or(\s|%20)+1(=|%3d)1|sleep\(|%27|<script|\.\./|%2e%2e)"}
        title, desc, fps = f"{f.title.replace('Potential ', 'Possible ')}", "주입형 페이로드 패턴", ["Security testing"]
    elif cat == "web.discovery":
        sel = {"sc-status": 404}
        th = {"group_by": ["src_ip"], "timespan_sec": 300, "count_gte": 100, "distinct_field": "url_path"}
        title, desc, fps = "Possible Forced Browsing", "404 다수 + 경로 다양성", ["Broken links crawled by bots"]
    elif cat == "web.scripted_client":
        sel = {"c-useragent|contains": ["sqlmap", "nikto", "zgrab", "nuclei", "python-requests", "python-httpx", "Go-http-client"]}
        title, desc, fps = "Scripted / Scanner User-Agent", "비브라우저 클라이언트", ["Internal automation"]
    elif cat == "net.dns_anomaly":
        dom = ents.get("domain", "example.com")
        sel = {"query|endswith": f".{dom}"}
        th = {"group_by": ["src_ip"], "timespan_sec": 3600, "count_gte": 100, "distinct_field": "domain"}
        return {"format": "sigma", "data_source": "zeek_dns", "threshold": th, "attack": tags,
                "logic": _sigma(f"Possible DNS Tunneling to {dom}", "고유 서브도메인 대량 질의", "dns", sel, tags, "high",
                                ["CDN/telemetry with random labels"]),
                "title": f"Possible DNS Tunneling to {dom}"}
    elif cat.startswith("net."):
        dst = next((e.split(":", 1)[1] for e in f.entities if e.startswith("ip:") and not e.split(":", 1)[1].startswith("10.")), "any")
        rule = (f'alert tls $HOME_NET any -> {dst} any (msg:"SAW candidate: {f.title}"; flow:established,to_server; '
                f'threshold:type both, track by_src, count 10, seconds 600; classtype:policy-violation; sid:9900001; rev:1;)')
        return {"format": "suricata", "data_source": "suricata", "logic": rule, "title": f.title.replace("Potential ", "Possible "),
                "attack": tags, "threshold": {}}
    else:
        sel = {"uri_template": ents.get("uri_template", "*")}
        title, desc, fps = f.title.replace("Potential ", "Possible "), f.explanation_md[:200], []
    return {"format": "sigma", "data_source": "web", "threshold": th, "attack": tags, "title": title,
            "logic": _sigma(title, desc, "webserver", sel, tags, "high" if f.risk_level in ("high", "critical") else "medium", fps)}


# ------------------------------------------------------------------ CRUD / workflow
def _latest(s: Session, det_id: str) -> DetectionVersion:
    v = s.execute(select(DetectionVersion).where(DetectionVersion.detection_id == det_id)
                  .order_by(DetectionVersion.version.desc()).limit(1)).scalars().first()
    if v is None:
        raise NotFound("detection version not found")
    return v


def _validate(fmt: str, logic: str) -> list[str]:
    if fmt not in FORMATS:
        return [f"unknown format {fmt}"]
    if fmt == "sigma":
        errs = validate_with_pysigma(logic)
        if not errs:
            try:
                compile_rule(logic)
            except SigmaError as e:
                errs.append(f"local evaluator: {e}")
        return errs
    if fmt == "suricata":
        import re as _re

        if not _re.match(r"^(alert|drop|pass|reject)\s+\w+\s+\S+\s+\S+\s+(->|<>)\s+\S+\s+\S+\s+\(.*sid:\d+;.*\)$", logic.strip()):
            return ["invalid Suricata rule header/options (full validation requires `suricata -T`, ENV-06)"]
        return []
    if fmt == "regex":
        import re as _re

        try:
            _re.compile(logic)
        except _re.error as e:
            return [str(e)]
    return []


def create(s: Session, p: Principal, data: dict, source: dict | None = None) -> Detection:
    if not can(p, "detection.write"):
        raise Forbidden("detection.write")
    errs = _validate(data.get("format", "sigma"), data.get("logic", ""))
    if errs:
        raise ValueError("; ".join(errs))
    d = Detection(display_id=next_display_id(s, "DET", daily=False, width=4), created_by=p.user_id, created_by_name=p.username,
                  source=source or {})
    s.add(d)
    s.flush()
    s.add(_version_from(d.id, 1, data, p.username))
    audit.record(s, "detection.create", actor_id=p.user_id, actor_name=p.username, target_type="detection", target_id=d.id)
    return d


def _version_from(det_id: str, ver: int, data: dict, actor: str) -> DetectionVersion:
    validate_threshold(data.get("threshold") or {})
    tags = data.get("attack") or []
    if data.get("format", "sigma") == "sigma":
        try:
            tags = sorted(set(tags) | {f"attack.{t.lower()}" for t in attack_tags(compile_rule(data["logic"]))})
        except SigmaError:
            pass
    return DetectionVersion(detection_id=det_id, version=ver, title=data.get("title") or "Untitled detection",
                            description=data.get("description", ""), data_source=data.get("data_source", "web"),
                            format=data.get("format", "sigma"), logic=data["logic"], threshold=data.get("threshold") or {},
                            exceptions=data.get("exceptions") or [], false_positive=data.get("false_positive", ""),
                            severity=data.get("severity", "medium"), confidence=data.get("confidence", "medium"),
                            test_events=data.get("test_events") or [], attack=tags, created_by=actor)


def from_finding(s: Session, p: Principal, finding_id: str) -> Detection:
    f = s.get(Finding, finding_id)
    if f is None:
        raise NotFound("finding not found")
    require(s, p, "investigation.read", f.investigation_id)
    c = candidate_from_finding(f)
    c["description"] = f"Generated from {f.display_id} ({f.title}). 검토·테스트 후 승인 필요."
    return create(s, p, c, {"finding_id": f.id, "investigation_id": f.investigation_id})


def update(s: Session, p: Principal, det_id: str, data: dict) -> Detection:
    d = s.get(Detection, det_id)
    if d is None:
        raise NotFound("detection not found")
    if not can(p, "detection.write"):
        raise Forbidden("detection.write")
    cur = _latest(s, det_id)
    merged = {k: getattr(cur, k) for k in ("title", "description", "data_source", "format", "logic", "threshold", "exceptions",
                                           "false_positive", "severity", "confidence", "test_events", "attack")}
    merged.update({k: v for k, v in data.items() if v is not None})
    errs = _validate(merged["format"], merged["logic"])
    if errs:
        raise ValueError("; ".join(errs))
    d.current_version += 1
    d.status, d.updated_at = "draft", utcnow()  # any change leaves approved/deployed state → must be re-tested & approved
    s.add(_version_from(det_id, d.current_version, merged, p.username))
    audit.record(s, "detection.update", actor_id=p.user_id, actor_name=p.username, target_type="detection", target_id=det_id,
                 detail={"version": d.current_version})
    return d


# ------------------------------------------------------------------ historical testing
def _in_threshold(hits: list[dict], th: dict) -> list[dict]:
    return apply_threshold(hits, th)


def run_test(s: Session, p: Principal, det_id: str, investigation_ids: list[str] | None = None, max_events: int = 500_000,
             *, session_id: str | None = None) -> TestRun:
    d = s.get(Detection, det_id)
    if d is None:
        raise NotFound("detection not found")
    v = _latest(s, det_id)
    if v.format != "sigma":
        raise ValueError(f"local historical testing supports sigma only ({v.format}: test on the target engine, ENV-06/ENV-11)")
    rule = compile_rule(v.logic)
    validate_threshold(v.threshold)
    from saw.core.application.data_deletion import epoch
    from saw.core.application.identity import principal_of
    from saw.storage.models import User, UserSession

    readable = {i.id: i for i in list_for(s, p, 500)}
    scope = sorted({i for i in (investigation_ids or list(readable)) if i in readable})
    epochs = {iid: epoch(require(s, p, "investigation.read", iid)) for iid in scope}
    tested_version = v.version
    # Native search may take seconds. Do not retain investigation/SQLite writer locks while scanning.
    # A changed or deleted source invalidates the entire result before any samples can be published.
    s.commit()
    es = container.get().events
    exc = [Filter(**x) for x in v.exceptions]
    pre = [Filter(field="data_source", op="in", value=rule.data_sources)] if rule.data_sources else []
    hits_all, scanned = [], 0
    truncated = False
    evaluation_errors = 0
    deadline = monotonic() + 30
    per_inv: Counter = Counter()
    for inv_id in scope:
        matched = []
        for ev in es.iterate(inv_id, pre):
            if scanned >= max_events or monotonic() >= deadline:
                truncated = True
                break
            scanned += 1
            try:
                if evaluate(rule, ev):
                    matched.append(ev)
            except SigmaError:
                evaluation_errors += 1
                break
        if exc and matched:
            excluded = set()
            for event in es.iterate(inv_id, exc + pre, fields=["event_id"]):
                if len(excluded) >= max_events or monotonic() >= deadline:
                    truncated = True
                    break
                excluded.add(event["event_id"])
            matched = [e for e in matched if e["event_id"] not in excluded]
        try:
            matched = _in_threshold(matched, v.threshold)
        except SigmaError:
            evaluation_errors += 1
            matched = []
        per_inv[inv_id] = len(matched)
        hits_all += [(inv_id, e) for e in matched]
        if truncated or evaluation_errors:
            break
    verdict = {i: readable[i].verdict for i in scope}
    tp = sum(n for i, n in per_inv.items() if verdict.get(i) == "attack")
    fp = sum(n for i, n in per_inv.items() if verdict.get(i) in ("normal", "false_positive"))
    unl = sum(per_inv.values()) - tp - fp
    tss = sorted(e.get("timestamp") for _, e in hits_all if e.get("timestamp"))
    days = max(1.0, (datetime.fromisoformat(tss[-1]) - datetime.fromisoformat(tss[0])).total_seconds() / 86400) if tss else 1.0
    unit = []
    for t in v.test_events:
        try:
            got = evaluate(rule, t.get("event") or {})
            unit.append({"expected": t.get("expected"), "matched": got, "ok": got == (t.get("expected") == "match")})
        except SigmaError as e:
            unit.append({"expected": t.get("expected"), "error": str(e), "ok": False})
    fp_groups = Counter(str(e.get("src_ip")) for i, e in hits_all if verdict.get(i) in ("normal", "false_positive")).most_common(3)
    attack_invs = [i for i in scope if verdict.get(i) == "attack"]
    recall_ok = all(per_inv[i] > 0 for i in attack_invs) if attack_invs else None
    result = {"hits": len(hits_all), "scanned": scanned, "truncated": truncated, "evaluation_errors": evaluation_errors,
              "execution": "partial" if truncated or evaluation_errors else "complete", "investigations": len(scope),
              "tp": tp, "fp": fp, "unlabeled": unl, "days": round(days, 2), "est_daily_alerts": round(len(hits_all) / days, 2),
              "per_investigation": [{"id": i, "display_id": readable[i].display_id, "verdict": verdict.get(i), "hits": n}
                                    for i, n in per_inv.most_common() if n],
              "fp_common": [{"src_ip": k, "count": n} for k, n in fp_groups], "unit_tests": unit,
              "detects_confirmed_attacks": recall_ok,
              "histogram": Counter((e.get("timestamp") or "")[:13] for _, e in hits_all).most_common(48),
              "samples": [{"investigation_id": i, "event_id": e["event_id"], "timestamp": e.get("timestamp"), "src_ip": e.get("src_ip"),
                           "uri": e.get("uri")} for i, e in hits_all[:20]]}
    passed = (not truncated and not evaluation_errors and all(u["ok"] for u in unit)
              and (recall_ok is not False) and len(hits_all) > 0)
    s.expire_all()
    current_user = s.get(User, p.user_id)
    if current_user is None or current_user.status != "active":
        raise Forbidden("시험 중 사용자 권한이 변경되어 결과를 저장하지 않았습니다. 권한을 확인하고 다시 시험하세요.")
    if session_id:
        current_session = s.get(UserSession, session_id)
        if (current_session is None or current_session.user_id != p.user_id
                or current_session.revoked_at is not None or not current_session.mfa_passed
                or current_session.expires_at.replace(tzinfo=UTC) <= utcnow()):
            raise Forbidden("시험 중 로그인 상태가 변경되어 결과를 저장하지 않았습니다. 다시 로그인하고 시험하세요.")
    current_principal = principal_of(current_user)
    if not can(current_principal, "detection.write"):
        raise Forbidden("시험 중 사용자 권한이 변경되어 결과를 저장하지 않았습니다. 권한을 확인하고 다시 시험하세요.")
    for iid in scope:
        current = require(s, current_principal, "investigation.read", iid)
        if epoch(current) != epochs[iid]:
            raise Forbidden("시험 중 조사 자료가 변경되어 결과를 저장하지 않았습니다. 다시 시험하세요.")
        if current.verdict != verdict[iid]:
            raise ValueError("조사 판단이 변경되었습니다. 탐지 시험을 다시 실행하세요.")
    # Keep the version check and final status transition atomic with concurrent rule edits.
    s.execute(sql_update(Detection).where(Detection.id == det_id).values(id=det_id)
              .execution_options(synchronize_session=False))
    d = s.scalar(select(Detection).where(Detection.id == det_id).execution_options(populate_existing=True))
    if d is None or d.current_version != tested_version:
        raise ValueError("탐지 룰 버전이 변경되었습니다. 다시 시험하세요.")
    v = _latest(s, det_id)
    tr = TestRun(detection_id=det_id, version=tested_version, scope={"investigations": scope}, result=result, passed=passed, ran_by=p.username)
    s.add(tr)
    if d.status == "draft":
        d.status = "test"
        v.status_at_version = "test"
    audit.record(s, "detection.test", actor_id=p.user_id, actor_name=p.username, target_type="detection", target_id=det_id,
                 detail={"version": v.version, "hits": len(hits_all), "passed": passed})
    s.flush()
    return tr


def has_passing_test(s: Session, det_id: str, version: int) -> bool:
    """Legacy passed flags cannot authorize rules whose scan was incomplete."""
    return s.execute(select(TestRun.id).where(
        TestRun.detection_id == det_id, TestRun.version == version, TestRun.passed.is_(True),
        func.coalesce(TestRun.result["truncated"].as_boolean(), False).is_(False),
        func.coalesce(TestRun.result["evaluation_errors"].as_integer(), 0) == 0,
        func.coalesce(TestRun.result["execution"].as_string(), "complete") == "complete",
    ).limit(1)).first() is not None


def approve(s: Session, p: Principal, det_id: str) -> Detection:
    d = s.get(Detection, det_id)
    if d is None:
        raise NotFound("detection not found")
    if not can(p, "detection.approve"):
        raise Forbidden("detection.approve")
    v = _latest(s, det_id)
    if v.created_by == p.username or d.created_by == p.user_id:
        raise Forbidden("reviewer must differ from the creator (4-eyes)")
    if v.format == "sigma" and not has_passing_test(s, det_id, v.version):
        raise ValueError("a passing historical test run of the current version is required before approval")
    d.status, v.status_at_version, v.reviewed_by = "approved", "approved", p.username
    audit.record(s, "detection.approve", actor_id=p.user_id, actor_name=p.username, target_type="detection", target_id=det_id,
                 detail={"version": v.version})
    return d


def record_deployment(s: Session, p: Principal, det_id: str, target: str, note: str) -> Detection:
    """SAW does not deploy. A human deploys via the existing rule-management process and records it here."""
    d = s.get(Detection, det_id)
    if d is None:
        raise NotFound("detection not found")
    if d.status not in ("approved", "deployed"):
        raise ValueError("only approved detections can be recorded as deployed")
    d.deployments = [*(d.deployments or []), {"target": target, "note": note, "by": p.username, "at": utcnow().isoformat(),
                                               "version": d.current_version}]
    d.status = "deployed"
    audit.record(s, "detection.deployed_recorded", actor_id=p.user_id, actor_name=p.username, target_type="detection", target_id=det_id,
                 detail={"target": target})
    return d


def deprecate(s: Session, p: Principal, det_id: str) -> Detection:
    d = s.get(Detection, det_id)
    if d is None:
        raise NotFound("detection not found")
    if not can(p, "detection.approve"):
        raise Forbidden("detection.approve")
    d.status = "deprecated"
    audit.record(s, "detection.deprecate", actor_id=p.user_id, actor_name=p.username, target_type="detection", target_id=det_id)
    return d


def export(s: Session, det_id: str, fmt: str) -> tuple[str, str]:
    v = _latest(s, det_id)
    if fmt == "native":
        return v.logic, "text/plain"
    if fmt == "opensearch":
        if v.format != "sigma":
            raise ValueError("opensearch export requires a sigma rule")
        return "\n".join(to_opensearch_lucene(v.logic)), "text/plain"
    if fmt == "generic":
        rule = compile_rule(v.logic)
        lines = [f"# {rule.title}", f"data_source in {rule.data_sources}", f"condition: {rule.condition}"]
        for name, groups in rule.detections.items():
            lines.append(f"{name}: " + " OR ".join("(" + " AND ".join(f"{f} {'|'.join(m) or '='} {vals}" for f, m, vals in g) + ")" for g in groups))
        if v.threshold:
            lines.append(f"threshold: {v.threshold}")
        return "\n".join(lines), "text/plain"
    if fmt == "logpresso":
        raise NotImplementedError("Logpresso query export requires the official query grammar documentation (ENV-11)")
    raise ValueError("format must be native|opensearch|generic|logpresso")


def to_dict(s: Session, d: Detection, full: bool = False) -> dict:
    v = _latest(s, d.id)
    out = {"id": d.id, "display_id": d.display_id, "status": d.status, "version": v.version, "title": v.title, "format": v.format,
           "data_source": v.data_source, "severity": v.severity, "attack": v.attack, "created_by": d.created_by_name,
           "reviewed_by": v.reviewed_by, "deployments": d.deployments, "source": d.source, "updated_at": d.updated_at}
    if full:
        out["current"] = {k: getattr(v, k) for k in ("title", "description", "data_source", "format", "logic", "threshold",
                                                     "exceptions", "false_positive", "severity", "confidence", "test_events", "attack",
                                                     "created_by", "reviewed_by", "status_at_version", "created_at")}
        out["versions"] = [{"version": x.version, "title": x.title, "created_by": x.created_by, "status": x.status_at_version,
                            "created_at": x.created_at, "logic": x.logic}
                           for x in s.execute(select(DetectionVersion).where(DetectionVersion.detection_id == d.id)
                                              .order_by(DetectionVersion.version)).scalars()]
        out["test_runs"] = [{"id": t.id, "version": t.version, "passed": t.passed, "ran_by": t.ran_by, "ran_at": t.ran_at, "result": t.result}
                            for t in s.execute(select(TestRun).where(TestRun.detection_id == d.id).order_by(TestRun.ran_at.desc())).scalars()]
    return out


# ------------------------------------------------------------------ coverage (docs/34 V5)
def coverage(s: Session, p: Principal) -> dict:
    from saw.attack.catalog import COMPONENT_SOURCES, DATA_NEEDS, TACTICS
    from saw.core.application.analysis import present_sources

    invs = list_for(s, p, 500)
    sources: set[str] = set()
    for i in invs:
        sources |= set(present_sources(i.id))
    attack_ids = {i.id for i in invs if i.verdict == "attack"}
    observed: Counter = Counter()
    for f in s.execute(select(Finding).where(Finding.investigation_id.in_(attack_ids))).scalars() if attack_ids else []:
        for a in f.attack or []:
            if a.get("confidence") != "candidate":
                observed[a["technique_id"]] += 1
    dets: dict[str, list[dict]] = {}
    for d in s.execute(select(Detection).where(Detection.status.in_(["test", "approved", "deployed"]))).scalars():
        v = _latest(s, d.id)
        validated = s.execute(select(TestRun).where(TestRun.detection_id == d.id, TestRun.passed.is_(True))).first() is not None
        for t in v.attack:
            tid = t.split(".", 1)[1].upper() if t.lower().startswith("attack.") else t.upper()
            dets.setdefault(tid, []).append({"display_id": d.display_id, "status": d.status, "validated": validated})
    cells = []
    for tid, t in TECHNIQUES.items():
        if t.get("sub") and not observed[tid] and tid not in dets and tid not in DATA_NEEDS:
            continue  # coverage grid: parents always, sub-techniques when relevant
        needs = DATA_NEEDS.get(tid, [])
        vis = None if not needs else any(COMPONENT_SOURCES.get(n, set()) & sources for n in needs)
        ds = dets.get(tid, [])
        good = [x for x in ds if x["status"] in ("approved", "deployed")]
        state = ("detected_validated" if any(x["validated"] for x in good) else "detected_unvalidated" if good else
                 "gap" if observed[tid] else "no_visibility" if vis is False else "none")
        cells.append({"technique_id": tid, "name": t["name"], "tactics": t["tactics"], "observed": observed[tid], "visibility": vis,
                      "detections": ds, "state": state, "data_needed": [{"component": n, "available": bool(COMPONENT_SOURCES.get(n, set()) & sources)} for n in needs]})
    gaps = sorted((c for c in cells if c["state"] == "gap"), key=lambda c: -c["observed"])
    return {"tactics": [{"id": a, "short": b, "name": c} for a, b, c in TACTICS], "cells": cells, "gaps": gaps[:10],
            "sources": sorted(sources), "attack_investigations": len(attack_ids)}


def coverage_layer(cov: dict) -> dict:
    score = {"detected_validated": 100, "detected_unvalidated": 60, "gap": 10, "no_visibility": 0, "none": 30}
    color = {"detected_validated": "#3ccf91", "detected_unvalidated": "#f5b324", "gap": "#ff5a5f", "no_visibility": "#555b6e", "none": "#8a93a6"}
    return {"name": "SAW detection coverage", "versions": {"layer": "4.5", "navigator": "5.1.0", "attack": "18"}, "domain": "enterprise-attack",
            "description": "Visibility × Detection × Validation × Observed (SAW)",
            "techniques": [{"techniqueID": c["technique_id"], "score": score[c["state"]], "color": color[c["state"]],
                            "comment": f"{c['state']}; observed {c['observed']}; detections {len(c['detections'])}"} for c in cov["cells"]]}


_ = Investigation
