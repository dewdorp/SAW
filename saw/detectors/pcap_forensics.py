"""Forensic detectors over PCAP-derived data (saw.integrations.pcapkit → zeek_http/zeek_files/pcap_auth/pcap_arp).

Detection scope follows the categories of pcap-forensics-analyzer (reference only; reimplemented): web attacks in
traffic with response success signals, web-shell upload→use, malware delivery (executables, masquerading, exploit
content, high-entropy payloads, exploit-kit chains), cleartext credentials and weak passwords, brute force,
ARP spoofing, DGA-like NXDOMAIN bursts, direct-IP HTTP and IOC matches. Wording stays "Potential/Possible";
every finding carries "확인·대응 권고" for the analyst — SAW never blocks or changes anything itself.
"""
from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from datetime import datetime
from typing import Any
from urllib.parse import unquote_plus

from saw.analyzers.ioc.observables import ip_scope, registered_domain
from saw.analyzers.patterns import scan_value
from saw.core.schemas.query import Filter
from saw.detectors.base import AttackMap, DetectorContext, FindingDraft, check, metric

HTTP = Filter(field="data_source", value="zeek_http")
FILES = Filter(field="data_source", value="zeek_files")
AUTH = Filter(field="data_source", value="pcap_auth")
ARP = Filter(field="data_source", value="pcap_arp")
DNS = Filter(field="data_source", value="zeek_dns")
CONN = Filter(field="data_source", value="zeek_conn")
AUTH_PORTS = {22: "ssh", 23: "telnet", 445: "smb", 1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
              5900: "vnc", 21: "ftp", 110: "pop3", 143: "imap", 25: "smtp"}
LOG4SHELL = re.compile(r"(?i)\$\{\s*(jndi|\$\{[^}]*\}j)\s*:|\$\{(lower|upper|env|sys|::-)[^}]*\}")
SHELLSHOCK = re.compile(r"\(\)\s*\{\s*[:;]")
DNS_ALLOW = ("in-addr.arpa", "ip6.arpa", "local", "akamaiedge.net", "akadns.net", "edgekey.net", "edgesuite.net",
             "cloudfront.net", "amazonaws.com", "googlevideo.com", "1e100.net", "gstatic.com", "windowsupdate.com",
             "microsoft.com", "msedge.net", "trafficmanager.net", "azureedge.net", "apple.com", "icloud.com",
             "naver.net", "kakao.com", "daumcdn.net")
PATTERN_FAMILY = {"potential_sql_injection": "sqli", "potential_xss": "xss", "potential_traversal_lfi": "path_traversal",
                  "potential_ssrf_rfi": "ssrf_rfi", "potential_command_injection": "cmdi", "potential_ssti": "ssti",
                  "potential_deserialization": "deserialization"}
FAMILY = {
    "sqli": ("SQL Injection", "T1190", "SQL 오류/데이터 노출 응답"),
    "xss": ("Cross-Site Scripting", "T1189", "스크립트 반사 응답"),
    "path_traversal": ("Path Traversal / LFI", "T1190", "시스템 파일 내용 응답"),
    "cmdi": ("Command Injection", "T1059", "명령 실행 결과 응답"),
    "ssti": ("Template Injection", "T1190", "템플릿 평가 결과"),
    "ssrf_rfi": ("SSRF / Remote File Inclusion", "T1190", "외부 자원 응답"),
    "log4shell": ("Log4Shell (JNDI) Injection", "T1190", "후속 LDAP/RMI 연결"),
    "shellshock": ("Shellshock", "T1190", "명령 실행 결과 응답"),
    "deserialization": ("Insecure Deserialization", "T1190", "오류/실행 응답"),
}


def _ext(e: dict) -> dict:
    return (e.get("ext") or {}).get("zeek") or {}


def _q(flt: list[Filter]) -> dict:
    return {"filters": [f.model_dump() for f in flt]}


def _ts(e: dict) -> float:
    try:
        return datetime.fromisoformat((e.get("timestamp") or "").replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def _ids(evs: list[dict], n: int = 20) -> list[str]:
    return [e["event_id"] for e in evs[:n]]


def _span(evs: list[dict]) -> tuple[str | None, str | None]:
    ts = sorted(e.get("timestamp") for e in evs if e.get("timestamp"))
    return (ts[0], ts[-1]) if ts else (None, None)


def _advice(*lines: str) -> str:
    return "\n\n### 확인·대응 권고 (분석가 판단 후 수행)\n" + "\n".join(f"- {x}" for x in lines)


class WebAttackInTraffic:
    id, version, category, stage = "pcap.web_attack", "1.0.0", "pcap.web_attack", "EXPLOITATION"
    data_sources = {"zeek_http"}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        groups: dict[tuple[str, str], list[tuple[dict, Any]]] = defaultdict(list)
        for e in ctx.events.iterate(ctx.investigation_id, [HTTP]):
            x = _ext(e)
            parts = [unquote_plus(e.get("uri") or ""), e.get("user_agent") or "", x.get("referrer") or "",
                     x.get("request_body_preview") or ""]
            fams = set()
            for v in parts:
                if not v:
                    continue
                for h in scan_value(v[:4096]):
                    fams.add(PATTERN_FAMILY.get(h.pattern, h.pattern))
                if LOG4SHELL.search(v):
                    fams.add("log4shell")
                if SHELLSHOCK.search(v):
                    fams.add("shellshock")
            for fam in fams:
                if fam in FAMILY:
                    groups[(fam, e.get("dst_ip") or "")].append((e, x))
        out = []
        for (fam, dst), items in sorted(groups.items(), key=lambda kv: -len(kv[1]))[:10]:
            name, tid, signal = FAMILY[fam]
            evs = [e for e, _ in items]
            success = [e for e, x in items if x.get("response_indicators")]
            srcs = sorted({e.get("src_ip") for e in evs if e.get("src_ip")})
            ok_status = sum(1 for e in evs if 200 <= (e.get("status_code") or 0) < 300)
            inds = sorted({i for _, x in items for i in x.get("response_indicators") or []})
            lo, hi = _span(evs)
            flt = [HTTP, Filter(field="dst_ip", value=dst)]
            out.append(FindingDraft(
                self.id, self.version, f"Potential {name} in Captured Traffic", self.category, self.stage,
                0.85 if success else 0.65, "high" if success else "medium",
                [metric("requests", len(evs), label="Requests with pattern"), metric("sources", len(srcs), label="Source IPs"),
                 metric("success_responses", len(success), label="Responses with success signal"),
                 metric("http_2xx", ok_status, label="2xx responses")],
                [check("Attack pattern in request (URI/header/body)", True, name),
                 check(f"Response success signal ({signal})", bool(success), ", ".join(inds) or "없음")],
                [f"ip:{s}" for s in srcs[:5]] + [f"ip:{dst}"], _q(flt), lo, hi, f"{self.id}:{fam}:{dst}",
                attack=[AttackMap(tid, "high" if success else "medium", "요청 패턴 + 응답 성공 징후",
                                  condition_met=bool(success) or fam in ("log4shell", "shellshock"),
                                  rationale="pattern match is a hypothesis; response evidence raises confidence")],
                success_signal=bool(success),
                explanation=f"{dst} 대상 요청 {len(evs)}건에서 {name} 패턴 관측"
                            + (f", 응답에서 공격 성공 징후({', '.join(inds)}) 관측." if success else ".")
                            + _advice("관련 세션의 응답 본문을 확인해 실제 데이터 노출 여부를 판단",
                                      "대상 웹 서버 로그에서 동일 출발지의 다른 요청과 시간대를 확인",
                                      "취약 파라미터가 확인되면 개발 담당에 조치(입력 검증·파라미터 바인딩) 요청"),
                sample_event_ids=_ids(evs), total_events=len(evs)))
        return out


def _last_segment(uri: str | None) -> str:
    return (uri or "").split("?", 1)[0].split("#", 1)[0].rstrip("/").rsplit("/", 1)[-1].lower()


def _refused(e: dict) -> bool:
    """The server answered that the path does not exist or may not be used: a request, but not a use."""
    try:
        return int(e.get("status_code")) in (400, 401, 403, 404, 405, 410)
    except (TypeError, ValueError):
        return False  # no status seen (capture ended, response lost): not evidence either way, keep it


class WebShellUpload:
    id, version, category, stage = "pcap.webshell", "1.0.0", "pcap.webshell", "PERSISTENCE"
    data_sources = {"zeek_files", "zeek_http"}
    SCRIPT_EXT = {"php", "php5", "phtml", "jsp", "jspx", "asp", "aspx", "ashx", "asmx", "cfm", "war"}
    TOMCAT = re.compile(r"(?i)/manager/(html/upload|text/deploy)")

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        inv = ctx.investigation_id
        uploads = []
        for e in ctx.events.iterate(inv, [FILES]):
            x = _ext(e)
            fn = (x.get("filename") or "").lower()
            if x.get("direction") == "upload" and (fn.rsplit(".", 1)[-1] in self.SCRIPT_EXT or x.get("kind") in ("php", "jsp_asp")):
                uploads.append((e, x, fn))
        for e in ctx.events.iterate(inv, [HTTP]):
            if self.TOMCAT.search(e.get("uri") or "") and e.get("method") in ("POST", "PUT"):
                uploads.append((e, _ext(e), (e.get("uri") or "").rsplit("/", 1)[-1].lower()))
        out = []
        for e, x, fn in uploads[:5]:
            t0 = _ts(e)
            name = fn.rsplit("/", 1)[-1].split("?")[0]
            dst = e.get("dst_ip") or (x.get("rx_hosts") or [None])[0]
            src = e.get("src_ip") or (x.get("tx_hosts") or [None])[0]
            # "Used" needs more than the same file name somewhere: the same server, the name as the last path segment
            # (not a substring of another name), after the upload, and at least one request the server did not refuse.
            later = [h for h in ctx.events.search(
                inv, [HTTP, Filter(field="uri", op="contains", value=name)] + ([Filter(field="dst_ip", value=dst)] if dst else []),
                limit=200)["events"]
                if _ts(h) > t0 and h.get("method") in ("GET", "POST") and _last_segment(h.get("uri")) == name] if name and dst else []
            used = [h for h in later if not _refused(h)]
            refused = len(later) - len(used)
            lo, hi = _span([e] + used)
            out.append(FindingDraft(
                self.id, self.version, "Potential Web Shell Upload" + (" and Use" if used else ""), self.category,
                self.stage, 0.95 if used else 0.8, "high" if used else "medium",
                [metric("uploads", 1, label="Server-side script upload"), metric("later_requests", len(used), label="Requests to uploaded path")],
                [check("Server-side script uploaded (PUT/multipart/Tomcat Manager)", True, name or x.get("http_uri")),
                 check("Same file requested on the same server afterwards (not refused)", bool(used),
                       f"{len(used)}건" + (f" · 거부된 요청(404 등) {refused}건은 제외" if refused else ""))],
                [f"ip:{src}", f"ip:{dst}"], _q([HTTP, Filter(field="dst_ip", value=dst)]), lo, hi,
                f"{self.id}:{dst}:{name}",
                attack=[AttackMap("T1505.003", "high" if used else "medium", "업로드 후 해당 경로 요청", condition_met=bool(used)),
                        AttackMap("T1190", "medium", "공개 애플리케이션 업로드 기능 악용", condition_met=True)],
                success_signal=bool(used),
                explanation=f"{src} → {dst} 서버측 스크립트 `{name}` 업로드" + (f", 이후 {len(used)}회 요청." if used else ".")
                            + _advice("웹 서버에서 업로드 파일 존재 여부와 해시를 확인(추출 파일 해시와 대조)",
                                      "웹 서버 계정의 프로세스 실행 이력 확인", "확인 시 서버 격리 여부를 운영 절차에 따라 결정"),
                sample_event_ids=[e["event_id"]] + _ids(used, 10), total_events=1 + len(used)))
        return out


class MalwareDelivery:
    id, version, category, stage = "pcap.malware_delivery", "1.0.0", "pcap.malware_delivery", "DELIVERY"
    data_sources = {"zeek_files"}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        inv = ctx.investigation_id
        files = [(e, _ext(e)) for e in ctx.events.iterate(inv, [FILES])]
        buckets: dict[str, list[tuple[dict, dict]]] = defaultdict(list)
        for e, x in files:
            if x.get("direction") == "upload":
                continue  # uploads are handled by the web-shell detector
            cat, ent, size = x.get("category"), x.get("entropy") or 0, x.get("seen_bytes") or 0
            if x.get("masquerade"):
                buckets["masquerade"].append((e, x))
            elif cat == "executable":
                buckets["executable"].append((e, x))
            elif cat == "exploit_content":
                buckets["exploit"].append((e, x))
            elif cat == "script" and x.get("kind") in ("powershell", "vbscript", "batch", "shell"):
                buckets["script"].append((e, x))
            elif cat == "unknown" and ent >= 7.5 and size >= 10240:
                buckets["high_entropy"].append((e, x))
        spec = {
            "masquerade": ("Potential Masqueraded Executable Download", 0.9, "high", [("T1036.008", "high"), ("T1105", "high")]),
            "executable": ("Potential Executable Download", 0.7, "medium", [("T1105", "medium")]),
            "exploit": ("Potential Exploit Content Download (Flash/Java)", 0.6, "medium", [("T1203", "low"), ("T1189", "low")]),
            "script": ("Potential Script Payload Download", 0.65, "medium", [("T1105", "medium"), ("T1059", "low")]),
            "high_entropy": ("Potential Encrypted/Obfuscated Payload", 0.55, "low", [("T1027", "low")]),
        }
        out = []
        for key, items in buckets.items():
            title, sev, conf, techs = spec[key]
            evs = [e for e, _ in items]
            hashes = sorted({x.get("sha256") for _, x in items if x.get("sha256")})
            hosts = sorted({h for _, x in items for h in x.get("rx_hosts") or []})
            lo, hi = _span(evs)
            names = ", ".join(sorted({x.get("filename") or "(이름 없음)" for _, x in items})[:5])
            out.append(FindingDraft(
                self.id, self.version, title, self.category, self.stage, sev, conf,
                [metric("files", len(items), label="Files"), metric("receivers", len(hosts), label="Receiving hosts"),
                 metric("max_entropy", max((x.get("entropy") or 0) for _, x in items), label="Max entropy (bits/byte)")],
                [check("Actual type by magic bytes", True, ", ".join(sorted({x.get('kind') or '?' for _, x in items}))),
                 check("Declared type differs (extension/Content-Type)", key == "masquerade",
                       ", ".join(sorted({str(x.get('declared_category')) for _, x in items}))),
                 check("File names", None, names)],
                [f"ip:{h}" for h in hosts[:5]] + [f"hash:{h}" for h in hashes[:5]],
                {"filters": [FILES.model_dump(), Filter(field="hash", op="in", value=hashes[:50]).model_dump()]},
                lo, hi, f"{self.id}:{key}", attack=[AttackMap(t, c, "파일 전송 관측") for t, c in techs],
                explanation=f"{len(items)}개 파일 ({names}) 전송 관측."
                            + _advice("추출 파일의 SHA-256으로 내부 위협정보·백신 결과를 조회(외부 조회는 정책 허용 시)",
                                      "수신 호스트에서 해당 파일 실행 여부를 EDR/로그로 확인",
                                      "실행 흔적이 있으면 호스트 격리 여부를 운영 절차에 따라 결정"),
                sample_event_ids=_ids(evs), total_events=len(evs)))
        out += self._chain(ctx, files)
        return out

    def _chain(self, ctx: DetectorContext, files: list[tuple[dict, dict]]) -> list[FindingDraft]:
        """Landing page → exploit content → payload for one client within 120 s (exploit-kit style chain)."""
        by_client: dict[str, list[tuple[float, dict, dict]]] = defaultdict(list)
        for e, x in files:
            for h in x.get("rx_hosts") or []:
                by_client[h].append((_ts(e), e, x))
        out = []
        for client, items in by_client.items():
            items.sort(key=lambda t: t[0])
            for i, (t0, e0, x0) in enumerate(items):
                if x0.get("category") != "exploit_content":
                    continue
                landing = [e for t, e, x in items[:i] if x.get("category") == "web" and t0 - t <= 120]
                payload = [e for t, e, x in items[i + 1:] if t - t0 <= 120 and
                           (x.get("category") == "executable" or (x.get("entropy") or 0) >= 7.5)]
                if landing and payload:
                    evs = landing[-1:] + [e0] + payload[:1]
                    lo, hi = _span(evs)
                    out.append(FindingDraft(
                        self.id, self.version, "Potential Exploit Kit Infection Chain", self.category, "DELIVERY", 0.95, "high",
                        [metric("chain_steps", 3, label="Steps"), metric("window_s", round(_ts(payload[0]) - _ts(landing[-1])), unit="s",
                                                                          label="Landing → payload")],
                        [check("Landing page", True, _ext(landing[-1]).get("http_uri")),
                         check("Exploit content (Flash/Java)", True, x0.get("kind")),
                         check("Payload (executable/high entropy)", True, _ext(payload[0]).get("kind"))],
                        [f"ip:{client}"], {"filters": [FILES.model_dump()]}, lo, hi, f"{self.id}:chain:{client}",
                        attack=[AttackMap("T1189", "high", "랜딩→익스플로잇→페이로드 연쇄"), AttackMap("T1203", "medium", "익스플로잇 콘텐츠 후 페이로드")],
                        explanation=f"{client}: 120초 내 랜딩 페이지 → {x0.get('kind')} → 페이로드 순서로 수신."
                                    + _advice("피해 의심 호스트를 우선 조사 대상으로 지정", "Referer 체인의 최초 유입 사이트 확인",
                                              "IDS(Suricata) 결과가 있으면 함께 확인"),
                        sample_event_ids=[e["event_id"] for e in evs], total_events=3))
                    break
        return out


class CleartextCredentials:
    id, version, category, stage = "pcap.cleartext_auth", "1.0.0", "pcap.cleartext_auth", "AUTHENTICATION"
    data_sources = {"pcap_auth"}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        evs = list(ctx.events.iterate(ctx.investigation_id, [AUTH]))
        if not evs:
            return []
        out = []
        protos = sorted({e.get("protocol") for e in evs if e.get("protocol")})
        users = sorted({e.get("user") for e in evs if e.get("user")})
        lo, hi = _span(evs)
        out.append(FindingDraft(
            self.id, self.version, "Potential Cleartext Credential Exposure", self.category, self.stage, 0.5, "high",
            [metric("attempts", len(evs), label="Authentications in cleartext"), metric("accounts", len(users), label="Accounts"),
             metric("protocols", len(protos), label="Protocols")],
            [check("Credentials readable on the network", True, ", ".join(protos)),
             check("Passwords stored by SAW", False, "아니오 — 길이·취약 여부만 기록")],
            [f"user:{u}" for u in users[:10]], _q([AUTH]), lo, hi, f"{self.id}:exposure",
            attack=[AttackMap("T1552", "low", "평문 인증 정보 노출(위험 요소)", condition_met=False,
                              rationale="exposure is a weakness; adversary capture is not observed")],
            explanation=f"{', '.join(protos)} 평문 인증 {len(evs)}건 (계정 {len(users)}개)."
                        + _advice("해당 서비스의 암호화(FTPS/SFTP, IMAPS/POP3S, SMTP STARTTLS, HTTPS) 적용 여부 확인",
                                  "노출된 계정의 비밀번호 변경 필요성을 계정 관리자와 검토"),
            sample_event_ids=_ids(evs), total_events=len(evs)))
        weak = [e for e in evs if _ext(e).get("password_weak") and e.get("outcome") == "success"]
        if weak:
            lo, hi = _span(weak)
            accts = sorted({f"{e.get('protocol')}:{e.get('user')}" for e in weak})
            out.append(FindingDraft(
                self.id, self.version, "Possible Weak or Default Password Accepted", self.category, "AUTHENTICATION", 0.8, "high",
                [metric("logins", len(weak), label="Successful weak-password logins")],
                [check("Login succeeded", True, ", ".join(accts[:5])),
                 check("Password is in the weak/default list or very short", True, "비밀번호 자체는 저장하지 않음")],
                [f"user:{e.get('user')}" for e in weak[:10]], _q([AUTH, Filter(field="outcome", value="success")]), lo, hi,
                f"{self.id}:weak", attack=[AttackMap("T1078.001", "medium", "기본/취약 비밀번호 로그인 성공")],
                explanation=f"취약/기본 비밀번호로 로그인 성공 {len(weak)}건: {', '.join(accts[:5])}."
                            + _advice("해당 계정의 비밀번호를 즉시 변경하도록 계정 관리자에게 요청",
                                      "로그인 이후 같은 세션에서 수행된 명령·전송 파일을 확인"),
                sample_event_ids=_ids(weak), total_events=len(weak)))
        return out


class BruteForceAuth:
    id, version, category, stage = "pcap.bruteforce", "1.0.0", "pcap.bruteforce", "AUTHENTICATION"
    data_sources = {"pcap_auth", "zeek_conn"}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        p = {"min_failures": 5, "min_connections": 15, "window_s": 300, **ctx.params}
        inv = ctx.investigation_id
        out = []
        groups: dict[tuple, list[dict]] = defaultdict(list)
        for e in ctx.events.iterate(inv, [AUTH]):
            groups[(e.get("src_ip"), e.get("dst_ip"), e.get("protocol"))].append(e)
        for (src, dst, proto), evs in groups.items():
            evs.sort(key=_ts)
            fails = [e for e in evs if e.get("outcome") == "failure"]
            if len(fails) < p["min_failures"]:
                continue
            success_after = [e for e in evs if e.get("outcome") == "success" and _ts(e) >= _ts(fails[0])]
            users = sorted({e.get("user") for e in evs if e.get("user")})
            lo, hi = _span(evs)
            spray = len(users) >= 5
            tid = "T1110.003" if spray else "T1110.001"
            out.append(FindingDraft(
                self.id, self.version, f"Potential {'Password Spraying' if spray else 'Brute Force'} ({proto})" +
                (" with Successful Login" if success_after else ""), self.category, self.stage,
                0.95 if success_after else 0.7, "high",
                [metric("failures", len(fails), label="Failed logins"), metric("accounts", len(users), label="Accounts tried"),
                 metric("successes_after", len(success_after), label="Successful logins after failures")],
                [check(f"Failures ≥ {p['min_failures']}", True, len(fails)),
                 check("Success after failures", bool(success_after), ", ".join(sorted({e.get('user') or '' for e in success_after})))],
                [f"ip:{src}", f"ip:{dst}"] + [f"user:{u}" for u in users[:5]],
                _q([AUTH, Filter(field="src_ip", value=src), Filter(field="dst_ip", value=dst)]), lo, hi,
                f"{self.id}:{src}:{dst}:{proto}",
                attack=[AttackMap(tid, "high", "다수 실패 후 성공" if success_after else "다수 인증 실패", condition_met=True),
                        AttackMap("T1078", "medium", "실패 후 성공 로그인", condition_met=bool(success_after))],
                success_signal=bool(success_after),
                explanation=f"{src} → {dst} {proto} 로그인 실패 {len(fails)}회, 계정 {len(users)}개"
                            + (f", 이후 로그인 성공 {len(success_after)}건." if success_after else ".")
                            + _advice("성공한 계정의 이후 활동(명령, 파일 전송)을 확인",
                                      "출발지 IP의 다른 서비스 접근 여부 확인", "계정 잠금·비밀번호 변경 필요성을 계정 관리자와 검토"),
                sample_event_ids=_ids(fails, 10) + _ids(success_after, 10), total_events=len(evs)))
        # encrypted services: count short connections (no visibility into success/failure)
        rows = ctx.events.group_by(inv, [CONN, Filter(field="dst_port", op="in", value=[p_ for p_ in AUTH_PORTS if p_ in (22, 3389, 445, 1433, 3306, 5432, 5900, 23)])],
                                   ["src_ip", "dst_ip", "dst_port"], [], size=2000)
        for r in rows:
            if r["count"] < p["min_connections"]:
                continue
            k = r["key"]
            flt = [CONN, Filter(field="src_ip", value=k["src_ip"]), Filter(field="dst_ip", value=k["dst_ip"]),
                   Filter(field="dst_port", value=k["dst_port"])]
            svc = AUTH_PORTS.get(int(k["dst_port"]), str(k["dst_port"]))
            out.append(FindingDraft(
                self.id, self.version, f"Potential Brute Force by Connection Volume ({svc})", self.category, self.stage,
                0.55, "medium", [metric("connections", r["count"], label=f"Connections to {svc}")],
                [check(f"Connections ≥ {p['min_connections']}", True, r["count"]),
                 check("Outcome visible", False, "암호화된 프로토콜 — 성공/실패 확인 불가")],
                [f"ip:{k['src_ip']}", f"ip:{k['dst_ip']}"], _q(flt), None, None,
                f"{self.id}:conn:{k['src_ip']}:{k['dst_ip']}:{k['dst_port']}",
                attack=[AttackMap("T1110", "low", "인증 서비스 반복 연결", condition_met=False,
                                  rationale="connection volume alone; authentication result not observable")],
                explanation=f"{k['src_ip']} → {k['dst_ip']}:{k['dst_port']} ({svc}) 연결 {r['count']}회."
                            + _advice("대상 서버의 인증 로그(성공/실패)를 확인해 무차별 대입 여부를 판단"),
                total_events=r["count"]))
        return out[:15]


class ArpSpoofing:
    id, version, category, stage = "pcap.arp_spoof", "1.0.0", "pcap.arp_spoof", "LATERAL"
    data_sources = {"pcap_arp"}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        by_ip: dict[str, list[dict]] = defaultdict(list)
        for e in ctx.events.iterate(ctx.investigation_id, [ARP]):
            by_ip[e.get("src_ip") or ""].append(e)
        out = []
        for ip, evs in by_ip.items():
            macs = sorted({_ext(e).get("mac") for e in evs if _ext(e).get("mac")})
            if len(macs) < 2:
                continue
            lo, hi = _span(evs)
            replies = sum(_ext(e).get("replies") or 0 for e in evs)
            out.append(FindingDraft(
                self.id, self.version, "Potential ARP Spoofing (one IP, multiple MACs)", self.category, self.stage, 0.8, "high",
                [metric("macs", len(macs), label="MAC addresses for IP"), metric("replies", replies, label="ARP replies")],
                [check("Same IP announced by several MACs", True, f"{ip}: {', '.join(macs)}"),
                 check("Known legitimate cause (VRRP/HSRP, NIC change)", None, "운영 담당 확인 필요")],
                [f"ip:{ip}"] + [f"mac:{m}" for m in macs], _q([ARP, Filter(field="src_ip", value=ip)]), lo, hi,
                f"{self.id}:{ip}", attack=[AttackMap("T1557.002", "medium", "한 IP에 복수 MAC 응답")],
                explanation=f"{ip} 에 대해 MAC {len(macs)}개({', '.join(macs)})가 ARP 응답."
                            + _advice("스위치의 MAC 주소 테이블로 실제 포트·장비 확인",
                                      "게이트웨이 IP라면 같은 시간대 트래픽 우회(중간자) 여부 확인",
                                      "이중화 장비(VRRP/HSRP)인지 네트워크 담당과 확인"),
                sample_event_ids=_ids(evs), total_events=len(evs)))
        return out


class DgaNxDomain:
    id, version, category, stage = "pcap.dga", "1.0.0", "pcap.dga", "OUTBOUND"
    data_sources = {"zeek_dns"}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        p = {"nx_threshold": 10, **ctx.params}
        by_src: dict[str, list[dict]] = defaultdict(list)
        for e in ctx.events.iterate(ctx.investigation_id, [DNS, Filter(field="ext.zeek.rcode_name", value="NXDOMAIN")]):
            d = (e.get("domain") or "").lower().rstrip(".")
            if d and not d.endswith(DNS_ALLOW):
                by_src[e.get("src_ip") or ""].append(e)
        out = []
        for src, evs in by_src.items():
            regs = sorted({registered_domain(e.get("domain") or "") for e in evs})
            if len({e.get("domain") for e in evs}) < p["nx_threshold"] or len(regs) < 3:
                continue  # many NX names under one domain is tunneling-like, handled by the DNS anomaly detector
            lo, hi = _span(evs)
            out.append(FindingDraft(
                self.id, self.version, "Potential DGA Activity (NXDOMAIN burst)", self.category, self.stage, 0.65, "medium",
                [metric("nx_names", len({e.get('domain') for e in evs}), label="Distinct NXDOMAIN names"),
                 metric("registered_domains", len(regs), label="Distinct registered domains")],
                [check(f"NXDOMAIN names ≥ {p['nx_threshold']}", True, len(evs)), check("Sample", None, ", ".join(regs[:5]))],
                [f"ip:{src}"], _q([DNS, Filter(field="src_ip", value=src)]), lo, hi, f"{self.id}:{src}",
                attack=[AttackMap("T1568.002", "medium", "다수의 존재하지 않는 도메인 질의")],
                explanation=f"{src} 가 존재하지 않는 도메인 {len(evs)}건 질의 (등록 도메인 {len(regs)}종)."
                            + _advice("해당 호스트의 실행 프로세스·자동 시작 항목을 EDR로 확인", "질의 직후 성공한 도메인이 있으면 C2 후보로 검토"),
                sample_event_ids=_ids(evs), total_events=len(evs)))
        return out


class DirectIpHttp:
    id, version, category, stage = "pcap.direct_ip_http", "1.0.0", "pcap.direct_ip_http", "OUTBOUND"
    data_sources = {"zeek_http"}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
        for e in ctx.events.iterate(ctx.investigation_id, [HTTP, Filter(field="ext.zeek.host_is_ip", value=True)]):
            dst = e.get("dst_ip") or ""
            if dst and ip_scope(dst) == "external":
                groups[(e.get("src_ip") or "", dst)].append(e)
        out = []
        for (src, dst), evs in sorted(groups.items(), key=lambda kv: -len(kv[1]))[:5]:
            lo, hi = _span(evs)
            out.append(FindingDraft(
                self.id, self.version, "Possible Direct-IP HTTP Communication", self.category, self.stage, 0.4, "medium",
                [metric("requests", len(evs), label="Requests with IP Host header")],
                [check("Host header is an IP literal (no DNS name)", True, dst),
                 check("Destination is external", True, dst)],
                [f"ip:{src}", f"ip:{dst}"], _q([HTTP, Filter(field="dst_ip", value=dst)]), lo, hi, f"{self.id}:{src}:{dst}",
                attack=[AttackMap("T1071.001", "low", "도메인 없이 IP로 HTTP 통신", condition_met=False,
                                  rationale="common for malware, also for some legitimate agents")],
                explanation=f"{src} → {dst} 도메인 없이 IP 주소로 HTTP 요청 {len(evs)}건."
                            + _advice("요청 URI·User-Agent로 정상 업데이트/관리 에이전트인지 확인"),
                sample_event_ids=_ids(evs), total_events=len(evs)))
        return out


class IocMatch:
    id, version, category, stage = "pcap.ioc_match", "1.0.0", "ioc.match", "OUTBOUND"
    data_sources = {"zeek_conn", "zeek_dns", "zeek_http", "zeek_files", "zeek_ssl", "web", "waf"}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        iocs: list[tuple[str, str]] = ctx.params.get("iocs") or []

        if not iocs:
            return []
        inv = ctx.investigation_id
        ips = sorted({v for t, v in iocs if t == "ip"})
        nets = []
        for t, v in iocs:
            if t == "cidr":
                try:
                    nets.append(ipaddress.ip_network(v, strict=False))
                except ValueError:
                    pass
        doms = sorted({v.lower().rstrip(".") for t, v in iocs if t == "domain"})
        hashes = sorted({v.lower() for t, v in iocs if t == "hash"})
        hits: list[tuple[str, str, list[dict]]] = []
        for ip in ips[:500]:
            for fld in ("dst_ip", "src_ip"):
                evs = ctx.events.search(inv, [Filter(field=fld, value=ip)], limit=50)["events"]
                if evs:
                    hits.append(("ip", ip, evs))
                    break
        for d in doms[:500]:
            evs = ctx.events.search(inv, [Filter(field="domain", op="in", value=[d])], limit=50)["events"] or \
                ctx.events.search(inv, [Filter(field="domain", op="contains", value="." + d)], limit=50)["events"]
            if evs:
                hits.append(("domain", d, evs))
        if hashes:
            evs = ctx.events.search(inv, [FILES, Filter(field="hash", op="in", value=hashes[:500])], limit=50)["events"]
            for h in sorted({e.get("hash") for e in evs}):
                hits.append(("hash", h, [e for e in evs if e.get("hash") == h]))
            # TLS fingerprints shared as IOCs: client JA3 / server JA3S (md5) and certificate SHA-1 / SHA-256
            for fld in ("ja3", "ja3s", "cert_sha1", "cert_sha256"):
                evs = ctx.events.search(inv, [Filter(field="data_source", value="zeek_ssl"),
                                              Filter(field=fld, op="in", value=hashes[:500])], limit=50)["events"]
                for h in sorted({e.get(fld) for e in evs}):
                    hits.append(("hash", h, [e for e in evs if e.get(fld) == h]))
        if nets:
            for e in ctx.events.iterate(inv, [CONN]):
                try:
                    addr = ipaddress.ip_address(e.get("dst_ip") or "")
                except ValueError:
                    continue
                net = next((n for n in nets if addr in n), None)
                if net is not None:
                    hits.append(("cidr", str(net), [e]))
                    break
        out = []
        for kind, value, evs in hits[:20]:
            lo, hi = _span(evs)
            out.append(FindingDraft(
                self.id, self.version, f"IOC Match: {kind} {value}", self.category, self.stage,
                0.85 if kind == "hash" else 0.7, "high",
                [metric("events", len(evs), label="Matching events")],
                [check("Listed in this investigation's IOC list", True, value),
                 check("Observed in evidence", True, f"{len(evs)}건")],
                [f"{'hash' if kind == 'hash' else 'domain' if kind == 'domain' else 'ip'}:{value}"],
                {"filters": []}, lo, hi, f"{self.id}:{kind}:{value}",
                attack=[AttackMap("T1105" if kind == "hash" else "T1071", "low", "IOC 일치", condition_met=False,
                                  rationale="IOC match shows contact, not the technique")],
                explanation=f"IOC 목록의 {kind} `{value}` 가 증거에서 {len(evs)}건 관측."
                            + _advice("IOC 출처·작성일을 확인해 현재도 유효한 지표인지 검토", "관련 호스트의 같은 시간대 활동 확인"),
                sample_event_ids=_ids(evs), total_events=len(evs)))
        return out


TLS = Filter(field="data_source", value="zeek_ssl")


def _iso_epoch(v: str | None) -> float | None:
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp() if v else None
    except ValueError:
        return None


class TlsCertificateAnomaly:
    """Server certificates seen in clear (TLS <= 1.2) that look like attacker infrastructure: self-signed, expired or
    not yet valid at connection time, issued days before use, not matching the requested server name, weak keys."""

    id, version, category, stage = "pcap.tls_certificate", "1.0.0", "pcap.tls_certificate", "OUTBOUND"
    data_sources = {"zeek_ssl"}
    WEIGHT = {"self_signed": 0.2, "expired": 0.15, "not_yet_valid": 0.15, "name_mismatch": 0.2, "fresh": 0.1, "weak": 0.1}
    LABEL = {"self_signed": "자체 서명 인증서", "expired": "접속 시점에 만료됨", "not_yet_valid": "접속 시점에 아직 유효하지 않음",
             "name_mismatch": "요청한 서버 이름과 인증서 이름 불일치", "fresh": "발급 3일 이내에 사용", "weak": "약한 키 또는 서명(SHA-1/MD5, RSA<2048)"}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        groups: dict[tuple[str, str], dict[str, Any]] = {}
        for e in ctx.events.iterate(ctx.investigation_id, [TLS, Filter(field="cert_sha1", op="exists")],
                                    fields=["event_id", "timestamp", "src_ip", "dst_ip", "dst_port", "domain", "ext"]):
            if ip_scope(str(e.get("dst_ip") or "")) != "external":
                continue  # internal services often use private CAs / self-signed certificates
            z = (e.get("ext") or {}).get("zeek") or {}
            cert = z.get("cert") or {}
            ts, nb, na = _iso_epoch(e.get("timestamp")), _iso_epoch(cert.get("not_before")), _iso_epoch(cert.get("not_after"))
            flags = set()
            if cert.get("self_signed"):
                flags.add("self_signed")
            if ts and na and ts > na:
                flags.add("expired")
            if ts and nb and ts < nb:
                flags.add("not_yet_valid")
            if ts and nb and 0 <= ts - nb < 3 * 86400:
                flags.add("fresh")
            if z.get("cert_name_match") is False:
                flags.add("name_mismatch")
            if (cert.get("key_type") == "rsa" and (cert.get("key_bits") or 4096) < 2048) or cert.get("sig_hash") in ("sha1", "md5"):
                flags.add("weak")
            if not flags:
                continue
            g = groups.setdefault((e["dst_ip"], cert.get("sha1") or ""), {"flags": set(), "events": [], "sni": set(), "cert": cert})
            g["flags"] |= flags
            g["events"].append(e)
            if e.get("domain"):
                g["sni"].add(e["domain"])
        out = []
        for (dst, sha1), g in sorted(groups.items(), key=lambda kv: -sum(self.WEIGHT[f] for f in kv[1]["flags"]))[:20]:
            flags, evs, cert = g["flags"], g["events"], g["cert"]
            sev = min(0.9, 0.3 + sum(self.WEIGHT[f] for f in flags))
            lo, hi = _span(evs)
            names = ", ".join(sorted(g["sni"])[:3]) or "(SNI 없음)"
            out.append(FindingDraft(
                self.id, self.version, "Potential Suspicious TLS Certificate", self.category, self.stage, sev,
                "high" if len(flags) >= 2 else "medium",
                [metric("connections", len(evs), label="Connections"), metric("anomalies", len(flags), label="Certificate anomalies")],
                [check(self.LABEL[f], f in flags, "예" if f in flags else "아니오") for f in self.LABEL]
                + [check("인증서", None, f"CN={cert.get('subject_cn')} / 발급자 CN={cert.get('issuer_cn')}"),
                   check("유효 기간", None, f"{cert.get('not_before', '')[:10]} ~ {cert.get('not_after', '')[:10]}"),
                   check("SHA-1 지문", None, sha1)],
                [f"ip:{dst}"] + [f"domain:{d}" for d in sorted(g["sni"])[:3]],
                _q([TLS, Filter(field="dst_ip", value=dst), Filter(field="cert_sha1", value=sha1)]), lo, hi,
                f"{self.id}:{dst}:{sha1}",
                attack=[AttackMap("T1573.002", "low", "비정상 인증서를 쓰는 외부 암호화 통신", condition_met=False,
                                  rationale="certificate anomalies suggest attacker-run infrastructure but do not prove C2")],
                explanation=f"{dst} ({names}) 의 서버 인증서: " + ", ".join(self.LABEL[f] for f in sorted(flags)) + f". 연결 {len(evs)}건."
                            + _advice("SHA-1 지문으로 내부 위협 정보·과거 사례를 검색", "이 목적지와 통신한 내부 호스트와 시간대를 확인",
                                      "정상 서비스(사내 장비·테스트 서버)인지 담당 부서에 확인"),
                sample_event_ids=_ids(evs), total_events=len(evs)))
        return out


PCAP_DETECTORS = [WebAttackInTraffic(), WebShellUpload(), MalwareDelivery(), CleartextCredentials(), BruteForceAuth(),
                  ArpSpoofing(), DgaNxDomain(), DirectIpHttp(), TlsCertificateAnomaly(), IocMatch()]
