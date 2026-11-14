"""Synthetic records for the authentication -> lookup flow scenarios (NDR HTTP, application, WAF, IPS, DDoS, FW).

Everything is synthetic: documentation/private addresses, *.example.test hosts, made-up accounts. The service host,
paths, cookie name, accounts and session values are parameters, so nothing about one service is fixed in the
engine or in a test. `truth` describes what was planted and is never given to the engine.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta

NDR_HEADER = ("event_time,_site,app,_schema,protocol,src_ip,src_port,src_country,dest_ip,dest_port,dest_country,"
              "_device_ip,_device_name,method,host,path,query,user_agent,referer,req_cookie,uuid,status,sc_bytes,cs_bytes")
APP_HEADER = "event_time,service,event,result,account,session_id,request_id,target,src_ip"
WAF_HEADER = ("event_time,_device_name,vendor,product,rule_id,rule_version,attack_name,action,src_ip,src_port,dest_ip,"
              "dest_port,host,method,path,query,status,request_id,raw_data")
IPS_HEADER = ("event_time,_device_name,vendor,product,signature_id,signature_version,attack_name,action,src_ip,"
              "src_port,dest_ip,dest_port,protocol,flow_id,raw_data")
DDOS_HEADER = ("start_time,end_time,_device_name,target_ip,target_host,vector,metric,unit,value,interval_seconds,"
               "detection_state,mitigation_state")
FW_HEADER = "_time,_device_ip,_device_name,action,src_ip,src_port,dst_ip,dst_port,protocol,tcp_flag,duration,sent_bytes,rcvd_bytes"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SyntheticBrowser/1.0"


def build(*, seed: int = 7, host: str = "portal.example.test", auth_path: str = "/auth.html",
          info_path: str = "/memberinfo", cookie: str = "JSESSIONID", account_prefix: str = "U",
          start: str = "2026-10-20 09:00:00", background_sessions: int = 20, server_ip: str = "10.40.1.10",
          days: int = 1, shuffle: bool = True) -> dict:
    rnd = random.Random(seed)
    t0 = datetime.strptime(start, "%Y-%m-%d %H:%M:%S")
    ndr, app, waf, ips, fw = [], [], [], [], []
    counter = [0]
    truth: dict = {"host": host, "auth_path": auth_path, "info_path": info_path, "cookie": cookie, "sessions": {}}

    def uid() -> str:
        counter[0] += 1
        return f"req-{seed}-{counter[0]:07d}"

    def stamp(t: datetime) -> str:
        return t.strftime("%Y-%m-%d %H:%M:%S")

    def request(t, ip, method, path, query, session, status=200, port=None):
        rid = uid()
        cookies = f"{cookie}={session}; lang=ko" if session else "-"
        ndr.append(f"{stamp(t)},site-a,http,http,TCP,{ip},{port or rnd.randint(40000, 60000)},KR,{server_ip},443,KR,"
                   f"10.40.0.2,ndr-syn-01,{method},{host},{path},{query or '-'},{UA},-,{cookies},{rid},{status},"
                   f"{rnd.randint(300, 4000)},{rnd.randint(200, 900)}")
        return rid

    def app_event(t, event, result, account, session, rid, target, ip):
        app.append(f"{stamp(t)},{host},{event},{result},{account},{session},{rid},{target or '-'},{ip}")

    def conn(t, ip, action="allow"):
        fw.append(f"{stamp(t)},10.40.0.1,fw-syn-01,{action},{ip},{rnd.randint(40000, 60000)},{server_ip},443,TCP,SA,"
                  f"{rnd.randint(1, 30)},{rnd.randint(500, 9000)},{rnd.randint(500, 90000)}")

    def login(t, ip, account, session, ok=True):
        request(t, ip, "GET", auth_path, "", session)
        rid = request(t + timedelta(seconds=4), ip, "POST", auth_path, "", session)  # HTTP 200 either way
        app_event(t + timedelta(seconds=4), "login", "success" if ok else "fail", account, session, rid, "", ip)
        conn(t, ip)
        return rid

    def lookup(t, ip, account, session, target, processed=True, status=200):
        rid = request(t, ip, "GET", info_path, f"id={target}", session, status=status)
        if processed:
            app_event(t, "memberinfo", "success", account, session, rid, target, ip)
        return rid

    acct = lambda n: f"{account_prefix}{n}"  # noqa: E731
    # A. authentication succeeded, then the same session read its own record.
    login(t0, "10.20.1.17", acct(17), "sess-a-0017")
    lookup(t0 + timedelta(seconds=12), "10.20.1.17", acct(17), "sess-a-0017", acct(17))
    truth["sessions"]["A"] = {"session": "sess-a-0017", "account": acct(17), "kind": "auth_success_then_own_lookup"}
    # B. HTTP 200 but the authentication failed; a lookup of another record followed. The WAF blocked that
    #    request, and the same request was seen again three seconds later answered 200.
    tb = t0 + timedelta(minutes=5)
    login(tb, "10.20.1.44", acct(20), "sess-b-0020", ok=False)
    rid_b = lookup(tb + timedelta(seconds=9), "10.20.1.44", acct(20), "sess-b-0020", acct(99), processed=False, status=403)
    waf.append(f"{stamp(tb + timedelta(seconds=9))},waf-syn-01,SynVendor,SynWAF,942100,4,Parameter Tampering,block,"
               f"10.20.1.44,51000,{server_ip},443,{host},GET,{info_path},id={acct(99)},403,{rid_b},"
               f"GET {info_path}?id={acct(99)} HTTP/1.1")
    lookup(tb + timedelta(seconds=12), "10.20.1.44", acct(20), "sess-b-0020", acct(99), processed=False, status=200)
    truth["sessions"]["B"] = {"session": "sess-b-0020", "attempted_account": acct(20), "target": acct(99),
                              "kind": "http_200_auth_failed_then_other_lookup_waf_block_then_retry"}
    # C. a session that was authenticated before the collected period: lookups with no authentication record.
    tc = t0 + timedelta(minutes=9)
    lookup(tc, "10.20.1.61", acct(30), "sess-c-0030", acct(30))
    lookup(tc + timedelta(seconds=40), "10.20.1.61", acct(30), "sess-c-0030", acct(30))
    truth["sessions"]["C"] = {"session": "sess-c-0030", "kind": "no_auth_record_in_window"}
    # D. two users behind one address (NAT): two sessions, two accounts, interleaved in time.
    td = t0 + timedelta(minutes=14)
    login(td, "10.20.9.9", acct(21), "sess-d-0021")
    login(td + timedelta(seconds=2), "10.20.9.9", acct(22), "sess-d-0022")
    lookup(td + timedelta(seconds=15), "10.20.9.9", acct(21), "sess-d-0021", acct(21))
    lookup(td + timedelta(seconds=16), "10.20.9.9", acct(22), "sess-d-0022", acct(22))
    truth["sessions"]["D"] = {"sessions": ["sess-d-0021", "sess-d-0022"], "ip": "10.20.9.9", "kind": "same_ip_two_users"}
    # E. logout, then a lookup in the same session with no new authentication.
    te = t0 + timedelta(minutes=20)
    login(te, "10.20.1.70", acct(40), "sess-e-0040")
    request(te + timedelta(seconds=20), "10.20.1.70", "GET", "/logout.do", "", "sess-e-0040")
    lookup(te + timedelta(seconds=50), "10.20.1.70", acct(40), "sess-e-0040", acct(40), processed=False)
    truth["sessions"]["E"] = {"session": "sess-e-0040", "kind": "lookup_after_logout"}
    # F. a path nobody registered, right after a lookup, in an otherwise ordinary session.
    tf = t0 + timedelta(minutes=26)
    login(tf, "10.20.1.81", acct(50), "sess-f-0050")
    lookup(tf + timedelta(seconds=10), "10.20.1.81", acct(50), "sess-f-0050", acct(50))
    request(tf + timedelta(seconds=13), "10.20.1.81", "GET", "/export/all.do", "fmt=csv", "sess-f-0050")
    truth["sessions"]["F"] = {"session": "sess-f-0050", "kind": "unregistered_step_after_lookup", "path": "/export/all.do"}
    # An IPS alert near session F's export: same addresses and time, no shared identifier.
    ips.append(f"{stamp(tf + timedelta(seconds=14))},ips-syn-01,SynVendor,SynIPS,2100455,2,Bulk Data Download,detect,"
               f"10.20.1.81,52011,{server_ip},443,TCP,flow-77,GET /export/all.do")
    # Background: ordinary sessions spread over the period, with static files.
    span = days * 86400 - 3600
    for i in range(background_sessions):
        tb0 = t0 + timedelta(seconds=rnd.randint(1800, max(1801, span)))
        ip, session, account = f"10.21.{rnd.randint(0, 250)}.{rnd.randint(2, 250)}", f"sess-bg-{seed}-{i:06d}", acct(1000 + i)
        login(tb0, ip, account, session)
        request(tb0 + timedelta(seconds=5), ip, "GET", "/static/app.js", "", session)
        for n in range(rnd.randint(1, 3)):
            lookup(tb0 + timedelta(seconds=10 + n * rnd.randint(5, 60)), ip, account, session, account)
    # Delivery artefacts: one record delivered twice.
    ndr.append(ndr[2])
    truth["duplicates"] = 1
    ddos = [f"{stamp(t0 + timedelta(minutes=4))},{stamp(t0 + timedelta(minutes=7))},ddos-syn-01,{server_ip},{host},"
            f"SYN Flood,pps,packets/s,185000,60,detected,mitigating"]
    truth["ddos"] = {"start": stamp(t0 + timedelta(minutes=4)), "end": stamp(t0 + timedelta(minutes=7))}
    if shuffle:
        rnd.shuffle(ndr)  # delivery order is not event order
        rnd.shuffle(app)

    def text(header, rows):
        return header + "\n" + "\n".join(rows) + "\n"

    return {"ndr.csv": text(NDR_HEADER, ndr), "app.csv": text(APP_HEADER, app), "waf.csv": text(WAF_HEADER, waf),
            "ips.csv": text(IPS_HEADER, ips), "ddos.csv": text(DDOS_HEADER, ddos), "fw.csv": text(FW_HEADER, fw),
            "truth": truth, "rows": {"ndr": len(ndr), "app": len(app), "waf": len(waf), "ips": len(ips), "fw": len(fw)}}


def knowledge(*, host: str = "portal.example.test", auth_path: str = "/auth.html", info_path: str = "/memberinfo",
              cookie: str = "JSESSIONID", logout_path: str = "/logout.do") -> list[dict]:
    """The knowledge an analyst would register for this service, as API bodies (flow steps are filled by the caller)."""
    def activity(method, path, meaning, role, **extra):
        return {"kind": "activity", "content": {"host": host, "method": method, "path": path, "match": "exact",
                                                "meaning": meaning, "role": role, **extra}}

    login = [{"source": "app", "event": "login", "field": "result", "op": "eq", "value": "success", "result": "success"},
             {"source": "app", "event": "login", "field": "result", "op": "eq", "value": "fail", "result": "failure"}]
    done = [{"source": "app", "event": "memberinfo", "field": "result", "op": "eq", "value": "success", "result": "success"}]
    return [activity("GET", auth_path, "인증 화면 접근", "auth_page"),
            activity("POST", auth_path, "인증 시도", "auth_attempt", outcomes=login),
            activity("", info_path, "회원정보 조회", "lookup", object_param="id", outcomes=done),
            activity("", logout_path, "로그아웃", "logout"),
            {"kind": "link", "content": {"host": host, "session_cookie": cookie, "request_id_confirmed": True}}]
