"""Deterministic synthetic logs for tests/demo (scenario from docs: API enumeration from cloud IPs, etc.).

All addresses use the FIXTURE enrichment ranges; data is synthetic.
"""
from __future__ import annotations

import gzip
import json
import random
from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9))
UA_BROWSER = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36",
              "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
              "BankApp/5.2.1 (Android 14; SM-S921N) okhttp/4.12.0"]
NORMAL_PATHS = ["/", "/main", "/api/accounts/summary", "/api/notice?page=1", "/static/app.js", "/static/app.css",
                "/api/customer/search?q=kim", "/login", "/api/products?category=card"]


def _line(ip: str, ts: datetime, method: str, uri: str, status: int, size: int, ua: str) -> str:
    t = ts.astimezone(KST).strftime("%d/%b/%Y:%H:%M:%S +0900")
    return f'{ip} - - [{t}] "{method} {uri} HTTP/1.1" {status} {size} "-" "{ua}"'


def scenario_weblog(seed: int = 7, normal: int = 3000, enum_count: int = 1200) -> list[str]:
    rnd = random.Random(seed)
    base = datetime(2026, 10, 5, 2, 30, tzinfo=KST)
    lines: list[tuple[datetime, str]] = []
    kr_ips = [f"121.{rnd.randint(128, 191)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}" for _ in range(160)]
    for i in range(normal):
        ts = base + timedelta(seconds=rnd.randint(0, 80 * 60))
        p = rnd.choice(NORMAL_PATHS)
        lines.append((ts, _line(rnd.choice(kr_ips), ts, "GET", p, 200 if p != "/login" else 200,
                                rnd.randint(300, 9000), rnd.choice(UA_BROWSER))))
    # API enumeration: 43 cloud IPs, same UA, sequential ids, mostly 200
    cloud_ips = ([f"43.{rnd.randint(200, 203)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}" for _ in range(31)]
                 + [f"34.64.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}" for _ in range(8)]
                 + [f"45.32.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}" for _ in range(4)])
    start = base + timedelta(minutes=28, seconds=41)
    for k in range(enum_count):
        ts = start + timedelta(milliseconds=int(k * 740 + rnd.randint(-60, 60)))
        status = 200 if rnd.random() < 0.914 else 404
        lines.append((ts, _line(cloud_ips[k % len(cloud_ips)], ts, "GET", f"/api/customer?id={10001 + k}", status,
                                rnd.randint(1700, 1900) if status == 200 else 120, "python-httpx/0.27")))
    # discovery + sensitive file probe from a VPS
    scanner = "104.248.11.20"
    probe = ["/.env", "/.git/config", "/config.php", "/backup.sql", "/wp-admin/", "/phpinfo.php", "/server-status",
             "/admin/", "/actuator/env", "/.aws/credentials"]
    t0 = base + timedelta(minutes=20)
    for k in range(260):
        ts = t0 + timedelta(milliseconds=k * 300)
        path = probe[k] if k < len(probe) else f"/{rnd.choice(['old', 'test', 'dev', 'tmp', 'bak'])}{k}/index.php"
        status = 200 if path == "/.env" else 404
        lines.append((ts, _line(scanner, ts, "GET", path, status, 87 if status == 200 else 150, "Mozilla/5.0 zgrab/0.x")))
    # SQLi-like mutation attempts
    sq = "61.72.33.9"
    for k, payload in enumerate(["1'", "1%27%20OR%201%3D1--", "1%20UNION%20SELECT%20null,version()--",
                                 "1%27%20AND%20SLEEP(5)--", "%252e%252e%252fetc%252fpasswd"]):
        ts = base + timedelta(minutes=31, seconds=k * 7)
        lines.append((ts, _line(sq, ts, "GET", f"/search?q={payload}", 500 if k == 2 else 200, 512, UA_BROWSER[0])))
    # 403 -> mutation -> 200
    mut = "43.201.77.5"
    for k, (m, uri, st) in enumerate([("GET", "/api/user?id=100", 403), ("GET", "/api/user?userId=100", 403),
                                      ("POST", "/api/user", 200)]):
        ts = base + timedelta(minutes=30, seconds=k * 20)
        lines.append((ts, _line(mut, ts, m, uri, st, 1832 if st == 200 else 512, "python-httpx/0.27")))
    # credential stuffing on /login
    cs = "211.36.9.77"
    for k in range(120):
        ts = base + timedelta(minutes=40, seconds=k * 2)
        lines.append((ts, _line(cs, ts, "POST", "/api/auth/login", 401 if k % 40 else 200, 90, "okhttp/4.9.0")))
    lines.sort(key=lambda x: x[0])
    return [x[1] for x in lines]


def scenario_waf_jsonl(seed: int = 7) -> list[str]:
    rnd = random.Random(seed)
    base = datetime(2026, 10, 4, 18, 31, tzinfo=timezone.utc)
    out = []
    for k in range(40):
        ts = base + timedelta(seconds=k * 3)
        out.append(json.dumps({"timestamp": ts.isoformat().replace("+00:00", "Z"), "src_ip": "61.72.33.9",
                               "method": "GET", "uri": "/search?q=1%27%20OR%201%3D1--", "status": 403,
                               "action": "block", "rule_id": "942100", "attack_type": "SQL Injection",
                               "host": "service.example.com"}))
    rnd.random()
    return out


def gz_bytes(lines: list[str]) -> bytes:
    return gzip.compress(("\n".join(lines) + "\n").encode("utf-8"))


def scenario_zeek(seed: int = 7) -> dict[str, list[str]]:
    """Synthetic Zeek JSON (conn/dns/ssl) + Suricata eve.json for the network part of the demo scenario."""
    rnd = random.Random(seed)
    t0 = datetime(2026, 10, 4, 17, 58, tzinfo=timezone.utc).timestamp()
    conn, dns, ssl, eve = [], [], [], []
    uid = 0

    def c(ts, src, sp, dst, dp, svc, ob, rb, dur, state="SF", proto="tcp"):
        nonlocal uid
        uid += 1
        conn.append(json.dumps({"ts": round(ts, 6), "uid": f"C{uid:08x}", "id.orig_h": src, "id.orig_p": sp, "id.resp_h": dst,
                                "id.resp_p": dp, "proto": proto, "service": svc, "duration": dur, "orig_bytes": ob,
                                "resp_bytes": rb, "conn_state": state, "history": "ShADadFf", "community_id": f"1:{uid:020d}="}))
    # background: internal clients to a few external services
    internal = [f"10.10.1.{i}" for i in range(30, 60)]
    ext = ["121.130.10.5", "121.131.22.9", "13.124.50.10", "34.64.20.7"]
    for _ in range(1500):
        ts = t0 + rnd.uniform(0, 2900)
        c(ts, rnd.choice(internal), rnd.randint(40000, 65000), rnd.choice(ext), 443, "ssl", rnd.randint(500, 9000),
          rnd.randint(2000, 90000), rnd.uniform(0.1, 30))
    # large outbound: api server -> 185.220.100.5 (3.2 GB in 4 long connections)
    for k in range(4):
        c(t0 + 1020 + k * 600, "10.10.1.21", 51000 + k, "185.220.100.5", 443, "ssl", 800 * 1024**2, 2 * 1024**2, 590.0)
    # periodic beacon every 60s +-1s to 43.201.88.10:443
    for k in range(48):
        c(t0 + 300 + k * 60 + rnd.uniform(-1, 1), "10.10.1.21", 52000 + k, "43.201.88.10", 443, "ssl", 512 + rnd.randint(-8, 8), 1024, 0.4)
    # long-lived ssh
    c(t0 + 50, "10.10.1.35", 50001, "45.32.10.20", 22, "ssh", 2_000_000, 5_000_000, 5400.0)
    # http on 443 (unexpected protocol)
    for k in range(5):
        c(t0 + 900 + k, "10.10.1.40", 53000 + k, "104.248.11.20", 443, "http", 300, 2000, 0.2)
    # internal port scan 10.10.1.50 -> 10.10.1.30
    for port in range(1, 121):
        c(t0 + 1500 + port * 0.05, "10.10.1.50", 45000, "10.10.1.30", port, None, 0, 0, 0.0, "REJ")
    # DNS: normal + tunneling-like subdomains
    for _ in range(400):
        ts = t0 + rnd.uniform(0, 2900)
        q = rnd.choice(["api.example.com", "update.vendor.com", "www.google.com", "login.bank.example.kr"])
        dns.append(json.dumps({"ts": ts, "uid": "D", "id.orig_h": rnd.choice(internal), "id.orig_p": 53000, "id.resp_h": "10.10.0.2",
                               "id.resp_p": 53, "proto": "udp", "query": q, "qtype_name": "A", "rcode_name": "NOERROR", "trans_id": 1}))
    for k in range(421):
        sub = "".join(rnd.choice("abcdef0123456789") for _ in range(32))
        dns.append(json.dumps({"ts": t0 + 1100 + k * 2.1, "uid": "D", "id.orig_h": "10.10.1.21", "id.orig_p": 53001,
                               "id.resp_h": "10.10.0.2", "id.resp_p": 53, "proto": "udp", "query": f"{sub}.suspicious-example.com",
                               "qtype_name": "TXT" if k % 3 == 0 else "A", "rcode_name": "NOERROR", "trans_id": k}))
    # TLS: common JA4 + one rare
    common = ["t13d1516h2_8daaf6152771_02713d6af862", "t13d1517h2_8daaf6152771_b0da82dd1658", "t12d1209h2_d34a8e72043a_b39be8c56a14"]
    for _ in range(300):
        ssl.append(json.dumps({"ts": t0 + rnd.uniform(0, 2900), "uid": "S", "id.orig_h": rnd.choice(internal), "id.orig_p": 50000,
                               "id.resp_h": rnd.choice(ext), "id.resp_p": 443, "version": "TLSv13", "cipher": "TLS_AES_128_GCM_SHA256",
                               "server_name": "api.example.com", "established": True, "ja4": rnd.choice(common)}))
    for k in range(48):
        ssl.append(json.dumps({"ts": t0 + 300 + k * 60, "uid": "S", "id.orig_h": "10.10.1.21", "id.orig_p": 52000 + k,
                               "id.resp_h": "43.201.88.10", "id.resp_p": 443, "version": "TLSv12", "cipher": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                               "server_name": "cdn-sync.example.net", "established": True, "ja4": "t12i0705h1_1a2b3c4d5e6f_9f8e7d6c5b4a"}))
    # Suricata alerts (rule metadata carries ATT&CK ids)
    for port in range(1, 121, 10):
        eve.append(json.dumps({"timestamp": datetime.fromtimestamp(t0 + 1500 + port * 0.05, timezone.utc).isoformat(),
                               "flow_id": port, "event_type": "alert", "src_ip": "10.10.1.50", "src_port": 45000, "dest_ip": "10.10.1.30",
                               "dest_port": port, "proto": "TCP", "community_id": f"1:scan{port}=",
                               "alert": {"signature_id": 2001219, "signature": "ET SCAN Potential SSH Scan / port sweep (synthetic)",
                                         "category": "Attempted Information Leak", "severity": 2,
                                         "metadata": {"mitre_technique_id": ["T1046"], "mitre_tactic_id": ["TA0007"]}}}))
    return {"zeek_conn.log": conn, "zeek_dns.log": dns, "zeek_ssl.log": ssl, "eve.json": eve}


def scenario_pcap(seed: int = 7) -> bytes:
    """Same network story as scenario_zeek, but as a real PCAP (for the built-in analyzer / Windows servers).

    Large transfers use header-only frames (stored bytes << wire bytes), so the file stays small.
    """
    from saw.devtools import pcap_writer as pw

    rnd = random.Random(seed)
    t0 = datetime(2026, 10, 4, 17, 58, tzinfo=timezone.utc).timestamp()
    w = pw.PcapWriter()
    internal = [f"10.10.1.{i}" for i in range(30, 60)]
    ext = ["121.130.10.5", "121.131.22.9", "13.124.50.10", "34.64.20.7"]
    hellos = [pw.client_hello("api.example.com"),
              pw.client_hello("www.example.kr", alpn="http/1.1"),
              pw.client_hello("update.vendor.com", exts=[e for e in pw.CHROME_EXTS if e != 0x4469])]
    port = 40000
    # background TLS browsing (common fingerprints, many hosts)
    for _ in range(150):
        port += 1
        w.tcp_session(t0 + rnd.uniform(0, 2900), rnd.choice(internal), port, rnd.choice(ext), 443,
                      [(rnd.choice(hellos), pw.server_hello()), (b"\x17\x03\x03\x00\x40" + b"\0" * 64, b"\x17\x03\x03\x01\x00" + b"\0" * 256)])
    # periodic beacon every 60s ±1s, rare client fingerprint (single host)
    beacon = pw.client_hello("cdn-sync.example.net", alpn="http/1.1", ciphers=[0xC030, 0xC02F, 0x009D, 0x009C, 0x0035, 0x002F, 0x000A],
                             exts=[0x0000, 0x000A, 0x000B, 0x000D, 0x0010], grease=False)
    for k in range(48):
        w.tcp_session(t0 + 300 + k * 60 + rnd.uniform(-1, 1), "10.10.1.21", 52000 + k, "43.201.88.10", 443,
                      [(beacon, pw.server_hello(0xC030, tls13=False))])
    # large outbound: API server → 185.220.100.5 (≈150 MB, upload-dominant)
    w.tcp_session(t0 + 1020, "10.10.1.21", 51000, "185.220.100.5", 443, [(hellos[0], pw.server_hello())], close="none")
    w.bulk(t0 + 1021, "10.10.1.21", 51000, "185.220.100.5", 443, 150 * 1024 * 1024, seg=60000, dur=240)
    # long-lived SSH (90 min, keepalives)
    w.tcp_session(t0 + 50, "10.10.1.35", 50001, "45.32.10.20", 22, [(b"SSH-2.0-OpenSSH_9.6\r\n", b"SSH-2.0-OpenSSH_8.9\r\n")], close="none")
    for k in range(1, 46):
        w.tcp(t0 + 50 + k * 120, "10.10.1.35", 50001, "45.32.10.20", 22, pw.PSH | pw.ACK, b"\0" * 48)
    w.tcp(t0 + 5450, "10.10.1.35", 50001, "45.32.10.20", 22, pw.FIN | pw.ACK)
    # plain HTTP on 443 (unexpected protocol)
    for k in range(5):
        w.tcp_session(t0 + 900 + k, "10.10.1.40", 53000 + k, "104.248.11.20", 443,
                      [(pw.http_get("104.248.11.20", f"/gate.php?id={k}", "Mozilla/4.0"), pw.http_resp(200, b"ok", "text/plain"))])
    # internal port scan 10.10.1.50 → 10.10.1.30 (SYN → RST)
    for p in range(1, 121):
        w.tcp(t0 + 1500 + p * 0.05, "10.10.1.50", 45000 + p, "10.10.1.30", p, pw.SYN)
        w.tcp(t0 + 1500 + p * 0.05 + 0.001, "10.10.1.30", p, "10.10.1.50", 45000 + p, pw.RST | pw.ACK)
    # DNS: normal + tunneling-like subdomains
    tid = 0
    for _ in range(200):
        tid += 1
        ts, q, h = t0 + rnd.uniform(0, 2900), rnd.choice(["api.example.com", "update.vendor.com", "www.google.com"]), rnd.choice(internal)
        w.udp(ts, h, 53000 + tid % 1000, "10.10.0.2", 53, pw.dns_query(tid, q))
        w.udp(ts + 0.004, "10.10.0.2", 53, h, 53000 + tid % 1000, pw.dns_response(tid, q, "203.0.113.10"))
    for k in range(250):
        tid += 1
        sub = "".join(rnd.choice("abcdef0123456789") for _ in range(32))
        qt = 16 if k % 3 == 0 else 1
        w.udp(t0 + 1100 + k * 2.1, "10.10.1.21", 54001, "10.10.0.2", 53, pw.dns_query(tid, f"{sub}.suspicious-example.com", qt))
        w.udp(t0 + 1100 + k * 2.1 + 0.02, "10.10.0.2", 53, "10.10.1.21", 54001, pw.dns_response(tid, f"{sub}.suspicious-example.com", None, 3, qt))
    return w.to_bytes()


PE_SAMPLE = b"MZ" + b"\x90" * 58 + (0x40).to_bytes(4, "little") + b"PE\x00\x00" + bytes(range(256)) * 40


def scenario_pcap_forensics(seed: int = 11) -> bytes:
    """Compromise story for the PCAP forensic detectors (all synthetic, inert payloads):
    SQLi with leaked /etc/passwd, web shell upload→use, masqueraded EXE, exploit-kit chain, FTP brute force→success
    + file download, SMTP AUTH in cleartext, ARP spoofing of the gateway, NXDOMAIN burst (DGA), direct-IP HTTP.
    """
    import base64

    from saw.devtools import pcap_writer as pw

    rnd = random.Random(seed)
    t0 = datetime(2026, 10, 6, 1, 10, tzinfo=timezone.utc).timestamp()
    w = pw.PcapWriter()
    web, attacker, victim = "10.20.1.15", "203.0.113.66", "10.20.5.33"
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    # 1) SQL injection with a success signal in the response
    for k, q in enumerate(["/item?id=1", "/item?id=1%27%20OR%20%271%27%3D%271", "/item?id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
                           "/download?file=..%2F..%2F..%2Fetc%2Fpasswd"]):
        body = b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n" if "passwd" in q else \
            b"You have an error in your SQL syntax near ''1''" if "%27" in q else b"<html>item</html>"
        w.tcp_session(t0 + k * 2, attacker, 40100 + k, web, 80,
                      [(pw.http_get("shop.example.com", q, "sqlmap/1.8"), pw.http_resp(200, body, "text/html"))])
    # 2) web shell: PUT shell.jsp then use it
    shell = b"<%@ page import=\"java.io.*\" %><% Runtime.getRuntime().exec(request.getParameter(\"c\")); %>"
    put = (b"PUT /uploads/shell.jsp HTTP/1.1\r\nHost: shop.example.com\r\nContent-Type: application/octet-stream\r\n"
           b"Content-Length: " + str(len(shell)).encode() + b"\r\n\r\n" + shell)
    w.tcp_session(t0 + 20, attacker, 40200, web, 80, [(put, pw.http_resp(201, b"created", "text/plain"))])
    for k in range(3):
        w.tcp_session(t0 + 30 + k, attacker, 40210 + k, web, 80,
                      [(pw.http_get("shop.example.com", f"/uploads/shell.jsp?c=id%3B{k}", "curl/8.0"),
                        pw.http_resp(200, b"uid=33(www-data) gid=33(www-data)", "text/plain"))])
    # 3) victim downloads an executable disguised as an image (direct IP host)
    w.tcp_session(t0 + 60, victim, 50300, "45.77.12.34", 80,
                  [(pw.http_get("45.77.12.34", "/img/invoice.jpg", ua), pw.http_resp(200, PE_SAMPLE, "image/jpeg"))])
    # 4) exploit-kit chain: landing page → Flash → high-entropy payload within 2 minutes
    land = b"<html><body><object data='/x/ad.swf'></object><script>var a='" + bytes(rnd.choice(b"abcdef") for _ in range(400)) + b"'</script></body></html>"
    w.tcp_session(t0 + 100, victim, 50310, "192.0.2.150", 80,
                  [(b"GET /landing.php HTTP/1.1\r\nHost: ek.example.org\r\nReferer: http://news.example.com/\r\nUser-Agent: " + ua.encode() + b"\r\n\r\n",
                    pw.http_resp(200, land, "text/html"))])
    swf = b"CWS\x0a" + bytes(rnd.getrandbits(8) for _ in range(3000))
    w.tcp_session(t0 + 105, victim, 50311, "192.0.2.150", 80,
                  [(pw.http_get("ek.example.org", "/x/ad.swf", ua), pw.http_resp(200, swf, "application/x-shockwave-flash"))])
    blob = bytes(rnd.getrandbits(8) for _ in range(20000))
    w.tcp_session(t0 + 112, victim, 50312, "192.0.2.150", 80,
                  [(pw.http_get("ek.example.org", "/x/p.html", ua), pw.http_resp(200, blob, "text/html"))])
    # 5) FTP brute force then success and a download
    c, s = (attacker, 41000), ("10.20.1.21", 21)
    lines = [(b"", b"220 ProFTPD ready\r\n")]
    for p in ("admin", "123456", "password", "qwerty", "letmein", "welcome"):
        lines += [(b"USER ftpadmin\r\n", b"331 Password required\r\n"), (b"PASS " + p.encode() + b"\r\n", b"530 Login incorrect\r\n")]
    lines += [(b"USER ftpadmin\r\n", b"331 Password required\r\n"), (b"PASS ftpadmin\r\n", b"230 User logged in\r\n"),
              (b"PASV\r\n", b"227 Entering Passive Mode (10,20,1,21,200,10)\r\n"),
              (b"RETR backup_customers.zip\r\n", b"150 Opening BINARY mode data connection\r\n")]
    t = w.tcp_session(t0 + 200, *c, *s, lines, close="none")
    w.tcp_session(t + 0.2, attacker, 41001, "10.20.1.21", 200 * 256 + 10,
                  [(b"", b"PK\x03\x04" + b"\x00" * 26 + b"customers.csv" + bytes(rnd.getrandbits(8) for _ in range(6000)))])
    w.tcp(t + 1, *s, *c, pw.PSH | pw.ACK, b"226 Transfer complete\r\n")
    # 6) SMTP AUTH LOGIN in cleartext
    b64 = lambda x: base64.b64encode(x.encode())  # noqa: E731
    w.tcp_session(t0 + 300, victim, 50400, "10.20.1.25", 25,
                  [(b"", b"220 mail.example.com ESMTP\r\n"), (b"EHLO pc\r\n", b"250 OK\r\n"), (b"AUTH LOGIN\r\n", b"334 VXNlcm5hbWU6\r\n"),
                   (b64("kim.analyst") + b"\r\n", b"334 UGFzc3dvcmQ6\r\n"), (b64("Autumn#2026") + b"\r\n", b"235 2.7.0 Authentication successful\r\n")])
    # 7) ARP spoofing of the gateway
    w.arp(t0 + 400, 2, "00:1a:2b:3c:4d:01", "10.20.0.1", "aa:bb:cc:00:00:33", victim)
    for k in range(5):
        w.arp(t0 + 401 + k, 2, "de:ad:be:ef:00:66", "10.20.0.1", "aa:bb:cc:00:00:33", victim)
    # 8) NXDOMAIN burst (DGA-like)
    for k in range(25):
        name = "".join(rnd.choice("bcdfghjklmnpqrstvwxz") for _ in range(12)) + rnd.choice([".com", ".net", ".info", ".biz"])
        w.udp(t0 + 500 + k, victim, 53500 + k, "10.20.0.2", 53, pw.dns_query(9000 + k, name))
        w.udp(t0 + 500 + k + 0.01, "10.20.0.2", 53, victim, 53500 + k, pw.dns_response(9000 + k, name, None, 3))
    return w.to_bytes()


NDR_HEADER = ("flow time,source ipaddr,source port,destination ipaddr,destination port,protocol,app category,app1,app2,"
              "source country,destination country,upload packets,upload byte,download packtes,download byte,meta type,"
              "meta filter,meta time,sequence,number of meta,transactionn id,server id,stream id,flow rowid,meta data"
              + "," * 19)


def scenario_ndr_meta_csv(seed: int = 13, normal: int = 600) -> str:
    """Synthetic NDR meta-search CSV export: mobile-banking traffic + SQLi/traversal/scanner and an ID walk.

    One row per meta record (http_request / http_response / traffic) like the appliance export; cookies carry
    fake session ids so the importer's redaction can be verified.
    """
    import csv
    import io

    rnd = random.Random(seed)
    server, host = "203.0.113.10", "mbank.example.com"
    base = datetime(2026, 10, 3, 17, 30, tzinfo=KST)
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    buf.write(NDR_HEADER + "\n")
    seq = [30000]
    flow = [600000]

    def row(ts: datetime, src: str, sport: int, meta: str, up: int, down: int) -> None:
        seq[0] += 1
        w.writerow([ts.strftime("%Y-%m-%d %H:%M"), src, sport, server, 8080, 6, "Web", "HTTP", "HTTP",
                    "KR" if src.startswith(("211.", "175.", "59.")) else "US", "KR", 4, up, 5, down, "meta",
                    "filtered=none", "time=" + ts.strftime("%Y-%m-%d %H:%M:%S+0900"), f"seq={seq[0]}",
                    "num_of_meta=2", "transaction_id=0", "server_id=11100", "stream=1", f"flow_rowid={flow[0]}", meta]
                   + [""] * 19)

    def exchange(ts: datetime, src: str, method: str, path: str, status: int, ua: str, size: int = 900) -> None:
        flow[0] += 1
        sport = rnd.randint(40000, 65000)
        sid = "".join(rnd.choice("0123456789abcdef") for _ in range(32))
        row(ts, src, sport, f"type=http_request;method=request;hostname={host};method={method};num_of_req=1;path={path};"
            f"ua={ua};refer=;content_type=application/x-www-form-urlencoded; charset=utf-8;multi_attname=;"
            f"content_language=;accept_language=ko-KR,ko;q=0.9;xfwd=;cookie=JSESSIONID={sid}; WMONID=w{sid[:8]}",
            700, size)
        row(ts + timedelta(milliseconds=40), src, sport, f"type=http_response;method=response;ret_code={status};"
            f"num_of_res=1;content_type=application/json;server=Bank;content_disposition=;set_cookie=", 700, size)
        row(ts + timedelta(milliseconds=50), src, sport, f"type=traffic;Uploadpackets=4;Downloadpackets=5;"
            f"Uploadbytes=700;Downloadbytes={size}", 700, size)

    app_ua = "BankApp/7.1 (iPhone; iOS 18.7)"
    for k in range(normal):
        exchange(base + timedelta(seconds=k * 3), f"211.{rnd.randint(1, 250)}.{rnd.randint(1, 250)}.{rnd.randint(1, 250)}",
                 "POST", rnd.choice(["/BCOM/main.do", "/ACCT/summary.do", "/TRNS/list.do", "/CARD/bill.do"]), 200, app_ua)
    attacker, t = "45.77.12.34", base + timedelta(minutes=40)
    for k, p in enumerate(["/login.do?id=admin'%20OR%20'1'='1", "/search.do?q=1%20UNION%20SELECT%20user,pass%20FROM%20t",
                           "/download.do?file=../../../../etc/passwd", "/.env", "/.git/config", "/admin/backup.sql"]):
        exchange(t + timedelta(seconds=k * 2), attacker, "GET", p, 200 if "passwd" in p else 404, "sqlmap/1.8.4#stable")
    walker = "52.79.10.20"
    for k in range(300):
        exchange(base + timedelta(minutes=50, seconds=k), walker, "GET", f"/api/customer?id={10001 + k}", 200,
                 "python-httpx/0.27")
    return buf.getvalue()


def scenario_kr_firewall_csv(seed: int = 17) -> bytes:
    """Synthetic Korean-header firewall export saved by Excel (CP949) with a 60 s beacon and a large upload."""
    rnd = random.Random(seed)
    base = datetime(2026, 10, 3, 9, 0, tzinfo=KST)
    lines = ["발생시간,출발지 IP,출발지포트,목적지 IP,목적지포트,프로토콜,송신바이트,수신바이트,정책명,조치"]
    for k in range(400):
        ts = base + timedelta(seconds=k * 7)
        lines.append(f"{ts:%Y-%m-%d %H:%M:%S},10.10.{rnd.randint(1, 9)}.{rnd.randint(2, 250)},{rnd.randint(40000, 65000)},"
                     f"203.0.113.{rnd.randint(2, 40)},443,TCP,{rnd.randint(500, 3000)},{rnd.randint(2000, 90000)},업무망-인터넷,허용")
    for k in range(48):
        ts = base + timedelta(seconds=60 * k + rnd.uniform(-0.8, 0.8))
        lines.append(f"{ts:%Y-%m-%d %H:%M:%S},10.10.5.20,{50000 + k},45.77.12.34,443,TCP,420,380,업무망-인터넷,허용")
    lines.append(f"{base + timedelta(hours=1):%Y-%m-%d %H:%M:%S},10.10.5.20,51999,45.77.12.34,8443,TCP,3400000000,5200,"
                 "업무망-인터넷,허용")
    return ("\r\n".join(lines) + "\r\n").encode("cp949")


def make_cert(cn: str, *, issuer: tuple | None = None, san: list[str] | None = None, not_before: datetime,
              days: int = 365, rsa_bits: int = 2048, ca: bool = False):
    """Synthetic X.509 certificate (DER) and its key: issuer=(name, key) signs it, else it is self-signed."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    iname, ikey = issuer if issuer else (name, key)
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(iname).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(not_before)
         .not_valid_after(not_before + timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in san]), critical=False)
    from cryptography.hazmat.primitives.serialization import Encoding

    cert = b.sign(ikey, hashes.SHA256())
    return cert.public_bytes(Encoding.DER), (name, key)


def scenario_tls_certs() -> bytes:
    """TLS 1.2 sessions with server certificates: a suspicious external one (self-signed, issued the day before,
    SNI mismatch, RSA-1024), a normal external one signed by a CA, and an internal self-signed service."""
    from saw.devtools import pcap_writer as pw

    t0 = datetime(2026, 10, 3, 9, 0, tzinfo=timezone.utc)
    w = pw.PcapWriter()
    bad, _ = make_cert("localhost", not_before=t0 - timedelta(days=1), days=30, rsa_bits=1024)
    ca_der, ca = make_cert("Example Root CA", not_before=t0 - timedelta(days=2000), days=4000, ca=True)
    good, _ = make_cert("www.example.com", issuer=ca, san=["www.example.com", "example.com"],
                        not_before=t0 - timedelta(days=200))
    internal, _ = make_cert("intranet.corp.local", not_before=t0 - timedelta(days=500), days=3650)
    client = "10.20.1.21"
    for k, (srv, sni, chain) in enumerate([("45.77.12.34", "update.example.com", [bad]),
                                           ("52.79.10.20", "www.example.com", [good, ca_der]),
                                           ("10.20.1.5", "intranet.corp.local", [internal])]):
        for rep in range(3):
            w.tcp_session(t0.timestamp() + 60 * k + 5 * rep, client, 50100 + 10 * k + rep, srv, 443,
                          [(pw.client_hello(sni), pw.server_flight_tls12(chain))])
    return w.to_bytes()
