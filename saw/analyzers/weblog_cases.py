"""Synthetic web server log cases for paste analysis (Korean UI text, English code).

Every case is generated deterministically from a seed: documentation and private addresses only (198.51.100.0/24,
203.0.113.0/24, 192.0.2.0/24, 10.0.0.0/8), host names under example.test, no real organisation. Attack requests are
short, well-known detection test strings (for example ``' OR '1'='1``); nothing in them runs against anything.
Each case states which result the analysis is expected to show, and a test checks that it does.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9))
BASE = datetime(2026, 11, 3, 9, 0, tzinfo=KST)
BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
]
SHOP_PATHS = ["/", "/product/list", "/product/view", "/cart", "/static/app.js", "/static/site.css", "/images/logo.png",
              "/event/winter", "/notice", "/search"]
PORTAL_PATHS = ["/", "/main", "/board/list", "/board/view", "/mypage", "/static/portal.css", "/static/portal.js"]


def _ext_ip(r: random.Random) -> str:
    return f"{r.choice(['198.51.100', '203.0.113', '192.0.2'])}.{r.randint(2, 250)}"


def _int_ip(r: random.Random, net: str = "10.20") -> str:
    return f"{net}.{r.randint(1, 30)}.{r.randint(2, 250)}"


def _clf(t: datetime) -> str:
    return t.strftime("%d/%b/%Y:%H:%M:%S %z")


def combined(t, ip, method, uri, status, size, ua, ref="-", user="-") -> str:
    return f'{ip} - {user} [{_clf(t)}] "{method} {uri} HTTP/1.1" {status} {size} "{ref}" "{ua}"'


def common(t, ip, method, uri, status, size, user="-") -> str:
    return f'{ip} - {user} [{_clf(t)}] "{method} {uri} HTTP/1.1" {status} {size}'


def _normal(r: random.Random, n: int, paths: list[str], ips: list[str], start: datetime, span_s: int):
    rows = []
    for _ in range(n):
        t = start + timedelta(seconds=r.randint(0, span_s))
        p = r.choice(paths)
        if p == "/product/view":
            p += f"?id={r.randint(100, 180)}"
        if p == "/board/view":
            p += f"?no={r.randint(1000, 1100)}"
        if p == "/search":
            p += "?q=" + r.choice(["coat", "gift", "boots", "card"])
        status = r.choices([200, 304, 404], [88, 10, 2])[0]
        rows.append((t, r.choice(ips), "GET", p, status, 0 if status == 304 else r.randint(800, 40000), r.choice(BROWSERS)))
    return rows


def _lines(rows, fmt) -> list[str]:
    return [fmt(*row) for row in sorted(rows, key=lambda x: x[0])]


def case_apache_scan(r: random.Random) -> list[str]:
    ips = [_ext_ip(r) for _ in range(25)] + [_int_ip(r) for _ in range(5)]
    rows = _normal(r, 260, SHOP_PATHS, ips, BASE, 3600)
    scanner, ua = "198.51.100.23", "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000562)"
    t0 = BASE + timedelta(minutes=20)
    words = ["old", "test", "dev", "backup2", "tmp", "upload", "cgi-bin", "phpmyadmin", "wp-login.php", "shell", "info",
             "beta", "staging", "private", "docs", "api-old", "install", "setup", "demo", "files"]
    k = 0
    for w in words:
        for ext in ("", ".php", ".bak", ".zip", ".tar.gz", ".jsp", ".asp", ".txt"):
            rows.append((t0 + timedelta(milliseconds=350 * k), scanner, "GET", f"/{w}{ext}", 404, 196, ua))
            k += 1
    for i, (path, status, size) in enumerate([("/admin/", 200, 5120), ("/.git/config", 200, 312), ("/server-status", 403, 199),
                                              ("/.env", 404, 196), ("/backup/db.sql", 404, 196)]):
        rows.append((t0 + timedelta(seconds=60 + i), scanner, "GET", path, status, size, ua))
    return _lines(rows, combined)


def case_nginx_bruteforce(r: random.Random) -> list[str]:
    ips = [_ext_ip(r) for _ in range(30)]
    rows = _normal(r, 220, ["/", "/login", "/static/main.js", "/static/main.css", "/account/summary", "/notice"], ips, BASE, 3600)
    for _ in range(25):  # ordinary logins, mostly first try
        t = BASE + timedelta(seconds=r.randint(0, 3600))
        rows.append((t, r.choice(ips), "POST", "/api/v1/auth/login", r.choices([200, 401], [85, 15])[0], 182, r.choice(BROWSERS)))
    attacker, ua = "203.0.113.45", "python-requests/2.32.3"
    t0 = BASE + timedelta(minutes=31)
    for i in range(84):
        rows.append((t0 + timedelta(seconds=2 * i), attacker, "POST", "/api/v1/auth/login", 401, 64, ua))
    rows.append((t0 + timedelta(seconds=170), attacker, "POST", "/api/v1/auth/login", 200, 182, ua))
    rows.append((t0 + timedelta(seconds=172), attacker, "GET", "/account/summary", 200, 4096, ua))
    return _lines(rows, combined)


IIS_HEADER = ["#Software: Microsoft Internet Information Services 10.0", "#Version: 1.0", "#Date: 2026-11-03 00:00:00",
              "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) "
              "sc-status sc-substatus sc-win32-status time-taken"]


def _iis(t: datetime, ip: str, method: str, stem: str, query: str, status: int, ua: str, taken: int) -> str:
    u = t.astimezone(timezone.utc)
    return (f"{u:%Y-%m-%d %H:%M:%S} 10.10.1.20 {method} {stem} {query or '-'} 443 - {ip} {ua.replace(' ', '+')} - "
            f"{status} 0 0 {taken}")


def case_iis_sqli(r: random.Random) -> list[str]:
    ips = [_int_ip(r, "10.31") for _ in range(20)] + [_ext_ip(r) for _ in range(10)]
    rows = []
    for _ in range(240):
        t = BASE + timedelta(seconds=r.randint(0, 3600))
        stem = r.choice(["/default.aspx", "/board/list.aspx", "/board/view.aspx", "/css/site.css", "/js/site.js"])
        q = f"no={r.randint(1, 400)}" if stem == "/board/view.aspx" else ""
        rows.append((t, r.choice(ips), "GET", stem, q, r.choices([200, 304], [9, 1])[0], r.choice(BROWSERS), r.randint(5, 90)))
    attacker, ua = "203.0.113.88", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/118.0 Safari/537.36"
    probes = ["no=1'", "no=1%27%20OR%20%271%27=%271", "no=1%20UNION%20SELECT%20NULL--", "no=1%20AND%201=1",
              "no=1%20AND%201=2", "no=1;WAITFOR%20DELAY%20%270:0:5%27--", "no=1%20ORDER%20BY%2010--",
              "no=1%20UNION%20SELECT%20NULL,NULL--", "no=-1%20OR%201=1--"]
    t0 = BASE + timedelta(minutes=44)
    for i in range(27):
        q = probes[i % len(probes)]
        status = 500 if "'" in q.replace("%27", "'") and i % 3 == 0 else 200
        rows.append((t0 + timedelta(seconds=4 * i), attacker, "GET", "/board/view.aspx", q, status, ua, r.randint(30, 6000)))
    return IIS_HEADER + [_iis(*row) for row in sorted(rows, key=lambda x: x[0])]


def case_tomcat_sensitive(r: random.Random) -> list[str]:
    ips = [_int_ip(r, "10.40") for _ in range(25)]
    rows = []
    for _ in range(200):
        t = BASE + timedelta(seconds=r.randint(0, 3600))
        p = r.choice(["/app/main.do", "/app/list.do", f"/app/detail.do?seq={r.randint(1, 900)}", "/app/js/common.js"])
        rows.append((t, r.choice(ips), "GET", p, 200, r.randint(900, 30000)))
    prober = "192.0.2.77"
    t0 = BASE + timedelta(minutes=12)
    for i, (p, s, b) in enumerate([("/manager/html", 401, 2473), ("/manager/html", 401, 2473), ("/host-manager/html", 401, 2473),
                                   ("/WEB-INF/web.xml", 404, 0), ("/app/WEB-INF/web.xml", 404, 0), ("/actuator", 200, 812),
                                   ("/actuator/env", 200, 6120), ("/actuator/heapdump", 404, 0), ("/console/", 404, 0),
                                   ("/admin/", 404, 0), ("/app/backup.zip", 404, 0), ("/app/config.properties.bak", 200, 1630),
                                   ("/.git/HEAD", 404, 0), ("/.env", 404, 0)]):
        rows.append((t0 + timedelta(seconds=3 * i), prober, "GET", p, s, b))
    # Tomcat AccessLogValve "common" plus %D (milliseconds)
    return [common(*row) + f" {r.randint(1, 80)}" for row in sorted(rows, key=lambda x: x[0])]


def case_webtob_enumeration(r: random.Random) -> list[str]:
    ips = [_int_ip(r, "10.50") for _ in range(30)]
    rows = []
    for _ in range(300):
        t = BASE + timedelta(seconds=r.randint(0, 3600))
        p = r.choice(["/ib/main.jsp", "/ib/notice/list.jsp", f"/ib/notice/view.jsp?no={r.randint(1, 60)}", "/ib/css/ib.css",
                      "/ib/js/ib.js"])
        rows.append((t, r.choice(ips), "GET", p, 200, r.randint(900, 25000)))
    worker = "10.50.9.41"
    t0 = BASE + timedelta(minutes=8)
    for i in range(260):
        rows.append((t0 + timedelta(milliseconds=600 * i), worker, "GET", f"/api/v1/customers/{100201 + i}/profile", 200,
                     r.randint(640, 720)))
    return _lines(rows, common)


def _haproxy(t, ip, method, uri, status, size, ua) -> str:
    u = f"{t:%b} {t.day:>2} {t:%H:%M:%S}"
    return (f"{u} lb01 haproxy[2201]: {ip}:{40000 + int(t.timestamp()) % 20000} [{t:%d/%b/%Y:%H:%M:%S}.{t.microsecond // 1000:03d}] "
            f"fe_https~ be_shop/app0{int(t.timestamp()) % 3 + 1} 0/0/1/{12 + size % 30}/{14 + size % 30} {status} {size} - - ---- "
            f"12/12/1/1/0 0/0 {{shop.example.test|{ua}}} \"{method} {uri} HTTP/1.1\"")


def case_haproxy_scanner(r: random.Random) -> list[str]:
    ips = [_ext_ip(r) for _ in range(30)]
    rows = _normal(r, 240, SHOP_PATHS, ips, BASE, 3600)
    tool, ua = "198.51.100.40", "sqlmap/1.8.4#stable (https://sqlmap.org)"
    t0 = BASE + timedelta(minutes=17)
    payloads = ["id=101%27", "id=101%27%20AND%20%271%27=%271", "id=101%20AND%201=1", "id=101%20UNION%20ALL%20SELECT%20NULL--",
                "id=101%29%20AND%20SLEEP%285%29--", "id=101%20OR%20NOT%201=1"]
    for i in range(130):
        rows.append((t0 + timedelta(milliseconds=800 * i), tool, "GET", f"/product/view?{payloads[i % len(payloads)]}",
                     r.choice([200, 200, 500]), r.randint(300, 5000), ua))
    return _lines(rows, _haproxy)


def _nginx_json(t, ip, method, uri, status, size, ua, host="files.example.test") -> str:
    return json.dumps({"time_iso8601": t.isoformat(), "remote_addr": ip, "remote_user": "", "request": f"{method} {uri} HTTP/1.1",
                       "status": status, "body_bytes_sent": size, "http_referer": "", "http_user_agent": ua,
                       "request_time": round(0.002 + size / 8e7, 3), "host": host}, ensure_ascii=False)


def case_nginx_json_large(r: random.Random) -> list[str]:
    ips = [_int_ip(r, "10.60") for _ in range(30)]
    rows = []
    for _ in range(260):
        t = BASE + timedelta(seconds=r.randint(0, 3600))
        p = r.choice(["/", "/list", f"/download/notice-{r.randint(1, 40)}.pdf", "/static/f.css"])
        rows.append((t, r.choice(ips), "GET", p, 200, r.randint(2000, 400000), r.choice(BROWSERS)))
    taker = "10.60.7.19"
    t0 = BASE + timedelta(minutes=50)
    for i in range(64):
        rows.append((t0 + timedelta(seconds=9 * i), taker, "GET", f"/export/customer-{i + 1:03d}.csv", 200,
                     2_000_000 + r.randint(0, 200_000), BROWSERS[0]))
    return _lines(rows, _nginx_json)


def case_caddy_normal(r: random.Random) -> list[str]:
    ips = [_int_ip(r, "10.70") for _ in range(40)]
    out = []
    for _ in range(320):
        t = BASE + timedelta(seconds=r.randint(0, 7200))
        p = r.choice(["/", "/approval/list", f"/approval/view/{r.randint(5000, 5400)}", "/calendar", "/assets/app.js",
                      "/assets/app.css", "/api/notifications"])
        status = r.choices([200, 304, 302], [85, 12, 3])[0]
        out.append((t.timestamp(), {"level": "info", "ts": round(t.timestamp(), 3), "logger": "http.log.access", "msg": "handled request",
                                    "request": {"remote_ip": r.choice(ips), "remote_port": str(r.randint(40000, 65000)),
                                                "proto": "HTTP/2.0", "method": "GET", "host": "portal.example.test", "uri": p,
                                                "headers": {"User-Agent": [r.choice(BROWSERS)]}},
                                    "bytes_read": 0, "duration": round(r.uniform(0.001, 0.08), 4),
                                    "size": 0 if status != 200 else r.randint(500, 60000), "status": status}))
    for i in range(24):  # the load balancer health check: a tool, but expected
        t = BASE + timedelta(minutes=5 * i)
        out.append((t.timestamp(), {"level": "info", "ts": round(t.timestamp(), 3), "logger": "http.log.access", "msg": "handled request",
                                    "request": {"remote_ip": "10.70.0.2", "remote_port": "41000", "proto": "HTTP/1.1", "method": "GET",
                                                "host": "portal.example.test", "uri": "/healthz", "headers": {"User-Agent": ["kube-probe/1.31"]}},
                                    "bytes_read": 0, "duration": 0.0004, "size": 2, "status": 200}))
    return [json.dumps(row, ensure_ascii=False) for _, row in sorted(out, key=lambda x: x[0])]


def _apache_err(t: datetime, module: str, level: str, ip: str, msg: str) -> str:
    return f"[{t:%a %b %d %H:%M:%S}.{t.microsecond:06d} {t:%Y}] [{module}:{level}] [pid {3100 + t.second}:tid 140221] [client {ip}:{52000 + t.second}] {msg}"


def case_apache_error_modsecurity(r: random.Random) -> list[str]:
    rows = []
    attacker = "203.0.113.77"
    t0 = BASE + timedelta(minutes=5)
    for i in range(36):
        t = t0 + timedelta(seconds=5 * i, microseconds=r.randint(0, 999999))
        rule, msg, tag = r.choice([("942100", "SQL Injection Attack Detected via libinjection", "attack-sqli"),
                                   ("941100", "XSS Attack Detected via libinjection", "attack-xss"),
                                   ("930120", "OS File Access Attempt", "attack-lfi")])
        rows.append((t, _apache_err(t, "security2", "error", attacker,
                                    f'ModSecurity: Warning. detected {tag} using libinjection. [file "/etc/modsecurity/crs/rules.conf"] '
                                    f'[line "45"] [id "{rule}"] [msg "{msg}"] [severity "CRITICAL"] [tag "{tag}"] '
                                    f'[hostname "shop.example.test"] [uri "/product/view"] [unique_id "Zt{i:04d}"]')))
        if i % 3 == 2:
            rows.append((t + timedelta(milliseconds=2), _apache_err(t, "security2", "error", attacker,
                         'ModSecurity: Access denied with code 403 (phase 2). Operator GE matched 5 at TX:anomaly_score. '
                         '[file "/etc/modsecurity/crs/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "80"] [id "949110"] '
                         f'[msg "Inbound Anomaly Score Exceeded (Total Score: 10)"] [hostname "shop.example.test"] '
                         f'[uri "/product/view"] [unique_id "Zb{i:04d}"]')))
    for i in range(12):
        t = BASE + timedelta(minutes=r.randint(0, 59), seconds=r.randint(0, 59))
        ip = _ext_ip(r)
        rows.append((t, _apache_err(t, "authz_core", "error", ip,
                                    "AH01630: client denied by server configuration: /var/www/shop/.htaccess")))
    for i in range(6):
        t = BASE + timedelta(minutes=r.randint(0, 59))
        rows.append((t, f"[{t:%a %b %d %H:%M:%S}.{t.microsecond:06d} {t:%Y}] [mpm_event:notice] [pid 3001:tid 140220] "
                        "AH00489: Apache/2.4.62 (Unix) configured -- resuming normal operations"))
    return [line for _, line in sorted(rows, key=lambda x: x[0])]


def _nginx_err(t, level, msg, ip, method, uri, host="www.example.test") -> str:
    return (f"{t:%Y/%m/%d %H:%M:%S} [{level}] 2214#2214: *{1000 + int(t.timestamp()) % 9000} {msg}, client: {ip}, "
            f"server: {host}, request: \"{method} {uri} HTTP/1.1\", host: \"{host}\"")


def case_nginx_error_probe(r: random.Random) -> list[str]:
    rows = []
    prober = "198.51.100.61"
    t0 = BASE + timedelta(minutes=2)
    probe = ["/.env", "/.env.bak", "/.git/config", "/.git/HEAD", "/config.php.bak", "/wp-config.php.old", "/backup.sql",
             "/db.sql", "/.aws/credentials", "/id_rsa", "/.htpasswd", "/phpinfo.php", "/server-status", "/web.config",
             "/.svn/entries", "/backup/site.zip"]
    for i, p in enumerate(probe * 2):
        t = t0 + timedelta(seconds=i)
        rows.append((t, _nginx_err(t, "error", f'open() "/usr/share/nginx/html{p}" failed (2: No such file or directory)',
                                   prober, "GET", p)))
    for i in range(5):
        t = t0 + timedelta(seconds=40 + i)
        rows.append((t, _nginx_err(t, "error", 'access forbidden by rule', prober, "GET", "/admin/")))
    flooder = "203.0.113.52"
    for i in range(18):
        t = BASE + timedelta(minutes=30, seconds=i)
        rows.append((t, _nginx_err(t, "error", 'limiting requests, excess: 10.%03d by zone "login"' % (100 + i * 7),
                                   flooder, "POST", "/api/v1/auth/login")))
    for i in range(4):
        t = BASE + timedelta(minutes=45 + i)
        rows.append((t, _nginx_err(t, "error", "upstream timed out (110: Connection timed out) while reading response header "
                                   "from upstream", _int_ip(r), "GET", "/api/v1/report/monthly")))
    return [line for _, line in sorted(rows, key=lambda x: x[0])]


def _vhost(t, ip, method, uri, status, size, ua, host="www.example.test") -> str:
    return f"{host}:443 " + combined(t, ip, method, uri, status, size, ua)


def case_vhost_mutation(r: random.Random) -> list[str]:
    ips = [_ext_ip(r) for _ in range(70)]
    rows = []
    for _ in range(320):
        t = BASE + timedelta(seconds=r.randint(0, 3600))
        rows.append((t, r.choice(ips), "GET", r.choice(SHOP_PATHS), 200, r.randint(800, 40000), r.choice(BROWSERS),
                     r.choice(["www.example.test", "shop.example.test", "event.example.test"])))
    actor, ua = "198.51.100.90", BROWSERS[1]
    t0 = BASE + timedelta(minutes=37)
    rows += [(t0, actor, "GET", "/admin/users", 403, 199, ua, "www.example.test"),
             (t0 + timedelta(seconds=4), actor, "GET", "/admin/users", 403, 199, ua, "www.example.test"),
             (t0 + timedelta(seconds=9), actor, "POST", "/admin/users", 200, 8800, ua, "www.example.test"),
             (t0 + timedelta(seconds=30), actor, "GET", "/admin/export/members.xlsx", 200, 182000, ua, "www.example.test")]
    return _lines(rows, _vhost)


CASES = [
    {"id": "WL01", "server": "Apache", "title": "경로 대량 탐색 뒤 관리자 페이지와 .git 설정 파일 응답",
     "format": "ncsa_combined", "build": case_apache_scan,
     "scenario": "외부 출발지 하나가 스캐너(Nikto) User-Agent로 없는 경로 160개를 1분 안에 요청한 뒤 /admin/과 /.git/config에서 200을 받았습니다.",
     "look_for": ["404가 몰린 출발지와 그 출발지의 성공 응답", "성공한 민감 경로(/admin/, /.git/config)의 실제 노출 여부"],
     "expected": ["web.discovery", "web.sensitive_file_probe", "web.scripted_client"],
     "normal_possibility": "회사가 맡긴 취약점 점검이면 점검 일정·출발지 주소와 맞는지 확인합니다."},
    {"id": "WL02", "server": "Nginx", "title": "로그인 API 무차별 대입 뒤 성공",
     "format": "ncsa_combined", "build": case_nginx_bruteforce,
     "scenario": "한 출발지가 python-requests로 로그인 API에 3분 동안 84번 실패(401)한 뒤 한 번 성공(200)하고 계좌 요약을 열었습니다.",
     "look_for": ["실패 비율과 시도 간격", "성공 뒤 바로 이어진 요청"],
     "expected": ["web.credential_attack"],
     "normal_possibility": "사내 자동화 시험이면 시험 계정과 시간대가 맞는지 확인합니다. combined 형식에는 계정 이름이 없어 어떤 계정인지는 애플리케이션 로그로 확인해야 합니다."},
    {"id": "WL03", "server": "IIS", "title": "게시판 번호 값에 SQL 주입 구문과 500 오류",
     "format": "iis_w3c", "build": case_iis_sqli,
     "scenario": "외부 출발지가 /board/view.aspx의 no 값에 SQL 구문을 바꿔 가며 27번 넣었고 일부는 500 오류가 났습니다.",
     "look_for": ["주입 구문이 든 요청과 응답 코드", "500 오류가 난 요청(취약점 신호일 수 있음)"],
     "expected": ["web.injection_like"],
     "normal_possibility": "IIS 시각은 UTC로 기록됩니다. 화면 시각은 한국 시간으로 바꿔 보여 줍니다."},
    {"id": "WL04", "server": "Tomcat", "title": "Tomcat 관리 화면·actuator·설정 백업 파일 탐색",
     "format": "ncsa_combined", "build": case_tomcat_sensitive,
     "scenario": "외부 출발지가 /manager/html(401), /WEB-INF/web.xml(404), /actuator/env(200), config.properties.bak(200)을 차례로 요청했습니다.",
     "look_for": ["200을 받은 민감 경로의 응답 크기", "Tomcat 관리 화면 인증 실패"],
     "expected": ["web.sensitive_file_probe"],
     "normal_possibility": "Tomcat 기본 common 형식에는 User-Agent가 없어 도구 판별은 하지 못합니다. 끝의 숫자(%D)는 처리 시간으로 보관합니다."},
    {"id": "WL05", "server": "WebtoB·JEUS", "title": "내부 주소가 고객 번호를 하나씩 올리며 조회",
     "format": "ncsa_combined", "build": case_webtob_enumeration,
     "scenario": "내부 주소 하나가 /api/v1/customers/{번호}/profile을 0.6초마다 번호를 1씩 올려 260번 조회했고 모두 200이었습니다.",
     "look_for": ["번호가 순서대로 바뀐 비율과 성공 비율", "그 주소가 배치 서버인지(자산·업무 정보)"],
     "expected": ["web.api_enumeration"],
     "normal_possibility": "등록된 배치 작업이면 정상일 수 있습니다. 자산·업무에 배치 일정이 있으면 함께 확인합니다."},
    {"id": "WL06", "server": "HAProxy", "title": "부하 분산기 로그의 sqlmap 접속과 SQL 주입 시도",
     "format": "haproxy_http", "build": case_haproxy_scanner,
     "scenario": "HAProxy가 요청 헤더(Host·User-Agent)를 함께 기록하도록 설정돼 있고, 한 출발지가 sqlmap으로 130번 요청했습니다.",
     "look_for": ["도구 User-Agent", "주입 구문 요청과 500 응답"],
     "expected": ["web.injection_like", "web.scripted_client"],
     "normal_possibility": "헤더 기록(capture request header)이 없으면 User-Agent가 비어 도구 판별을 하지 못합니다."},
    {"id": "WL07", "server": "Nginx (JSON)", "title": "파일 서버에서 고객 CSV 64개를 내려받음",
     "format": "web_json_access", "build": case_nginx_json_large,
     "scenario": "내부 주소 하나가 /export/customer-001.csv부터 064까지 약 2MB씩, 모두 약 130MB를 10분 안에 내려받았습니다.",
     "look_for": ["다른 출발지와 비교한 누적 응답 크기", "내려받은 파일 이름"],
     "expected": ["web.large_response"],
     "normal_possibility": "정기 자료 추출 담당자일 수 있습니다. 요청 승인 기록과 맞춰 봅니다."},
    {"id": "WL08", "server": "Caddy (JSON)", "title": "사내 결재 포털의 평범한 하루(대조 사례)",
     "format": "web_json_access", "build": case_caddy_normal,
     "scenario": "직원 40명이 결재 포털을 쓰고 부하 분산기가 5분마다 /healthz를 확인합니다. 공격 행위는 없습니다.",
     "look_for": ["탐지 결과가 없음을 확인", "상태 확인 요청(kube-probe)은 도구지만 예상된 접속"],
     "expected": [],
     "normal_possibility": "결과가 없다는 것은 붙여넣은 범위 안에서 기준을 넘는 활동이 없었다는 뜻이지 안전 확인은 아닙니다."},
    {"id": "WL09", "server": "Apache (오류 로그)", "title": "ModSecurity가 주입 공격을 경고하고 차단",
     "format": "apache_error", "build": case_apache_error_modsecurity,
     "scenario": "error_log에 ModSecurity 경고(942100·941100·930120)와 이상 점수 초과 차단(949110, 403)이 남았습니다.",
     "look_for": ["규칙 번호별 건수와 차단 건수", "같은 출발지의 접근 기록(access_log)을 함께 확인"],
     "expected": [],
     "normal_possibility": "오류 로그에는 요청 값이 없어 어떤 값이 들어왔는지는 접근 로그나 ModSecurity 감사 로그로 확인해야 합니다."},
    {"id": "WL10", "server": "Nginx (오류 로그)", "title": "없는 비밀 파일 요청과 로그인 요청 제한",
     "format": "nginx_error", "build": case_nginx_error_probe,
     "scenario": "한 출발지가 .env·.git·백업 파일을 요청해 open() failed가 32번 남았고, 다른 출발지는 로그인 요청 제한에 18번 걸렸습니다.",
     "look_for": ["없는 파일로 기록된 민감 경로", "요청 제한에 걸린 출발지"],
     "expected": ["web.sensitive_file_probe"],
     "normal_possibility": "오류 로그에는 응답 코드가 없어 성공 여부는 접근 로그로 확인해야 합니다."},
    {"id": "WL11", "server": "Apache (vhost_combined)", "title": "관리자 경로 403 뒤 방식을 바꿔 200",
     "format": "apache_vhost_combined", "build": case_vhost_mutation,
     "scenario": "한 출발지가 /admin/users에 GET으로 403을 두 번 받은 뒤 POST로 200을 받고 회원 목록 엑셀을 내려받았습니다.",
     "look_for": ["같은 경로에서 거부 → 방식 변경 → 성공", "그 뒤 내려받은 관리자 내보내기 파일"],
     "expected": ["web.request_mutation_success", "web.sensitive_file_probe"],
     "normal_possibility": "관리자가 정상 화면 흐름으로 POST를 쓰는 경우일 수 있습니다. 그 계정의 관리자 권한을 확인합니다."},
]


def build(case_id: str) -> str:
    c = next(x for x in CASES if x["id"] == case_id)
    return "\n".join(c["build"](random.Random(f"saw-weblog-{case_id}"))) + "\n"


def catalog() -> list[dict]:
    out = []
    for c in CASES:
        text = build(c["id"])
        out.append({k: v for k, v in c.items() if k != "build"} | {"lines": text.count("\n"), "bytes": len(text.encode("utf-8"))})
    return out
