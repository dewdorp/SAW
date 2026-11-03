"""Generate additional offline practice cases (C021 onward) from synthetic NDR/FW records.

Every case is synthetic: documentation or private addresses, *.example hosts, a "가상" sector name and a
"[가상]" title. Risky request content is written as [DEFANGED-...] markers, never as a working payload.
Each stage has one answer that only states what the cited rows show, three answers that over-claim,
under-claim or misread a number, and an explanation for every answer. Counts in the text are computed from
the rows written to the CSVs, so the cards cannot drift from the files.

    python -m saw.devtools.practice_cases            # rewrite C021+ in the web practice pack
    python -m saw.devtools.practice_cases --check    # fail if the pack differs from a fresh generation
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import random
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACK = ROOT / "apps/web/src/pages/practice/practice-cases.json"
DATA = ROOT / "apps/web/public/practice-data/v1"
FIRST = 21          # C001-C020 are the hand-authored set and are never rewritten
VARIANTS = 5        # cases per scenario family
SEED = "saw-practice-v1.1"

NDR = ["event_time", "_site", "app", "_schema", "protocol", "src_ip", "src_port", "src_country", "dest_ip", "dest_port",
       "dest_country", "_device_ip", "_device_name", "method", "host", "path", "query", "user_agent", "referer",
       "req_cookie", "uuid", "status", "sc_bytes", "cs_bytes"]
FW = ["_time", "_device_ip", "_device_name", "action", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
      "tcp_flag", "duration", "sent_bytes", "rcvd_bytes"]
NDR_CITE = ["event_time", "_device_name", "src_ip", "src_port", "dest_ip", "dest_port", "protocol", "method", "host",
            "path", "query", "user_agent", "status", "sc_bytes", "cs_bytes"]
FW_CITE = ["_time", "_device_name", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "action", "tcp_flag",
           "duration", "sent_bytes", "rcvd_bytes"]
SECTORS = ["은행", "카드사", "증권사", "캐피탈", "생명보험사", "손해보험사", "저축은행"]
KST = timezone(timedelta(hours=9))
FOLLOW_Q = "초기 자료와 이번에 받은 자료만 합쳐 볼 때, 어느 판단 기록이 근거에 맞습니까?"


def ts(d: datetime) -> str:
    return d.isoformat(timespec="seconds")


def hm(d: datetime) -> str:
    return d.strftime("%m/%d %H:%M:%S")


def mb(n: int) -> str:
    return f"{n / 1048576:.1f}MB"


@dataclass
class Ctx:
    no: int
    variant: int
    rng: random.Random
    sector: str
    net: int
    day: datetime
    ndr: list = field(default_factory=list)
    fw: list = field(default_factory=list)

    @property
    def inside(self) -> str:
        return f"10.{self.net}"

    def ext(self, block: str = "198.51.100") -> str:
        return f"{block}.{self.rng.randrange(20, 240)}"

    def add_ndr(self, when, src, dst, path, *, status=200, sc=1800, cs=320, method="GET", query="", host=None,
                ua="ExampleClient/1.0", dport=443, sport=None):
        self.ndr.append({"event_time": ts(when), "_site": "site-a", "app": "HTTP", "_schema": "http", "protocol": "TCP",
                         "src_ip": src, "src_port": str(sport or 40000 + len(self.ndr)), "dest_ip": dst,
                         "dest_port": str(dport), "_device_ip": f"{self.inside}.0.254", "_device_name": "ndr-01",
                         "method": method, "host": host or f"svc{self.variant + 1}.example", "path": path,
                         "query": query, "user_agent": ua, "uuid": f"u{self.no:03d}{len(self.ndr):04d}",
                         "status": str(status), "sc_bytes": str(sc), "cs_bytes": str(cs)})
        return self.ndr[-1]

    def add_fw(self, when, src, dst, port, action="allow", *, sent=600, rcvd=3000, proto="TCP", duration=2.0,
               sport=None, flag=None):
        self.fw.append({"_time": ts(when), "_device_ip": f"{self.inside}.0.253", "_device_name": "fw-01",
                        "action": action, "src_ip": src, "src_port": str(sport or 50000 + len(self.fw)),
                        "dst_ip": dst, "dst_port": str(port), "protocol": proto,
                        "tcp_flag": flag or ("FA" if action == "allow" else "S"), "duration": str(duration),
                        "sent_bytes": str(sent), "rcvd_bytes": str(rcvd if action == "allow" else 0)})
        return self.fw[-1]


@dataclass
class Choice:
    text: str
    why: str


@dataclass
class Extra:
    """One family-specific additional record and how it should be read."""
    source: str
    summary: str
    fields: dict
    right: Choice
    wrong: list
    next_check: str


@dataclass
class Scenario:
    title: str
    kind: str                  # "ndr" or "fw": the file the cited rows come from
    agg: str                   # aggregate sentence of the window
    question: str
    right: Choice
    wrong: list                # three Choice
    next_check: str
    cite: list                 # indexes into the scenario rows of `kind`
    extra: Extra
    work: str                  # what an approved job would have been, for the reply envelopes


# ---------------------------------------------------------------- background traffic

PATHS = ["/home", "/assets/main.css", "/assets/app.js", "/notice", "/help/", "/board/list", "/api/v1/menu", "/favicon.ico"]


def background(c: Ctx):
    start = c.day - timedelta(days=34)
    rng = c.rng
    for _ in range(rng.randrange(118, 142)):
        when = start + timedelta(days=rng.randrange(33), hours=rng.randrange(8, 19), minutes=rng.randrange(60),
                                 seconds=rng.randrange(60))
        c.add_ndr(when, f"{c.inside}.1.{rng.randrange(10, 250)}", f"{c.inside}.0.240", rng.choice(PATHS),
                  status=rng.choice([200] * 9 + [304]), sc=rng.randrange(800, 6000), cs=rng.randrange(200, 500),
                  host="intranet.example")
    for _ in range(rng.randrange(118, 142)):
        when = start + timedelta(days=rng.randrange(33), hours=rng.randrange(8, 19), minutes=rng.randrange(60),
                                 seconds=rng.randrange(60))
        if rng.random() < .9:
            c.add_fw(when, f"{c.inside}.1.{rng.randrange(10, 250)}", f"192.0.2.{rng.randrange(150, 200)}", 443,
                     sent=rng.randrange(300, 1500), rcvd=rng.randrange(1000, 9000))
        else:
            c.add_fw(when, f"{c.inside}.1.{rng.randrange(10, 250)}", f"192.0.2.{rng.randrange(150, 200)}",
                     rng.choice([25, 139, 8080]), "deny", duration=0.0)
    c.ndr.sort(key=lambda r: r["event_time"])
    c.fw.sort(key=lambda r: r["_time"])


# ---------------------------------------------------------------- scenario families
# Each family appends its rows after the background and returns what the rows show.

def f_traversal(c: Ctx) -> Scenario:
    src, dst, rng = c.ext(), f"{c.inside}.0.20", c.rng
    n = rng.randrange(9, 15)
    ok = rng.randrange(1, 3)
    codes = [200] * ok + [400] * rng.randrange(2, 5)
    codes += [404] * (n - len(codes))
    rng.shuffle(codes)
    t = c.day.replace(hour=10)
    for i, code in enumerate(codes):
        c.add_ndr(t + timedelta(seconds=4 * i), src, dst, "/download", status=code, sc=512 if code != 200 else 512,
                  query=f"file=[DEFANGED-traversal]/conf_{i}.txt")
    n400, n404 = codes.count(400), codes.count(404)
    return Scenario(
        "경로 조작 문자열과 응답 크기", "ndr",
        f"NDR 상태: HTTP 200 {ok}건, HTTP 400 {n400}건, HTTP 404 {n404}건; 응답 크기는 모두 512바이트",
        "경로 조작 표시가 든 /download 요청의 결과를 어떻게 기록합니까?",
        Choice(f"요청 {n}건 중 200은 {ok}건이고 응답 크기가 모두 512바이트로 같다. 파일 반환은 WAS 응답 기록으로 확인한다.",
               "같은 출발지가 경로 조작 표시가 든 파일 요청을 반복했다. 200도 오류 응답과 같은 크기라 실제 파일이 반환됐는지는 이 로그로 알 수 없다."),
        [Choice(f"200 응답이 {ok}건 있으므로 설정 파일 유출로 확정한다.",
                "HTTP 200은 서버가 응답했다는 뜻일 뿐 요청한 파일을 돌려줬다는 증거가 아니다. 크기도 오류 응답과 같다."),
         Choice("대부분 400·404이므로 공격이 모두 실패했다고 보고 종결한다.",
                f"200 응답 {ok}건의 내용은 확인되지 않았다. 실패가 다수라는 것으로 전체 실패를 결론 낼 수 없다."),
         Choice(f"200이 {ok + 2}건이고 응답 크기가 점점 커진다. 크기 변화를 근거로 유출량을 계산한다.",
                f"원문에서 200은 {ok}건이고 크기는 모두 512바이트로 같다. 숫자를 원문 행에서 다시 센다.")],
        "추가로 확인할 자료: WAS 응답 본문·파일 접근 기록.",
        [0, 1, 2, n - 1],
        Extra("WAS 접근 기록", "같은 시각 WAS 기록에는 해당 요청이 모두 '허용되지 않은 경로'로 거부되었다고 남아 있습니다.",
              {"server": "was-01", "rejected": n, "returned_files": 0, "window": f"{hm(t)}~{hm(t + timedelta(seconds=4 * (n - 1)))}"},
              Choice("WAS 기록 범위에서는 파일 반환이 없었다. 기록이 다루는 서버(was-01)와 구간에 한정해 남긴다.",
                     "WAS가 요청 전부를 거부했다고 기록했다. 다른 서버나 구간까지 넓혀 결론 내지 않는다."),
              [Choice("WAS 기록이 있으므로 출발지를 내부 점검으로 분류한다.", "거부 기록은 요청 결과이지 수행 주체의 승인 근거가 아니다."),
               Choice("NDR 200이 있으므로 WAS 기록보다 NDR을 우선해 유출로 기록한다.", "서버가 남긴 처리 결과가 응답 코드보다 직접적이다."),
               Choice("WAS 기록이 있으니 같은 출발지의 다른 날짜 요청도 모두 거부된 것으로 본다.", "기록 범위는 이 구간뿐이다.")],
              "아직 열려 있는 확인: 출발지의 정체와 다른 서버 요청 여부."),
        "취약점 점검 작업")


def f_sqli(c: Ctx) -> Scenario:
    src, dst, rng = c.ext("203.0.113"), f"{c.inside}.0.21", c.rng
    n500, n200 = rng.randrange(4, 9), rng.randrange(3, 6)
    codes = [500] * n500 + [200] * n200
    rng.shuffle(codes)
    t = c.day.replace(hour=14)
    for i, code in enumerate(codes):
        c.add_ndr(t + timedelta(seconds=6 * i), src, dst, "/search", status=code, sc=980 if code == 500 else 4200,
                  query=f"q=[DEFANGED-sqli-{i}]")
    n = len(codes)
    return Scenario(
        "검색 입력과 서버 오류", "ndr", f"NDR 상태: HTTP 500 {n500}건, HTTP 200 {n200}건",
        "의심 입력 표시가 든 /search 요청의 응답을 어떻게 요약합니까?",
        Choice(f"요청 {n}건 중 500 {n500}건·200 {n200}건이다. 500은 서버 오류이고 자료 조회 성공의 증거가 아니다. DB 감사 기록을 확인한다.",
               "입력값이 오류를 일으켰을 가능성은 있지만 조회된 자료는 HTTP 로그로 알 수 없다."),
        [Choice(f"500 오류 {n500}건은 DB가 응답한 것이므로 자료 유출이 확정된다.", "오류 응답은 처리 실패를 뜻한다. 유출 여부는 DB·앱 기록으로 본다."),
         Choice("200 응답이 섞여 있으므로 정상 검색으로 종결한다.", "200은 일반 검색 결과일 수도, 다른 결과일 수도 있다. 입력 표시를 무시할 근거가 아니다."),
         Choice(f"500 {n200}건·200 {n500}건이다. 오류가 더 적으니 영향이 작다.", "두 숫자를 서로 바꿨다. 원문에서 상태별 건수를 다시 센다.")],
        "추가로 확인할 자료: DB 감사 기록·앱 오류 로그.", [0, 1, 2, n - 1],
        Extra("DB 감사 기록", "해당 구간 검색 계정의 DB 질의는 모두 구문 오류로 끝났고 반환 행은 0건입니다.",
              {"db": "db-search", "errors": n500, "rows_returned": 0},
              Choice("DB 기록 범위에서 반환된 행은 없다. 이 DB와 구간에 한정해 영향 없음으로 남긴다.", "질의가 오류로 끝났다는 직접 기록이다."),
              [Choice("오류가 났으니 공격자가 구조를 알아냈다고 확정한다.", "오류 메시지 노출은 응답 본문을 봐야 한다."),
               Choice("반환 0건이므로 출발지 차단 조치도 불필요하다고 기록한다.", "영향 판단과 대응 필요성은 별개다."),
               Choice("DB 기록이 있으니 HTTP 200 요청도 모두 오류였다고 본다.", "200 요청은 DB 오류 기록과 다른 요청이다.")],
              "아직 열려 있는 확인: 200 응답의 본문과 출발지 차단 여부."),
        "보안 점검 작업")


def f_login(c: Ctx) -> Scenario:
    src, dst, rng = c.ext(), f"{c.inside}.0.22", c.rng
    fails = rng.randrange(12, 25)
    t = c.day.replace(hour=rng.choice([3, 11, 22]))
    for i in range(fails):
        c.add_ndr(t + timedelta(seconds=3 * i), src, dst, "/login", status=401, sc=640, method="POST")
    redirect = t + timedelta(seconds=3 * fails + 2)
    c.add_ndr(redirect, src, dst, "/login", status=302, sc=310, method="POST")
    return Scenario(
        "로그인 실패 뒤 리다이렉트", "ndr", f"NDR 상태: HTTP 401 {fails}건, HTTP 302 1건",
        "같은 출발지의 /login 요청 결과를 어떻게 기록합니까?",
        Choice(f"401 {fails}건 뒤 {hm(redirect)}에 302 1건이 있다. 302는 이동 응답일 뿐이므로 로그인 성공은 인증 기록으로 확인한다.",
               "실패가 반복된 뒤 응답 종류가 바뀌었다. 302는 성공·잠금 안내·오류 페이지 이동 모두 가능하다."),
        [Choice("마지막 302는 로그인 성공이므로 계정 탈취로 확정한다.", "응답 코드만으로 인증 결과를 알 수 없다."),
         Choice("모든 요청이 401이므로 로그인은 한 번도 성공하지 않았다.", f"{hm(redirect)}의 302 1건을 빠뜨렸다."),
         Choice(f"302가 먼저 나오고 그 뒤 401 {fails}건이 이어졌다. 성공 뒤 차단된 것으로 본다.", "순서를 반대로 읽었다. 302는 마지막 행이다.")],
        "추가로 확인할 자료: 인증 서버 기록·계정 잠금 이력.", [0, 1, fails - 1, fails],
        Extra("인증 서버 기록", f"{hm(redirect)} 요청은 '계정 잠금 안내'로 이동했고 세션은 발급되지 않았습니다.",
              {"auth_server": "auth-01", "result": "locked", "session_issued": False},
              Choice("인증 기록상 302는 잠금 안내 이동이고 세션 발급이 없다. 이 계정의 로그인 성공 근거는 없다.", "응답 코드의 의미를 인증 서버가 직접 설명한다."),
              [Choice("잠금이 걸렸으니 대응이 끝났으므로 출발지는 확인하지 않는다.", "반복 시도한 출발지와 다른 계정 시도는 여전히 확인 대상이다."),
               Choice("세션이 없어도 302가 있었으니 성공으로 남긴다.", "인증 서버 기록이 성공을 부정한다."),
               Choice("잠금 기록이 있으니 다른 서비스 계정도 모두 안전하다고 기록한다.", "기록 범위는 이 인증 서버뿐이다.")],
              "아직 열려 있는 확인: 같은 출발지의 다른 계정 시도."),
        "계정 점검 작업")


def f_idor(c: Ctx) -> Scenario:
    src, dst, rng = f"{c.inside}.1.{rng_host(c)}", f"{c.inside}.0.23", c.rng
    n = rng.randrange(24, 40)
    start_id = 1000 + rng.randrange(0, 9000)
    codes = [rng.choice([200, 200, 403, 404]) for _ in range(n)]
    t = c.day.replace(hour=16)
    for i, code in enumerate(codes):
        c.add_ndr(t + timedelta(seconds=2 * i), src, dst, f"/api/v1/accounts/{start_id + i}", status=code,
                  sc=2300 if code == 200 else 420)
    a, b, d = codes.count(200), codes.count(403), codes.count(404)
    return Scenario(
        "객체 번호 순차 조회", "ndr", f"NDR 상태: HTTP 200 {a}건, HTTP 403 {b}건, HTTP 404 {d}건; 번호 {start_id}~{start_id + n - 1}",
        "연속 번호 API 요청을 어떻게 요약합니까?",
        Choice(f"번호 {start_id}~{start_id + n - 1}을 차례로 요청해 200 {a}건·403 {b}건·404 {d}건이다. 200 응답이 요청자 권한 안의 자료였는지는 앱 감사로 확인한다.",
               "번호를 하나씩 올려 요청한 기록이다. 200이 권한 위반인지는 계정과 객체 소유 관계를 알아야 한다."),
        [Choice(f"200 {a}건은 모두 다른 고객 정보이므로 개인정보 유출로 확정한다.", "응답 대상의 소유자와 요청 계정의 권한을 확인하지 않았다."),
         Choice("내부 출발지이므로 업무 조회로 보고 종결한다.", "내부 주소라는 사실은 승인된 업무의 근거가 아니다."),
         Choice(f"200 {b}건·403 {a}건이다. 대부분 거부되었다.", "200과 403 건수를 서로 바꿨다.")],
        "추가로 확인할 자료: 앱 감사 기록(계정·객체 소유자).", [0, 1, 2, n - 1],
        Extra("앱 감사 기록", f"요청 계정은 상담 업무 권한으로 조회 가능한 계좌가 {max(1, a // 3)}개뿐입니다.",
              {"account": "agent-0193", "role": "상담", "authorized_objects": max(1, a // 3)},
              Choice(f"권한 범위는 {max(1, a // 3)}개뿐이므로 나머지 200 응답은 권한 밖 조회 가능성이 있다. 객체별로 대조해 확정한다.",
                     "권한 범위와 응답 건수를 대조할 근거가 생겼다. 개별 객체 대조 전에는 '가능성'으로 남긴다."),
              [Choice("권한이 있는 계정이므로 모든 조회가 정상이다.", "권한 범위가 응답 건수보다 작다."),
               Choice("권한 밖 조회가 확정됐으므로 해당 직원을 징계 대상으로 기록한다.", "객체별 대조와 사유 확인이 남았다."),
               Choice("감사 기록이 있으니 404 응답도 권한 밖 조회로 센다.", "404는 객체가 없다는 응답이다.")],
              "아직 열려 있는 확인: 200 응답 객체별 소유자 대조."),
        "데이터 정합성 점검")


def rng_host(c: Ctx) -> int:
    return c.rng.randrange(20, 240)


def f_upload(c: Ctx) -> Scenario:
    src, dst, rng = c.ext(), f"{c.inside}.0.24", c.rng
    name = f"img_{rng.randrange(1000, 9999)}.jsp"
    t = c.day.replace(hour=1)
    c.add_ndr(t, src, dst, "/board/upload", status=200, method="POST", cs=rng.randrange(3000, 9000), sc=420)
    k = rng.randrange(4, 9)
    for i in range(k):
        c.add_ndr(t + timedelta(minutes=2 + i), src, dst, f"/files/{name}", status=200, sc=rng.randrange(200, 400),
                  query=f"[DEFANGED-cmd-{i}]")
    return Scenario(
        "업로드 뒤 같은 파일 요청", "ndr", f"NDR: POST /board/upload 1건 뒤 /files/{name} 요청 {k}건(모두 200)",
        "업로드 요청과 이후 파일 요청을 어떻게 기록합니까?",
        Choice(f"업로드 1건 뒤 같은 이름 파일 요청 {k}건이 200이다. 파일 내용과 실행 여부는 서버 파일·WAS 기록으로 확인한다.",
               "업로드한 이름의 파일을 곧바로 반복 요청한 흐름이다. 실행형 파일이 저장·실행됐는지는 서버에서 확인해야 한다."),
        [Choice("파일 요청이 200이므로 웹셸 실행과 서버 장악으로 확정한다.", "200은 응답했다는 뜻이다. 실행 결과는 서버 기록으로 확인한다."),
         Choice("게시판 업로드는 일반 기능이므로 정상 이용으로 종결한다.", f"확장자가 .jsp인 파일을 업로드 직후 {k}번 요청한 점이 설명되지 않았다."),
         Choice(f"업로드가 {k}건이고 파일 요청은 1건이다.", "업로드 1건·파일 요청 여러 건을 반대로 읽었다.")],
        "추가로 확인할 자료: 업로드 디렉터리 파일 목록·WAS 실행 기록.", [0, 1, 2, k],
        Extra("서버 파일 목록", f"업로드 디렉터리에 {name}가 존재하며 실행 권한이 없는 정적 경로로 설정되어 있습니다.",
              {"server": "was-02", "file": name, "exists": True, "executable_path": False},
              Choice("파일은 저장됐지만 실행되지 않는 경로다. 실행은 확인되지 않았고, 파일 삭제와 업로드 검증 보완을 후속으로 남긴다.",
                     "저장 사실과 실행 가능성을 구분했다."),
              [Choice("실행 경로가 아니므로 업로드 자체도 문제없다.", "실행형 확장자가 저장된 것은 보완할 문제다."),
               Choice("파일이 있으므로 실행도 되었다고 기록한다.", "설정상 실행되지 않는 경로다."),
               Choice("파일 목록이 있으니 다른 서버에도 같은 파일이 없다고 본다.", "기록 범위는 was-02뿐이다.")],
              "아직 열려 있는 확인: 다른 웹 서버의 같은 파일 여부."),
        "게시판 기능 점검")


def f_offhours_admin(c: Ctx) -> Scenario:
    src, dst, rng = c.ext("203.0.113"), f"{c.inside}.0.25", c.rng
    hour = rng.choice([2, 3, 4])
    k = rng.randrange(5, 10)
    t = c.day.replace(hour=hour)
    for i in range(k):
        c.add_ndr(t + timedelta(seconds=20 * i), src, dst, rng.choice(["/admin/", "/admin/users", "/admin/logs"]), status=200,
                  sc=rng.randrange(3000, 7000))
    post = t + timedelta(seconds=20 * k + 5)
    c.add_ndr(post, src, dst, "/admin/settings", status=200, method="POST", cs=900)
    return Scenario(
        "새벽 관리 경로 요청", "ndr", f"NDR: 관리 경로 GET {k}건·POST 1건, 모두 200, 시각 {hour:02d}시대",
        "업무 시간 밖의 관리 경로 요청을 어떻게 기록합니까?",
        Choice(f"{hour:02d}시대에 외부 출발지가 관리 경로를 {k + 1}번 요청했고 마지막 POST /admin/settings가 200이다. 변경 내용과 계정은 관리자 감사 로그로 확인한다.",
               "시간대·출발지·변경 요청이 겹친다. 실제 설정 변경과 사용 계정은 앱 감사로 확인한다."),
        [Choice("200이므로 관리자 계정 탈취와 설정 변조로 확정한다.", "응답 코드는 변경 성공이나 계정 정체를 알려 주지 않는다."),
         Choice("관리자 원격 근무일 수 있으므로 정상으로 종결한다.", "가능성만으로 종결할 수 없다. 근무·접속 승인 기록이 필요하다."),
         Choice(f"POST 요청이 {k}건이고 GET은 1건이다.", "GET과 POST 건수를 바꿨다.")],
        "추가로 확인할 자료: 관리자 감사 로그·원격 접속 승인 기록.", [0, 1, k - 1, k],
        Extra("관리자 감사 로그", f"{hm(post)} 설정 변경은 '알림 수신 주소' 1개 항목이며 계정은 admin-ops입니다.",
              {"account": "admin-ops", "changed": "notify_email", "at": ts(post)},
              Choice("변경된 항목과 계정이 확인됐다. 계정 사용자에게 수행 여부를 확인하고 변경 전 값을 복원할지 판단한다.",
                     "무엇이 바뀌었는지 알게 됐지만 누가 했는지는 계정만으로 확정되지 않는다."),
              [Choice("알림 주소만 바뀌었으니 영향이 없다.", "알림 주소 변경은 경보 우회에 쓰일 수 있다."),
               Choice("admin-ops 계정 소유자가 수행한 것으로 확정한다.", "계정 사용과 사람의 수행은 다를 수 있다."),
               Choice("감사 로그에 1개 항목만 있으니 GET 요청도 모두 정상 조회다.", "조회 요청의 목적은 감사 로그로 설명되지 않았다.")],
              "아직 열려 있는 확인: 계정 사용자 본인 확인과 접속 출발지 승인 여부."),
        "관리자 원격 작업")


def f_scanner_then_block(c: Ctx) -> Scenario:
    src, dst, rng = c.ext(), f"{c.inside}.0.26", c.rng
    k = rng.randrange(10, 18)
    t = c.day.replace(hour=13)
    for i in range(k):
        c.add_ndr(t + timedelta(seconds=2 * i), src, dst, f"/{rng.choice(['old', 'test', 'bak', 'tmp', 'dev'])}{i}/", status=404,
                  ua="ExampleScanner/2.0", sc=300)
    last_ndr = t + timedelta(seconds=2 * (k - 1))
    block = last_ndr + timedelta(seconds=rng.randrange(20, 90))
    m = rng.randrange(5, 12)
    for i in range(m):
        c.add_fw(block + timedelta(seconds=3 * i), src, dst, 443, "deny", duration=0.0)
    return Scenario(
        "스캐너 요청과 이후 차단", "fw",
        f"NDR 404 {k}건({hm(t)}~{hm(last_ndr)}); FW 처리: deny {m}건({hm(block)}부터)",
        "같은 출발지의 웹 요청과 방화벽 기록을 시간 순서로 어떻게 정리합니까?",
        Choice(f"{hm(last_ndr)}까지 NDR 404 {k}건이 서버에 도달했고, {hm(block)}부터 FW 차단 {m}건이다. 차단 이전 요청의 서버 처리를 확인한다.",
               "차단은 이후 요청에만 적용됐다. 차단 전에 도달한 요청은 별도로 본다."),
        [Choice("FW가 차단했으므로 이 출발지의 모든 요청은 서버에 닿지 않았다.", f"차단 전에 NDR 404 {k}건이 기록됐다."),
         Choice("404만 있으므로 스캐너는 아무것도 찾지 못했고 조사할 필요가 없다.", "404는 해당 경로가 없다는 뜻일 뿐 다른 요청·출발지 정보는 남는다."),
         Choice(f"FW 차단이 먼저 시작되고 그 뒤 NDR 404 {k}건이 이어졌다.", "시간 순서를 반대로 읽었다.")],
        "추가로 확인할 자료: 차단 정책 적용 시각·같은 출발지의 다른 서비스 요청.", [0, 1, m - 1],
        Extra("차단 정책 이력", f"자동 차단 정책이 {hm(block)}에 이 출발지를 등록했고 24시간 유지됩니다.",
              {"policy": "auto-block", "src_ip": src, "registered_at": ts(block), "ttl_hours": 24},
              Choice("차단 등록 시각과 FW 차단 시작이 일치한다. 24시간 뒤 해제 이후의 재접근 여부를 이어서 본다.", "차단 시점이 설명되었고 남은 위험은 해제 이후다."),
              [Choice("차단 정책이 있으므로 이 출발지는 영구히 접근할 수 없다.", "유지 시간은 24시간이다."),
               Choice("정책 등록 전 요청도 정책에 따라 차단된 것으로 본다.", "등록 이전 요청은 NDR에 404로 남았다."),
               Choice("자동 차단이 동작했으니 출발지는 공격자로 확정한다.", "자동 차단 조건은 스캐너 형태일 뿐 의도를 확정하지 않는다.")],
              "아직 열려 있는 확인: 차단 해제 이후 재접근."),
        "외부 취약점 진단")


def f_upload_fw(c: Ctx) -> Scenario:
    src, dst, rng = f"{c.inside}.1.{rng_host(c)}", c.ext("203.0.113"), c.rng
    n = rng.randrange(5, 10)
    t = c.day.replace(hour=23)
    total = 0
    for i in range(n):
        sent = rng.randrange(40, 120) * 1048576
        total += sent
        c.add_fw(t + timedelta(minutes=7 * i), src, dst, 443, sent=sent, rcvd=rng.randrange(4000, 9000), duration=float(rng.randrange(60, 300)))
    return Scenario(
        "야간 외부 송신량", "fw", f"FW 처리: allow {n}건; sent_bytes 합계 {mb(total)}",
        "야간 외부 연결의 송신량을 어떻게 기록합니까?",
        Choice(f"23시대 세션 {n}개에서 내부 단말이 외부로 보낸 양(sent_bytes)이 합계 {mb(total)}이다. 내용은 프록시·DLP 기록으로 확인한다.",
               "방향(내부→외부)과 송신량은 FW로 알 수 있지만 무엇을 보냈는지는 알 수 없다."),
        [Choice(f"송신 {mb(total)}이므로 고객정보 유출로 확정한다.", "보낸 양은 내용이나 자료 등급을 알려 주지 않는다."),
         Choice(f"rcvd_bytes가 크므로 외부에서 {mb(total)}을 내려받은 기록이다.", "sent_bytes가 큰 값이다. 방향을 바꿔 읽었다."),
         Choice("암호화(443) 통신이므로 내용 확인이 불가능해 정상으로 본다.", "내용을 볼 수 없다는 것은 정상의 근거가 아니다.")],
        "추가로 확인할 자료: 프록시 기록(도메인·파일명)·DLP 탐지.", [0, 1, n - 1],
        Extra("프록시 기록", f"같은 세션은 클라우드 백업 서비스 도메인(backup.example)으로 기록되어 있고 사용자 계정은 bk-agent입니다.",
              {"domain": "backup.example", "account": "bk-agent", "sessions": n},
              Choice("목적지 서비스와 계정이 확인됐다. 백업 대상·승인 여부를 확인하기 전까지 반출 여부는 미확정으로 둔다.", "서비스 이름이 업무 승인을 뜻하지는 않는다."),
              [Choice("백업 서비스이므로 정상으로 종결한다.", "어떤 자료를 누구 승인으로 보냈는지는 아직 모른다."),
               Choice("외부 클라우드이므로 유출로 확정한다.", "승인된 백업일 수 있다."),
               Choice("프록시 기록이 있으니 FW 송신량은 무시한다.", "송신량은 백업 범위를 대조할 근거다.")],
              "아직 열려 있는 확인: 백업 정책 승인과 대상 폴더."),
        "야간 백업 작업")


def f_download_ndr(c: Ctx) -> Scenario:
    src, dst, rng = f"{c.inside}.1.{rng_host(c)}", c.ext("192.0.2"), c.rng
    n = rng.randrange(4, 8)
    t = c.day.replace(hour=15)
    total_sc = 0
    for i in range(n):
        sc = rng.randrange(20, 80) * 1048576
        total_sc += sc
        c.add_ndr(t + timedelta(minutes=3 * i), src, dst, f"/share/pkg_{i}.zip", status=200, sc=sc, cs=rng.randrange(400, 900),
                  host="files.example")
    return Scenario(
        "HTTP 응답 바이트 방향", "ndr", f"NDR: GET {n}건 모두 200; sc_bytes 합계 {mb(total_sc)}, cs_bytes는 건당 1KB 미만",
        "외부 파일 서버와의 HTTP 기록에서 큰 바이트는 어느 방향입니까?",
        Choice(f"sc_bytes(서버→클라이언트 응답) 합계 {mb(total_sc)}로 내부 단말이 내려받은 양이다. 반출이 아니라 반입으로 기록하고 파일 검사 결과를 확인한다.",
               "응답 바이트가 크고 요청 바이트가 작다. 이 기록은 다운로드 방향이다."),
        [Choice(f"내부에서 외부로 {mb(total_sc)}을 보냈으므로 자료 반출이다.", "sc_bytes는 서버가 보낸 응답이다. 방향을 반대로 읽었다."),
         Choice("200 응답이므로 파일이 안전하다고 본다.", "응답 성공과 파일 안전성은 무관하다."),
         Choice(f"cs_bytes 합계가 {mb(total_sc)}이다.", "큰 값은 sc_bytes다. 열 이름을 확인한다.")],
        "추가로 확인할 자료: 단말 백신·샌드박스 검사 결과.", [0, 1, n - 1],
        Extra("단말 검사 결과", f"내려받은 파일 {min(4, n)}개는 검사 결과 이상 없음" + (", 나머지는 검사 기록이 없습니다." if n > 4 else "입니다."),
              {"scanned": min(4, n), "clean": min(4, n), "not_scanned": max(0, n - 4)},
              Choice(f"검사된 {min(4, n)}개만 이상 없음이다. 검사되지 않은 {max(0, n - 4)}개는 남은 확인으로 둔다." if n > 4
                     else "내려받은 파일 모두 검사 결과 이상 없음이다. 출처 승인 여부는 별도로 남긴다.",
                     "검사 범위를 넘어서 결론 내리지 않는다."),
              [Choice("일부가 이상 없으므로 모든 파일이 안전하다.", "검사되지 않은 파일이 있을 수 있다."),
               Choice("검사 결과가 있으므로 출처 서버도 신뢰할 수 있다.", "파일 검사 결과는 서버 신뢰를 보장하지 않는다."),
               Choice("검사 기록이 있으니 이 내려받기는 반출로 다시 분류한다.", "방향은 변하지 않는다.")],
              "아직 열려 있는 확인: 파일 출처의 업무 승인."),
        "패키지 배포 작업")


def f_beacon(c: Ctx) -> Scenario:
    src, dst, rng = f"{c.inside}.1.{rng_host(c)}", c.ext("192.0.2"), c.rng
    interval = rng.choice([30, 60, 120, 300])
    n = rng.randrange(16, 26)
    t = c.day.replace(hour=rng.choice([0, 9, 19]))
    for i in range(n):
        c.add_fw(t + timedelta(seconds=interval * i + rng.choice([0, 0, 1])), src, dst, 8443, sent=rng.randrange(180, 240),
                 rcvd=rng.randrange(90, 130), duration=0.4)
    return Scenario(
        "일정 간격 외부 연결", "fw", f"FW 처리: allow {n}건; 간격 약 {interval}초; 건당 송수신 300바이트 미만",
        "같은 목적지로의 반복 연결을 어떻게 기록합니까?",
        Choice(f"약 {interval}초 간격으로 {n}번 연결했고 건당 송수신이 매우 작다. 어떤 프로그램이 연결했는지는 단말 기록(EDR)으로 확인한다.",
               "간격이 일정하고 크기가 작은 연결은 자동 통신의 특징이다. 악성 여부는 프로세스로 판단한다."),
        [Choice("일정 간격이므로 악성코드 비컨으로 확정한다.", "업데이트 확인·모니터링 에이전트도 같은 형태를 보인다."),
         Choice("데이터가 거의 없으므로 위험이 없다.", "작은 통신도 명령 수신에 쓰일 수 있다."),
         Choice(f"간격은 약 {interval * 2}초이고 {n // 2}번 연결했다.", "원문 시각 간격과 건수를 다시 센다.")],
        "추가로 확인할 자료: EDR 프로세스 기록·목적지 평판.", [0, 1, 2, n - 1],
        Extra("EDR 프로세스 기록", "연결 프로세스는 서명된 자산관리 에이전트(agentd.exe)이며 설치 이력이 있습니다.",
              {"process": "agentd.exe", "signed": True, "installed_by": "it-deploy"},
              Choice("연결 주체가 서명된 자산관리 에이전트로 확인됐다. 목적지가 그 에이전트의 승인 서버인지 대조한 뒤 판단한다.", "주체가 밝혀졌고 남은 것은 목적지 승인 여부다."),
              [Choice("서명된 프로그램이므로 목적지와 관계없이 정상이다.", "정상 프로그램도 변조된 설정으로 다른 곳에 연결할 수 있다."),
               Choice("EDR 기록이 있어도 간격이 일정하니 악성으로 본다.", "주체 확인 기록을 무시했다."),
               Choice("에이전트이므로 같은 단말의 다른 외부 연결도 모두 정상이다.", "다른 연결은 이 기록 범위 밖이다.")],
              "아직 열려 있는 확인: 목적지와 에이전트 승인 서버 대조."),
        "자산관리 에이전트 배포")


def f_rdp_spread(c: Ctx) -> Scenario:
    src, rng = f"{c.inside}.1.{rng_host(c)}", c.rng
    n = rng.randrange(8, 15)
    allow = rng.randrange(1, 4)
    flags = ["allow"] * allow + ["deny"] * (n - allow)
    rng.shuffle(flags)
    t = c.day.replace(hour=11)
    for i, act in enumerate(flags):
        c.add_fw(t + timedelta(seconds=5 * i), src, f"{c.inside}.2.{10 + i}", 3389, act,
                 sent=4200 if act == "allow" else 0, rcvd=9800, duration=40.0 if act == "allow" else 0.0)
    return Scenario(
        "여러 서버의 원격 데스크톱 포트", "fw", f"FW 처리: allow {allow}건, deny {n - allow}건; 목적지 {n}개·포트 3389",
        "한 단말의 3389 접촉을 어떻게 요약합니까?",
        Choice(f"목적지 {n}개의 3389에 접촉해 허용 {allow}건·차단 {n - allow}건이다. 허용 세션의 로그인 여부는 대상 서버 보안 로그로 확인한다.",
               "허용은 네트워크 연결이 성립했다는 뜻까지다. 로그인 성공은 서버 기록으로 본다."),
        [Choice(f"허용 {allow}건은 원격 로그인 성공이므로 내부 확산으로 확정한다.", "연결 허용과 로그인 성공은 다르다."),
         Choice("대부분 차단되었으므로 위험이 없다.", f"허용된 {allow}건의 세션은 확인되지 않았다."),
         Choice(f"허용 {n - allow}건·차단 {allow}건이다.", "허용과 차단 건수를 바꿨다.")],
        "추가로 확인할 자료: 대상 서버 로그인 기록(4624/4625 등).", [0, 1, n - 1],
        Extra("대상 서버 보안 로그", f"허용된 서버 {allow}개 중 1개에서 같은 시각 로그인 실패만 기록되었습니다."
              + (" 나머지는 기록 수집 대상이 아닙니다." if allow > 1 else ""),
              {"servers_checked": 1, "logon_success": 0, "logon_failure": 3, "not_collected": allow - 1},
              Choice("확인한 서버 1개에서는 로그인 성공이 없다. 기록이 없는 나머지 허용 서버는 미확인으로 남긴다." if allow > 1
                     else "확인한 서버에서는 로그인 성공이 없다. 단말이 여러 서버에 접촉한 이유는 계속 확인한다.",
                     "기록이 있는 범위만 결론에 쓴다."),
              [Choice("로그인 실패만 있으므로 모든 서버에서 실패했다.", "수집되지 않은 서버는 알 수 없다."),
               Choice("로그인 실패가 있었으니 계정 탈취 시도로 확정한다.", "실패의 원인(잘못된 입력·점검)은 아직 모른다."),
               Choice("서버 로그가 있으니 FW 차단 기록은 볼 필요가 없다.", "차단 기록은 시도 범위를 보여 준다.")],
              "아직 열려 있는 확인: 미수집 서버의 로그인 기록."),
        "서버 원격 점검")


def f_smb_blocked(c: Ctx) -> Scenario:
    src, rng = f"{c.inside}.1.{rng_host(c)}", c.rng
    n = rng.randrange(12, 30)
    t = c.day.replace(hour=rng.choice([10, 17]))
    for i in range(n):
        c.add_fw(t + timedelta(seconds=1 * i), src, f"{c.inside}.3.{20 + i}", 445, "deny", duration=0.0)
    return Scenario(
        "파일 공유 포트 전체 차단", "fw", f"FW 처리: deny {n}건; 목적지 {n}개·포트 445",
        f"{n}개 목적지의 445 차단 기록을 어떻게 기록합니까?",
        Choice(f"목적지 {n}개 모두 차단되어 연결은 성립하지 않았다. 단말이 왜 짧은 시간에 445를 연달아 시도했는지는 단말 기록으로 확인한다.",
               "결과(차단)와 원인(단말 행위)을 나누어 남긴다."),
        [Choice("모두 차단되었으므로 조사할 것이 없다.", "차단은 결과다. 시도를 만든 단말의 상태는 남은 질문이다."),
         Choice("445 접촉은 랜섬웨어 확산으로 확정한다.", "점검 도구·잘못된 드라이브 연결도 같은 기록을 남긴다."),
         Choice(f"목적지 {n}개 중 일부는 허용되었다.", "원문 처리 결과는 모두 deny다.")],
        "추가로 확인할 자료: 단말 프로세스·네트워크 드라이브 설정.", [0, 1, n - 1],
        Extra("단말 기록", "같은 시각 단말에서 서명되지 않은 도구(netscan_tmp.exe)가 실행되었습니다.",
              {"process": "netscan_tmp.exe", "signed": False, "user": "user-0412"},
              Choice("차단과 별개로 단말에서 미서명 도구가 실행됐다. 단말 격리 필요성과 실행 경위를 확인한다.", "원인 후보가 생겼으므로 단말 대응으로 넘어간다."),
              [Choice("차단되었으니 도구 실행은 문제가 아니다.", "도구는 다른 경로로 동작할 수 있다."),
               Choice("미서명 도구이므로 악성코드 감염으로 확정한다.", "실행 경위·파일 분석 전이다."),
               Choice("단말 기록이 있으니 다른 단말의 445 시도는 없다고 본다.", "기록 범위는 이 단말뿐이다.")],
              "아직 열려 있는 확인: 도구 실행 경위와 파일 분석."),
        "네트워크 자산 점검")


def f_port_sweep(c: Ctx) -> Scenario:
    src, dst, rng = c.ext(), f"{c.inside}.0.27", c.rng
    ports = sorted(rng.sample([21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443], rng.randrange(9, 15)))
    if 443 not in ports:
        ports[-1] = 443
        ports.sort()
    t = c.day.replace(hour=4)
    allowed = [p for p in ports if p in (80, 443)]
    for i, p in enumerate(ports):
        c.add_fw(t + timedelta(seconds=i), src, dst, p, "allow" if p in allowed else "deny", duration=0.1 if p in allowed else 0.0,
                 sent=120, rcvd=240)
    return Scenario(
        "한 서버의 여러 포트", "fw", f"FW 처리: allow {len(allowed)}건, deny {len(ports) - len(allowed)}건; 포트 {len(ports)}종",
        "외부 출발지가 한 서버의 여러 포트에 접촉한 기록을 어떻게 요약합니까?",
        Choice(f"포트 {len(ports)}종에 1초 간격으로 접촉해 웹 포트({'·'.join(map(str, allowed))})만 허용됐다. 열린 포트의 이후 요청을 확인한다.",
               "짧은 간격의 여러 포트 접촉은 포트 확인의 특징이다. 허용된 포트의 이후 활동이 남은 질문이다."),
        [Choice("허용된 포트로 침입에 성공했다.", "허용은 서비스 포트가 열려 있다는 뜻이다. 이후 요청을 봐야 한다."),
         Choice("대부분 차단되었으므로 무시한다.", "허용 포트의 이후 활동이 확인되지 않았다."),
         Choice(f"포트 {len(ports) // 2}종에만 접촉했다.", "원문 포트 수를 다시 센다.")],
        "추가로 확인할 자료: 허용 포트의 이후 웹 요청·IPS 경보.", [0, 1, len(ports) - 1],
        Extra("IPS 경보", "같은 출발지에 대해 '포트 확인' 경보 1건이 있으며 이후 웹 요청 경보는 없습니다.",
              {"alerts": 1, "signature": "port-scan-generic", "later_web_alerts": 0},
              Choice("IPS도 포트 확인으로 보았고 이후 웹 경보는 없다. 경보가 없다는 것은 탐지 범위 안의 결과로만 남긴다.", "경보 부재는 활동 부재의 증거가 아니다."),
              [Choice("이후 경보가 없으므로 공격이 끝났다.", "탐지되지 않은 요청이 있을 수 있다."),
               Choice("IPS 경보가 있으므로 출발지를 공격자로 확정한다.", "경보는 형태를 말할 뿐 의도를 확정하지 않는다."),
               Choice("IPS 기록이 있으니 FW 허용 기록은 오탐이다.", "두 기록은 서로 다른 사실이다.")],
              "아직 열려 있는 확인: 허용 포트로 이어진 요청."),
        "외부 노출 점검")


def f_clock_skew(c: Ctx) -> Scenario:
    src, dst, rng = f"{c.inside}.1.{rng_host(c)}", f"{c.inside}.0.28", c.rng
    n = rng.randrange(5, 9)
    t = c.day.replace(hour=10)
    for i in range(n):
        sport = 61000 + i
        when = t + timedelta(minutes=4 * i)
        c.add_ndr(when, src, dst, f"/report/{i}", status=200, sport=sport)
        c.add_fw(when - timedelta(hours=9), src, dst, 443, sport=sport)
    return Scenario(
        "장비 간 9시간 차이", "fw",
        f"NDR {n}건과 FW {n}건의 출발지 포트가 하나씩 대응하며 FW 시각이 모두 정확히 9시간 이르다",
        "같은 출발지 포트의 NDR·FW 기록 시각이 다를 때 어떻게 기록합니까?",
        Choice(f"출발지 포트 {n}개가 하나씩 대응하고 모든 쌍이 정확히 9시간 차이다. 장비 시각대 설정 차이로 보고 시각을 맞춘 뒤 대조한다.",
               "일정한 9시간 차이는 UTC·KST 설정 차이의 전형이다. 두 번 접속한 것이 아니다."),
        [Choice("같은 연결이 9시간 간격으로 두 번 발생했다.", "출발지 포트까지 같은 쌍이 모두 같은 차이를 보인다."),
         Choice("FW 기록은 시각이 틀렸으므로 버리고 NDR만 쓴다.", "시각을 보정하면 FW 처리 결과를 그대로 쓸 수 있다."),
         Choice("차이가 경우마다 달라 대응시킬 수 없다.", "모든 쌍의 차이가 정확히 9시간이다.")],
        "추가로 확인할 자료: 각 장비의 시각대 설정.", [0, 1, n - 1],
        Extra("장비 설정", "fw-01의 로그 시각대가 UTC로 설정되어 있으나 내보내기 시 +09:00 표기가 붙었습니다.",
              {"device": "fw-01", "log_timezone": "UTC", "export_suffix": "+09:00"},
              Choice("FW 시각에 9시간을 더해 NDR과 맞춘 뒤 판단한다. 다른 FW 기록도 같은 보정이 필요한지 확인한다.", "원인이 설정으로 확인됐다."),
              [Choice("설정 문제이므로 FW 기록 전체를 신뢰할 수 없다.", "시각만 보정하면 된다."),
               Choice("NDR 시각에서 9시간을 빼서 맞춘다.", "잘못된 쪽은 FW다."),
               Choice("보정 없이 그대로 두고 판단 기록에 메모만 남긴다.", "보정하지 않으면 시간 순서 판단이 틀린다.")],
              "아직 열려 있는 확인: 다른 장비의 시각대."),
        "로그 수집 설정 점검")


def f_ssh_long(c: Ctx) -> Scenario:
    src, dst, rng = f"{c.inside}.0.{rng_host(c)}", c.ext(), c.rng
    n = rng.randrange(2, 5)
    t = c.day.replace(hour=20)
    total, longest = 0, 0
    for i in range(n):
        dur = rng.randrange(3600, 14400)
        rcvd = rng.randrange(100, 400) * 1048576
        total += rcvd
        longest = max(longest, dur)
        c.add_fw(t + timedelta(minutes=30 * i), src, dst, 22, sent=rng.randrange(2, 9) * 1048576, rcvd=rcvd, duration=float(dur))
    return Scenario(
        "서버의 외부 SSH 장시간 세션", "fw", f"FW 처리: allow {n}건; 최장 {longest // 3600}시간대 세션; rcvd_bytes 합계 {mb(total)}",
        "내부 서버에서 외부 22번 포트로 나간 세션을 어떻게 기록합니까?",
        Choice(f"서버가 외부 22에 {n}번 연결했고 최장 {longest // 60}분, 받은 양(rcvd_bytes) 합계 {mb(total)}이다. 서버의 SSH 사용자와 받은 파일을 확인한다.",
               "서버가 먼저 외부로 연결해 많은 양을 받았다. 사용자와 파일이 남은 질문이다."),
        [Choice(f"서버가 외부로 {mb(total)}을 보냈다.", "rcvd_bytes는 받은 양이다. 방향을 바꿨다."),
         Choice("SSH는 암호화되므로 관리자 업무로 보고 종결한다.", "암호화는 업무 승인을 뜻하지 않는다."),
         Choice("세션이 길어서 공격자의 지속 접속으로 확정한다.", "패키지 동기화 등 업무도 길 수 있다.")],
        "추가로 확인할 자료: 서버 SSH 클라이언트 기록·내려받은 파일 목록.", [0, n - 1],
        Extra("서버 명령 기록", "서버의 배포 계정이 외부 저장소에서 패키지를 동기화하는 예약 작업이 있습니다.",
              {"account": "deploy", "job": "pkg-sync", "schedule": "매일 20:00"},
              Choice("예약 작업 시각과 세션 시작이 맞는다. 저장소 주소가 승인된 곳인지 대조한 뒤 판단한다.", "주체·시각이 설명됐고 목적지 승인이 남았다."),
              [Choice("예약 작업이므로 목적지와 관계없이 정상이다.", "예약 작업이 변조될 수 있다."),
               Choice("예약 작업은 공격자가 만든 지속 수단이다.", "근거 없이 반대 결론을 내렸다."),
               Choice("배포 계정이므로 다른 서버의 22 연결도 정상이다.", "기록 범위 밖이다.")],
              "아직 열려 있는 확인: 저장소 주소 승인."),
        "패키지 동기화")


def f_dns_burst(c: Ctx) -> Scenario:
    src, dst, rng = f"{c.inside}.1.{rng_host(c)}", "203.0.113.53", c.rng
    n = rng.randrange(40, 70)
    t = c.day.replace(hour=12)
    for i in range(n):
        c.add_fw(t + timedelta(seconds=10 * i), src, dst, 53, proto="UDP", sent=rng.randrange(60, 180), rcvd=rng.randrange(80, 260),
                 duration=0.1, flag="-")
    return Scenario(
        "외부 DNS로의 잦은 질의", "fw", f"FW 처리: allow {n}건; UDP 53; {n * 10 // 60}분 동안",
        "내부 단말이 외부 DNS 서버로 짧은 시간 많이 연결한 기록을 어떻게 기록합니까?",
        Choice(f"약 {n * 10 // 60}분 동안 외부 DNS(203.0.113.53)로 {n}번 질의했다. 질의한 도메인은 FW로 알 수 없으므로 DNS·프록시 기록으로 확인한다.",
               "횟수와 목적지는 알 수 있지만 도메인 이름은 FW 기록에 없다."),
        [Choice("DNS 터널링으로 자료를 반출했다.", "질의 내용 없이 터널링을 확정할 수 없다."),
         Choice("DNS는 일상 통신이므로 정상이다.", "사내 DNS가 아닌 외부 DNS로 직접 간 점이 설명되지 않았다."),
         Choice(f"{n // 2}번 질의했고 TCP를 썼다.", "원문은 UDP이고 건수가 다르다.")],
        "추가로 확인할 자료: DNS 질의 기록·단말 DNS 설정.", [0, 1, n - 1],
        Extra("DNS 질의 기록", "질의 도메인 대부분이 긴 임의 문자열 하위 도메인(xk3...example)입니다.",
              {"domains": "*.example (임의 문자열 하위 도메인)", "unique_labels": n - 3},
              Choice("임의 문자열 하위 도메인이 반복된다. 터널링 가능성이 높아졌으므로 단말 격리와 프로세스 확인을 진행한다.", "가능성이 커졌지만 확정은 단말 분석 뒤다."),
              [Choice("도메인이 example이므로 테스트 트래픽이다.", "도메인 이름으로 목적을 정할 수 없다."),
               Choice("터널링이 확정되었으므로 유출량을 FW 바이트로 계산해 보고한다.", "아직 확정이 아니고 바이트는 질의 크기다."),
               Choice("DNS 기록이 있으니 FW 기록은 필요 없다.", "FW는 외부 DNS 직접 사용 사실을 보여 준다.")],
              "아직 열려 있는 확인: 질의를 만든 프로세스."),
        "DNS 설정 변경 작업")


FAMILIES = [f_traversal, f_sqli, f_login, f_idor, f_upload, f_offhours_admin, f_scanner_then_block, f_upload_fw,
            f_download_ndr, f_beacon, f_rdp_spread, f_smb_blocked, f_port_sweep, f_clock_skew, f_ssh_long, f_dns_burst]


# ---------------------------------------------------------------- assembly

def fid(case: str, kind: str) -> str:
    return "F" + hashlib.sha256(f"{SEED}:{case}:{kind}".encode()).hexdigest()[:12]


def options(rng: random.Random, right: Choice, wrong: list) -> tuple[list, str]:
    order = [right, *wrong]
    rng.shuffle(order)
    opts = [{"id": f"opt-{i + 1}", "text": o.text, "explanation": o.why} for i, o in enumerate(order)]
    return opts, opts[order.index(right)]["id"]


def stage(rng, sid, title, observation, evidence, question, right, wrong, next_check):
    opts, correct = options(rng, right, wrong)
    refs = " · ".join(e["id"] for e in evidence)
    return {"id": sid, "title": title, "observation": observation, "evidence": evidence, "question": question,
            "options": opts, "correctId": correct, "rationale": f"{right.why} 근거 참조: {refs}.", "nextCheck": next_check}


def cite(kind: str, row: dict, line: int) -> dict:
    when = datetime.fromisoformat(row["event_time" if kind == "ndr" else "_time"])
    if kind == "ndr":
        summary = f"{hm(when)} · {row['src_ip']} → {row['dest_ip']}:{row['dest_port']} · {row['method']} {row['path']} → {row['status']}"
        fields = {k: row[k] for k in NDR_CITE if row.get(k)}
    else:
        summary = f"{hm(when)} · {row['src_ip']} → {row['dst_ip']}:{row['dst_port']} · {row['action']} · {row['protocol']}"
        fields = {k: row[k] for k in FW_CITE if row.get(k)}
    return {"id": f"{kind}.csv:{line}", "source": kind.upper(), "summary": summary, "fields": fields}


def envelopes(c: Ctx, cid: str, sc: Scenario, rows: list, kind: str, at: datetime) -> list:
    """Four independent additional-material stages: the family's own record plus three reply situations."""
    key = "event_time" if kind == "ndr" else "_time"
    first, last = rows[0], rows[-1]
    src = first["src_ip"]
    dst = first["dest_ip" if kind == "ndr" else "dst_ip"]
    port = int(first["dest_port" if kind == "ndr" else "dst_port"])
    start, end = datetime.fromisoformat(first[key]), datetime.fromisoformat(last[key])
    stamp = f"이 봉투는 초기 자료에 독립적으로 더하는 가정입니다. 기준 시각: {hm(at)} KST."
    job = f"J-{cid}"
    out = {}
    e = sc.extra
    out["extra"] = (e.source, e.summary, e.fields, e.right, e.wrong, e.next_check)
    other = f"198.51.100.{(int(src.split('.')[-1]) + 97) % 200 + 20}"
    hours = c.rng.randrange(2, 6)
    out["mismatch"] = ("담당자 회신", f"{sc.work}이었다는 회신의 실행표는 다른 출발지({other})의 {hours}시간 전 실행을 가리킵니다.",
                       {"received_at": ts(at), "claimed_src_ip": other, "claimed_dst_ip": dst, "claimed_dst_port": port,
                        "claimed_window_start": ts(start - timedelta(hours=hours)), "claimed_window_end": ts(start - timedelta(hours=hours - 1))},
                       Choice(f"회신의 출발지({other})와 시각이 관측과 다르므로 이번 활동을 설명하지 못한다. 같은 출발지·구간의 실행 기록을 다시 요청한다.",
                              "회신이 다루는 범위가 관측 범위와 겹치지 않는다. 이 자료가 지지하지 않는 결론은 유보한다."),
                       [Choice("회신을 받았으므로 정상으로 종결한다.", "회신 도착과 관측 범위의 설명은 다르다."),
                        Choice("관측 범위를 회신에 적힌 출발지·시각으로 고쳐 일치시킨다.", "관측 사실을 바꾸면 불일치가 사라진 것처럼 보일 뿐이다."),
                        Choice("회신이 틀렸으므로 침해로 확정한다.", "맞지 않는 회신은 그 주장을 뒷받침하지 못할 뿐 반대 결론의 증거가 아니다.")],
                       "아직 열려 있는 확인: 회신 범위가 다른 이유.")
    out["match"] = ("담당자 회신", f"{sc.work} {job}의 실행 기록이 출발지·대상·포트·시각과 모두 일치합니다.",
                    {"received_at": ts(at), "job_id": job, "claimed_src_ip": src, "claimed_dst_ip": dst, "claimed_dst_port": port,
                     "claimed_window_start": ts(start - timedelta(minutes=1)), "claimed_window_end": ts(end + timedelta(minutes=1)),
                     "approved_by": "가상 승인자"},
                    Choice(f"회신이 관측 범위를 모두 덮으므로 이 범위는 승인 작업 {job}로 설명된다. 작업 번호와 대조 근거를 검증 기록에 남긴다.",
                           "출발지·대상·포트·시각이 모두 일치하는 회신은 관측 범위를 설명한다. 다른 활동은 별도로 본다."),
                    [Choice("일치하는 회신이 있으므로 조사 기간의 다른 활동까지 모두 정상으로 종결한다.", "회신이 다루는 범위만 설명된다."),
                     Choice("작업이어도 공격과 구별할 수 없으므로 회신을 무시한다.", "범위가 일치하는 승인 기록은 판단 근거가 된다."),
                     Choice("작업 번호만 기록하고 대조한 범위는 남기지 않는다.", "나중에 검토할 수 있도록 대조 범위를 함께 남긴다.")],
                    "아직 열려 있는 확인: 없음(이 범위 한정).")
    mid = rows[len(rows) // 2]
    mid_t = datetime.fromisoformat(mid[key])
    rest = sum(1 for r in rows if datetime.fromisoformat(r[key]) > mid_t)
    out["partial"] = ("담당자 회신", f"회신의 작업 시간은 관심 구간 앞부분({hm(start)}~{hm(mid_t)})만 포함합니다. 이후 기록 {rest}건은 범위 밖입니다.",
                      {"received_at": ts(at), "job_id": job, "claimed_src_ip": src, "claimed_window_start": ts(start), "claimed_window_end": ts(mid_t)},
                      Choice(f"앞부분은 작업으로 설명되지만 {hm(mid_t)} 이후 기록 {rest}건은 설명되지 않는다. 남은 구간을 계속 확인 대상으로 둔다.",
                             "회신이 일부만 덮으면 덮지 못한 부분은 열린 질문으로 남는다."),
                      [Choice("작업 회신이 있으므로 전체 구간을 정상으로 본다.", f"이후 {rest}건은 작업 시간 밖이다."),
                       Choice("일부가 맞지 않으므로 앞부분까지 모두 의심으로 되돌린다.", "일치하는 부분은 설명된 것으로 남긴다."),
                       Choice("회신 시간을 관심 구간 끝까지 늘려 기록한다.", "회신에 적힌 범위를 바꿔 기록하면 안 된다.")],
                      f"아직 열려 있는 확인: {hm(mid_t)} 이후 {rest}건.")
    out["silent"] = ("자료 요청 이력", "판단 기준시각까지 접수된 회신·첨부 자료가 없습니다.",
                     {"requested_at": ts(at - timedelta(days=2)), "checked_at": ts(at), "replies": 0},
                     Choice("회신이 없다는 것은 정상의 근거가 아니다. 미해결로 남기고 담당·기한을 다시 정한다.",
                            "답이 없으면 질문은 열린 채로 남는다."),
                     [Choice("회신이 없으므로 담당 부서가 이상 없다고 본 것으로 간주한다.", "침묵은 확인이 아니다."),
                      Choice("회신이 없으므로 침해로 확정한다.", "자료가 없다는 것은 어느 쪽의 증거도 아니다."),
                      Choice("요청을 취소하고 조사를 종료한다.", "질문이 해결되지 않았다.")],
                     "아직 열려 있는 확인: 원래 요청 전체.")
    picks = ["extra"] + [["mismatch", "match", "partial"], ["mismatch", "partial", "silent"],
                         ["match", "partial", "silent"], ["mismatch", "match", "silent"]][c.variant % 4]
    stages = []
    for n, k in enumerate(picks, 1):
        source, summary, fields, right, wrong, nxt = out[k]
        f = fid(cid, k)
        ev = [{"id": f"{f}:{'record' if k == 'extra' else 'reply'}", "source": source, "summary": summary, "fields": fields}]
        stages.append(stage(c.rng, f, f"후속 자료 {n}", stamp, ev, FOLLOW_Q, right, wrong, nxt))
    return stages


def write_csv(path: Path, headers: list, rows: list) -> bytes:
    out = io.StringIO(newline="")
    w = csv.writer(out, lineterminator="\r\n")
    w.writerow(headers)
    for r in rows:
        w.writerow([r.get(h, "") for h in headers])
    return ("﻿" + out.getvalue()).encode("utf-8")


def build() -> tuple[list, dict]:
    cases, files = [], {}
    for f_index, family in enumerate(FAMILIES):
        for v in range(VARIANTS):
            no = FIRST + f_index * VARIANTS + v
            cid = f"C{no:03d}"
            rng = random.Random(f"{SEED}:{cid}")
            sector = SECTORS[(no - 1) % len(SECTORS)]
            day = datetime(2026, 9, 1, tzinfo=KST) + timedelta(days=(no * 3) % 50)
            c = Ctx(no, v, rng, sector, 40 + no, day)
            background(c)
            base = {"ndr": len(c.ndr), "fw": len(c.fw)}
            sc = family(c)
            rows = (c.ndr if sc.kind == "ndr" else c.fw)[base[sc.kind]:]
            first_line = base[sc.kind] + 2
            picked = list(dict.fromkeys(i % len(rows) for i in sc.cite))
            # Every outcome the aggregate counts (status or action) has at least one cited row behind it.
            outcome = "status" if sc.kind == "ndr" else "action"
            for i, r in enumerate(rows):
                if r[outcome] not in {rows[j][outcome] for j in picked}:
                    picked.append(i)
            evidence = [cite(sc.kind, rows[i], first_line + i) for i in sorted(picked)]
            # The window covers every scenario row of both files, so "NDR n건·FW m건 in this window" holds.
            moments = [datetime.fromisoformat(r["event_time"]) for r in c.ndr[base["ndr"]:]]
            moments += [datetime.fromisoformat(r["_time"]) for r in c.fw[base["fw"]:]]
            w0, w1 = min(moments), max(moments)
            n_ndr, n_fw = len(c.ndr) - base["ndr"], len(c.fw) - base["fw"]
            observation = (f"가상 {sector} · 관심 구간 {hm(w0)}–{hm(w1)} KST. 이 구간 NDR {n_ndr}건·FW {n_fw}건. "
                           f"아래는 대표 행입니다. 관심 구간 집계({sc.kind}.csv {first_line}–{first_line + len(rows) - 1}행): {sc.agg}.")
            initial = stage(rng, f"{cid}-initial", "초기 자료", observation, evidence, sc.question, sc.right, sc.wrong, sc.next_check)
            at = w1 + timedelta(hours=8)
            follow = envelopes(c, cid, sc, rows, sc.kind, at)
            cases.append({"id": cid, "title": f"[가상] {sc.title}", "sources": ["NDR", "FW"],
                          "summary": f"가상 {sector} · 원본 NDR {len(c.ndr)}건, FW {len(c.fw)}건 (배경 자료 포함).",
                          "initial": initial, "followups": follow})
            files[f"{cid}/ndr.csv"] = write_csv(DATA / cid / "ndr.csv", NDR, c.ndr)
            files[f"{cid}/fw.csv"] = write_csv(DATA / cid / "fw.csv", FW, c.fw)
    return cases, files


def render(pack_text: str) -> tuple[str, dict]:
    pack = json.loads(pack_text)
    kept = [c for c in pack["cases"] if int(c["id"][1:]) < FIRST]
    cases, files = build()
    pack["version"] = "1.1.0"
    pack["cases"] = kept + cases
    return json.dumps(pack, ensure_ascii=False, indent=2) + "\n", files


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="compare with the files on disk instead of writing")
    args = ap.parse_args(argv)
    text, files = render(PACK.read_text("utf-8"))
    if args.check:
        stale = [] if PACK.read_text("utf-8") == text else [str(PACK)]
        stale += [rel for rel, data in files.items() if not (DATA / rel).is_file() or (DATA / rel).read_bytes() != data]
        for s in stale:
            print("stale:", s, file=sys.stderr)
        return 1 if stale else 0
    PACK.write_bytes(text.encode("utf-8"))
    for rel, data in files.items():
        (DATA / rel).parent.mkdir(parents=True, exist_ok=True)
        (DATA / rel).write_bytes(data)
    print(f"{len(files) // 2} generated cases, {len(files)} CSVs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
