"""Build the worked "business flow" cases from the real parsers and the real flow engine.

python -m saw.devtools.flow_cases DEST            # case JSON files, index.json and the sample archive
python -m saw.devtools.flow_cases --archive DEST  # only the sample archive (used by the web build and the media)

Each case file is a finished analysis for reading: input, the steps done in the product, the knowledge applied, the
observed flow, device records, the normal alternative, the conclusion with its limits, and the source rows.
The archive holds only what an analyst (or a runner) starts from: the logs and the knowledge to register. The
conclusions live in the case files and never in the archive.
"""
from __future__ import annotations

import argparse
import io
import json
import zipfile
from pathlib import Path

from saw.devtools import flow_samples

SEED, SESSIONS = 7, 40
FILES = ("ndr.csv", "app.csv", "waf.csv", "ips.csv", "ddos.csv", "fw.csv")
ARCHIVE = "flow-sample.zip"
README = """SAW 업무 흐름 사례 재현 자료 (모두 가상 자료)

1. 지식·탐지 > 업무 의미·흐름 화면이 비어 있는지 확인합니다.
2. 새 조사를 만들고 ndr.csv, app.csv, waf.csv, ips.csv, ddos.csv, fw.csv 를 올립니다.
3. 조사 > 업무 흐름 > "업무 의미 등록"에서 knowledge.json 의 항목을 등록합니다
   (또는 전체 로그에서 /auth.html 요청을 열어 "메모하고 기억하기").
4. "최신 지식으로 다시 분석"을 누르면 사례집과 같은 흐름이 나옵니다.

knowledge.json 은 분석가가 등록할 지식이며 정답이 아닙니다. 사례의 결론은 이 묶음에 들어 있지 않습니다.
주소는 사설 대역, 호스트는 *.example.test, 계정은 가상입니다.
"""


def _sample() -> dict:
    return flow_samples.build(seed=SEED, background_sessions=SESSIONS)


def _knowledge_file() -> dict:
    items = flow_samples.knowledge()
    return {"note": "분석가가 등록할 지식입니다. 흐름의 단계는 등록된 업무 의미를 고릅니다.", "items": items,
            "flow": {"name": "인증 후 본인정보 조회", "classification": "normal",
                     "steps": [{"meaning": "인증 화면 접근", "optional": True}, {"meaning": "인증 시도", "state": "success"},
                               {"meaning": "회원정보 조회", "repeat": True}]}}


def archive_bytes() -> bytes:
    sample, buffer = _sample(), io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as z:
        for name in (*FILES, "README.txt", "knowledge.json"):
            data = (README if name == "README.txt" else json.dumps(_knowledge_file(), ensure_ascii=False, indent=1)
                    if name == "knowledge.json" else sample[name])
            info = zipfile.ZipInfo(name, date_time=(2026, 11, 13, 0, 0, 0))  # fixed time: the archive is reproducible
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data.encode("utf-8"))
    return buffer.getvalue()


def write_archive(destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / ARCHIVE
    target.write_bytes(archive_bytes())
    return target


def _run(sample: dict, *, with_link: bool = True) -> dict:
    import hashlib

    from saw.flows.engine import Compiled, analyze
    from saw.parsers import security_profiles
    from saw.parsers.registry import parse_text

    # Linking references depend on a per-installation key. The case files use a fixed one so they are reproducible;
    # an installation shows different reference values for the same sessions.
    security_profiles._ref_key = lambda: hashlib.sha256(b"saw.flow-cases/1").digest()

    items = [{"id": f"k{i}", "version": 1, "org_unit_id": None, "title": b["content"].get("meaning", "연결 기준"), **b}
             for i, b in enumerate(flow_samples.knowledge()) if with_link or b["kind"] != "link"]
    by = {i["content"].get("meaning"): i["id"] for i in items if i["kind"] == "activity"}
    items.append({"id": "kf", "version": 1, "org_unit_id": None, "kind": "flow", "title": "인증 후 본인정보 조회", "content": {
        "host": "portal.example.test", "name": "인증 후 본인정보 조회", "classification": "normal",
        "steps": [{"activity": by["인증 화면 접근"], "optional": True}, {"activity": by["인증 시도"], "state": "success"},
                  {"activity": by["회원정보 조회"], "repeat": True}]}})
    events = {name: parse_text(sample[name], max_lines=10_000_000)["events"] for name in FILES}
    for name, rows in events.items():
        for e in rows:
            e["source_file"] = name
    web = sorted(events["ndr.csv"], key=lambda e: (e["timestamp"], e["event_id"]))
    result = analyze(web, app_events=events["app.csv"], alerts=events["waf.csv"] + events["ips.csv"],
                     ddos=events["ddos.csv"], compiled=Compiled(items))
    lines = {e["event_id"]: (e["source_file"], e["raw_ref"]["line_no"]) for rows in events.values() for e in rows}
    return {"result": result, "lines": lines, "items": items}


def _rows(flow: dict, lines: dict) -> list[dict]:
    rows = []
    for s in flow["steps"]:
        src = lines.get(s["event_id"], ("", ""))
        rows.append({"원본": f"{src[0]} {src[1]}행", "시각(UTC)": s["time"], "업무 의미": s["meaning"],
                     "요청": f"{s['method']} {s['path']}", "HTTP": s.get("status_code"),
                     "업무 결과": {"success": "성공", "failure": "실패", "unknown": "미확인"}[s["outcome"]],
                     "결과 근거": s["outcome_basis"], "인증 문맥": s.get("auth_context_text", "")})
    for d in flow["devices"]:
        src = lines.get(d["event_id"], ("", ""))
        rows.append({"원본": f"{src[0]} {src[1]}행", "시각(UTC)": d["time"], "업무 의미": f"{str(d['source']).upper()} {d['alert_name']}",
                     "요청": f"장비 조치 {d['device_action']}", "HTTP": d.get("http_status"), "업무 결과": "—",
                     "결과 근거": d["link_basis"], "인증 문맥": "같은 요청" if d["link"] == "same_request" else "관련 후보"})
    return rows


def _case(cid, title, classification, flow, lines, *, alternative, conclusion, limits, extra=None) -> dict:
    return {"id": cid, "title": title, "classification": classification, "synthetic": True,
            "input": {"archive": ARCHIVE, "files": list(FILES),
                      "note": "가상 자료입니다. 같은 묶음 하나로 모든 흐름 사례를 재현합니다. 세션 참조 값(8자리)은 설치마다 다르게 표시됩니다."},
            "platform_steps": [
                "조사 목록 > 새 조사: 관계사와 기간을 정하고 묶음의 CSV 6개를 올립니다(업로드 뒤 자동 분석).",
                "조사 > ② 조사 > 업무 흐름 > 업무 의미 등록: /auth.html(GET 인증 화면 접근, POST 인증 시도), /memberinfo(회원정보 조회), /logout.do(로그아웃), 세션 쿠키 JSESSIONID를 등록합니다.",
                "업무 흐름 > 최신 지식으로 다시 분석: 등록한 의미가 기록에 붙고 흐름이 시간순으로 묶입니다.",
                "살펴볼 흐름에서 이 사례의 흐름을 펼쳐 시간순 표·확인된 사실·확인되지 않은 것·다음 확인을 읽습니다.",
                "'이 흐름의 원문 보기'로 ③ 전체 로그에서 원문 행을 대조하고, '판단 남기기 · 기억하기'로 이번 사건의 판단을 남깁니다."],
            "knowledge_applied": sorted({s["meaning"] for s in flow["steps"]}) + ["연결 기준: 세션 쿠키 JSESSIONID, uuid = 요청 ID"],
            "observed": {"summary": flow["summary"], "link": flow["link_text"], "sequence": flow["sequence"],
                         "confirmed": flow["confirmed"], "inferred": flow["inferred"], "unknown": flow["unknown"],
                         "next_checks": flow["next_checks"],
                         "conformance": [{"name": c["name"], "status": c["status"], "deviations": c["deviations"]}
                                         for c in flow["conformance"]]},
            "devices": [{"source": d["source"], "alert_name": d["alert_name"], "device_action": d["device_action"],
                         "http_status": d["http_status"], "link": d["link"], "link_basis": d["link_basis"]}
                        for d in flow["devices"]],
            "normal_alternative": alternative, "conclusion": conclusion, "limits": limits,
            "rows": _rows(flow, lines), **(extra or {})}


def cases() -> list[dict]:
    sample = _sample()
    run = _run(sample)
    flows, lines = run["result"]["flows"], run["lines"]

    def of(account=None, flag=None):
        return next(f for f in flows if (account and account in f["accounts"] + f["attempted_accounts"])
                    or (flag and flag in f["flags"] and not account))

    no_link = _run(sample, with_link=False)["result"]
    nat = next(f for f in no_link["flows"] if f["src_ips"] == ["10.20.9.9"])
    d = run["result"]["ddos"][0]
    export = next(t for t in run["result"]["discovery"]["transitions"] if t["to"].endswith("/export/all.do"))
    out = [
        _case("F01", "인증 성공 뒤 같은 세션의 본인정보 조회", "등록된 흐름과 일치 · 영향 없음", of("U17"), lines,
              alternative="정상 업무 흐름으로 등록한 '인증 후 본인정보 조회'와 순서·결과가 같습니다.",
              conclusion="인증 성공(애플리케이션 기록)과 조회 처리(애플리케이션 기록)가 같은 세션·같은 계정으로 연결됩니다. 조회 대상은 본인입니다.",
              limits=["응답 본문은 자료에 없어 반환된 내용은 확인하지 않았습니다.", "등록된 흐름과 같다는 것이 이 사건의 정상 판정을 대신하지 않습니다. 판단은 분석가가 남깁니다."]),
        _case("F02", "HTTP 200이지만 인증은 실패, 뒤이어 다른 대상 조회", "의심 · 처리 여부 미확인", of("U20"), lines,
              alternative="로그인 실패 뒤 사용자가 화면을 다시 불러 왔거나, 다른 유효 세션·SSO가 있었을 수 있습니다. 첫 조회는 WAF가 403으로 응답했고 3초 뒤 같은 조회가 200으로 관측됐습니다.",
              conclusion="인증 시도의 HTTP 응답은 200이지만 애플리케이션 기록의 결과는 실패입니다. 그 뒤 같은 세션에서 다른 대상(U99) 조회가 두 번 관측됐고, 처리됐다는 애플리케이션 기록은 없습니다.",
              limits=["두 번째 조회(HTTP 200)가 실제로 회원정보를 반환했는지는 확인되지 않았습니다.",
                      "WAF 차단 기록은 403 요청과 같은 요청(요청 ID 일치)이며, 200 요청과는 '관련 후보'입니다. 하나의 결론으로 합치지 않았습니다.",
                      "권한 우회라고 단정하지 않습니다. 응답 본문·애플리케이션 감사 기록이 필요합니다."]),
        _case("F03", "인증 기록 없이 시작되는 조회(수집 구간 이전 인증 가능)", "판단 불가 · 자료 부족", of(flag="no_prior_auth_observed"), lines,
              alternative="수집 구간 전에 로그인한 기존 세션이거나 SSO로 들어온 세션이면 인증 요청이 이 자료에 없습니다.",
              conclusion="같은 세션에서 본인정보 조회가 처리됐지만, 이 세션의 인증 기록은 자료에 없습니다. 인증되지 않은 상태가 확인된 것이 아닙니다.",
              limits=["인증 우회로 판정하지 않았습니다.", "수집 구간 이전의 인증 기록 또는 SSO 기록을 받아야 판단할 수 있습니다."]),
        _case("F04", "같은 IP의 두 사용자(NAT) — 세션으로 나눈 경우와 나누지 못한 경우", "정상 대안 있음 · 연결 기준에 따라 달라짐", of("U21"), lines,
              alternative="사무실 NAT 뒤의 두 사용자가 2초 간격으로 각자 로그인해 각자 정보를 조회했습니다.",
              conclusion="세션 쿠키를 연결 기준으로 등록하면 10.20.9.9의 요청 6건이 세션 2개·계정 2개(U21, U22)의 흐름으로 나뉩니다. 각 흐름은 등록된 흐름과 일치합니다.",
              limits=["연결 기준이 없으면 SAW는 이 6건을 한 '후보'로만 묶고 같은 사용자라고 말하지 않습니다(아래 비교).",
                      "IP가 같다는 이유로 두 사용자를 한 행위자로 합치지 않습니다."],
              extra={"comparison": {"title": "연결 기준을 등록하지 않았을 때 같은 자료의 결과",
                                    "summary": nat["summary"], "link": nat["link_text"], "unknown": nat["unknown"],
                                    "counts": {"세션으로 연결": no_link["counts"]["sessions_confirmed"],
                                               "IP·시간 후보": no_link["counts"]["sessions_candidate"]}}}),
        _case("F05", "로그아웃 뒤 같은 세션의 조회", "의심 · 서버 처리 미확인", of("U40"), lines,
              alternative="브라우저가 로그아웃 뒤 남은 화면에서 요청을 다시 보냈고 서버가 거부했을 수 있습니다.",
              conclusion="인증 성공 → 로그아웃 → 같은 세션의 조회 요청 순서로 관측됐습니다. 조회가 처리됐다는 애플리케이션 기록은 없습니다.",
              limits=["HTTP 200만으로 조회가 처리됐다고 보지 않았습니다.", "세션 만료·재발급 정책은 서비스 담당 확인이 필요합니다."]),
        _case("F06", "등록되지 않은 경로로 이어진 새 전이(전체 내려받기 후보)", "새로 보인 흐름 · 의미 미등록", of("U50"), lines,
              alternative="관리자용 내보내기 기능을 권한 있는 사용자가 쓴 것일 수 있습니다. 경로의 업무 의미가 아직 등록되지 않았습니다.",
              conclusion=f"'{export['from']}' 뒤에 '{export['to']}'로 이어지는 전이가 흐름 {export['sessions']}개에서 처음 관측됐습니다. 등록된 흐름으로 설명되지 않습니다.",
              limits=["처음 보였다는 것은 공격이라는 뜻이 아닙니다.", "IPS 'Bulk Data Download' 기록은 같은 출발지·목적지·1초 차이의 관련 후보이며, 같은 통신이라는 식별자는 없습니다.",
                      "'의미 기억하기'로 이 경로를 등록하면 다음 분석부터 의미가 붙습니다."],
              extra={"discovery": {"from": export["from"], "to": export["to"], "sessions": export["sessions"],
                                   "first": export["first"], "explained_by_registered_flow": False}}),
    ]
    b = of("U20")
    out.append({"id": "F07", "title": "DDoS 관측 구간과 같은 시간대의 요청 흐름", "classification": "서비스 단위 관측 · 흐름과 연결하지 않음",
                "synthetic": True, "input": out[0]["input"], "platform_steps": out[0]["platform_steps"][:3] + [
                    "업무 흐름 > 'DDoS 관측 구간' 표에서 구간·벡터·지표·탐지/완화 상태와 구간 안 HTTP 요청·5xx 수를 봅니다.",
                    "같은 시간대의 흐름에는 'DDoS 구간과 같은 시간대' 표시만 붙습니다."],
                "knowledge_applied": out[0]["knowledge_applied"],
                "observed": {"summary": f"{d['vector']} {d['value']} {d['unit']} ({d['start']} ~ {d['end_raw']}), 탐지 {d['detection_state']} · 완화 {d['mitigation_state']}. "
                                        f"구간 안 HTTP 요청 {d['requests']}건, 5xx {d['server_errors']}건.",
                             "link": "집계 구간(서비스 단위)", "sequence": [], "confirmed": [d["note"]],
                             "inferred": [line for line in b["inferred"] if "DDoS" in line], "unknown": [
                                 "서비스 응답시간·가용성 지표가 자료에 없어 서비스 영향은 확인되지 않았습니다."],
                             "next_checks": ["서비스 상태 지표(응답시간·오류율)와 완화 장비의 처리 기록 요청"], "conformance": []},
                "devices": [], "normal_alternative": "같은 시간대에 일어난 무관한 요청일 수 있습니다.",
                "conclusion": "DDoS 구간과 F02 흐름의 시간이 겹칩니다. 집계 자료이므로 특정 세션의 행위로 연결하지 않았고, 주의 분산 공격이라고 단정하지 않았습니다.",
                "limits": ["동시 관측은 동일 공격자·인과관계의 근거가 아닙니다.", "5xx 0건은 HTTP 기록에서 센 값이며 서비스 영향이 없었다는 증명이 아닙니다."],
                "rows": [{"원본": f"ddos.csv {lines[d['event_id']][1]}행", "시각(UTC)": d["start"], "업무 의미": f"DDoS {d['vector']}",
                          "요청": f"{d['value']} {d['unit']}", "HTTP": None, "업무 결과": "—", "결과 근거": f"집계 주기 {d['interval_seconds']}초",
                          "인증 문맥": "서비스 구간"}]})
    return out


def write(destination: Path) -> dict:
    destination.mkdir(parents=True, exist_ok=True)
    items = cases()
    for item in items:
        (destination / f"{item['id']}.json").write_text(json.dumps(item, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
    index = [{"id": c["id"], "title": c["title"], "classification": c["classification"]} for c in items]
    (destination / "index.json").write_text(json.dumps(index, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
    write_archive(destination)
    return {"cases": len(items), "archive": ARCHIVE}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", nargs="?", type=Path)
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    if args.archive:
        print(write_archive(args.archive))
    elif args.destination:
        print(write(args.destination))
    else:
        parser.error("destination or --archive is required")
