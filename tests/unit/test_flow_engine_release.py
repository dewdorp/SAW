"""Long periods: silent groupings are written out and released, and a session's state continues into its next part."""
from saw.devtools import flow_samples
from saw.flows.engine import Compiled, analyze
from saw.parsers.registry import parse_text


def _items():
    return [{"id": f"k{i}", "version": 1, "org_unit_id": None, "title": "", **b} for i, b in enumerate(flow_samples.knowledge())]


def _web(sample):
    return sorted(parse_text(sample["ndr.csv"], max_lines=10_000_000)["events"], key=lambda e: (e["timestamp"], e["event_id"]))


def test_released_groupings_give_the_same_flows_as_keeping_everything():
    sample = flow_samples.build(seed=5, background_sessions=400, days=6)
    app = parse_text(sample["app.csv"], max_lines=10_000_000)["events"]
    kw = dict(alerts=[], ddos=[], compiled=Compiled(_items()))
    whole = analyze(_web(sample), app_events=[dict(e) for e in app], options={"release_seconds": 10**9}, **kw)
    swept = analyze(_web(sample), app_events=[dict(e) for e in app], options={"sweep_every": 50}, **kw)
    assert swept["completeness"]["flows_total"] == whole["completeness"]["flows_total"] == 407
    assert swept["counts"] == whole["counts"]
    assert sorted(f["summary"] for f in swept["flows"]) == sorted(f["summary"] for f in whole["flows"])
    assert swept["discovery"]["transitions_total"] == whole["discovery"]["transitions_total"]


def test_a_session_resumed_after_a_long_silence_keeps_its_authentication_state():
    header = flow_samples.NDR_HEADER + "\n"
    row = ("{t},s,http,h,TCP,10.1.1.5,50000,KR,10.2.2.2,443,KR,10.9.9.9,ndr1,{m},portal.example.test,{p},{q},UA,-,"
           "JSESSIONID=long,{u},200,512,300\n")
    web = header + row.format(t="2026-10-20 09:00:00", m="POST", p="/auth.html", q="-", u="r1") \
        + "".join(row.format(t=f"2026-10-20 {10 + n // 60:02d}:{n % 60:02d}:00", m="GET", p="/static/x.js", q="-", u=f"n{n}")
                  .replace("JSESSIONID=long", f"JSESSIONID=other{n}") for n in range(450)) \
        + row.format(t="2026-10-20 18:30:00", m="GET", p="/memberinfo", q="id=U1", u="r2")
    app = ("event_time,service,event,result,account,session_id,request_id,target,src_ip\n"
           "2026-10-20 09:00:00,portal.example.test,login,success,U1,long,r1,-,10.1.1.5\n")
    result = analyze(sorted(parse_text(web)["events"], key=lambda e: e["timestamp"]), app_events=parse_text(app)["events"],
                     alerts=[], ddos=[], compiled=Compiled(_items()), options={"sweep_every": 10})
    later = next(f for f in result["flows"] if f["sequence"] == ["회원정보 조회"])
    # Nine hours later, in another part of the same session: still "after a confirmed success", not "no prior auth".
    assert later["flags"] == [] and any("앞부분에서 이어받았습니다" in line for line in later["inferred"])
    assert result["completeness"]["flows_total"] == 2
