"""Flows at the start, middle and end of a larger upload; installed-content versions; the worked flow cases."""
import json
from datetime import datetime, timedelta

from saw.devtools import flow_cases, flow_samples
from tests.api.test_flow_knowledge import _flows, _inv, _org, _register, _upload
from tests.api.test_text_uploads import _process


def _planted(at: str, session: str, account: str, ip: str) -> str:
    """One authentication -> lookup pair, as NDR rows without a header."""
    t = datetime.strptime(at, "%Y-%m-%d %H:%M:%S")
    row = ("{t},site-a,http,http,TCP,{ip},50001,KR,10.40.1.10,443,KR,10.40.0.2,ndr-syn-01,{m},portal.example.test,{p},{q},UA,-,"
           "JSESSIONID={s},{u},200,900,300")
    return "\n".join([
        row.format(t=t.strftime("%Y-%m-%d %H:%M:%S"), ip=ip, m="POST", p="/auth.html", q="-", s=session, u=f"plant-{session}-1"),
        row.format(t=(t + timedelta(seconds=7)).strftime("%Y-%m-%d %H:%M:%S"), ip=ip, m="GET", p="/memberinfo", q=f"id={account}",
                   s=session, u=f"plant-{session}-2")]) + "\n"


def test_flows_at_the_start_middle_and_end_of_a_large_upload_are_all_found(senior):
    """16: more records than one read batch; planted flows before, between and after the background."""
    org = _org(senior)
    _register(senior)
    inv = _inv(senior, org)
    sample = flow_samples.build(seed=31, background_sessions=2600, days=5, start="2026-10-20 09:00:00", shuffle=False)
    assert sample["rows"]["ndr"] > 12_000  # several 5,000-record batches
    ndr = (sample["ndr.csv"] + _planted("2026-10-19 00:00:01", "plant-first", "P1", "10.30.0.1")
           + _planted("2026-10-22 12:00:00", "plant-middle", "P2", "10.30.0.2")
           + _planted("2026-10-25 23:59:50", "plant-last", "P3", "10.30.0.3"))
    _process(senior, inv["id"], "ndr.csv", ndr.encode())
    run = _flows(senior, inv)["run"]
    result = run["result"]
    assert run["status"] == "complete" and result["completeness"]["truncated"] is False
    assert result["counts"]["records_read"] == sample["rows"]["ndr"] + 6
    assert result["counts"]["sessions_confirmed"] == 2600 + 7 + 3
    # The whole period was analysed, not the first batch: the bounds are the planted first and last records.
    assert result["time"]["first"] == "2026-10-18T15:00:01Z" and result["time"]["last"] == "2026-10-25T14:59:57Z"
    shown = {f["src_ips"][0] for f in result["flows"]}
    assert result["completeness"]["flows_total"] == 2610 and result["completeness"]["flows_shown"] == len(result["flows"])
    # More flows than are listed: the count says so, and the planted ones are reachable through the transition counts.
    transition = next(t for t in result["discovery"]["transitions"] if (t["from"], t["to"]) == ("인증 시도", "회원정보 조회"))
    assert transition["sessions"] >= 2600 + 3
    assert shown  # flows needing a look are listed first, whatever their position in time
    assert {"10.20.1.44", "10.20.1.70"} <= shown


def test_installed_versions_distinguish_application_bundle_content_and_knowledge(senior, settings, tmp_path):
    """15: what is installed is reported part by part, so a half-applied update is visible."""
    from pathlib import Path

    dist = Path(settings.web_dist)
    body = senior.get("/system/versions").json()
    from saw.version import __version__

    assert body["app_version"] == __version__ and set(body) >= {"web_bundle", "schema", "casebook", "knowledge", "notes"}
    assert body["knowledge"]["flow_items"] == 0
    _register(senior)
    assert senior.get("/system/versions").json()["knowledge"]["flow_items"] == 6
    from saw.apps.api.routers.system import casebook_status

    fake = tmp_path / "dist"
    cases = fake / "reference-data" / "platform-cases"
    cases.mkdir(parents=True)
    assert casebook_status(tmp_path / "nothing")["installed"] is False
    (cases / "index.json").write_text(json.dumps([{"id": "W01"}, {"id": "W02"}]), encoding="utf-8")
    (cases / "W01.json").write_text("{}", encoding="utf-8")
    partial = casebook_status(fake)
    assert partial["consistent"] is False and partial["missing_case_files"] == ["W02"] and "일부만 적용" in partial["text"]
    (cases / "W02.json").write_text("{}", encoding="utf-8")
    (fake / "reference-data" / "content-version.json").write_text(json.dumps({"version": "x", "casebook": {"cases": 60}}), encoding="utf-8")
    assert casebook_status(fake)["consistent"] is False  # the declared content is newer than the files on disk
    (fake / "reference-data" / "content-version.json").write_text(json.dumps({"version": "x", "casebook": {"cases": 2}}), encoding="utf-8")
    ok = casebook_status(fake)
    assert ok["consistent"] is True and ok["cases"] == 2 and ok["declared"]["version"] == "x"
    assert dist is not None


def test_the_shipped_casebook_and_flow_cases_match_their_generators():
    from pathlib import Path

    from saw.apps.api.routers.system import casebook_status

    public = Path(__file__).resolve().parents[2] / "apps" / "web" / "public"
    status = casebook_status(public)
    assert status["consistent"] is True and status["cases"] == 60 and status["declared"]["flow_cases"]["cases"] == 7
    built = flow_cases.cases()
    root = public / "reference-data" / "flow-cases"
    assert [c["id"] for c in json.loads((root / "index.json").read_text(encoding="utf-8"))] == [c["id"] for c in built]
    for case in built:
        assert json.loads((root / f"{case['id']}.json").read_text(encoding="utf-8")) == case  # real engine output
        assert case["synthetic"] is True and case["rows"] and case["limits"] and case["normal_alternative"]
    assert (root / flow_cases.ARCHIVE).read_bytes() == flow_cases.archive_bytes()
    # The archive is what a runner starts from: logs and the knowledge to register, never a conclusion.
    import io
    import zipfile

    with zipfile.ZipFile(io.BytesIO(flow_cases.archive_bytes())) as z:
        names = set(z.namelist())
        text = "".join(z.read(n).decode("utf-8") for n in names)
    assert names == {*flow_cases.FILES, "README.txt", "knowledge.json"}
    for case in built:
        assert case["conclusion"] not in text and case["title"] not in text


def test_reproducing_a_flow_case_from_its_archive_gives_the_documented_result(senior):
    """The case text is not a mock: uploading the archive's files and registering its knowledge gives the same flow."""
    org = _org(senior)
    _register(senior)
    inv = _inv(senior, org)
    _upload(senior, inv, flow_samples.build(seed=flow_cases.SEED, background_sessions=flow_cases.SESSIONS))
    flows = _flows(senior, inv)["run"]["result"]["flows"]
    documented = {c["id"]: c for c in flow_cases.cases()}
    mask = lambda text: __import__("re").sub(r"[0-9a-f]{8}", "<ref>", text)  # noqa: E731 - references differ per installation
    summaries = {mask(f["summary"]) for f in flows}
    for cid in ("F01", "F02", "F03", "F05", "F06"):
        assert mask(documented[cid]["observed"]["summary"]) in summaries, cid
