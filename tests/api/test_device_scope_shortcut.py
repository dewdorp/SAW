"""Unregistered records are counted, not re-read, by device observers: the saved reports stay identical."""
from saw.detection import runtime
from saw.devtools.security_csv_samples import fw_csv, ndr_csv
from tests.api.test_text_uploads import _process

OBSERVERS = ("waf.observation", "ips.observation", "ddos.observation", "ndr.observation")


def _reports(api, inv_id):
    runs = api.get(f"/investigations/{inv_id}/analysis-runs").json()["runs"]
    run = api.get(f"/investigations/{inv_id}/analysis-runs/{runs[0]['id']}").json()
    out = {}
    for e in run["executions"]:
        if e["detector_id"] in OBSERVERS:
            detail = {k: v for k, v in e["detail"].items() if k not in {"partitions", "effective_pins"}}
            out[e["detector_id"]] = (e["status"], e["input_count"], e["match_count"], detail)
    return out


def test_counting_unregistered_scopes_gives_the_same_reports_as_reading_them(analyst, monkeypatch):
    """PPA-03: same status, counts, quality and limitations, without materialising every unregistered row."""
    used = []
    counted_report = runtime._unresolved_device_report

    def spy(det, *args, **kwargs):
        out = counted_report(det, *args, **kwargs)
        used.append((det.id, out is not None))
        return out
    monkeypatch.setattr(runtime, "_unresolved_device_report", spy)
    inv = analyst.post("/investigations", json={"title": "unregistered devices"}).json()
    _process(analyst, inv["id"], "fw.csv", fw_csv())
    _process(analyst, inv["id"], "ndr.csv", ndr_csv("chain"))
    counted = _reports(analyst, inv["id"])
    assert counted and all(v[3]["counts"]["records"] > 0 for v in counted.values() if v[0] != "not_applicable")
    assert {d for d, quick in used if quick} >= {"ips.observation", "ddos.observation", "ndr.observation"}

    calls = []
    original = runtime.ScopedEventStore.__init__

    def tracking(self, *args, **kwargs):
        calls.append(1)
        original(self, *args, **kwargs)
    monkeypatch.setattr(runtime, "COUNT_UNRESOLVED_DEVICE_SCOPES", False)
    monkeypatch.setattr(runtime.ScopedEventStore, "__init__", tracking)
    job = analyst.post(f"/investigations/{inv['id']}/reanalyze").json()
    assert analyst.get(f"/jobs/{job['id']}").json()["state"] == "COMPLETED"
    read = _reports(analyst, inv["id"])
    assert calls, "the full pass really read the rows"
    assert read == counted
