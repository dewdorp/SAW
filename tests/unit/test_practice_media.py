"""The distribution must ship the complete, authored offline practice corpus only."""
import json
import zipfile
from pathlib import Path

import pytest

from saw.devtools import build_release
from saw.devtools.release_manifest import BundleError


PUBLIC_CASES = build_release.ROOT / "apps/web/public/reference-data/platform-cases"
WORKED_IDS = [f"W{i:02d}" for i in range(1, 61)]


def put(path: Path, content: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def test_offline_web_dist_copies_authoritative_samples_only(tmp_path, monkeypatch):
    web, out = tmp_path / "apps/web", tmp_path / "out"
    monkeypatch.setattr(build_release, "ROOT", tmp_path)
    expected = {f"practice-data/v1/C{i:03d}/{kind}.csv": f"{i},{kind}\r\n".encode()
                for i in range(1, 21) for kind in ("ndr", "fw")}
    expected["reference-data/long-window.html"] = b"long window worked investigation"
    case_prefix = "reference-data/platform-cases"
    expected[f"{case_prefix}/index.json"] = (PUBLIC_CASES / "index.json").read_bytes()
    assert [c["id"] for c in json.loads(expected[f"{case_prefix}/index.json"])] == WORKED_IDS
    for n, case in enumerate(WORKED_IDS, 1):
        expected[f"{case_prefix}/{case}.json"] = (PUBLIC_CASES / f"{case}.json").read_bytes()
        item = json.loads(expected[f"{case_prefix}/{case}.json"])
        assert item["id"] == case and len(item["steps"]) == 5
        assert all(s["action"] and s["finding"] for s in item["steps"])
        assert not (set(item) | set().union(*(s.keys() for s in item["steps"]))) & {
            "questions", "quiz", "answer", "answers", "correctAnswer", "score", "grading"}
        images = ("candidate.png", "raw.png") if n <= 6 else ("lead.webp", "raw.webp")
        for i, name in enumerate(images, 1):
            image = f"shots/{case}-{name}"
            assert item["steps"][i]["image"] == image
            expected[f"{case_prefix}/{image}"] = image.encode()
    # Worked flow cases and the content version are authored files too; their archive is rebuilt from the generator.
    public_ref = PUBLIC_CASES.parent
    for rel in ["content-version.json", "flow-cases/index.json", *(f"flow-cases/F{n:02d}.json" for n in range(1, 8))]:
        expected[f"reference-data/{rel}"] = (public_ref / rel).read_bytes()
    put(web / "public/reference-data/flow-cases/flow-sample.zip", (public_ref / "flow-cases/flow-sample.zip").read_bytes())
    put(web / "dist/version.json", b'{"version": "test"}')
    put(web / "src/pages/practice/practice-cases.json",
        json.dumps({"cases": [{"id": f"C{i:03d}"} for i in range(1, 21)]}).encode())
    for rel, content in expected.items():
        put(web / "public" / rel, content)
        put(web / "dist" / rel, content)
    put(web / "dist/index.html", b"web application")
    put(web / "dist/assets/app.js", b"app()")
    put(web / "dist/practice-data/v1/C001/unlisted.csv", b"unlisted")
    put(web / "dist/practice-data/v1/C021/extra.html", b"unlisted")
    put(web / "dist/unrelated.csv", b"unlisted")
    put(web / "dist" / case_prefix / "shots/unlisted.png", b"unlisted")
    put(web / "dist" / case_prefix / "W60.zip", b"stale supplied ZIP")
    put(web / "dist" / case_prefix / "W61.zip", b"unlisted")
    build_release.copy_web_dist(out)
    target = out / "app/apps/web/dist"
    shipped = {p.relative_to(target).as_posix(): p.read_bytes() for p in target.rglob("*") if p.is_file()}
    sample = target / "reference-data/long-window-sample.zip"
    del shipped["reference-data/long-window-sample.zip"]
    with zipfile.ZipFile(sample) as archive:
        names = set(archive.namelist())
        assert {"fw.csv", "ndr.csv", "operations.csv", "truth.json"} <= names
        assert "unlisted.csv" not in names
        assert sum(json.loads(archive.read("truth.json"))["row_counts"].values()) == 132750
    distinct_inputs = set()
    for case in WORKED_IDS:
        rel = f"{case_prefix}/{case}.zip"
        del shipped[rel]
        with zipfile.ZipFile(target / rel) as archive:
            assert sorted(archive.namelist()) == [f"{case}/{name}" for name in ("followup.json", "fw.csv", "ndr.csv")]
            followup = json.loads(archive.read(f"{case}/followup.json"))
            assert followup["case_id"] == case and followup["records"]
            ledgers = [archive.getinfo(f"{case}/{name}.csv") for name in ("fw", "ndr")]
            assert all(info.file_size > 1_000_000 for info in ledgers)
            distinct_inputs.add(tuple(info.CRC for info in ledgers))
    assert len(distinct_inputs) == len(WORKED_IDS)
    assert shipped.pop("reference-data/flow-cases/flow-sample.zip") == (public_ref / "flow-cases/flow-sample.zip").read_bytes()
    assert shipped == {**expected, "index.html": b"web application", "assets/app.js": b"app()",
                       "version.json": b'{"version": "test"}'}

    stale_index = json.dumps([{"id": case} for case in WORKED_IDS[:-1]]).encode()
    for folder in ("public", "dist"):
        put(web / folder / case_prefix / "index.json", stale_index)
    with pytest.raises(BundleError, match="platform case index"):
        build_release.copy_web_dist(tmp_path / "stale-index")

    # An existing file at the correct path is not sufficient when dist is stale.
    put(web / "dist/practice-data/v1/C020/fw.csv", b"wrong content")
    with pytest.raises(BundleError, match="C020/fw.csv"):
        build_release.copy_web_dist(tmp_path / "stale")
    (web / "dist/practice-data/v1/C020/fw.csv").unlink()
    with pytest.raises(BundleError, match="C020/fw.csv"):
        build_release.copy_web_dist(tmp_path / "partial")


def test_empty_web_build_cannot_be_packaged_as_having_practice_data(tmp_path, monkeypatch):
    monkeypatch.setattr(build_release, "ROOT", tmp_path)
    put(tmp_path / "apps/web/dist/index.html", b"web application")
    put(tmp_path / "apps/web/src/pages/practice/practice-cases.json", json.dumps({"cases": [{"id": "C001"}]}).encode())
    with pytest.raises(BundleError, match="practice-data"):
        build_release.copy_web_dist(tmp_path / "incomplete")


def test_a_case_list_without_ids_cannot_be_packaged(tmp_path, monkeypatch):
    monkeypatch.setattr(build_release, "ROOT", tmp_path)
    put(tmp_path / "apps/web/src/pages/practice/practice-cases.json", json.dumps({"cases": []}).encode())
    with pytest.raises(BundleError, match="practice"):
        build_release.copy_web_dist(tmp_path / "none")
