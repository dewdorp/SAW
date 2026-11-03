"""The distribution must ship the complete, authored offline practice corpus only."""
import json
from pathlib import Path

import pytest

from saw.devtools import build_release
from saw.devtools.release_manifest import BundleError


def put(path: Path, content: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def test_offline_web_dist_copies_authoritative_samples_only(tmp_path, monkeypatch):
    web, out = tmp_path / "apps/web", tmp_path / "out"
    monkeypatch.setattr(build_release, "ROOT", tmp_path)
    expected = {f"practice-data/v1/C{i:03d}/{kind}.csv": f"{i},{kind}\r\n".encode()
                for i in range(1, 21) for kind in ("ndr", "fw")}
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
    build_release.copy_web_dist(out)
    target = out / "app/apps/web/dist"
    shipped = {p.relative_to(target).as_posix(): p.read_bytes() for p in target.rglob("*") if p.is_file()}
    assert shipped == {**expected, "index.html": b"web application", "assets/app.js": b"app()"}

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
