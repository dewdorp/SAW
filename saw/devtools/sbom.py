"""SBOM + third-party notices for the offline bundle (adopted from the Codex comparison).

Writes <out>/sbom.cdx.json (CycloneDX 1.5) and <out>/THIRD-PARTY-NOTICES.md covering:
Python runtime wheels (pinned deploy/windows/requirements.txt, licenses from installed metadata), web UI production
npm packages (`pnpm licenses list --prod --json`), bundled binaries and data (OpenSearch, PostgreSQL, Python, WinSW,
MITRE ATT&CK). Usage: python -m saw.devtools.sbom --out offline-bundle [--npm-json licenses.json]
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import uuid
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BINARIES = [  # (name, version, license, supplier, purpose)
    ("Eclipse Temurin JDK", "21.0.11+10", "GPL-2.0-with-classpath-exception", "Eclipse Adoptium", "OpenSearch bundled Java runtime; corresponding source included"),
    ("llama.cpp", "b11429-d812350", "MIT", "ggml-org contributors", "local CPU inference; model weights excluded; compiler runtime exception notices included"),
    ("OpenSearch", "2.19.6", "Apache-2.0", "OpenSearch Project", "event search engine"),
    ("analysis-nori (OpenSearch plugin)", "2.19.6", "Apache-2.0", "OpenSearch Project", "Korean analyzer"),
    ("PostgreSQL", "16.15", "PostgreSQL", "PostgreSQL Global Development Group (EDB binaries)", "database"),
    ("CPython", "3.12.10", "PSF-2.0", "Python Software Foundation", "runtime"),
    ("WinSW", "2.12.0", "MIT", "WinSW contributors", "Windows service wrapper"),
    ("MITRE ATT&CK Enterprise (compact catalog)", "19.2", "LicenseRef-MITRE-ATTACK-Terms", "The MITRE Corporation",
     "technique catalog; see data/mitre/ATTACK-LICENSE.txt"),
]


def _py_license(name: str) -> str:
    try:
        md = metadata(name)
    except PackageNotFoundError:
        return "NOASSERTION"
    expr = md.get("License-Expression")
    if expr:
        return expr.strip()
    classifiers = [c.split("::")[-1].strip() for c in md.get_all("Classifier") or [] if c.startswith("License ::")]
    lic = (md.get("License") or "").strip()
    if lic and len(lic) <= 60 and "\n" not in lic and lic.upper() != "UNKNOWN":
        return lic
    return " / ".join(classifiers) or "NOASSERTION"


def python_components(req: Path) -> list[dict]:
    out = []
    for line in req.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^([A-Za-z0-9_.\-]+)==([^\s;#]+)", line.strip())
        if m:
            name, ver = m.groups()
            out.append({"type": "library", "name": name, "version": ver, "purl": f"pkg:pypi/{name.lower()}@{ver}",
                        "licenses": [{"license": {"name": _py_license(name)}}], "group": "python"})
    return out


def npm_components(npm_json: dict) -> list[dict]:
    out = []
    for lic, pkgs in npm_json.items():
        for p in pkgs:
            for ver in p.get("versions") or [p.get("version")]:
                out.append({"type": "library", "name": p["name"], "version": ver, "purl": f"pkg:npm/{p['name']}@{ver}",
                            "licenses": [{"license": {"name": lic}}], "group": "web"})
    return sorted(out, key=lambda c: c["name"])


def load_npm(npm_json_path: str | None) -> dict:
    if npm_json_path:
        return json.loads(Path(npm_json_path).read_text(encoding="utf-8-sig"))
    pnpm = shutil.which("pnpm") or shutil.which("pnpm.cmd")
    if not pnpm:
        return {}
    r = subprocess.run([pnpm, "licenses", "list", "--prod", "--json"], cwd=ROOT / "apps" / "web",
                       capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300, check=False)
    return json.loads(r.stdout) if r.returncode == 0 and r.stdout.strip().startswith("{") else {}


def build(out: Path, npm_json_path: str | None = None) -> dict:
    comps = python_components(ROOT / "deploy" / "windows" / "requirements.txt")
    comps += npm_components(load_npm(npm_json_path))
    comps += [{"type": "application", "name": n, "version": v, "licenses": [{"license": {"name": lic}}],
               "supplier": {"name": sup}, "description": why, "group": "bundled"} for n, v, lic, sup, why in BINARIES]
    for c in comps:
        c["bom-ref"] = f"{c['group']}:{c['name']}@{c['version']}"
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
           "metadata": {"timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "component": {"type": "application", "name": "SAW - SOC Analysis Workbench", "version": __import__("saw.version", fromlist=["__version__"]).__version__}},
           "components": comps}
    out.mkdir(parents=True, exist_ok=True)
    (out / "sbom.cdx.json").write_text(json.dumps(bom, ensure_ascii=False, indent=1), encoding="utf-8")
    lines = ["# Third-party notices — SAW offline bundle", "",
             f"Generated {bom['metadata']['timestamp']}. Machine-readable list: `sbom.cdx.json` (CycloneDX 1.5).", "",
             "Copyleft-style licenses to review with your legal/compliance team: "
             + (", ".join(sorted({c['licenses'][0]['license']['name'] for c in comps
                                  if re.search(r"GPL|EPL|MPL|CDDL", c['licenses'][0]['license']['name'])})) or "none"), ""]
    for group, title in (("bundled", "Bundled binaries and data"), ("python", "Python packages"), ("web", "Web UI (npm, production)")):
        lines += [f"## {title}", "", "| Component | Version | License |", "|---|---|---|"]
        lines += [f"| {c['name']} | {c['version']} | {c['licenses'][0]['license']['name']} |" for c in comps if c["group"] == group]
        lines.append("")
    lines += ["MITRE ATT&CK®: © The MITRE Corporation. Reproduced and distributed with the permission of The MITRE Corporation "
              "(see data/mitre/ATTACK-LICENSE.txt)."]
    (out / "THIRD-PARTY-NOTICES.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"components": len(comps), "python": sum(c["group"] == "python" for c in comps),
            "web": sum(c["group"] == "web" for c in comps)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "offline-bundle"))
    ap.add_argument("--npm-json")
    a = ap.parse_args()
    print(build(Path(a.out), a.npm_json))


if __name__ == "__main__":
    main()
