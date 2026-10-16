"""Assemble immutable offline media from pinned public inputs and an explicit source allowlist."""
from __future__ import annotations
import argparse
import json
import shutil
import subprocess
import zipfile
from pathlib import Path
from saw.devtools.release_manifest import BundleError, digest, safe_relative, seal
ROOT = Path(__file__).resolve().parents[2]
PUBLIC_DATA = ('data/mitre/ATTACK-LICENSE.txt','data/mitre/enterprise-attack.compact.json',
 'data/enrichment/FIXTURE','data/enrichment/README.md','data/enrichment/asn_ranges.csv',
 'data/enrichment/cloud_ranges.csv','data/enrichment/tor_exits.txt')
PUBLIC_DOCS = (
 'docs/BEHAVIOR-ANALYSIS-GUIDE.md',
 'docs/BEHAVIOR-VALIDATION-2026-10-16.md',
 'docs/examples/behavior-case-A-report.html',
 'docs/examples/behavior-case-B-report.html',
 'docs/examples/behavior/agent-evidence.zip',
 'docs/examples/behavior/evaluator-answer.jsonl',
 'docs/examples/behavior/SHA256SUMS.txt',
 'docs/examples/behavior/case-A.csv',
 'docs/examples/behavior/case-B.csv',
 'docs/examples/behavior/case-C.csv',
 'docs/examples/behavior/case-D.csv',
 'docs/verification/behavior-http-2026-10-16.json',
 'docs/verification/behavior-questions-2026-10-16.json',
 'docs/verification/behavior-native-2026-10-16.json',
 'docs/verification/behavior-native-fixes-2026-10-16.json',
 'docs/verification/behavior-benchmark-2026-10-16.json',
 'docs/verification/behavior-browser-download-2026-10-16.json',
 'docs/assets/behavior-20261016/01-scope.jpg',
 'docs/assets/behavior-20261016/02-timeline.jpg',
 'docs/assets/behavior-20261016/03-request-comparison.jpg',
 'docs/assets/behavior-20261016/04-analyst-check.jpg',
 'docs/assets/behavior-20261016/05-report-cover.jpg',
 'docs/assets/behavior-20261016/06-report-chart.jpg',
 'docs/assets/behavior-20261016/07-raw-evidence.jpg',
 'docs/assets/behavior-20261016/08-missing-data.jpg',
 'docs/assets/behavior-20261016/09-approved-golden.jpg',
 'docs/assets/behavior-20261016/10-golden-export.jpg',
 'docs/assets/behavior-20261016/11-followup-contract.jpg',
 'docs/assets/behavior-20261016/12-metrics.jpg',

 'docs/OFFLINE-CONTENT-GUIDE.md','docs/GUIDANCE-GOLDEN-GUIDE.md',
 'docs/GUIDANCE-CONTENT-VALIDATION-2026-10-15.md',
 'docs/verification/guidance-content-http-2026-10-15.json',
 'docs/assets/guidance-content/02-closure.jpg','docs/examples/guidance-waf-synthetic.csv',
 'examples/content-packages/synthetic-rules-parsers.json',
 'examples/content-packages/synthetic-rules-parsers-r2.json',
 'examples/content-packages/synthetic-demo.log','examples/content-packages/synthetic-demo-r2.log',
 'examples/content-packages/SHA256SUMS.txt',
 'docs/INSTALL-WINDOWS.md','docs/LOCAL-AI-DESIGN.md','docs/LOCAL-MODEL-GUIDE.md',
 'docs/LOCAL-AI-VALIDATION-2026-10-12.md','docs/OFFLINE-RELEASE-2026-10-12.md',
 'docs/OFFLINE-RELEASE-VALIDATION-2026-10-12.md','docs/USER-MANUAL.md',
 'docs/DETECTION-CATALOG-GUIDE.md','docs/DETECTION-LIVE-WALKTHROUGH.md',
 'docs/DEMO-GUIDE.md','docs/DETECTION-VALIDATION-2026-10-12.md',
 'docs/assets/local-ai-2026-10-12/02-static-model-selected.jpg',
 'docs/assets/local-ai-2026-10-12/03-assistant-runtime-limit.jpg',
 'docs/verification/local-ai-static-2026-10-12.json',
 'docs/verification/offline-release-2026-10-12.json',
 'docs/assets/detection-validation-2026-10-12/01-catalog.jpg',
 'docs/assets/detection-validation-2026-10-12/02-rule-detail.jpg',
 'docs/assets/detection-validation-2026-10-12/03-rule-disabled.jpg',
 'docs/assets/detection-validation-2026-10-12/04-ndr-policy.jpg',
 'docs/assets/detection-validation-2026-10-12/05-flow.jpg',
 'docs/assets/detection-validation-2026-10-12/06-investigation.jpg')
WINDOWS_FILES = ('install.ps1','verify-bundle.ps1','backup.ps1','uninstall.ps1','requirements.txt',
 'saw-ctl.ps1','saw-service.xml','postgresql-service.xml','setup-opensearch.ps1','setup-postgresql.ps1')

def copy_file(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.is_symlink() or source.is_junction():
        raise BundleError('links forbidden in build input')
    shutil.copyfile(source, destination)

def copy_public_guides(out: Path):
    for rel in PUBLIC_DOCS:
        if not (ROOT / rel).is_file():
            raise BundleError('public guide missing: ' + rel)
        copy_file(ROOT / rel, out / 'app' / rel)
    copy_file(ROOT / 'docs/INSTALL-WINDOWS.md', out / 'INSTALL-WINDOWS.md')
    copy_file(ROOT / 'docs/OFFLINE-RELEASE-2026-10-12.md', out / 'START-HERE.md')


def copy_app_sources(out: Path):
    # Only executable source modules, migrations, and authored detector YAML enter app/saw.
    for p in (ROOT/'saw').rglob('*'):
        if not p.is_file() or '__pycache__' in p.parts: continue
        if p.suffix != '.py' and p.relative_to(ROOT).as_posix() not in {
            'saw/storage/migrations/script.py.mako',
            'saw/core/application/guidance_rules.yaml',
            'saw/detectors/packs/ndr_policies.yaml','saw/detectors/packs/scenarios.yaml',
            'saw/detectors/packs/web_extended_signatures.yaml','saw/detectors/packs/web_signatures.yaml'}: continue
        copy_file(p,out/'app'/p.relative_to(ROOT))

def assemble(inputs: Path, out: Path, native: Path | None = None):
    if out.exists(): raise BundleError('output must be a fresh directory')
    if native is None: raise BundleError('native AI runtime required for this release')
    from types import SimpleNamespace
    from saw.llm.model_packs import runtime_spec
    runtime_spec(SimpleNamespace(llm_runtime_root=str(native), llm_runtime_manifest_sha256=digest(native/'runtime-manifest.json')))
    provenance = json.loads((inputs / 'provenance.json').read_text(encoding='utf-8'))
    for row in provenance['files']:
        p = inputs / safe_relative(row['path'])
        if p.stat().st_size != row['bytes'] or digest(p) != row['sha256']:
            raise BundleError('build input integrity failure: ' + row['path'])
    out.mkdir(parents=True)
    allowed = {'python','opensearch','postgresql','wheels','bootstrap','sources','sdists','licenses','winsw'}
    for row in provenance['files']:
        rel=row['path']
        if rel.split('/')[0] in allowed and not rel.endswith('python-3.12.10-amd64.exe'):
            copy_file(inputs/rel,out/rel)
    copy_file(inputs/'provenance.json',out/'provenance.json')
    copy_app_sources(out)
    for rel in PUBLIC_DATA + ('pyproject.toml',):
        if (ROOT/rel).is_file(): copy_file(ROOT/rel,out/'app'/rel)
    for name in WINDOWS_FILES:
        copy_file(ROOT/'deploy/windows'/name,out/'app/deploy/windows'/name)
    for p in (ROOT/'apps/web/dist').rglob('*'):
        if p.is_file() and p.suffix in {'.html','.js','.css','.svg','.ico','.png','.woff','.woff2'}:
            copy_file(p,out/'app/apps/web/dist'/p.relative_to(ROOT/'apps/web/dist'))
    for name in ['install.ps1','verify-bundle.ps1','backup.ps1','uninstall.ps1']:
        copy_file(ROOT/'deploy/windows'/name,out/name)
    copy_public_guides(out)
    if native:
        for p in native.rglob('*'):
            if p.is_file(): copy_file(p,out/'llm-runtime'/p.relative_to(native))
    for wheel in (out/'wheels').glob('*.whl'):
        with zipfile.ZipFile(wheel) as archive:
            for name in archive.namelist():
                if not name.endswith('/') and any(token in Path(name).name.lower() for token in ('license','notice','copying')):
                    dest=out/'licenses/python'/wheel.stem/safe_relative(name)
                    dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(archive.read(name))
    license_doc = inputs/'npm-licenses.json'
    if license_doc.exists():
        for packages in json.loads(license_doc.read_text(encoding='utf-8-sig')).values():
            for package in packages:
                for location in package.get('paths',[]):
                    folder=Path(location)
                    if not folder.resolve().is_relative_to((ROOT/'apps/web/node_modules').resolve()):
                        raise BundleError('npm license source outside pinned dependencies')
                    for p in folder.iterdir():
                        if p.is_file() and any(x in p.name.lower() for x in ('license','notice','copying')):
                            name=package['name'].replace('/','-').replace('@','')
                            copy_file(p,out/'licenses/web'/name/p.name)
    from saw.devtools.sbom import build
    build(out,str(inputs/'npm-licenses.json') if (inputs/'npm-licenses.json').exists() else None)
    version=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    return seal(out,{'source_commit':version,'source_worktree_included':True,
        'target':'Windows 10 Enterprise LTSC 2019 x64 build17763','target_validation':'PENDING_CLEAN_LTSC',
        'model_weights':'EXCLUDED','native_ai_runtime':'INCLUDED' if native else 'NOT_INCLUDED',
        'python_wheels':len(list((out/'wheels').glob('*.whl'))),'python':'3.12.10',
        'postgresql':'16.15-1','opensearch':'2.19.6','pcap':'built-in deterministic pcapkit'})

def main():
    p=argparse.ArgumentParser();p.add_argument('--inputs',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True);p.add_argument('--native',type=Path)
    a=p.parse_args();print(json.dumps(assemble(a.inputs.resolve(),a.out.resolve(),a.native.resolve() if a.native else None)))
if __name__=='__main__':main()
