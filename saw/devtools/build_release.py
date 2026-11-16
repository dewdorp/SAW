"""Assemble immutable offline media from pinned public inputs and an explicit source allowlist."""
from __future__ import annotations
import argparse
import json
import re
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
 'docs/ANALYST-WORKFLOW-GUIDE-20261029.md',
 'docs/verification/analyst-fixes-20261030.md',
 'docs/RECURRING-SECURITY-CSV-GUIDE-20261025.md',
 'docs/samples/security-csv/fw-mixed-devices.csv',
 'docs/samples/security-csv/ndr-potential-chain.csv',
 'docs/samples/security-csv/ndr-normal.csv',
 'docs/samples/security-csv/ndr-label-only.csv',
 'docs/samples/security-csv/ndr-missing-response.csv',
 'docs/images/security-csv-20261025/csv-upload.png',
 'docs/images/security-csv-20261025/csv-fw-complete.png',
 'docs/images/security-csv-20261025/csv-ndr-complete.png',
 'docs/images/security-csv-20261025/csv-readiness.png',
 'docs/images/security-csv-20261025/csv-ndr-fields.png',
 'docs/images/security-csv-20261025/csv-scenarios.png',
 'docs/images/security-csv-20261025/csv-old-run.png',
 'docs/verification/affiliate-p5-validation-20261024.md',
 'docs/SAFE-REPROCESSING-GUIDE-20261024.md',
 'docs/opensearch-vendor-extensions.md',
 'docs/images/affiliate-p5-20261024/before-history.jpg',
 'docs/images/affiliate-p5-20261024/reprocess-choose.jpg',
 'docs/images/affiliate-p5-20261024/reprocess-complete.jpg',
 'docs/images/affiliate-p5-20261024/retained-v1-history.jpg',
 'docs/images/affiliate-p5-20261024/source-statistics.jpg',
 'docs/images/affiliate-p5-20261024/pcap-overview.jpg',
 'docs/images/affiliate-p5-20261024/pcap-capture-scope.jpg',
 'docs/images/affiliate-p5-20261024/pcap-session-evidence.jpg',
 'docs/AFFILIATE-GOLDEN-GUIDE-20261023.md',
 'docs/images/affiliate-p4-20261024/p4-holdout-answers-20261024.png',
 'docs/images/affiliate-p4-20261024/p4-holdout-result-20261024.png',
 'docs/images/affiliate-p4-20261024/p4-profiles-20261024.png',
 'docs/images/affiliate-p4-20261024/p4-release-approved-20261024.png',
 'docs/images/affiliate-p4-20261024/p4-release-awaiting-20261023.png',
 'docs/images/affiliate-p4-20261024/p4-release-revoked-20261024.png',
 'docs/verification/affiliate-p4-native-20261024.json',
 'docs/verification/affiliate-p4-final-gate-20261024.json',
 'docs/verification/affiliate-p4-browser-20261024.json',
 'docs/verification/affiliate-p4-validation-20261024.md',
 'docs/AFFILIATE-FOLLOWUP-REPORT-GUIDE-20261021.md',
 'docs/verification/affiliate-p3-validation-20261023.md',
 'docs/verification/affiliate-p3-native-20261023.json',
 'docs/verification/affiliate-p3-final-gate-20261023.json',
 'docs/verification/affiliate-p3-embedded-python-20261023.json',
 'docs/images/affiliate-p3-20261021/verified.png',
 'docs/images/affiliate-p3-20261021/export-completed.png',
 'docs/images/affiliate-p3-20261021/html-report.png',
 'docs/AFFILIATE-DETECTION-GUIDE-20261021.md',
 'docs/images/affiliate-p2-20261021/draft-active.png',
 'docs/images/affiliate-p2-20261021/selected-truth.png',
 'docs/images/affiliate-p2-20261021/policy-form.png',
 'docs/UPDATER-STABILIZATION-GUIDE-20261019.md',
 'docs/UPDATER-STABILIZATION-GUIDE-20261019.html',
 'docs/verification/updater-native-acceptance-20261019.md',
 'docs/verification/updater-flow-audit-20261019.md',
 'docs/assets/updater-20261019/01-baseline-required.png',
 'docs/assets/updater-20261019/02-media-diagnosis.png',
 'docs/assets/updater-20261019/03-compact-window.png',
 'docs/assets/updater-20261019/04-native-start.png',
 'docs/verification/updater-stabilization-20261019.json',
 'docs/verification/offline-release-2026-10-17.json',
 'docs/detection-rule-sources.md',
 'docs/adr/0016-windows-airgapped-deployment-and-builtin-pcap.md',
 'docs/verification/content-browser-2026-10-17.json',
 'docs/assets/content-20261017/01-import-preview.jpg',
 'docs/assets/content-20261017/02-fixtures-pass.jpg',
 'docs/assets/content-20261017/03-independent-review.jpg',
 'docs/assets/content-20261017/04-applied.jpg',
 'docs/assets/content-20261017/05-rollback-impact.jpg',
 'docs/assets/content-20261017/06-rolled-back.jpg',
 'docs/ADMIN-RULES-ANALYTICS-GUIDE.md',
 'docs/ADMIN-RULES-ANALYTICS-VALIDATION-2026-10-14.md',
 'docs/ASSISTANT-EVIDENCE-GUIDE.md',
 'docs/ASSISTANT-EVIDENCE-VALIDATION-2026-10-15.md',
 'docs/DETECTION-RULES-HOWTO.md',
 'docs/MODEL-16GB-KOREAN-GUIDE.md',
 'docs/MODEL-8B-KOREAN-SECURITY-GUIDE.md',
 'docs/STATISTICS-TEMPORAL-GUIDE.md',
 'docs/STATISTICS-TEMPORAL-VALIDATION-2026-10-14.md',
 'docs/assets/admin-rules-analytics-2026-10-14/01-source-statistics.jpg',
 'docs/assets/admin-rules-analytics-2026-10-14/02-source-table.jpg',
 'docs/assets/admin-rules-analytics-2026-10-14/03-peer-evidence.jpg',
 'docs/assets/admin-rules-analytics-2026-10-14/04-rule-help.jpg',
 'docs/assets/admin-rules-analytics-2026-10-14/05-rule-export.jpg',
 'docs/assets/admin-rules-analytics-2026-10-14/06-delete-preview.jpg',
 'docs/assets/admin-rules-analytics-2026-10-14/07-delete-completed.jpg',
 'docs/assets/admin-rules-analytics-2026-10-14/08-raw-drilldown.jpg',
 'docs/assets/assistant-evidence-2026-10-15/01-evidence-preview.jpg',
 'docs/assets/assistant-evidence-2026-10-15/02-note-saved.jpg',
 'docs/assets/assistant-evidence-2026-10-15/03-note-after-reload.jpg',
 'docs/assets/assistant-evidence-2026-10-15/04-raw-reference.jpg',
 'docs/assets/assistant-evidence-2026-10-15/05-explanation-template.jpg',
 'docs/assets/assistant-evidence-2026-10-15/06-preview-final-narrow.jpg',
 'docs/assets/statistics-temporal-2026-10-14/01-overview.jpg',
 'docs/assets/statistics-temporal-2026-10-14/02-statistics-controls.jpg',
 'docs/assets/statistics-temporal-2026-10-14/03-statistics-values.jpg',
 'docs/assets/statistics-temporal-2026-10-14/04-temporal-finding.jpg',
 'docs/assets/statistics-temporal-2026-10-14/05-evidence-80.jpg',
 'docs/assets/statistics-temporal-2026-10-14/06-original-line.jpg',
 'docs/assets/statistics-temporal-2026-10-14/07-status-chart.jpg',
 'docs/assets/statistics-temporal-2026-10-14/08-filtered-raw.jpg',
 'docs/samples/assistant-korean-security-evaluation.json',
 'docs/samples/temporal-behavior-160.jsonl',
 'docs/verification/assistant-evidence-2026-10-15.json',
 'docs/verification/statistics-temporal-2026-10-14.json',
 'docs/verification/installer-recovery-2026-10-18.md',
 'docs/INSTALL-RECOVERY-2026-10-18.md', 'docs/OFFLINE-RELEASE-2026-10-17.md', 'docs/OFFLINE-UPDATE-GUIDE.md',
 'docs/DOUBLE-CLICK-UPDATE-GUIDE.md',
 'docs/DOUBLE-CLICK-UPDATE-GUIDE.html',
 'docs/verification/desktop-update-2026-10-18.json',
 'docs/assets/desktop-update-20261018/01-update-window.png',
 'docs/OFFLINE-RELEASE-VALIDATION-2026-10-17.md',
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
DESKTOP_WINDOWS_FILES = ('UPDATE-SAW.cmd', 'update-ui.ps1', 'update-ui.psm1', 'update-worker.ps1')
WINDOWS_FILES = ('test-update-environment.ps1','install-state.ps1','install-python.ps1','setup-postgresql-state.ps1','install-paths.ps1','update.ps1','install.ps1','verify-bundle.ps1','backup.ps1','uninstall.ps1','requirements.txt',
 'saw-ctl.ps1','saw-service.xml','postgresql-service.xml','setup-opensearch.ps1','setup-postgresql.ps1') + DESKTOP_WINDOWS_FILES
MEDIA_WINDOWS_FILES = ('test-update-environment.ps1','install.ps1', 'verify-bundle.ps1', 'backup.ps1', 'uninstall.ps1', 'update.ps1') + DESKTOP_WINDOWS_FILES

def copy_file(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.is_symlink() or source.is_junction():
        raise BundleError('links forbidden in build input')
    shutil.copyfile(source, destination)

def copy_windows_sources(out: Path):
    for name in WINDOWS_FILES:
        copy_file(ROOT / 'deploy/windows' / name, out / 'app/deploy/windows' / name)
    for name in MEDIA_WINDOWS_FILES:
        copy_file(ROOT / 'deploy/windows' / name, out / name)

def copy_public_guides(out: Path):
    for rel in PUBLIC_DOCS:
        if not (ROOT / rel).is_file():
            raise BundleError('public guide missing: ' + rel)
        copy_file(ROOT / rel, out / 'app' / rel)
    (out / 'INSTALL-WINDOWS.md').write_text(
        '# SAW 설치 안내\n\n[최신 매체 시작 안내](START-HERE.md)와 '
        '[전체 설치 설명서](app/docs/INSTALL-WINDOWS.md)를 확인하세요.\n\n'
        '기존 설치는 [업데이트·복구 안내](app/docs/OFFLINE-UPDATE-GUIDE.md)를 따릅니다.\n',
        encoding='utf-8')
    start = (ROOT / 'docs/INSTALL-RECOVERY-2026-10-18.md').read_text(encoding='utf-8')
    # The root entry point must rebase links from its app/docs source directory.
    start = re.sub(r'\]\((?![a-zA-Z][a-zA-Z0-9+.-]*:|#)([^)]+)\)',
                   r'](app/docs/\1)', start)
    start = '# 기존 설치 업데이트\n\n기존 계정과 자료를 유지하려면 UPDATE-SAW.cmd를 실행하고 [9항목 점검·복구 안내](app/docs/UPDATER-STABILIZATION-GUIDE-20261019.html)를 확인하세요. GitHub Source code ZIP은 설치 매체가 아닙니다.\n\n' + start
    (out / 'START-HERE.md').write_text(start, encoding='utf-8')


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
    copy_windows_sources(out)
    for p in (ROOT/'apps/web/dist').rglob('*'):
        if p.is_file() and p.suffix in {'.html','.js','.css','.svg','.ico','.png','.woff','.woff2'}:
            copy_file(p,out/'app/apps/web/dist'/p.relative_to(ROOT/'apps/web/dist'))
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
    from saw.storage.migrate import head
    version=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    return seal(out,{'source_commit':version,'source_worktree_included':True,'application_schema':head(),'installer_contract':'saw.install-resume/1','desktop_update_ui':1,'updater_inspection':1,
        'target':'Windows 10 Enterprise LTSC 2019 x64 build17763','target_validation':'PENDING_CLEAN_LTSC',
        'model_weights':'EXCLUDED','native_ai_runtime':'INCLUDED' if native else 'NOT_INCLUDED',
        'python_wheels':len(list((out/'wheels').glob('*.whl'))),'python':'3.12.10',
        'postgresql':'16.15-1','opensearch':'2.19.6','pcap':'built-in deterministic pcapkit'})

def main():
    p=argparse.ArgumentParser();p.add_argument('--inputs',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True);p.add_argument('--native',type=Path)
    a=p.parse_args();print(json.dumps(assemble(a.inputs.resolve(),a.out.resolve(),a.native.resolve() if a.native else None)))
if __name__=='__main__':main()
