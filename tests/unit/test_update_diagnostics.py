"""Safe complete preflight and media diagnostics; synthetic installations only."""
from pathlib import Path
import importlib.util
import json
import pytest

spec = importlib.util.spec_from_file_location("_diagnostic_fixture", Path(__file__).with_name("test_desktop_update.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
installation = fixture.installation
desktop_installation = fixture.desktop_installation

def test_inspection_returns_nine_rows_and_private_details(desktop_installation):
    root, bundle, baseline, recovery, state = desktop_installation
    result = fixture.run_case(desktop_installation)
    report = result["diagnostic_summary"]
    assert report["schema"] == "saw.update-inspection/1"
    assert [r["id"] for r in report["rows"]] == [
        "paths", "access", "baseline", "media", "services", "stores",
        "configuration_runtime", "recovery", "overall"]
    assert all(r["status"] in {"pass","action_required","fail","not_run"} for r in report["rows"])
    assert result["status"] == "ready"
    assert not recovery.exists()
    assert (state / report["details_file"]).is_file()

def test_missing_baseline_does_not_hide_media_result(desktop_installation):
    root, bundle, baseline, recovery, state = desktop_installation
    result = fixture.desktop().run("inspect", root, bundle, state, controller=fixture.ControlledLifecycle())
    rows = {r["id"]:r for r in result["diagnostic_summary"]["rows"]}
    assert rows["baseline"]["code"] == "baseline_required"
    assert rows["media"]["status"] == "pass"
    assert rows["configuration_runtime"]["status"] == "not_run"
    assert result["status"] == "failed"

def test_preflight_rejects_bad_recovery_before_stop(desktop_installation):
    root, bundle, baseline, recovery, state = desktop_installation
    recovery.mkdir()
    control = fixture.ControlledLifecycle()
    result = fixture.run_case(desktop_installation, "apply", control, maintenance_confirmed=True)
    assert result["status"] == "failed"
    assert control.events == []
    assert result["diagnostic_summary"]["rows"][7]["status"] == "fail"

def test_migration_failure_is_reported_during_inspect(desktop_installation, monkeypatch):
    backend=fixture.updater()
    def bad(*args):
        raise backend.UpdateError("Migration downgrade or changed migration history is not supported")
    monkeypatch.setattr(backend,"_migration_chain",bad)
    control=fixture.ControlledLifecycle()
    result=fixture.run_case(desktop_installation,control=control)
    assert result["status"] == "failed"
    assert result["diagnostic_summary"]["rows"][6]["status"] == "fail"
    assert control.events == []

def test_media_errors_are_distinct_and_safe(desktop_installation):
    root,bundle,baseline,recovery,state=desktop_installation
    manifest=fixture.updater()._manifest
    target=bundle/"release-manifest.json"
    original=target.read_bytes()
    target.write_text("private-secret-token-invalid-json",encoding="utf-8")
    with pytest.raises(manifest.BundleError) as caught:
        manifest.verify(bundle)
    assert caught.value.code == "media_manifest_invalid"
    assert "private-secret-token" not in str(caught.value)
    target.write_bytes(original)
    first=bundle/json.loads(original)["files"][0]["path"]
    first.write_bytes(first.read_bytes()+b"changed")
    with pytest.raises(manifest.BundleError) as caught:
        manifest.verify(bundle)
    assert caught.value.code == "media_hash_mismatch"


@pytest.mark.parametrize("fault,expected", [
    ("source", "media_source_archive"), ("manifest_missing", "media_manifest_missing"),
    ("file_missing", "media_file_missing"), ("hash", "media_hash_mismatch"),
    ("manifest", "media_manifest_invalid"), ("extra", "media_unexpected_file"),
    ("payload", "media_payload_missing"),
])
def test_native_ps_and_python_media_agree(desktop_installation, fault, expected, tmp_path):
    import os, subprocess, base64
    if os.name != "nt":
        pytest.skip("Windows PowerShell 5.1 native verifier")
    bundle=desktop_installation[1]
    manifest=fixture.updater()._manifest
    path=bundle/"release-manifest.json"
    document=json.loads(path.read_text())
    first=bundle/document["files"][0]["path"]
    if fault in ("source", "manifest_missing"):
        path.unlink()
        if fault=="source":
            (bundle/"pyproject.toml").write_text("[project]")
    elif fault=="file_missing":
        first.unlink()
    elif fault=="hash":
        first.write_bytes(first.read_bytes()+b"changed")
    elif fault=="manifest":
        path.write_text("private-content-not-disclosed")
    elif fault=="extra":
        (bundle/"extra.txt").write_text("private-content-not-disclosed")
    elif fault=="payload":
        document["files"]=[r for r in document["files"] if r["path"]!="install.ps1"]
        path.write_text(json.dumps(document))
    with pytest.raises(manifest.BundleError) as caught:
        manifest.verify(bundle)
    assert caught.value.code==expected
    verifier=Path(__file__).resolve().parents[2]/"deploy/windows/verify-bundle.ps1"
    script="$env:PSModulePath=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/Modules'; try { & '"+str(verifier).replace("'","''")+"' -BundleDir '"+str(bundle).replace("'","''")+"' *> $null; exit 9 } catch { [Console]::Write($_.Exception.Data['SawCode']); exit 0 }"
    ps=Path(os.environ["SystemRoot"])/"System32/WindowsPowerShell/v1.0/powershell.exe"
    result=subprocess.run([str(ps),"-NoProfile","-ExecutionPolicy","RemoteSigned","-EncodedCommand",base64.b64encode(script.encode("utf-16-le")).decode()],capture_output=True,timeout=60)
    assert result.returncode==0
    assert result.stdout.decode().strip()==expected
    assert b"private-content" not in result.stdout+result.stderr


def test_apply_rechecks_after_inspection(desktop_installation):
    root,bundle,baseline,recovery,state=desktop_installation
    assert fixture.run_case(desktop_installation)["status"]=="ready"
    fixture.write(root,"app/saw/main.py","changed after inspection")
    control=fixture.ControlledLifecycle()
    result=fixture.run_case(desktop_installation,"apply",control,maintenance_confirmed=True)
    assert result["status"]=="failed" and control.events==[]
    assert result["code"]=="source_changed"


def test_preflight_space_failure_does_not_stop(desktop_installation,monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(fixture.updater().shutil,"disk_usage",lambda *_:SimpleNamespace(free=1))
    control=fixture.ControlledLifecycle()
    result=fixture.run_case(desktop_installation,"apply",control,maintenance_confirmed=True)
    assert result["code"]=="recovery_headroom_insufficient"
    assert control.events==[]


def test_status_publish_failure_never_returns_completed(desktop_installation,monkeypatch):
    original=fixture.desktop().State.write
    def failed(self,phase,*args,**kwargs):
        if phase in ("completed","failed"):
            raise OSError("private-status-write-content")
        return original(self,phase,*args,**kwargs)
    monkeypatch.setattr(fixture.desktop().State,"write",failed)
    result=fixture.run_case(desktop_installation,"apply",maintenance_confirmed=True)
    assert result["status"]=="failed"
    assert result["code"]=="state_write_failed"
    assert "private-status" not in json.dumps(result)


@pytest.mark.parametrize("point",["copy","receipt","switch","metadata"])
def test_apply_failures_preserve_synthetic_evidence(desktop_installation,monkeypatch,point):
    backend=fixture.updater()
    root,bundle,baseline,recovery,state=desktop_installation
    evidence=root/"data/objects/generated-updater-evidence.txt"
    evidence.parent.mkdir(parents=True,exist_ok=True)
    evidence.write_text("Synthetic updater evidence generated by this test")
    if point=="copy":
        old=backend._copy_tree
        def fail(source,target):
            old(source,target)
            if target==recovery/"installation":
                raise OSError("private-backup-failure")
        monkeypatch.setattr(backend,"_copy_tree",fail)
    elif point=="receipt":
        old=backend._json
        def fail(path,data):
            if path.name=="recovery-point.json":
                raise OSError("private-receipt-failure")
            return old(path,data)
        monkeypatch.setattr(backend,"_json",fail)
    elif point=="switch":
        old=backend.os.rename
        def fail(source,target):
            if Path(source)==recovery/"new-app":
                raise OSError("private-switch-failure")
            return old(source,target)
        monkeypatch.setattr(backend.os,"rename",fail)
    else:
        old=backend.os.replace
        def fail(source,target):
            if Path(target)==root/"installed-release-manifest.json":
                raise OSError("private-metadata-failure")
            return old(source,target)
        monkeypatch.setattr(backend.os,"replace",fail)
    control=fixture.ControlledLifecycle()
    result=fixture.run_case(desktop_installation,"apply",control,maintenance_confirmed=True)
    assert result["status"]=="failed"
    assert "start" not in control.events
    assert evidence.read_text()=="Synthetic updater evidence generated by this test"
    if point in ("copy","receipt","switch"):
        assert (root/"app/saw/main.py").read_text()=="old app"
    if point in ("switch","metadata"):
        assert result["recovery_verified"] is True
    assert "private-" not in json.dumps(result)


def test_controller_resumes_missing_root_after_restore_interruption(desktop_installation,monkeypatch):
    backend=fixture.updater()
    root,bundle,baseline,recovery,state=desktop_installation
    backend.apply(root,bundle,recovery,baseline)
    fixture.write(root,"data/objects/later-synthetic.txt","newer synthetic record")
    rename=backend.os.rename
    def interrupted(source,target):
        rename(source,target)
        if Path(source)==root:
            raise KeyboardInterrupt("synthetic process interruption")
    monkeypatch.setattr(backend.os,"rename",interrupted)
    with pytest.raises(KeyboardInterrupt):
        fixture.desktop().run("restore",root,bundle,state,recovery_point=recovery,
            maintenance_confirmed=True,confirm=True,controller=fixture.ControlledLifecycle())
    assert not root.exists()
    monkeypatch.setattr(backend.os,"rename",rename)
    control=fixture.ControlledLifecycle()
    result=fixture.desktop().run("restore",root,bundle,state,recovery_point=recovery,
        maintenance_confirmed=True,confirm=True,controller=control)
    assert result["status"]=="completed"
    assert control.events==["start","health"]
    assert (root/"app/saw/main.py").read_text()=="old app"
    assert (Path(result["retained_installation"])/"data/objects/later-synthetic.txt").read_text()=="newer synthetic record"
    assert result["diagnostic_summary"]["rows"][8]["status"]=="pass"


def test_failure_keeps_known_current_step(desktop_installation,monkeypatch):
    def failed(*args,**kwargs):
        raise OSError("synthetic failure after stop")
    monkeypatch.setattr(fixture.updater(),"_stopped",failed)
    result=fixture.run_case(desktop_installation,"apply",maintenance_confirmed=True)
    assert result["status"]=="failed"
    assert result["current_step"]=="snapshot"
    assert result["last_completed_step"]=="stop"


def _acl_summary(diagnostics, code="unsafe_access"):
    from saw.devtools.update_diagnostics import Inspection

    error = RuntimeError("private-exception-text-must-not-appear")
    error.diagnostics = diagnostics
    report = Inspection()
    report.error("access", error, code)
    return report.summary()["rows"][1]


@pytest.mark.parametrize("reason,meaning,expectation", [
    ("access_metadata_unreadable", "권한 정보를 읽지 못", "권한 정보를 읽을 수"),
    ("access_metadata_file_missing", "조회 당시 파일을 찾지 못", "검사 대상 파일"),
    ("access_metadata_path_missing", "조회 당시 경로를 찾지 못", "검사 대상 경로"),
    ("access_metadata_sharing_violation", "공유 조건이 충돌", "읽을 수 있는 공유 조건"),
    ("access_metadata_lock_violation", "파일 잠금이 충돌", "잠금이 권한 정보 조회를 막지"),
    ("access_metadata_denied", "권한 정보 조회가 거부", "권한 정보 조회가 허용"),
    ("access_enumeration_failed", "검사 대상 열거 또는 실행 계정 확인", "대상 열거와 실행 계정 확인"),
    ("access_enumeration_missing", "열거하는 동안 파일 또는 경로를 찾지 못", "현재 검사 대상 전체"),
    ("unsupported_ace", "지원하지 않는", "allow/deny ACE"),
    ("untrusted_owner", "허용되지 않은 소유자", "허용된 소유자"),
    ("untrusted_allow", "허용 범위를 벗어난", "경로별 허용"),
    ("owner_rights_service_change", "서비스 접근 권한", "복사 전후"),
])
def test_acl_summary_explains_first_violation_without_private_fields(reason, meaning, expectation):
    row = _acl_summary({
        "scope": "snapshot", "checked": 41, "violations": 3,
        "items": [
            {"path": "data/postgresql", "reason": reason,
             "sid": "private-sid-text", "rights": "private-rights-text",
             "message": "private-item-message"},
            {"path": "private-second-item", "reason": "private-second-reason"},
        ],
        "truncated": True, "location": "private-top-level-location",
        "expected": "private-top-level-expected", "actual": "private-top-level-actual",
        "exception": "private-raw-exception",
    })
    assert row["status"] == "fail" and row["code"] == "unsafe_access"
    assert meaning in row["reason"]
    assert not any(value in row["reason"] for value in ("정상 회전", "악의적 변경", "자동 수정"))
    assert row["location"] == "복구본: data/postgresql"
    assert expectation in row["expected"]
    assert row["actual"] == "검사 41개 · 확인 필요 3건 · 상세 목록 일부 생략"
    assert "private-" not in json.dumps(row)


@pytest.mark.parametrize("scope,path,location", [
    ("installation", "app/saw/main.py", "설치: app/saw/main.py"),
    ("snapshot", ".", "복구본: ."),
    ("copy", "<private-data>", "복사 대상: <private-data>"),
])
def test_acl_summary_identifies_safe_scope_and_location(scope, path, location):
    row = _acl_summary({
        "scope": scope, "checked": 1, "violations": 1,
        "items": [{"path": path, "reason": "owner_rights_service_change"}],
        "truncated": False,
    }, code="owner_semantics_unpreserved")
    assert row["location"] == location
    assert row["code"] == "owner_semantics_unpreserved"
    assert row["actual"] == "검사 1개 · 확인 필요 1건"


def test_acl_summary_unknown_reason_stays_fixed_without_guessing_cause():
    row = _acl_summary({
        "scope": "installation", "checked": 0, "violations": 1,
        "items": [{"path": ".", "reason": "private-file-deleted-during-race"}],
        "truncated": False,
    })
    assert row["reason"] == "접근 권한 검사에서 확인이 필요한 항목이 있습니다."
    assert row["expected"] == "접근 권한 정책을 모두 확인할 수 있어야 합니다."
    assert row["actual"] == "검사 0개 · 확인 필요 1건"
    assert not any(value in json.dumps(row) for value in ("private-", "삭제", "경합"))


@pytest.mark.parametrize("path", [
    None, True, 12, {"private-path": "secret"}, "x" * 241,
    "app/saw/private\npath", "app/saw/private\u202epath",
    "C:/private-record", "../private-record", "data/objects/private-record",
])
def test_acl_summary_rejects_paths_outside_safe_backend_contract(path):
    row = _acl_summary({
        "scope": "installation", "checked": 2, "violations": 1,
        "items": [{"path": path, "reason": "untrusted_owner"}], "truncated": False,
    })
    assert row["location"] == "설치: 위치 미확인"
    assert "private-" not in json.dumps(row)


@pytest.mark.parametrize("count", [True, -1, 2**31, "private-count", None])
def test_acl_summary_does_not_stringify_invalid_counts(count):
    row = _acl_summary({
        "scope": "installation", "checked": count, "violations": count,
        "items": [{"path": ".", "reason": "untrusted_allow"}], "truncated": False,
    })
    assert row["actual"] == "검사 건수 미확인 · 확인 필요 건수 미확인"
    assert "private-" not in json.dumps(row)


@pytest.mark.parametrize("items", [
    None, "private-items", [{"path": ".", "reason": {"private-reason": "secret"}}],
    [{"path": ".", "reason": "untrusted_owner"}] * 31,
])
def test_acl_summary_malformed_items_remain_bounded_and_safe(items):
    row = _acl_summary({
        "scope": {"private-scope": "secret"}, "checked": 2, "violations": 1,
        "items": items, "truncated": "private-truncated",
    })
    assert row["reason"] == "접근 권한 검사에서 확인이 필요한 항목이 있습니다."
    assert row["location"].startswith("접근 권한 검사: ")
    assert row["actual"] == "검사 2개 · 확인 필요 1건"
    assert all(isinstance(value, str) and len(value) <= 600 for value in row.values())
    assert "private-" not in json.dumps(row)


def test_acl_summary_preserves_flat_non_acl_diagnostic_contract():
    from saw.devtools.update_diagnostics import Inspection

    error = RuntimeError("private-exception")
    error.diagnostics = {"location": "app/saw/main.py", "expected": "original", "actual": "changed"}
    report = Inspection()
    report.error("baseline", error, "source_changed")
    row = report.summary()["rows"][2]
    assert (row["location"], row["expected"], row["actual"]) == ("app/saw/main.py", "original", "changed")
    assert "private-" not in json.dumps(row)



@pytest.mark.parametrize("attempts", [1, 2, 3])
def test_acl_summary_shows_bounded_whole_scan_attempts(attempts):
    row = _acl_summary({
        "scope": "installation", "checked": 9, "violations": 2,
        "items": [{"path": ".", "reason": "access_metadata_unreadable"}],
        "attempts": attempts, "truncated": True,
    })
    assert row["status"] == "fail"
    assert row["actual"] == (
        f"검사 9개 · 확인 필요 2건 · 전체 검사 시도 {attempts}회"
        " · 검사 항목 건너뜀 없음 · 상세 목록 일부 생략"
    )


@pytest.mark.parametrize("attempts", [True, 0, 4, "private-attempts", None, 1.5, {"private": "attempts"}])
def test_acl_summary_never_displays_invalid_attempt_counts(attempts):
    row = _acl_summary({
        "scope": "installation", "checked": 9, "violations": 2,
        "items": [{"path": ".", "reason": "access_metadata_unreadable"}],
        "attempts": attempts, "truncated": False,
    })
    assert row["actual"] == "검사 9개 · 확인 필요 2건"
    assert "private-" not in json.dumps(row)
