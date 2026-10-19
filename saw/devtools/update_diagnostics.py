"""Bounded, non-secret updater inspection reports shared with the native UI."""
from __future__ import annotations
import re
import unicodedata

IDS = ("paths", "access", "baseline", "media", "services", "stores",
       "configuration_runtime", "recovery", "overall")
LABELS = {
    "paths": "설치·매체·복구 경로", "access": "설치 권한",
    "baseline": "기존 설치 버전", "media": "새 매체 무결성",
    "services": "Windows 서비스와 프로세스", "stores": "PostgreSQL·OpenSearch 구성",
    "configuration_runtime": "설정·런타임·마이그레이션", "recovery": "복구 가능성", "overall": "최종 업데이트 가능 여부"}
REMEDIES = {
    "baseline_required": "원래 설치에 사용한 전체 오프라인 매체를 선택하세요. 없으면 해당 릴리스를 다시 확보하세요. 추정 기준으로 진행하지 않습니다.",
    "source_changed": "로컬 수정 파일을 보존하고 원래 배포본과 관리자가 비교하세요. 운영 폴더에 ZIP을 덮어쓰지 마세요.",
    "media_source_archive": "GitHub Source code ZIP 대신 SAW-...-model-free-win-x64.zip 릴리스 자산을 풀어 선택하세요.",
    "media_manifest_missing": "전체 오프라인 ZIP을 새 폴더에 다시 풀고 release-manifest.json이 있는 최상위 폴더를 선택하세요.",
    "media_manifest_invalid": "손상된 매니페스트를 직접 고치지 말고 새로 검증한 전체 배포 ZIP을 반입하세요.",
    "media_payload_missing": "실행 파일과 런타임이 들어 있는 전체 오프라인 배포 ZIP을 반입하세요.",
    "media_file_missing": "백신 격리·반입 누락·압축 해제 결과를 확인하고 원본 ZIP을 새 폴더에 다시 푸세요.",
    "media_hash_mismatch": "파일이 배포본과 다릅니다. 매체를 사용하지 말고 검증된 원본 ZIP을 새 폴더에 다시 푸세요.",
    "media_unexpected_file": "매체에 추가 파일이 있습니다. 설치 자료를 섞지 말고 원본 ZIP을 별도 새 폴더에 푸세요.",
    "unsafe_access": "상세 진단의 소유자·ACE·범위를 관리자가 검토하세요. 전체 ACL 초기화나 Everyone 권한 부여는 하지 마세요.",
    "unsafe_owner": "상세 진단의 소유자를 관리자가 확인하세요. 검사에서 소유권을 변경하지 않습니다.",
    "administrator_required": "관리자 권한으로 설치 점검을 다시 실행하세요. 미실행 항목은 검증된 상태가 아닙니다.",
    "recovery_not_fresh": "기존 복구본을 보존하고 새 빈 복구 위치를 선택하세요. 이전 상태로 돌아가려면 복구 버튼을 사용하세요.",
    "insufficient_space": "설치·복구본을 보존하면서 같은 볼륨의 여유 공간을 확보하세요.",
    "recovery_headroom_insufficient": "백업과 전체 복원에 필요한 여유 공간을 확보한 뒤 다시 점검하세요.",
    "migration_unsupported": "현재 버전에서 지원되는 매체인지 확인하세요. 변경된 과거 마이그레이션이나 다운그레이드는 적용하지 않습니다.",
}
DEFAULT_REMEDY = "표시한 항목과 상세 진단을 확인한 뒤 다시 점검하세요. 기존 설치·설정·복구본은 그대로 보관하세요."


ACCESS_REASONS = {
    "access_metadata_unreadable": ("접근 권한 정보를 읽지 못했습니다.", "접근 권한 정보를 읽을 수 있어야 합니다."),
    "access_metadata_file_missing": (
        "권한 정보 조회 당시 파일을 찾지 못했습니다.", "검사 대상 파일이 존재하고 권한 정보를 읽을 수 있어야 합니다."),
    "access_metadata_path_missing": (
        "권한 정보 조회 당시 경로를 찾지 못했습니다.", "검사 대상 경로가 존재하고 권한 정보를 읽을 수 있어야 합니다."),
    "access_metadata_sharing_violation": (
        "권한 정보 조회 당시 다른 프로세스와 공유 조건이 충돌했습니다.", "권한 정보를 읽을 수 있는 공유 조건이어야 합니다."),
    "access_metadata_lock_violation": (
        "권한 정보 조회 당시 파일 잠금이 충돌했습니다.", "파일 잠금이 권한 정보 조회를 막지 않아야 합니다."),
    "access_metadata_denied": (
        "권한 정보 조회가 거부됐습니다.", "검사 대상의 권한 정보 조회가 허용돼야 합니다."),
    "access_enumeration_failed": ("검사 대상 열거 또는 실행 계정 확인을 마치지 못했습니다.", "검사 대상 열거와 실행 계정 확인을 마쳐야 합니다."),
    "access_enumeration_missing": (
        "검사 대상을 열거하는 동안 파일 또는 경로를 찾지 못했습니다.", "현재 검사 대상 전체를 열거할 수 있어야 합니다."),
    "unsupported_ace": ("지원하지 않는 접근 권한 항목(ACE)입니다.", "지원하는 allow/deny ACE 형식이어야 합니다."),
    "untrusted_owner": ("허용되지 않은 소유자입니다.", "경로별 허용된 소유자여야 합니다."),
    "untrusted_allow": ("허용 범위를 벗어난 접근 허용 권한입니다.", "경로별 허용 주체와 권한 범위를 만족해야 합니다."),
    "owner_rights_service_change": (
        "복사 후 서비스 접근 권한의 의미가 달라지거나 보존을 확인할 수 없습니다.",
        "복사 전후 서비스의 실효 접근 권한이 같아야 합니다."),
}
ACCESS_UNKNOWN = ("접근 권한 검사에서 확인이 필요한 항목이 있습니다.",
                  "접근 권한 정책을 모두 확인할 수 있어야 합니다.")


def _access_summary(detail):
    """Project only bounded ACL facts; never expose raw errors or ACE fields."""
    items = detail.get("items")
    item = (items[0] if isinstance(items, list) and 0 < len(items) <= 30
            and isinstance(items[0], dict) else {})
    reason_code = item.get("reason")
    reason, expected = (ACCESS_REASONS.get(reason_code, ACCESS_UNKNOWN)
                        if isinstance(reason_code, str) and len(reason_code) <= 64 else ACCESS_UNKNOWN)
    scope = detail.get("scope")
    label = ({"installation": "설치", "snapshot": "복구본", "copy": "복사 대상"}.get(scope, "접근 권한 검사")
             if isinstance(scope, str) else "접근 권한 검사")
    path = item.get("path")
    # Accept only the public path vocabulary produced by _safe_access_path.
    fixed = {".", "app", "data", "logs", "models", "secrets", "tls", "run",
             "saw-ctl.json", "saw-ctl.ps1", ".saw-install-state.json",
             "installed-release-manifest.json", "recovery-point.json",
             "update-result.json", "state.json", "installation", "previous-app", "new-app",
             "app/.env", "data/postgresql", "logs/postgresql"}
    public = ("app/saw/", "app/deploy/", "venv/", "pgsql/", "llm-runtime/",
              "opensearch-2.19.6/bin/", "opensearch-2.19.6/lib/",
              "opensearch-2.19.6/jdk/", "opensearch-2.19.6/plugins/",
              "opensearch-2.19.6/config/")
    safe_path = isinstance(path, str) and len(path) <= 240 and (
        path == "<private-data>" or (
            re.fullmatch(r"[A-Za-z0-9_./@+ -]+", path) and ".." not in path.split("/")
            and (path in fixed or path.startswith(public)
                 or path in {prefix.rstrip("/") for prefix in public})))
    location = label + ": " + (path if safe_path else "위치 미확인")
    checked, violations = detail.get("checked"), detail.get("violations")
    checked_text = (f"검사 {checked}개" if type(checked) is int and 0 <= checked < 2**31
                    else "검사 건수 미확인")
    violations_text = (f"확인 필요 {violations}건" if type(violations) is int and 0 <= violations < 2**31
                       else "확인 필요 건수 미확인")
    actual = checked_text + " · " + violations_text
    attempts = detail.get("attempts")
    if type(attempts) is int and 1 <= attempts <= 3:
        actual += f" · 전체 검사 시도 {attempts}회 · 검사 항목 건너뜀 없음"
    if detail.get("truncated") is True:
        actual += " · 상세 목록 일부 생략"
    return {"reason": reason, "location": location, "expected": expected, "actual": actual}

def text(value, limit=600):
    if not isinstance(value, (str, int)):
        return ""
    value = str(value)
    return "".join(c for c in value if unicodedata.category(c) not in {"Cc", "Cf"})[:limit]

class Inspection:
    def __init__(self):
        self.rows = {key: {"id": key, "status": "not_run", "code": "not_run",
                          "reason": "선행 검사가 아직 완료되지 않았습니다.", "location": "",
                          "expected": "", "actual": "", "remedy": ""} for key in IDS}
        self.details = {}
        self.errors = []

    def set(self, key, status="pass", code="verified", *, reason=None, location="",
            expected="", actual="", diagnostics=None):
        self.rows[key] = {"id": key, "status": status, "code": code,
                          "reason": text(reason or (LABELS[key] + (" 확인 완료" if status == "pass" else " 확인 필요"))),
                          "location": text(location), "expected": text(expected), "actual": text(actual),
                          "remedy": "" if status == "pass" else REMEDIES.get(code, DEFAULT_REMEDY)}
        if diagnostics:
            self.details[key] = diagnostics

    def error(self, key, error, code):
        if not isinstance(code, str) or not re.fullmatch(r"[a-z_]{1,64}", code):
            code = key + "_failed"
        detail = getattr(error, "diagnostics", None)
        detail = detail if isinstance(detail, dict) else {}
        # Only explicitly generated structured diagnostic fields are displayed.
        fields = {name: detail.get(name, "") for name in ("location", "expected", "actual")}
        if key == "access" and any(name in detail for name in ("scope", "checked", "violations", "items")):
            fields = _access_summary(detail)
        self.set(key, "action_required" if code in ("baseline_required", "administrator_required") else "fail",
                 code, **fields, diagnostics=detail)
        self.errors.append(error)

    def summary(self):
        return {"schema": "saw.update-inspection/1", "rows": [self.rows[key] for key in IDS],
                "details_file": "inspection-details.json"}

    def document(self):
        return {"schema": "saw.update-inspection-details/1",
                "summary": self.summary(), "details": self.details,
                "notice": "설치 점검은 해당 시점의 결과입니다. 적용 직전 유지보수 잠금 안에서 다시 검사합니다."}
