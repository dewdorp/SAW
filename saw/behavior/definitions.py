"""Versioned local measurements, derived from the supplied whitepaper table 7."""
from __future__ import annotations

from copy import deepcopy

DEFINITIONS_VERSION = "saw-web-behavior/1.0"
METRICS = (
    ("requests_10s", "10초 요청 수", 10, "건", 30),
    ("paths_60s", "60초 고유 경로 수", 60, "개", 30),
    ("status404_60s", "60초 404 응답 수", 60, "건", 15),
    ("repeats_60s", "60초 동일 요청 후보 수", 60, "건", 20),
    ("ua_600s", "10분 고유 User-Agent 수", 600, "개", 2),
)
# These explicit suffix choices are a SAW local selector, not a copied external rule pack.
DEFAULT_PROFILE = {
    "id": "theori-reference-v1", "label": "첨부 문서 참고 임계값",
    "thresholds": {mid: threshold for mid, _, _, _, threshold in METRICS},
    "ua_min_404": 2, "exclude_methods": ["OPTIONS"],
    "static_suffixes": [".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                        ".woff", ".woff2", ".ttf", ".eot"],
    "deduplicate_request_id": False,
}
DEFAULT_PROFILE["static_suffixes"].sort()
MAX_EVENTS = 100_000
MAX_SECONDS = 120
MAX_PARTITIONS = 4096
MAX_BUCKETS = 400
MAX_EVIDENCE = 200
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_METRIC_EVIDENCE = 16
MAX_SUMMARY_VALUES = 100
MAX_FIELD_LENGTH = 4096


FOLLOWUP_QUESTION_VERSION = "saw-web-behavior-questions/1.0"
FOLLOWUP_QUESTIONS = (
    {
        "id": "authorization",
        "label": "인가 점검·배치·NAT 공유 여부 확인",
        "condition": "참고 임계값에 도달했거나 동일 출발지의 여러 사용자가 섞였을 가능성이 있을 때",
        "question": "관측된 시각·출발지·대상 서비스와 요청 유형이 승인된 점검·배치·공유 출발지의 업무 범위에 들어가는가?",
        "needed_data": ["점검 승인 기록과 승인 범위", "배치 일정과 실행 기록", "관측 시각의 NAT·프록시 출발지 매핑"],
        "allowed_actions": ["이미 확보한 승인 문서·일정·실행 기록을 조회한다.",
                            "저장 결과의 시각·출발지·서비스·요청 범위와 문서의 범위를 대조한다.",
                            "자료 담당자에게 누락된 승인 범위와 공유 출발지 정보를 요청한다."],
        "resolution_criteria": ["일치·불일치·확인 불가를 구분하고 비교한 범위와 근거 ID를 확인 기록에 남긴다.",
                                "정상 업무 설명은 확인한 요청·시각·서비스 범위에만 적용한다."],
        "if_unresolved": "승인 여부와 출발지 공유 관계를 미확인으로 남기고 필요한 담당자·자료를 후속 확인에 기록한다.",
        "forbidden_claims": ["임계값 도달만으로 공격·AI 사용·침해 성공을 단정하지 않는다.",
                             "IP가 같다는 이유만으로 단일 사용자·행위자로 단정하지 않는다.",
                             "승인 자료가 없다는 사실을 무허가 행위의 증거로 바꾸지 않는다."],
        "items": ["관측 시각·출발지·대상 서비스가 승인 범위와 일치하는지 확인"],
    },
    {
        "id": "origin_outcome",
        "label": "원본 서버 응답과 후속 결과 확인",
        "condition": "허용 기록 또는 공격 의심 요청이 있으며 실제 처리·영향을 확인해야 할 때",
        "question": "허용 또는 공격 의심 요청을 원본 서버가 어떻게 처리했고 실제 변경·실행·정보 노출을 입증하는 후속 기록이 있는가?",
        "needed_data": ["원본 서버 접근·오류 로그와 요청 식별자", "보존된 응답 내용", "관련 호스트의 파일·프로세스·변경 기록"],
        "allowed_actions": ["이미 확보한 WAF·서버·호스트 기록을 요청 ID와 시각 범위로 대조한다.",
                            "보존된 응답과 변경 흔적을 열람하고 누락된 원본 자료를 담당자에게 요청한다."],
        "resolution_criteria": ["허용·차단 관찰과 원본 처리 결과를 따로 기록한다.",
                                "성공·실패·영향 여부는 해당 결과를 입증하는 증거와 범위를 연결해 판단한다."],
        "if_unresolved": "요청 행위 관찰과 실제 성공·피해 미확인을 구분하고 필요한 서버·호스트 자료를 후속 확인에 남긴다.",
        "forbidden_claims": ["WAF 허용 또는 2xx 응답만으로 공격 성공을 단정하지 않는다.",
                             "수집하지 않은 호스트 흔적이 없다고 단정하지 않는다.",
                             "의심 요청을 실제 서비스에 재전송하거나 실행하여 결과를 만들어 내지 않는다."],
        "items": ["WAF 허용과 원본 서버 처리 성공을 구분하고 후속 변경 흔적 확인"],
    },
    {
        "id": "collection",
        "label": "UA 수집 설정·시각 정밀도·수집 연속성 확인",
        "condition": "미수집·빈 값·알 수 없는 시각 정밀도·관측 공백 등 품질 제한이 있을 때",
        "question": "필요한 필드와 원래 시각 정밀도가 수집 설정에 정의되어 있으며 관측 공백 동안 수집이 유지되었는가?",
        "needed_data": ["해당 버전의 로그 형식·필드 수집 설정", "원본 시각 표현과 센서 시간 설정", "수집기 상태·누락·중단 기록"],
        "allowed_actions": ["보존된 로그 형식과 원본 표본을 비교한다.",
                            "기존 수집 상태·센서 시각 설정 기록을 확인하고 누락 자료를 요청한다."],
        "resolution_criteria": ["필드별 값 존재·기록된 빈 값·미수집·알 수 없음을 분리해 기록한다.",
                                "공백 원인이나 수집 연속성은 이를 뒷받침하는 별도 상태 기록이 있을 때만 확인으로 바꾼다."],
        "if_unresolved": "필드·시각 정밀도·수집 연속성의 미확인 상태와 측정 가능한 부분집합을 유지한다.",
        "forbidden_claims": ["기록된 빈 UA 값을 실제 HTTP 헤더 부재로 단정하지 않는다.",
                             "정규화 시각의 .000 표기만으로 밀리초 정밀도가 수집되었다고 단정하지 않는다.",
                             "관측이 없는 구간을 수집 장애 또는 활동 없음으로 단정하지 않는다."],
        "items": ["빈 값과 미수집 필드를 구분하고 공백 구간의 수집 상태 확인"],
    },
)
TOOL_IDENTITY_QUESTION = {
    "id": "tool_identity",
    "label": "조건부 도구 문자열과 별도 실행 근거 확인",
    "condition": "조건부 도구 문자열 또는 기존 스캐너·도구 태그가 실제 수집 기록에서 관찰된 경우",
    "question": "관찰된 식별 문자열이 승인된 점검·제품 기록과 일치하며 실제 도구 실행·모델 호출을 뒷받침하는 별도 증거가 있는가?",
    "needed_data": ["문자열이 관찰된 요청 원본과 기존 탐지 근거", "승인된 도구·제품·점검 목록",
                    "이미 확보된 호스트 실행 기록", "명시적 모델 호출 또는 이그레스 기록(있는 경우)"],
    "allowed_actions": ["저장된 문자열 근거와 승인된 제품·점검 문서를 대조한다.",
                        "이미 확보된 호스트·모델 호출·이그레스 기록이 있으면 해당 시각·식별자를 비교한다.",
                        "필요한 자료의 보유 여부를 담당자에게 확인하고 누락 자료를 요청한다."],
    "resolution_criteria": ["문자열 관찰과 승인된 사용 여부를 근거 ID 및 확인 범위와 함께 기록한다.",
                            "도구 실행·모델 호출은 각각을 뒷받침하는 별도 기록이 있을 때만 확인으로 기록한다."],
    "if_unresolved": "문자열 관찰 사실만 유지하고 실제 도구 실행·행위자·AI 사용·외부 통신은 미확인으로 남긴다.",
    "forbidden_claims": ["문자열 하나만으로 특정 도구 실행·행위자·AI 사용·침해 성공을 단정하지 않는다.",
                         "코드에 정의된 조건부 문자열을 첨부 문서 기본 실행의 관측 사실로 바꾸지 않는다.",
                         "모델 호출·이그레스 자료 미수집을 외부 통신 없음 또는 모델 호출 확인으로 바꾸지 않는다.",
                         "외부 모델 API·의심 호스트·관리 콘솔에 능동 접속하여 근거를 만들지 않는다."],
    "items": ["관찰 문자열의 조건과 문서 검증 범위를 확인하고 승인된 사용·실행 증거를 별도로 비교"],
}


def followup_questions(indicators):
    """Return passive review questions; the function performs no retrieval or external action."""
    questions = deepcopy(list(FOLLOWUP_QUESTIONS))
    observed = [item for item in indicators if item.get("state") == "observed" and
                item.get("category") in {"tool_string", "scanner_tool"}]
    if observed:
        tool = deepcopy(TOOL_IDENTITY_QUESTION)
        tool["indicator_ids"] = [item["id"] for item in observed]
        tool["evidence_ids"] = list(dict.fromkeys(eid for item in observed for eid in item.get("evidence_ids", [])))
        questions.append(tool)
    for question in questions:
        question["question_version"] = FOLLOWUP_QUESTION_VERSION
    return questions


def resolve_profile(profile=None):
    """Return a fresh validated profile, never accepting a production-policy setting."""
    out = deepcopy(DEFAULT_PROFILE)
    if profile is None:
        return out
    if not isinstance(profile, dict) or set(profile) - set(out):
        raise ValueError("unknown behavior profile fields")
    for key in ("id", "label"):
        if key in profile and (not isinstance(profile[key], str) or len(profile[key]) > 128):
            raise ValueError(f"invalid profile {key}")
    thresholds = profile.get("thresholds", {})
    if not isinstance(thresholds, dict) or set(thresholds) - set(out["thresholds"]):
        raise ValueError("unknown behavior threshold")
    for key, value in thresholds.items():
        if type(value) is not int or not 1 <= value <= MAX_EVENTS:
            raise ValueError("threshold must be an integer from 1 to 100000")
        out["thresholds"][key] = value
    for key in ("exclude_methods", "static_suffixes"):
        if key not in profile:
            continue
        value = profile[key]
        if not isinstance(value, list) or len(value) > 40 or any(
                not isinstance(v, str) or not v or len(v) > 32 for v in value):
            raise ValueError(f"invalid {key}")
        if key == "static_suffixes" and any(not v.startswith(".") or "/" in v or "?" in v for v in value):
            raise ValueError("static suffixes must be explicit file suffixes")
        out[key] = sorted(set(v.upper() if key == "exclude_methods" else v for v in value))
    if "ua_min_404" in profile:
        value = profile["ua_min_404"]
        if type(value) is not int or not 1 <= value <= MAX_EVENTS:
            raise ValueError("ua_min_404 must be a positive bounded integer")
        out["ua_min_404"] = value
    if "deduplicate_request_id" in profile:
        if type(profile["deduplicate_request_id"]) is not bool:
            raise ValueError("deduplicate_request_id must be boolean")
        out["deduplicate_request_id"] = profile["deduplicate_request_id"]
    if any(out[k] != DEFAULT_PROFILE[k] for k in out if k not in ("id", "label")):
        out["id"], out["label"] = "saw-local-v1", "SAW 로컬 프로필"
    return out
