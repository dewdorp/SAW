"""What each NDR/FW export column means, how this investigation used it, and how many records carried it.

States: "linked" (feeds analysis as a common field), "candidate" (linked, but direction/unit/row meaning needs
the device's confirmation), "raw" (kept verbatim, not used by default analysis). Counts are server-side over
the whole investigation, never over the rows a screen happened to load.
"""
from __future__ import annotations

from saw import container
from saw.core.schemas.query import Filter

# (column, meaning, common field or None, state, how it is used / caution)
NDR = [
    ("event_time", "이벤트 기록 시각", "timestamp", "linked", "기간·순서의 기준. 요청/응답/세션 종료 중 무엇인지는 장비 기준 확인"),
    ("_site", "원천 사이트 구분", None, "raw", "관계사와 자동 동일시하지 않음(등록된 관계 사용)"),
    ("app", "응용·L7 프로토콜 분류", None, "raw", "포트만으로 앱을 확정하지 않음"),
    ("_schema", "원천 스키마 식별자", None, "raw", "형식 변경 감지에 사용, 파서 버전 아님"),
    ("protocol", "통신 프로토콜", "protocol", "linked", "TCP/UDP와 L7 값의 층위 구분"),
    ("src_ip", "기록된 출발지 IP", "src_ip", "linked", "실사용자·실제 클라이언트로 자동 확정하지 않음"),
    ("src_port", "기록된 출발지 포트", "src_port", "linked", "통신 쌍 비교"),
    ("src_country", "출발지 국가 정보", None, "raw", "공격자 국적·악성 판정에 쓰지 않음"),
    ("dest_ip", "기록된 목적지 IP", "dst_ip", "linked", "공통 목적지로 연결, 원래 이름도 보존"),
    ("dest_port", "기록된 목적지 포트", "dst_port", "linked", "서비스·범위 비교"),
    ("dest_country", "목적지 국가 정보", None, "raw", "출처·규격 확인 전 변환하지 않음"),
    ("_device_ip", "원천 장비 IP", None, "raw", "통신 출발지·피해 자산으로 바꾸지 않음"),
    ("_device_name", "원천 장비 이름", None, "raw", "장비별 설정 재사용에 사용"),
    ("method", "HTTP 요청 메서드", "method", "linked", "POST 자체를 공격으로 보지 않음"),
    ("host", "HTTP 대상 호스트 후보", "hostname", "linked", "클라이언트가 보낸 값일 수 있음"),
    ("path", "HTTP 요청 경로", "url_path", "linked", "경로 탐색·민감 경로 분석"),
    ("query", "HTTP 쿼리 문자열", "url_query", "linked", "경로와 합쳐 요청 분석, DNS 도메인으로 쓰지 않음"),
    ("user_agent", "요청의 User-Agent", "user_agent", "linked", "보조 단서, 프로그램 신원 확정 아님"),
    ("referer", "요청의 Referer", None, "raw", "보조 단서, 조작 가능"),
    ("req_cookie", "요청 쿠키", None, "raw", "이름만 저장, 값은 원본 파일에만 보존. 로그인 성공을 뜻하지 않음"),
    ("uuid", "원천 식별값", None, "raw", "역할·유일 범위 미확인 — 세션·사용자로 합치지 않음"),
    ("status", "HTTP 응답 상태 코드", "status_code", "linked", "200을 정상·성공으로 치환하지 않음"),
    ("sc_bytes", "서버→클라이언트 바이트 후보", "bytes_out", "candidate", "응답량 후보. 행 단위·헤더 포함·누적 여부 확인 필요"),
    ("cs_bytes", "클라이언트→서버 바이트 후보", "bytes_in", "candidate", "요청량 후보. 외부 송신량과 동일시하지 않음"),
]
FW = [
    ("_time", "로그 기록 시각", "timestamp", "linked", "발생·수집·시작·종료 역할은 장비 확인 필요"),
    ("_device_ip", "원천 FW 장비 IP", None, "raw", "장비·관측 위치 연결"),
    ("_device_name", "원천 FW 장비 이름", None, "raw", "장비별 설정 재사용"),
    ("action", "장비 처리 결과", "enforcement_action", "linked", "허용은 통신·공격 성공과 다름"),
    ("src_ip", "기록된 출발지 IP", "src_ip", "linked", "관계사·구역과 함께 해석"),
    ("src_port", "기록된 출발지 포트", "src_port", "linked", "통신 쌍 연결"),
    ("dst_ip", "기록된 목적지 IP", "dst_ip", "linked", "목적지 확산·새 상대 분석"),
    ("dst_port", "기록된 목적지 포트", "dst_port", "linked", "서비스·포트 탐색 분석"),
    ("protocol", "통신 프로토콜", "protocol", "linked", "표현·계층 확인"),
    ("tcp_flag", "TCP 플래그 기록", None, "raw", "단일/누적 여부 미확인 — SYN만으로 연결 성공 확정 안 함"),
    ("duration", "지속시간", None, "candidate", "단위(초/밀리초)와 행 의미는 장비 설정에서 확인"),
    ("sent_bytes", "송신 바이트(방향 기준 확인 필요)", "bytes_out", "candidate", "출발지/장비 기준·누적 여부 확인 전 전체 트래픽으로 보지 않음"),
    ("rcvd_bytes", "수신 바이트(방향 기준 확인 필요)", "bytes_in", "candidate", "sent_bytes와 한 쌍으로 다룸"),
]
FORMATS = {"en_ndr_http_csv": ("NDR HTTP (영문 헤더)", NDR), "en_fw_csv": ("FW (영문 헤더)", FW)}


def build(inv_id: str) -> dict:
    es = container.get().events
    out = []
    for parser, (label, fields) in FORMATS.items():
        base = [Filter(field="parser", value=parser)]
        total = es.count(inv_id, base, None)
        if not total:
            continue
        rows = []
        for column, meaning, common, state, note in fields:
            target = common or f"ext.security_csv.{column}"
            filled = es.count(inv_id, base + [Filter(field=target, op="exists")], None)
            rows.append({"column": column, "meaning": meaning, "common_field": common, "state": state,
                         "use": note, "records_with_value": filled, "records": total})
        out.append({"parser": parser, "label": label, "records": total, "fields": rows})
    return {"formats": out, "states": {"linked": "공통 필드로 분석에 연결", "candidate": "연결했으나 방향·단위·행 의미 확인 필요",
                                       "raw": "원문으로 보존(기본 분석에 쓰지 않음)"}}
