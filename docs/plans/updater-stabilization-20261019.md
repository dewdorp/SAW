# 기존 설치 업데이트 안정화 — 설계와 실행 계획

기준: main 723e2a6. 통합 브랜치 codex/updater-stabilization-20261019.
사용자가 전체 코드 수정·시험·새 매체·통합 PR을 승인한 요청이며, 운영 설치 변경은 수행하지 않는다.

## 설계 계약
1. 상태 파일과 복구 메타데이터는 생성 순간부터 현재 사용자 소유자, 보호된 사용자/SYSTEM DACL, 원자적 교체를 사용한다.
2. OWNER RIGHTS는 검증한 실제 소유자의 권한으로 평가한다. NetworkService의 기존 경로별 최소 범위를 유지한다. 검사에서 ACL을 변경하지 않는다.
3. Procrun의 Registry32/64를 모두 읽고 타입, 경로, 중복, 상충을 검증한다. 실제 SCM 계정과 프로세스도 검증하며 등록/레지스트리는 변경하지 않는다.
4. 설치 점검은 설치·서비스에 읽기 전용이다. 경로/권한/기준/매체/서비스/저장소/설정·런타임/복구/최종 판정의 9행을 제공한다. 독립 검사는 계속하고 의존 검사는 미실행으로 기록한다.
5. 매체 오류는 소스 ZIP, manifest 누락·손상, 필수 payload 누락, 실제 파일 누락, 해시 불일치, 추가 파일을 구분한다. 원시 예외·설정·비밀은 보고하지 않는다.
6. 적용 직전 유지보수 잠금 안에서 다시 검사한다. 중지 전에 경로/ACL/공간/복구 위치/마이그레이션 계보를 확인하고, 중지 후 완전 복구본을 검증한 다음 교체한다.
7. 복구의 디렉터리 교체에는 보호된 복구 폴더에 단계 기록을 남긴다. 설치 경로가 사라진 중단 상황도 검증된 스냅샷/보관본/기록으로 재시도하며 새로운 자료를 별도 보존한다.
8. 기존 설치 manifest가 우선한다. 구형 설치는 검증된 원래 전체 매체와 실제 설치 파일을 대조하고, 성공한 적용에서 새 manifest를 남긴다. 원본이 없으면 추정 기준을 만들지 않는다.
9. 자동 복원으로 새 자료를 덮지 않는다. 실패 후 검증한 복구본과 보관 위치·다음 조치를 표시하며 사용자 확인 후 복구하고 서비스/HTTPS를 다시 검증한다.

## 실행 순서
- [x] 원래 요청, 현행 전체 경로, PR #1/#2 읽기 전용 분석
- [ ] 상태/ACL 회귀와 구현 (담당 agent update_acl_state)
- [ ] 서비스/Registry 회귀와 구현 (담당 agent update_service_validation)
- [ ] 9행 UI와 안전한 상세 표시/PS5.1 폼 시험 (담당 agent update_flow_ui_audit)
- [ ] 매체 분류, 사전 점검, 트랜잭션/중단 복구, 오류 주입 시험 (담당 root)
- [ ] 통합 시험 및 독립 코드 검토
- [ ] 합성 PostgreSQL/OpenSearch/HTTPS 실제 업데이트·복구 및 자료 보존 확인
- [ ] 새 전체 오프라인 매체 빌드·봉인·ZIP 전체 entry 검증
- [ ] 운영 현장 검증 절차/사용자 문서/진행 기록, 새 PR 및 새 릴리스

## 검증 경계
개발 PC Windows 버전과 실제 토큰은 시험 시 기록한다. LTSC 2019/관리자 서비스 토큰은 사용 가능한 경우에만 실측 PASS로 적는다. fixture 단위 시험과 실제 저장소/기동 시험, 물리적 더블클릭과 폼 이벤트를 구분한다. 기존 ZIP/manifest는 수정하지 않는다.

## 근거
- PR #1: https://github.com/dewdorp/SAW/pull/1
- PR #2: https://github.com/dewdorp/SAW/pull/2
- OWNER RIGHTS: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
- 기본 객체 소유자: https://learn.microsoft.com/en-us/windows/win32/secauthz/owner-of-a-new-object
- Procrun Registry32: https://commons.apache.org/proper/commons-daemon/procrun
