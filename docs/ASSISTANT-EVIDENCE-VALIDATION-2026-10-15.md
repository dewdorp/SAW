# 선택 탐지 Assistant 실제 검증 기록 — 2026-10-15

이 기록은 복사본 `F:/codex/SAW-Claude-main`의 증분 변경이다. 시작 소스는 `c3c01b6ba9b2e3255f32d5ac2359d216884f9f58`이다. 원본 `F:/claude/saw`, 실제 은행 자료, 운영 환경은 수정·반입하지 않았다. 모델·비밀값·합성 시험 DB는 Git에 포함하지 않는다.

## 1. 구현과 자동 시험

- 선택 탐지 근거 미리보기 API, 3개 주요 동작, 명시적 노트 저장과 근거 원문 이동을 연결했다. 다른 사건·탐지 응답은 표시·저장하지 않는다.
- 기존 이벤트 표본 조회에서 빠지던 탐지 시간 조건을 적용했다. 필터와 시간은 함께 제한한다. 범위가 없으면 조회하지 않고 건수 `null`, 실제 0건과 구별한다. 조회 권한·없는 탐지·다른 사건 탐지를 시험했다.
- 미리보기는 최대3개 원문 참조, 주요 생성은 이벤트 본문0개·선택 탐지1개·지표/체크/ATT&CK 각 최대4개를 사용한다. 제목/값을 마스킹하고 생략과 한계를 표시한다. 과거 사례/RAG의 검색 품질 개선을 구현했다고 보고하지 않는다.
- 비교 기준은 한글 수치 설명으로 표시하지만 구조화된 기준값은 유지한다. `passed:null`은 미확인이다. 템플릿과 실제 모델 답변을 구별하고 인용 ID 검사를 사실성 검증으로 표시하지 않는다.
- 서버 전체 **851통과·2건너뜀, 241.19초, exit0**. 분리 PG 환경/Windows symlink 권한에 따른 기존 건너뜀이며 native 공백을 통과로 세지 않는다. 기존 Starlette/httpx 경고1개가 남는다.
- 화면 전체 **144통과·26파일, 26.41초, workers2**, 이후 `tsc --noEmit` exit0. 최종 CSS는 브라우저와 후속 build로 확인했다. Ruff E9/F와 diff 검사를 수행했다.
- 최종 `pnpm build` **20.25초·exit0**. Workbench 약2,063kB(minified)/643kB(gzip) 큰 chunk 경고가 남으며 저사양 성능 인수를 뜻하지 않는다.

이번 중간 기본 worker 화면 시험의 AdminData 영향 미리보기 대기 실패1건은 단독 시험과 제한 worker 전체 시험에서 통과했지만 원인은 미확정이다. 마지막 CSS build의 첫 실행도 산출물 생성 뒤 Node `UV_HANDLE_CLOSING` assertion으로 exit -1073740791이 났다. 파일/의존성 변경 없이 같은 명령을 재실행해 exit0을 얻었다. 재통과를 근본 원인 해결로 기록하지 않는다. 기존 History503 및 과거 CPU 오류를 이번 결과로 해결 처리하지 않는다.

시험 명령은 `.qa/run-assistant-tests.py tests -p no:cacheprovider`(SAW 환경변수 제거·dotenv 미사용), `pnpm vitest run --maxWorkers=2 --minWorkers=1`, `pnpm tsc --noEmit`, `pnpm build`이다. 새 회귀 시험은 실패를 먼저 확인한 뒤 통과시켰다. 독립 재검토는 실제 응답 필드 불일치·미확인 표시·미조회/0건 구분을 수정한 후 차단 지적이 없었으며, 검토자가 별도로 native 시험을 실행한 것은 아니다.

## 2. 실제 브라우저 흐름

격리된 개발 SQLite·템플릿 provider·`claude-check`·가상160건으로 확인했다.

| 실제 수행 | 결과 |
|---|---|
| F-1006 선택 → 근거 요약 | 전체160 중 선택 구간80건, 표본 참조3건 |
| 시간 범위 | UTC01:45:00~01:59:59.999999, 화면 KST10:45~10:59 |
| 근거 설명/추가 확인/보고서 초안 버튼 | 세 동작 모두 결과 표시, LLM 아님 명시 |
| 보고서 초안 → 노트 저장 | 성공 표시, 새로고침 후 메모에 보존 |
| 표본 evt 참조 → 원본 | 합성 파일71번째 줄과 정확한 시각 확인 |
| 목록 복귀/다른 탐지 선택 | 이전 답변·저장 상태가 제거됨 |
| 좁은 창/넓은 창 | 554px 및1440px 배치 확인, 시험 viewport 복구 |

좁은 창에서 참고 패널 높이가1px로 줄어 버튼이 이벤트 서랍 뒤에 가리던 오류를 실제 재현했다. 해당 media query에 최소 높이를 주고, 긴 경고/값이 줄바꿈되게 보완했다. 최종 참고 패널 clientHeight239px, clientWidth=scrollWidth=459px이며 클릭·스크롤·생성이 동작했다. 화면 파일은 `docs/assets/assistant-evidence-2026-10-15/`에 있다. [따라하기](ASSISTANT-EVIDENCE-GUIDE.md).

## 3. 실제 Foundation-Sec-8B CPU 실행

| 항목 | 이번 실행 |
|---|---|
| 모델 | `fdtn-ai/Foundation-Sec-8B` BASE, Q4 GGUF |
| revision | `9e6bb1f70b402e55bbf68cfd7abf88458daf09b3` |
| 파일 | 4,921,462,592bytes, SHA256 `98989f9e89414f8607fe76727b46852a3ec6f3d534fc6f6259a50b02bf14e681` |
| runtime manifest SHA256 | `d0bb50baf0baf16516dea9feafcca4cdbfd449ab6e6fb68816b0281b125867e2` |
| 호스트 | Windows11 Pro26200, i5-12600, 메모리약32GB, CPU만 사용 |
| 파일 검증 API | HTTP200, 기존 고정 파일 실제 검증 |
| 활성화의 짧은 추론 | completion120.969초·exit0, 활성화 API전체156.734초·HTTP200 |
| 선택 탐지 설명 | 실제 tokenize598토큰 → completion277.922초 TIMEOUT/125 → API전체301.594초·HTTP400 `cpu_wall_budget` |
| 출력·품질 | 선택 설명의 검증된 출력 없음, 품질 미채택 |
| 정리 | 비활성화 HTTP200, active=None, 시험 계정 비활성, 탐지 판단 불변 |

실행은 격리 합성 DB에서 TestClient API를 통해 실제 `llama-tokenize.exe`/`llama-completion.exe`를 호출했다. native 프로세스는 LPAC·네트워크 capability0·작업 메모리상한8GiB·동시1개·kill-on-close였다. 짧은 생성 peak working set4,866,949,120bytes는 모델 프로세스 한 개의 관측값이며 SAW/OpenSearch 포함16GB 서버 사용량이 아니다. 시간 제한을 올리거나 보호를 낮추지 않았다.

실행 도중 후속 리뷰에서 `query_available`/null 건수 안내와 화면 표현을 보완했다. 위 native 실행은 그 직전 프롬프트이며 **최종 프롬프트의 성능 합격 기록이 아니다**. 유효한 시간/필터·지표·비교 기준을 사용한 실제 실행 실패 자체만 기록한다. 브라우저 템플릿의 성공을 native 모델 성공으로 대신하지 않는다.

모델팩의 권리 상태는 여전히 PENDING_REVIEW이며 기존 승인된 내부 합성 시험 범위만 사용했다. 운영 자료·재배포·학습·운영 모델 채택 권리를 새로 승인하지 않았다. BASE와 Instruct를 혼동하지 않으며 새 모델 가중치는 받지 않았다.

## 4. 한국어 평가·학습·운영 인수

고정 합성 평가8사례와 검토 기준을 작성했다. 후보 모델에 실행하지 않았으므로 한국어·관제 품질 합격률은 없다. Foundation Instruct를 보안 우선 평가, Kanana8B를 한국어 비교 후보로 둘 뿐 채택하지 않았다. Foundation Instruct는 별도 메시지 형식과 tokenizer/EOS 검증이 필요한 미지원 상태다. [정확한 후보·반입 가이드](MODEL-8B-KOREAN-SECURITY-GUIDE.md).

이번 optimizer 실행·adapter 변화·저장/재로딩·SFT·품질 향상은 모두 미실행이다. RAG 지식 갱신이나 채팅/노트 저장을 학습 완료로 보지 않는다. 실제 PG/RLS/OpenSearch/S3/Redis/TLS/복원은 이번 변경에서 재인수하지 않았다. 이전 실행 기록은 별도 역사적 결과다.

기존10/12 모델 제외 설치 ZIP은 그대로이고 새 소스는 그 ZIP에 미포함이다. 깨끗한 LTSC2019빌드17763에서의 오프라인 설치/재시작, 16GB 공동 접속·전체 메모리·지연, 관리자 서비스/TLS/복원, 운영 자료·운영 배포 승인은 남는다. 문서·브라우저·개발기 성공을 제품 전체 완료로 해석하지 않는다.

재개 순서: 후보 serializer/원본 template hash 계약 → 승인된 후보 파일 반입 → 같은8사례의 한국어·보안 정확성/지연 비교 → 새 모델 제외 매체 제작 및 대상OS 인수. 기준 미달 후보는 기존 선택을 바꾸지 않는다.

수치·화면 SHA256·로컬 로그 지문: [기계 판독 기록](verification/assistant-evidence-2026-10-15.json).
