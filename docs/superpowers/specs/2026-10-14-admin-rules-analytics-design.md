# 관리자 데이터 관리와 분석 가시성 증분 설계

기준일: 2026-10-14. 기준 소스043297c, 수정 대상 F:\codex\SAW-Claude-main. 사용자는 관리자 삭제, 탐지 룰 등록 설명/Export, 정상 로그 중 이상행위, 16GB 무GPU 모델 추천/반입 가이드, 로그 종류·출발지 통계와 화면 개선을 요청했다. 이전의 일반 판단/승인 위임에 따라 구현을 연속 수행한다. 원본 F:\claude\saw와 실제 은행 자료는 변경하거나 복제하지 않는다.

## 의도와 성공 조건

관리자는 활성 데이터를 정리할 수 있고 분석가는 어떤 규칙으로 탐지됐는지 파일로 확인한다. 조사자는 전체 로그에서 비교할 대상을 좁히고 같은 조건의 정상 다수와 다른 행동의 근거를 원문까지 확인한다. 단일 희소값/2xx/LLM 답변을 공격 확정으로 바꾸지 않는다. 새로운 모델은 추천/반입 절차만 제공하며 현재 Foundation BASE를 자동 교체하지 않는다.

## A. 관리자 삭제

전용 admin.data.delete(ADMIN만)를 부여하되 ADMIN의 기존 조사 원문 읽기 권한을 확대하지 않는다. GET /admin/data는 종류(case/investigation/evidence), ID/표시ID/상태/생성일/집계만 제공한다. POST /admin/data/deletion-preview는 대상, 영향건수, 보존항목, 차단사유, 지문을 제공한다. POST /admin/data/deletions는 사유5..500자/정확한 표시ID/최신미리보기 지문을 요구한다. GET /admin/data/deletions/{id}, POST /admin/data/deletions/{id}/retry는 영속 상태와 오류코드를 제공한다.

증거 단위는 업로드 묶음 및 포함 파일 전체이다. 압축 내부 파일 하나만 삭제한다고 오인시키지 않는다. legal_hold, 진행/대기/입력대기 작업과 업로드, 공유객체, 지원되지 않는 저장소·참조는 차단한다. 조사 row lock과 영속 삭제 barrier로 새 분석/업로드/재시도/LLM 결과 저장을 차단한다. DB/OpenSearch/파일 삭제 단계는 영수증에 기록하고 실패시 미완료로 표시하여 재시도한다. 정상적인 목록에서 숨긴 것을 실제 파일 삭제 성공이라고 세지 않는다.

케이스는 활성 목록에서 폐기하고 모든 직접 조회를 차단하지만 리비전·스냅샷 보존 계약은 유지한다. 조사/증거 삭제는 지원하는 로컬 활성 원본 및 색인을 실제 정리하고 파생 결과/검색카드/RAG의 근거 재노출을 방지한다. 안전하게 무효화할 수 없는 참조는 preview에서 차단한다. 감사/인계기록/케이스 스냅샷/룰버전/시험기록/백업의 보존을 명시하며 완전 소거라고 부르지 않는다. 이 작업의 삭제 시험은 새 합성 저장소에서만 수행한다.

## B. 룰 등록과 내보내기

기본 YAML 시그니처/시나리오/NDR 정책, 코드 기반 탐지기, 사용자 Sigma 후보를 구분한다. 기본 목록 Export(JSON/YAML)은 실제 match/all/regex/regex_not/method/raw/응답조건·전체 examples/benign·사이트 설정/활성상태·버전을 포함한다. 코드 탐지기는 구현 코드 대신 ID/버전/지원자료와 코드형임을 표시한다. 사용자 룰은 단일 파일 또는 모든 현재 버전 JSON으로 내보내며 논리/임계값/예외/상태를 포함하되 실제 시험 이벤트/원문/조사 스냅샷은 넣지 않는다. 허가 없는 사용자는 거부하고 export 감사 기록을 남긴다. 파일내보내기는 승인·배포상태를 바꾸지 않는다.

화면에 한글 등록→구문검사→정상/이상 예제→현재 버전 과거자료시험→작성자와 다른 승인자→조사 재분석 순서를 설명한다. Sigma가 내부 조사에 적용되는 범위와 외부 SIEM 수동배포를 구분한다. 미지원 엔진은 성공인 척 표시하지 않는다. 새 룰의 기본 예시는 평범한 API200 전부가 아닌 제한된 합성 탐지 예제로 바꾼다. 화면에서 원본 룰 파일을 내려받고 실패를 표시한다.

## C. 로그 통계와 가시성

POST /investigations/{inv_id}/statistics: filters, time, group_by(data_source/source_file/src_ip/dst_ip/dst_port), size1..50(default20). 기존 조사 read 권한을 가장 먼저 검사한다. 응답은 scope, summary(matched_events/time_start/time_end/timestamp_missing), table(group_by/rows/key/count/bytes_out_sum/first_ts/last_ts/filter/shown_events/other_events/missing_events/limit/approximate), 단일 전체건수 timeline이다. 통계의 필터와 시간 범위는 모두 동일해야 한다.

파일은 evidence_id+source_file 복합키로 묶고 같은 증거 안 동명 파일 합산 가능성을 명시한다. raw_ref/ext/원문/자유필드를 집계로 노출하지 않는다. 상위N·누락·근삿값·기타의 분모를 명시한다. OpenSearch 분산 terms는 오차 정보가 없으면 근삿값으로 표시한다. bytes_out 합계는 기록된 값의 합계이며 중복 수집/방향 차이 때문에 실제 전송량이라고 단정하지 않는다. 화면은 로그 통계 탭·범위카드·시간추이·누를 수 있는 행·원본 로그 연결을 제공한다. 기존 Overview의 범위 혼합을 바로잡거나 전체조사 수치임을 명시한다.

## D. 정상 다수 속 행동 차이

새 peer_behavior는 해당 조사 안의 같은 data_source/dst_ip/dst_port/15분구간을 비교한다. 다른 출발지 최소20개, 각 최소5기록, 대상 최소5기록이 필요하다. 각 출발지는 자기 값을 제외한 median+6MAD와 절대차이/비율 하한을 함께 적용한다. 요청수>=20 및4배, 오류비율>=0.6 및0.4차이, 고유경로>=10 및4배, bytes/event>=64KiB 및8배 중 서로 다른 두 신호 이상에만 후보를 낸다. 비교할 목적지/서비스/시각 부족은 범위안내로 남긴다.

최대100000events/200cohorts/5000sourcegroups/10findings/20samples로 메모리·출력을 제한하며 상한은 부분분석으로 표시한다. 같은서비스/시간, 기준표본, 관측값·중앙값, 근거 필터와 정상 업무/NAT/배치 가능성을 보여준다. success_signal=false, 자동ATT&CK확정 없음. 공유승인없는 다른 종결조사의 자동 baseline 사용은 failclosed로 중단하며 정상으로 종결했다는 이유만으로 공유승인된 정상모델로 취급하지 않는다.

## E. 16GB 모델

공식 근거에 따라 Kanana1.5 2.1B Instruct Q4_K_M를 한국어 우선 시험 후보로 안내한다. Qwen3 4B는 adapter미지원 후보, Foundation8B Instruct는 영어보안 후보로 구분한다. 현재실행기지원과 실제GGUF/템플릿평가는별개다. 원본 revision과 quant제작자 revision/hash를 따로 기록하고 metadata만으로 검증성공/권리승인이라고 하지 않는다. 모델 교체/다운로드/학습/운영데이터는 이번에 자동 수행하지 않는다.

## 검증

기준전체서버/UI 시험을 먼저 실행한다. 각기능의 권한/누락/오류/재시도/시점경합/정상과이상 합성시험을 RED→GREEN으로 추가하고 전체회귀와typecheck/build를 수행한다. 실제 브라우저는 새합성 claude-check계정만, 스크린샷에 비밀값없음. 실제PostgreSQL/OpenSearch 가능하면 별도인스턴스에서 핵심삭제/통계흐름을 확인한다. 개발Windows11 성공을 LTSC17763 운영 인수로 확대하지 않는다. 기존 배포ZIP은 불변으로 유지한다.
