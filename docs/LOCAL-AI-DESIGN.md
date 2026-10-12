# 로컬 AI 모델 반입·선택 계약

작성일: 2026-10-12. 기존 SAW의 결정적 분석·Evidence·권한 계약을 유지하는 증분이다. 일반 구현 선택은 사용자가 위임했다. 운영 데이터 사용·운영 모델 채택·학습·재배포 권리 승인을 대신하지 않는다.

## 목적과 범위

모델 없는 본체 설치 매체를 제공하고, 관리자가 별도 반입한 GGUF 모델팩을 검증한 후 합성 개발 조사에서 선택할 수 있게 한다. 지정 모델은 `fdtn-ai/Foundation-Sec-8B`, revision `9e6bb1f70b402e55bbf68cfd7abf88458daf09b3`, BASE이다. 자동 다운로드나 대체 모델 선택은 없다. 모델 없는 설치에서도 결정적 분석과 오프라인 템플릿은 동작한다.

현재 실행 허용 범위는 합성 자료만이다. 모델팩 검증과 활성화는 운영 품질 승인, 운영 데이터 사용 승인, 실제 학습 성공을 의미하지 않는다. 운영 사용 확대는 권리·고정 품질 평가·대상 장비 검증과 별도 사용자 승인을 받은 후 구현/설정한다.

## 관리자 API

모든 경로는 `/api/v1` 아래이며, `ai.models.manage` 권한(관리자), 기존 세션·MFA·CSRF를 적용한다.

- `GET /admin/local-models`: `{active_pack_id, runtime, limits, models, synthetic_only:true}`. models는 검증된 목록이며 경로·원문·비밀값을 응답하지 않는다.
- `POST /admin/local-models/validate`, 본문 `{pack_id}`: 서버에 별도로 복사된 팩을 검증하고 등록한다. 성공은 검증행을 반환한다. 실패는 400이며 기존 선택을 유지한다.
- `POST /admin/local-models/activate`, 본문 `{pack_id,reason}`: 이유는 앞뒤 공백 제거 후 5~512자. 등록 때 저장한 manifest 지문과 모든 파일을 재검증하고 고정 합성 입력의 실제 CPU 생성을 확인한 뒤 선택과 감사를 같은 DB 트랜잭션으로 저장한다. 성공 응답은 `{active_pack_id,previous_pack_id,actual_inference:"EXECUTED",quality_adopted:false}`. 생성 실패 시 기존 선택을 유지한다.
- `POST /admin/local-models/deactivate`, 본문 `{reason}`: 선택을 해제하고 감사 기록을 남긴다. 실행 중 요청은 시작 때 선택한 모델로 계산하지만, 선택이 바뀌거나 해제되면 늦게 도착한 이전 답변은 저장하지 않는다. 다음 요청부터 변경된 선택을 사용한다.

목록 행: `{pack_id,model_id,revision,checkpoint_kind,prompt_format,quantization,manifest_sha256,status,synthetic_only,validated_at,actual_inference,detail}`. 무결성 검사 상태와 native 실행 상태를 구분한다. 감사에는 모델 식별자·지문·결과만 기록하고 프롬프트·원문·파일 절대경로를 넣지 않는다.

## 모델팩

서버 설정 `llm_models_root` 아래 `<pack_id>/manifest.json` 폴더로 반입한다. 팩 id는 소문자 영숫자·하이픈·밑줄 1~64자이며 경로를 입력받지 않는다. UNC·장치 경로·ADS·상위 경로·심볼릭 링크·정션·reparse 지점을 거부한다. 목록의 상대경로만 읽고 파일별 크기와 SHA256을 모두 확인한다. 이 검사는 전송 무결성 검사이며 게시자 진위나 법률 검토의 대체물이 아니다.

Manifest `saw.local-model-pack/1`: `pack_id`, `model_id`, `revision`(고정 40자리), `checkpoint_kind`(BASE/INSTRUCT), `prompt_format`, `quantization`, `model_file`, `config_file`, `tokenizer_file`, `license_files`, `license_status`, `files`(path/bytes/sha256), `runtime`(llama.cpp b11429/고정 commit), `synthetic_only:true`. 모델 실행 파일·스크립트·임의 인자·Python pickle·원격 코드·사용자 Jinja template은 받지 않는다.

초기 지원 format은 `base-completion-v1`과 고정된 `llama3-instruct-v1`뿐이다. BASE에는 chat template을 붙이지 않는다. Instruct는 Llama3 token 계약과 checkpoint 종류를 확인하고 고정 직렬화를 사용한다. config/tokenizer metadata와 GGUF magic/version을 검사하며 실제 native tokenizer/loader 실행은 별도 검증이다. Foundation의 지정 revision/Q4_K_M/hash는 코드로 고정하여 이름만 같은 대체 파일을 거부한다.

## 런타임과 자원

본체에 별도 신뢰한 llama.cpp runtime을 넣는다. `llm_runtime_root`와 배포자가 고정한 `llm_runtime_manifest_sha256`으로 native 파일 목록·버전·commit·전체 지문을 검증한다. 모델팩은 runtime을 제공하거나 교체하지 못한다. 모든 요청에서 동일 핸들의 쓰기/삭제 공유 금지와 해시 재검증을 하고, private runtime snapshot을 봉인해 DLL 추가·교체를 막는다.

Windows LPAC와 Job Object를 사용한다. OS loader에 필요한 읽기 전용 registryRead capability 하나만 허용하며 네트워크 capability는 0이다. 자식 프로세스 1, kill-on-close, 메모리·CPU·벽시계·출력 상한을 실행 전에 적용하며 실패 시 일반 프로세스 실행으로 우회하지 않는다. 보안 primitive는 기존 Codex의 검증된 Windows 구현 중 필요한 부분을 독립 모듈로 이식한다.

기본 동시 실행 1, CPU 4 threads 이하, context 1024 이하, 출력 128 tokens 이하, 벽시계 300초 이하, Job memory 8GiB 이하. 실제 tokenizer로 입력+출력 예산을 확인하고 초과 시 원문을 몰래 절삭하지 않는다. `llama-completion --no-conversation --offline`을 사용하고 GPU·원격·tool execution·학습은 사용하지 않는다.

## 서비스 연결

`selected_provider(settings=None)`는 현재 DB 선택을 스냅샷으로 읽어 `CPUProvider|None`를 반환한다. provider는 기존 `LLMRequest/LLMResponse` 인터페이스, `name`, `model`, `is_llm=True`, `synthetic_only=True`, `health()`를 제공한다. 서비스는 실제 조사 ID가 서버의 합성 조사 allowlist에 있는지 별도로 검사한 후 문맥을 전달한다. 모델 선택만으로 운영 자료 접근 권한을 얻지 않는다.

서버 재시작 후 DB 선택은 복구하지만 첫 요청에서 파일을 재검증한다. 반입·선택·비활성화와 실패는 감사 체인에 기록한다. 검증 실패한 출력은 서비스의 JSON/인용/범위 검사에서 별도로 거부한다.

## 검증

먼저 실패하는 회귀 시험을 기록한다. manifest 변조·누락·경로탈출·미지원 template·Foundation 신원 불일치, 관리자/CSRF, 활성화 실패 시 이전 선택 유지, 감사 트랜잭션, 재시작 선택 복구, 바쁜 CPU/시간/컨텍스트 제한을 검증한다. 모의 native 응답을 쓰는 계약 시험은 실제 모델 실행과 분리한다. 실제 smoke는 지정 Foundation과 합성 입력만 사용한다. 대상 LTSC 17763, 무GPU 16GB 공동 부하, 한국어 품질, 운영 인수는 각각 별도 결과로 남긴다.