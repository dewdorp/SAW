# 모델을 따로 반입하고 바꾸는 방법

2026-10-12 개발 파일럿 기준입니다. 모델 없는 본체 설치 후에도 로그·PCAP·규칙 분석과 템플릿 도움말을 사용할 수 있습니다. LLM은 결정적 탐지의 보조이며 자동 차단·종결·규칙 승인·학습을 하지 않습니다.

16GB·무GPU 서버의 한국어 후보 비교와 후보별 반입 조건은 [16GB 한국어 모델 가이드](MODEL-16GB-KOREAN-GUIDE.md)를 확인하세요. 추천 후보는 아직 실제 실행·품질 검증 전이며 현재 모델을 자동으로 바꾸지 않습니다.

## 1. 반입할 파일 준비

현재 지원 대상은 Llama 3 계열 GGUF(`Q4_K_M`, `Q5_K_M`, `Q8_0`)와 그 파일에 맞는 원본 `config.json`, `tokenizer_config.json`, LICENSE/NOTICE입니다. GGUF에는 실제 토크나이저가 들어 있어야 합니다. 임의 Hugging Face 폴더, safetensors, 다른 아키텍처, 사용자 스크립트와 Jinja template은 바로 실행하지 않습니다. 지원 밖 모델에는 별도 adapter 검증이 필요합니다.

초기 지정 후보는 **fdtn-ai/Foundation-Sec-8B BASE**, revision **9e6bb1f70b402e55bbf68cfd7abf88458daf09b3**입니다. 고정 Q4_K_M GGUF의 SHA256은 `98989f9e89414f8607fe76727b46852a3ec6f3d534fc6f6259a50b02bf14e681`, 크기는 4,921,462,592 bytes입니다. 이 모델은 대화형 Instruct 모델이 아니며 다른 모델로 자동 대체하지 않습니다. 다른 후보를 반입할 때는 그 후보의 정확한 id·revision·형식을 입력합니다.

## 2. 별도 모델 매체 만들기

본체를 설치한 PC에서 포함된 Python으로 실행합니다. 아래 경로는 예시이며 실제 반입 파일의 절대 경로로 바꾸세요. 인터넷 연결이나 파일 내려받기는 하지 않습니다. 모델 원본을 실행·변경하지 않고 새 폴더로 복사하면서 SHA256과 형식을 검증합니다.

```powershell
Set-Location C:\SAW\app
& C:\SAW\venv\Scripts\python.exe -m saw.devtools.model_pack `
  --inbox E:\SAW-model-media `
  --pack-id foundation-sec-q4 `
  --model-id fdtn-ai/Foundation-Sec-8B `
  --revision 9e6bb1f70b402e55bbf68cfd7abf88458daf09b3 `
  --kind BASE --quantization Q4_K_M `
  --model E:\approved-input\model.gguf `
  --config E:\approved-input\config.json `
  --tokenizer E:\approved-input\tokenizer_config.json `
  --license E:\approved-input\LICENSE `
  --license E:\approved-input\NOTICE
```

LICENSE/NOTICE는 실제 제공된 파일만 지정하고 `--license`를 반복할 수 있습니다. 없는 파일을 만들어 권리 승인으로 대신하지 마세요. 성공하면 `E:\SAW-model-media\foundation-sec-q4`에 manifest와 실제 파일이 생깁니다. 같은 묶음 이름을 덮어쓰지 않으므로 다른 모델·버전에는 새 이름을 사용하세요. 실패한 `.stage-*` 폴더는 선택 가능한 모델로 등록되지 않으며 자동 삭제하지 않습니다.

이 도구의 `FILES_VERIFIED`는 파일 무결성과 지원 형식 확인입니다. `PENDING_REVIEW`는 권리 검토가 남았다는 뜻이며, 게시자 진위·실제 생성·한국어 품질 승인과 다릅니다.

## 3. 폐쇄망 서버에 복사하고 화면에서 선택

1. 조직의 반입·권리 검토 후 모델 묶음 **폴더 전체**를 서버 `C:\SAW\models` 아래 복사합니다. 예: `C:\SAW\models\foundation-sec-q4\manifest.json`.
2. 관리자 계정과 MFA로 로그인하고 **관리 → 로컬 모델**을 엽니다.
3. **반입 묶음 ID**에 `foundation-sec-q4`를 입력하고 **검증 등록**을 누릅니다. 경로나 파일명을 입력하는 칸이 아닙니다.
4. 모델 id·고정 버전·BASE/Instruct·양자화·manifest 지문을 확인합니다.
5. **선택·해제 사유**를 5자 이상 쓰고 **합성 시험용으로 선택**을 누릅니다. 전체 파일 재검증과 고정 합성 입력의 실제 CPU 추론 후 선택됩니다. 실패하면 이전 선택을 유지합니다.
6. 다른 모델을 쓰려면 새 묶음 이름으로 1~5를 반복합니다. **모델 선택 해제**는 결정적 분석/기본 템플릿으로 돌아갑니다. 모델 전환 중 이미 실행되던 이전 선택의 답변은 저장하지 않습니다.

같은 pack의 파일을 제자리에서 바꾸지 마세요. 변조·누락·경로 링크·모델 DLL·미지원 형식은 거부합니다. 파일 검증에는 큰 모델을 모두 읽는 시간이 필요합니다. 해제는 진행 중 프로세스의 즉시 취소 버튼이 아니며, 실행 상한 내에서 종료되고 늦은 결과는 게시하지 않습니다.

## 4. 실제 분석에 쓰는 범위

이번 CPU 경로는 **승인된 합성 조사 ID만** 처리합니다. 관리자가 모델을 선택해도 모든 운영 조사에 자동 연결되지 않습니다. 시험용 조사 ID는 서버의 `SAW_LLM_SYNTHETIC_INVESTIGATION_IDS`에 등록하고 서버를 재시작합니다. 실제 업무 조사 ID를 합성으로 표시해서 이 제한을 우회하지 마세요.

조사의 AI 도우미에서 질문/분석 동작을 실행합니다. 문맥은 권한과 승인 상태를 검사하며 비밀값을 가립니다. 합성 전용 CPU에는 외부 Experience·전역 플레이북을 섞지 않습니다. 답변 생성 도중 계정·세션·조사 권한·사용한 승인 지식 또는 선택 모델이 바뀌면 답변 저장을 거부합니다.

출력은 JSON 형식과 인용 범위를 검사합니다. 잘못된 구조·모르는 인용은 답변으로 채택하지 않습니다. 유효한 인용도 사실을 증명하지 않으므로 분석가가 검토해야 합니다. 초기 GGUF 도우미는 설명·초안만 지원하며 구조화 헌팅 query 생성은 아직 지원하지 않습니다. 원문 코드·명령을 실행하지 않으며 모델 자체 응답이나 대화를 자동 학습시키지 않습니다.

## 5. 이번 검증과 남은 조건

새 CPU 실행기로 지정 Foundation 모델의 실제 생성·선택·해제를 실행했습니다. 한국어 요청의 첫 고정 시험은 JSON 구조가 유효했지만 **영어 응답과 잘못된 인용**을 냈습니다. 운영 답변용 품질은 미채택입니다. 자세한 실행·화면·최종 런타임 결과는 로컬 AI 검증 기록에 분리해 남깁니다.

GPU는 필요하지 않습니다. 동시 생성 1개, CPU 최대 4스레드, 문맥 1024토큰, 출력128토큰, 메모리8GiB, 시간300초 상한이 적용됩니다. 16GB 서버의 OpenSearch·다중 사용자 동시 부하와 LTSC2019 실기는 별도 검증이 필요하며 현재 개발기 실행으로 성능을 보장하지 않습니다. SFT/학습·한국어 품질 개선·운영 데이터 사용·운영 모델 교체는 이번 시험 성공에 포함되지 않습니다.
