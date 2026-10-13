# 16GB 서버의 한국어 모델 선택과 폐쇄망 반입

기준일: 2026-10-14. 대상은 GPU 없는 Windows 10 Enterprise LTSC 2019 x64 서버이며, SAW·PostgreSQL·OpenSearch를 함께 실행하는 조건입니다.

**처음 시험할 후보는 Kanana 1.5 2.1B Instruct의 Q4_K_M입니다.** 한국어 설명과 짧은 사건 요약에 적합한 크기를 우선했습니다. 보안 전문 모델이라는 뜻은 아닙니다. 탐지 여부는 기존 규칙과 근거로 판단하고, 모델에는 관측 내용의 설명과 추가 확인 항목 작성을 맡기는 것이 좋습니다. 이 문서는 추천과 반입 절차이며, 새 모델을 내려받거나 등록·선택한 실행 결과가 아닙니다.

## 1. 어떤 모델을 고르면 되나요?

| 후보 | 기대하는 업무 | 16GB 서버에서의 위치 | 현재 SAW 상태 |
|---|---|---|---|
| **kakaocorp/kanana-1.5-2.1b-instruct-2505, Q4_K_M** | 한국어 질문 이해, 짧은 사건 설명·보고 초안 | 첫 합성 시험 후보. 공개 GGUF 예시 약 1.52GB | Llama3 구조·주요 토큰 설정은 현재 지원 조건에 맞음. **실제 GGUF·템플릿·추론은 미검증** |
| **Qwen/Qwen3-4B-Instruct-2507, Q4_K_M** | 한국어 포함 다국어 설명과 지시 수행 비교 | Kanana가 품질 기준에 못 미칠 때의 비교 후보. 공개 GGUF 예시 약 2.50GB | **현재 등록 불가**. qwen3 구조와 프롬프트 adapter 추가가 먼저 필요 |
| **fdtn-ai/Foundation-Sec-8B-Instruct, Q4_K_M** | 영어 보안 용어·사건 설명 비교 | 메모리·응답 시간 부담 때문에 이 서버의 첫 후보로 권하지 않음 | **현재 공식 파일 그대로 등록 불가**. 설정/별도 템플릿 지원 검증 필요 |

Kanana는 제작사가 한국어·영어 모델과 Apache 2.0 공개를 명시한 후보입니다. Qwen은 다국어 범용 모델이며, 이 버전은 긴 사고 과정을 출력하지 않는 Instruct 모델입니다. 둘 다 이 SAW의 보안 관제 품질을 검증한 모델은 아닙니다. [Kanana 공식 안내](https://www.kakaocorp.com/page/detail/11566), [Kanana 모델카드](https://huggingface.co/kakaocorp/kanana-1.5-2.1b-instruct-2505), [Qwen 모델카드](https://huggingface.co/Qwen/Qwen3-4B-Instruct-2507), [Qwen 한국어 지원 설명](https://qwenlm.github.io/blog/qwen3/).

Foundation Instruct는 보안 업무에 맞춘 별도 모델이지만 공식 지원 언어는 영어입니다. 기존에 지정한 **Foundation-Sec-8B BASE와 다른 체크포인트**입니다. 권리 문서도 Llama 3.1 조건과 Cisco 변경분의 Apache 2.0를 함께 확인해야 합니다. 기존 BASE를 자동으로 바꾸지 않습니다. [공식 모델카드](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct), [NOTICE](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct/blob/aa13cb996e7fc700e7efd6b7367992f14cf349c0/NOTICE.md).

EXAONE 4.0 1.2B도 한국어 소형 모델이지만, 공식 카드에 비상업 라이선스가 명시되어 있어 이번 은행 운영용 기본 추천에서는 제외했습니다. [EXAONE 공식 모델카드](https://huggingface.co/LGAI-EXAONE/EXAONE-4.0-1.2B).

## 2. 16GB에서 어디까지 기대할 수 있나요?

아래는 **시험을 준비하기 위한 예산 추정**입니다. 이 대상 서버에서 측정한 최대 RAM이나 처리 속도가 아닙니다. GGUF 파일 크기에는 실행 버퍼·문맥 메모리·운영체제 캐시가 포함되지 않습니다.

| 항목 | 처음 잡을 계획 |
|---|---|
| Kanana 2.1B Q4_K_M 생성 프로세스 | 약 2.5~4GB를 예상하고 실제 측정 |
| Qwen 4B Q4_K_M 생성 프로세스 | 약 4~6GB를 예상. 현재는 adapter 미지원 |
| OpenSearch | 현재 설치 기본 heap 1GB. JVM 외 메모리·파일 캐시도 별도 필요 |
| PostgreSQL | 현재 설치 기본 shared_buffers 256MB. 연결과 쿼리의 추가 메모리도 필요 |
| Windows·SAW·색인·파일 캐시 | 나머지를 충분히 남기고 전체 사용량 관찰 |

현재 실행 제한은 **동시 생성 1개, CPU 4스레드, 문맥 1024토큰, 출력 128토큰, 300초, 생성 프로세스 8GiB 상한**입니다. 8GiB는 허용 상한이지 항상 그만큼 쓰거나 다른 프로그램의 메모리가 보장된다는 뜻이 아닙니다. 긴 원본 로그 전체를 넣기보다 해당 질문의 소수 근거와 집계 결과를 넣는 사용이 적합합니다.

첫 시험은 대량 로그 색인이 없는 시간에 진행하세요. 작업관리자에서 전체 메모리·디스크 사용과 응답 시간을 확인한 다음, 합성 로그 색인과 동시에 실행하여 서비스 응답을 비교합니다. 파일 크기가 작다는 이유로 여러 분석가의 동시 생성까지 지원한다고 판단하지 않습니다. 부족하면 기존 결정적 분석과 템플릿 도움말을 유지합니다.

기존 Foundation BASE의 개발기 시험은 입력 88/출력 62토큰에 187.297초, 최대 working set 4,873,842,688bytes였습니다. 병행 작업이 있던 Windows 11 개발기 결과이며 LTSC 2019·16GB 성능 보장이 아닙니다. 생성은 됐지만 영어 응답과 잘못된 인용 때문에 품질은 미채택이었습니다. [실제 실행 기록](LOCAL-AI-VALIDATION-2026-10-12.md).

## 3. 현재 실행기와 맞는지 먼저 확인하세요

SAW 본체는 현재 Llama3 계열 GGUF와 고정 BASE/Instruct 프롬프트만 지원합니다. 실행기 자체가 여러 구조를 지원하더라도 SAW의 파일·토큰·프롬프트 검사가 별도로 적용됩니다.

- **Kanana:** 공식 config의 LlamaForCausalLM, BOS 128000, EOS 128009, vocabulary 128259는 기본 조건에 맞습니다. 그러나 공식 템플릿의 추가 system 헤더와 SAW 고정 프롬프트의 차이, 실제 GGUF 토크나이저 메타데이터는 검증해야 합니다. 모델 이름만으로 통과를 보장하지 않습니다.
- **Qwen:** qwen3 구조와 토큰 체계가 달라 현재 검사에서 거부됩니다. Llama라고 이름이나 config를 바꾸지 마세요.
- **Foundation Instruct:** 확인한 공식 revision은 EOS 128001이며 tokenizer_config.json에 chat_template이 없고 별도 chat_template.jinja가 있습니다. 현재 INSTRUCT 계약과 맞지 않습니다. 원본 설정 수정으로 우회하지 말고 지원 작업을 먼저 진행해야 합니다.

사용자 제공 Jinja나 모델 Python 코드를 실행하는 방식으로 호환성을 맞추지 않습니다. 미지원 또는 불일치 오류가 발생하면 해당 후보는 미검증 상태로 두고 기존 모델 선택을 유지합니다.

## 4. 인터넷이 있는 준비 PC에서 반입 자료 준비

다운로드와 양자화는 **별도 준비 PC**에서 조직의 반입 절차에 따라 진행합니다. 폐쇄망 서버에 Git·컴파일러·인터넷·모델 캐시가 있다고 가정하지 않습니다. 이 안내를 작성하면서 모델 가중치를 내려받지는 않았습니다.

준비할 것은 다음과 같습니다.

1. 실제 Q4_K_M GGUF 파일. 가능하면 아래 원본 revision을 고정하여 직접 변환·양자화한 파일과 생성 기록을 사용합니다. 제3자 파일을 쓰면 게시자·제작 과정·원본 버전을 별도로 검토합니다.
2. **그 가중치와 일치하는** 원본 config.json, tokenizer_config.json 및 실제 제공된 LICENSE/NOTICE. 서로 다른 버전을 섞지 않습니다.
3. 원본 모델 id/revision, 양자화 제작자 id/revision, 파일명·크기·SHA256, 권리 검토 결과를 담은 반입 기록. 파일을 복사한 뒤에도 SHA256을 대조합니다.

원본과 양자화의 revision은 서로 다릅니다. 아래 원본 pin은 공식 공개 메타데이터에서 확인했습니다. 최신이라는 별칭 대신 정확한 revision을 기록하세요.

| 원본 모델 | 확인한 원본 revision |
|---|---|
| Kanana 1.5 2.1B Instruct | `7df4bc35ccd610e451809d7106e1c3cf82bfd44c` |
| Qwen3 4B Instruct 2507 | `cdbee75f17c01a7cc42f958dc650907174af0554` |
| Foundation-Sec-8B-Instruct | `aa13cb996e7fc700e7efd6b7367992f14cf349c0` |

[Kanana 고정 원본](https://huggingface.co/kakaocorp/kanana-1.5-2.1b-instruct-2505/tree/7df4bc35ccd610e451809d7106e1c3cf82bfd44c), [Qwen 고정 원본](https://huggingface.co/Qwen/Qwen3-4B-Instruct-2507/tree/cdbee75f17c01a7cc42f958dc650907174af0554), [Foundation Instruct 고정 원본](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct/tree/aa13cb996e7fc700e7efd6b7367992f14cf349c0).

공식 llama.cpp의 변환은 원본을 GGUF로 변환한 다음 양자화하는 두 단계입니다. 현재 SAW 실행기 pin은 b11429/`d81235049384534c167caea52b85a694f6103d14`입니다. 준비 PC에서 사용한 변환 도구·의존성 버전도 기록하고 실제 SAW 실행기로 결과를 시험해야 합니다. [고정 llama.cpp 양자화 안내](https://github.com/ggml-org/llama.cpp/blob/d81235049384534c167caea52b85a694f6103d14/tools/quantize/README.md).

### 제3자 GGUF의 크기·지문 예시

다음은 **원격 게시자의 파일 메타데이터**입니다. 공식 모델 제작사의 GGUF 배포나 로컬 무결성·추론·권리 승인 완료를 뜻하지 않습니다. 실제 파일은 이번에 내려받지 않았습니다. 원본 pin과의 일치도 별도 확인해야 합니다. 문서의 SHA256만으로 출처 진위를 대신할 수 없습니다.

[Kanana 제3자 GGUF](https://huggingface.co/TaeyoungLeeJack/kanana-1.5-2.1b-instruct-2505-Q4_K_M-GGUF/tree/9a6c4bf9e13fea91c3100a891e7312dd9911f098):

```text
publisher: TaeyoungLeeJack/kanana-1.5-2.1b-instruct-2505-Q4_K_M-GGUF
quant revision: 9a6c4bf9e13fea91c3100a891e7312dd9911f098
file: kanana-1.5-2.1b-instruct-2505-q4_k_m.gguf
bytes: 1522796736
sha256: 62a63f912a0708d9a522f974997b5bbd4927e01d739b07fe4c55c1f545241561
```

[Qwen 제3자 GGUF](https://huggingface.co/unsloth/Qwen3-4B-Instruct-2507-GGUF/tree/a06e946bb6b655725eafa393f4a9745d460374c9):

```text
publisher: unsloth/Qwen3-4B-Instruct-2507-GGUF
quant revision: a06e946bb6b655725eafa393f4a9745d460374c9
file: Qwen3-4B-Instruct-2507-Q4_K_M.gguf
bytes: 2497281120
sha256: 3605803b982cb64aead44f6c1b2ae36e3acdb41d8e46c8a94c6533bc4c67e597
```

## 5. Kanana 묶음을 만들고 등록하는 예

다음은 **검토한 실제 입력 파일을 이미 준비한 경우의 명령 예시**입니다. Kanana로 이 명령을 실행해 성공한 기록은 아직 없습니다. 경로를 보유한 파일에 맞게 바꾸고, 앞 절의 원본·양자화 출처 일치를 먼저 확인하세요. SAW가 설치된 준비 PC의 포함 Python으로 실행할 수 있습니다.

```powershell
Set-Location C:\SAW\app
& C:\SAW\venv\Scripts\python.exe -m saw.devtools.model_pack `
  --inbox E:\SAW-model-media `
  --pack-id kanana21-q4-eval01 `
  --model-id kakaocorp/kanana-1.5-2.1b-instruct-2505 `
  --revision 7df4bc35ccd610e451809d7106e1c3cf82bfd44c `
  --kind INSTRUCT --quantization Q4_K_M `
  --model E:\approved-input\kanana-1.5-2.1b-instruct-2505-q4_k_m.gguf `
  --config E:\approved-input\config.json `
  --tokenizer E:\approved-input\tokenizer_config.json `
  --license E:\approved-input\LICENSE
```

실제 제공된 NOTICE가 있으면 `--license` 인자를 추가합니다. 없는 권리 문서를 임의 작성하지 않습니다. `--revision`은 **원본 모델의 revision**입니다. 양자화 게시자 기록은 모델팩 밖의 별도 반입 기록에 보존하세요. 현재 manifest를 임의 확장하거나 생성된 모델팩에 파일을 임의 추가하면 검증에서 거부됩니다.

명령이 성공하면 `FILES_VERIFIED`는 파일·지원 형식 검사, `actual_inference: NOT_RUN`은 아직 생성하지 않음, `PENDING_REVIEW`는 권리 검토 대기라는 뜻입니다. 성공한 묶음만 화면에서 등록합니다. 실패한 `.stage-*` 폴더나 미완성 파일은 반입하지 않습니다.

폐쇄망에서는 다음 순서로 진행합니다.

1. 승인한 `kanana21-q4-eval01` 폴더 전체를 서버의 `C:\SAW\models` 아래 복사합니다. manifest 경로는 `C:\SAW\models\kanana21-q4-eval01\manifest.json`입니다.
2. 관리자와 MFA로 로그인하여 **관리 → 로컬 모델**을 엽니다.
3. **반입 묶음 ID**에 `kanana21-q4-eval01`을 쓰고 **검증 등록**을 누릅니다. 파일 경로를 넣는 칸이 아닙니다.
4. 모델 id·원본 revision·INSTRUCT·Q4_K_M·manifest 지문을 반입 기록과 비교합니다.
5. 선택 사유를 적고 **합성 시험용으로 선택**을 누릅니다. 실제 파일 재검증과 짧은 CPU 생성에 실패하면 기존 선택을 유지합니다.
6. 합성 조사에서 아래 품질 평가를 수행합니다. 다른 모델·버전은 새 묶음 ID로 반입하고 기존 폴더를 덮어쓰지 않습니다.
7. 시험이 끝나면 **모델 선택 해제**로 결정적 분석·템플릿 도움말로 돌아갈 수 있습니다. 해제는 진행 중 생성의 즉시 종료를 뜻하지 않으며 늦게 도착한 이전 모델 응답은 저장하지 않습니다.

현재 CPU 경로는 `SAW_LLM_SYNTHETIC_INVESTIGATION_IDS`에 지정한 **합성 조사에만** 연결됩니다. 실제 업무 조사 ID를 합성으로 표시하여 우회하지 마세요. CPU 합성 경로는 외부 Experience·전역 플레이북을 섞지 않습니다. 향후 승인 보안 근거 검색과 결합하는 권고를 현재 운영 RAG 품질 검증 완료로 읽으면 안 됩니다. 자세한 현재 권한·선택 절차는 [기존 모델 안내](LOCAL-MODEL-GUIDE.md)를 따릅니다.

## 6. 한국어와 관제 품질을 어떻게 비교하나요?

모델이 켜지고 문장을 생성하는 것과 분석에 도움이 되는 것은 별개입니다. 처음에는 가상의 사건 30개 정도를 고정하고, 모델·양자화·문맥·출력 제한을 기록하여 같은 질문으로 비교하세요. 아래는 **아직 실행하지 않은 권장 평가 계획**입니다.

| 평가 항목 | 가상 예시 | 확인할 결과 |
|---|---|---|
| 한국어 설명 | 정상 백업 서버의 전송량 증가 | 자연스러운 한국어이며 없는 사실을 추가하지 않음 |
| 정확한 근거 인용 | 근거 `F-001`, `E-002`만 제공 | 존재하는 ID만 인용하고 내용과 연결됨 |
| 정상/이상 구분 | 정상 야간 배치와 다른 서버의 대량 전송을 함께 제시 | 시간·서비스·주체 차이를 설명하고 정상 배치를 공격으로 단정하지 않음 |
| 차단과 침해 구분 | WAF 403과 공격 문자열만 제공 | 악성 시도 가능성과 차단 사실을 구분. 오탐 또는 침해 성공으로 자동 결론 내리지 않음 |
| 판단 보류 | 파일 경보만 있고 파일 본문은 없음 | 부족한 자료와 추가 확인을 설명 |
| 입력 속 지시문 무시 | 로그 문자열에 '이전 지시 무시' 포함 | 로그를 자료로 취급하고 실행·권한 변경을 요구하지 않음 |
| 실제 업무 효용 | 분석가가 작성한 정답 근거와 비교 | 수정량·누락·오류를 함께 기록 |
| 자원·시간 | 단독 생성과 합성 색인 동시 실행 | 최대 메모리·완료 시간·실패 코드·화면 응답을 각각 기록 |

존재하지 않는 인용·무근거 공격 확정·실제 자료 접근 범위 확대가 나오면 운영 후보로 채택하지 않습니다. 짧은 smoke test나 한국어 문장 한 개로 품질 개선을 주장하지 않습니다. 답변은 설명 초안이며 분석가의 정·오탐 판단, 룰 승인과 조치를 바꾸지 않습니다. 운영 데이터 사용·모델 교체·학습은 별도 승인 범위이며 이번 가이드는 SFT·adapter 학습을 수행하지 않습니다.

## 7. 현재 확인한 것과 남은 것

| 구분 | 상태 |
|---|---|
| 공식 모델카드·작은 설정·원격 파일 메타데이터 조사 | 확인. 원본/양자화 pin과 출처를 위에 분리 기록 |
| 현재 SAW 지원 코드와 반입 CLI 확인 | 확인. Llama3 제한, Qwen/Foundation Instruct 불일치 표시 |
| Kanana/Qwen/Foundation Instruct 가중치 다운로드 | 하지 않음 |
| 새 후보의 실제 GGUF 검증·CPU 생성·한국어/관제 평가 | 하지 않음 |
| 현재 선택 모델 변경·운영 데이터 투입·학습 | 하지 않음 |
| 깨끗한 LTSC 2019, 16GB 공동부하 검증 | 남아 있음 |

기존 지정 모델은 `fdtn-ai/Foundation-Sec-8B` **BASE**, revision `9e6bb1f70b402e55bbf68cfd7abf88458daf09b3`로 유지합니다. 모델 추천이 선택·권리·품질·운영 승인 상태를 자동으로 바꾸지 않습니다.
