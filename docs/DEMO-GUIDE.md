# SAW 데모 가이드 — 샘플 데이터로 따라하기

> 모든 데이터는 합성(synthetic)입니다. IP는 FIXTURE enrichment 대역, 호스트는 example.com.
> 샘플 파일 생성: `python -m saw.devtools.export_samples samples` → `samples/` 폴더(git 제외)

| 파일 | 용도 |
|---|---|
| `01_access.log.gz` | 웹 액세스 로그(nginx combined, 4,000+줄) — API 순차 열거 시나리오 |
| `02_waf_events.jsonl` | WAF 차단 이벤트 40건 (SQLi, 61.72.33.9) |
| `03_capture_zeek_suricata.zip` | PCAP에서 추출한 Zeek conn/dns/ssl + Suricata eve.json |
| `04_access_sample.log` | 작은 웹 로그 — Log 빠른 분석용 |
| `05_ioc_list.txt` | 위협 인텔 메일에서 받은 IOC 목록(defang 포함) |
| `06_http_request.txt` | 의심 HTTP 요청 원문 |
| `07_payload_encoded.txt` | URL 인코딩된 공격 페이로드 |
| `08_diff_a.txt`, `08_diff_b.txt` | 정상 요청 vs 변조 요청 비교 |
| `09_capture.pcap` | **실제 PCAP 파일** — 종류 PCAP로 업로드하면 내장 분석기가 연결·DNS·TLS(JA4)를 추출 |
| `10_incident.pcap` | **침해 사고 PCAP** — SQL 인젝션 성공, 웹셸 업로드·사용, 위장 실행 파일, 익스플로잇 킷, FTP 무차별 대입, 평문 SMTP 인증, ARP 스푸핑, DGA |
| `11_ioc_list.txt` | IOC 목록 — 종류 **IOC 목록**으로 올리면 PCAP·로그와 자동 대조 |
| `12_ndr_meta.csv` | **NDR 메타 검색 결과 CSV** — 자동 감지로 올리면 요청·응답을 짝지어 웹 이벤트로 변환(SQLi·민감 파일 탐색·ID 순차 조회 탐지) |
| `13_firewall_kr.csv` | **한글 열 이름 방화벽 CSV(CP949)** — 자동 감지로 네트워크 연결로 변환(60초 주기 통신·대용량 업로드 탐지) |
| `14_tls_certs.pcap` | **TLS 인증서 PCAP** — 자체 서명·이름 불일치·발급 직후·약한 키 인증서(의심) 1종과 정상·내부 인증서. PCAP 포렌식 → TLS 인증서 탭 |

---

## 시나리오 A — 이미 분석된 데모 사건 둘러보기 (5분)

**상황:** 새벽 02:30~03:50(KST), Customer Lookup API(AST-API-0012, 개인정보)에 클라우드 IP 43개가 같은 UA로 고객 ID를 순차 조회.

1. **Home → RECENT INVESTIGATIONS → `INV-20261006-001 Customer API 대량 조회 의심 (demo)`**
   위험도 HIGH(80), Evidence 3개(웹 로그, WAF, PCAP 추출 로그), Finding 17개.

2. **Attack Story 탭** (Story First)
   단계별 노드: 인프라(스캐너) → 정찰(민감 파일 탐색) → Discovery(Forced Browsing 404 259건) → 인증(Brute force) → Exploitation(SQLi/LFI) → **Data Access(API Enumeration)** → Outbound(대용량 전송·주기 통신·DNS 터널링).
   노드를 클릭하면 근거 Finding과 지표(요청 수, 소스 수, 시간)를 확인할 수 있습니다.

3. **Findings 탭 → `F-1001 Possible API Enumeration`** (Evidence)
   - 요청 1,200건 / 고유 객체 1,200 / **순차 비율 1.0** / 2xx 92%
   - 출발지 IP 43개(AWS·GCP·Vultr)
   - **요청률 81.2 req/min vs 자산 기준선 18–32 (2.5배)** ← 내부 자산 컨텍스트가 위험도에 반영
   - `id` 파라미터 10001→11200 +1 증가, 범위 100% 커버
   - "Possible / Potential" 표현과 근거 지표만 제시 — 판정은 분석가가 합니다.

4. **오른쪽 Context 패널** (Internal context first)
   - 자산 AST-API-0012: 담당 부서, 데이터 등급, 기대 국가(KR), 배치 스케줄(03:00 Customer Sync from 10.20.3.5)
     → "배치 아닌가?" 오탐 검토를 바로 할 수 있습니다.
   - **유사 사건:** `INV-20261006-003 (prior case)` — 이미 attack으로 종결, **승인된 SOC Experience**
     (확인 절차 · 대응 · 탐지 아이디어)가 함께 표시됩니다.

5. **Correlations** (Overview 탭)
   - `104.248.11.20`: 웹에서 404 260건(스캐너) + 네트워크에서 443포트 평문 HTTP
   - `61.72.33.9`: 웹 접근 → 30분 뒤 WAF SQLi 차단 40건
   - `10.10.1.50 → 10.10.1.30`: 포트 스캔(Zeek) + Suricata 경보

6. **DNS / TLS / Connections 탭** (PCAP Evidence가 있을 때 활성)
   - 10.10.1.21(API 서버) → 185.220.100.5 **3.2GB 아웃바운드**
   - 43.201.88.10으로 **60초 ±1초 주기 비컨** 48회
   - `*.suspicious-example.com` 32자 랜덤 서브도메인 421건(TXT 포함) → DNS 터널링 의심
   - 드문 JA4 TLS 지문(1개 호스트만 사용)

7. **ATT&CK 탭** — Finding 근거가 있는 기법만 매트릭스에 표시(T1595.002/003 등). Navigator 레이어 JSON 내보내기 가능.

8. **Raw 탭** (또는 `.` 키) — 원본 로그 라인. 필드 facet에서 `I`(포함) / `E`(제외)로 필터를 쌓아 범위를 좁힙니다.

9. **종결 → 지식화** (4-eyes)
   - Close: 판정(attack / benign / FP …) + **사유 필수**
   - SOC Experience 초안 생성 → 제출 → **다른 사람(manager)이 승인해야** Knowledge에 반영
   - 자동 차단·정책 변경은 하지 않습니다(Human-in-the-loop).

---

## 시나리오 B — 내 파일로 새 사건 만들기 (3분)

1. Home → Quick **Web Logs** (또는 Upload Files, 파일을 입력창에 드래그해도 됨)
   → 종류 `Web Logs`, 대상 **＋ 새 조사**, 제목 입력(선택) → `01_access.log.gz` 업로드
2. 자동으로 **Job 화면**으로 이동 — 파싱 → 정규화 → 탐지 → 스토리 진행 상황 확인
3. 같은 방식으로 `02_waf_events.jsonl`(종류 WAF Logs), `03_capture_zeek_suricata.zip`(종류 PCAP)을
   대상 **방금 만든 INV**로 추가 업로드 → 웹·WAF·네트워크가 한 사건에서 상관 분석됩니다.
4. Investigations에서 새 INV를 열면 시나리오 A와 같은 화면이 만들어집니다.

> Home 입력창 옆 드롭다운의 "새 분석 (저장 안 함)"은 **붙여넣기 빠른 분석**용(시나리오 C)입니다.

---

## 시나리오 C — 빠른 분석 (저장 없이, 각 30초)

| 메뉴 | 샘플 | 결과 |
|---|---|---|
| **Home 붙여넣기 (Universal)** | `05_ioc_list.txt` 내용 | defang 자동 해제, IP/URL/SHA256/이메일/CVE 유형 자동 감지 |
| **Analyze → IOC** | 같은 목록 | `43.201.88.10` → *FIXTURE-AMAZON, KR, AWS* + **내부에서 이미 96건 관측 (INV-20261006-001, 10.10.1.21)**. 외부 TI 조회는 버튼으로 명시 실행할 때만(OPSEC) |
| **Analyze → HTTP** | `06_http_request.txt` | UA를 `script(python-httpx)`로 분류, `id` 숫자 파라미터, Cookie 자동 마스킹 |
| **Analyze → Payload** | `07_payload_encoded.txt` | URL Decode 체인 자동 탐색 → `UNION SELECT`(SQLi), `../../etc/passwd`(LFI) 패턴. CyberChef 레시피 제공 |
| **Analyze → Diff** | `08_diff_a` + `08_diff_b` | `id +1`, **Authorization 헤더 제거**, UA 변경, `X-Original-URL: /admin` 추가 → 접근통제 우회 시도 형태 |
| **Analyze → Log** | `04_access_sample.log` 일부 | 파서 자동 선택(nginx_combined 0.95), 상위 IP(104.248.11.20 260건), URI 템플릿(`/api/customer?id=<NUM>`) |

---

## 시나리오 E — PCAP 포렌식 (5분)

1. 새 조사를 만들고 `11_ioc_list.txt`를 종류 **IOC 목록**으로, `10_incident.pcap`을 종류 **PCAP**으로 올립니다.
2. 작업대의 **PCAP 포렌식** 탭: 요약 판단 "침해 정황 의심", 심각 탐지 여러 건이 보입니다.
3. **탐지 결과**에서 확인할 것
   - `Potential Path Traversal / LFI in Captured Traffic` — 응답에 `/etc/passwd` 내용이 있어 **성공 징후** 표시
   - `Potential Web Shell Upload and Use` — `shell.jsp` 업로드 후 3회 사용
   - `Potential Masqueraded Executable Download` — `invoice.jpg`인데 실제는 실행 파일(PE)
   - `Potential Brute Force (ftp) with Successful Login` — 6회 실패 후 성공
   - `IOC Match: hash …` — IOC 목록의 해시와 추출 파일이 일치
4. **추출 파일** 하위 탭에서 위장 파일의 해시 확인, **평문 인증** 탭에서 비밀번호 없이 기록된 결과 확인
5. 탐지 상세 → 근거 이벤트 클릭 → **⇄ 스트림 보기**로 실제 오간 요청·응답 확인
6. **보고서 (HTML)** 버튼으로 결과를 한 장으로 저장

## 시나리오 D — 헌팅과 탐지 룰 (선택)

- **Hunting → 새 Hunt**: 가설 예) "API 서버 10.10.1.21이 외부로 주기 통신한다"
  → 구조화 쿼리 실행 → Pivot 후보(dst_ip, JA4) 클릭 → 결과를 Finding으로 승격 → Conclude
- **Detections → New detection**: Sigma YAML 작성 → **Historical Test 실행**(저장된 이벤트로 매칭 건수 확인)
  → 다른 사람이 Approve(4-eyes, 테스트 통과 필요) → OpenSearch 쿼리로 내보내기. **실제 배포는 SAW 밖에서 사람이**. Coverage 탭에서 ATT&CK 커버리지 확인.
- **Admin → Integrations**: `siem-mock`(Logpresso 모의) 커넥터로 SIEM 조회 결과 가져오기.

---

## 역할별 계정 (개발용)

| 계정 | 역할 | 주로 해볼 것 |
|---|---|---|
| analyst | 분석가 | 시나리오 A~C, 종결, Experience 초안 |
| senior | 선임 분석가 | 자산 정보 편집, 탐지 룰 |
| manager | 관제 매니저 | **Experience 승인(4-eyes)**, 감사 로그 검증 |
| admin | 관리자 | 사용자·MFA 재설정, 커넥터 (분석 권한 없음 — 역할 분리) |

비밀번호는 `var/dev-credentials.json`(git 제외). 첫 로그인 시 QR로 MFA를 등록합니다.
