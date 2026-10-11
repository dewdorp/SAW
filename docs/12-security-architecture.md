# 12. Security Architecture

SAW는 **공격자가 만든 데이터(로그·패킷·페이로드·파일)를 매일 처리하는 시스템**이다.
따라서 “분석 대상이 분석 도구를 공격하는” 시나리오를 1급 위협으로 다룬다. 위협 목록은 [13](13-threat-model.md).

## 1. 보안 원칙

1. **All analysis data is untrusted** — 파싱, 렌더링, 저장, LLM 전 구간.
2. **Least privilege** — 사용자(RBAC+ACL), 프로세스(샌드박스), 네트워크(Zone), DB 계정.
3. **No active touch** — 분석 대상 URL/도메인/IP에 SAW가 능동 접속하지 않는다 (기본). 
4. **Human approval** — 차단/정책/룰 배포 기능 없음. 지식·룰은 4-eyes.
5. **Everything audited** — 조회 포함.
6. **Defense in depth** — 앱 통제 + 컨테이너 통제 + 호스트 방화벽.

## 2. Identity & Access

### 2.1 인증
- Local: argon2id (m=64MB, t=3, p=4), 비밀번호 정책(길이 ≥ 12, 유출 목록 대조 – 오프라인 리스트).
- **MFA(TOTP) 기본 필수** (금융권 관리자·분석가 접근 통제 요구 대비).
- 세션: 서버측 세션 저장(Redis), 유휴 30분/절대 12시간, 동시 세션 제한, 로그아웃 시 즉시 폐기.
- 향후: LDAP/AD, OIDC(사내 IdP). 그룹 → Role 매핑.

### 2.2 인가 — RBAC + Investigation ACL
| Role | 요약 |
|---|---|
| Admin | 사용자·Connector·정책 관리. 분석 데이터 기본 접근 없음 (직무분리) |
| SOC Manager | 전체 Investigation 열람, 승인, Audit 조회 |
| Senior Analyst | 분석 + Experience/Detection 승인 + 사유 기반 Unmask |
| Analyst | 분석, 본인/공유된 Investigation |
| Viewer | 공유된 Investigation 읽기 전용 (마스킹 강제) |

- Investigation 단위 `owner/editor/viewer` 멤버십 (need-to-know).
- 단일 PDP(`core/security/authz`) — 모든 Use Case 진입점에서 호출, 테스트 매트릭스로 검증.

## 3. 데이터 보호

### 3.1 마스킹 (Sensitive Data Masking)
| 유형 | 탐지 | 기본 표시 |
|---|---|---|
| 주민등록번호/외국인등록번호 | 패턴 + 생년월일·체크디짓 검증 | `900101-1******` |
| 카드번호 | 13–19자리 + Luhn | `4111-****-****-1111` |
| 계좌번호 | 은행별 패턴 사전(설정) + 문맥 키워드 | 앞 3/뒤 2 |
| 휴대전화/이메일 | 패턴 | 부분 마스킹 |
| 인증정보 | Authorization 헤더, Cookie 세션, JWT, password= 파라미터, API Key 패턴 | 길이·해시 prefix만 |

- 적용 계층: **표시(API 응답), Export, LLM 컨텍스트**. 저장은 원본 유지(재현성) — 단, 정책으로 파싱 단계 토큰화(HMAC) 선택 가능.
- Unmask: 권한 + 사유 입력 + 감사 + (옵션) 관리자 알림. 응답은 해당 필드만, 캐시 금지 헤더.

### 3.2 암호화
- 전송: 외부 TLS 1.2+(1.3 우선), 내부 TLS(운영 필수, OpenSearch/PG/S3/Redis).
- 저장: 디스크(LUKS) + S3 SSE(KMS) + PG의 민감 컬럼(mfa_secret, connector secret) 애플리케이션 레벨 암호화(AES-GCM, 키는 KMS/Docker secret).
- Secret 관리: Docker secrets → 향후 Vault. 환경변수에 평문 비밀 금지. Connector 자격증명은 암호화 저장, UI에서 재조회 불가(write-only).

## 4. Untrusted Data Handling

### 4.1 업로드 (Secure File Upload)
| 통제 | 내용 |
|---|---|
| 크기 | 파트 ≤ 64 MB, 파일 ≤ 20 GB, Investigation 총량 정책 |
| 파일명 | 저장 키로 사용 금지(UUID), 표시용은 NFC 정규화·제어문자/경로구분자 제거·길이 255 |
| 타입 | 확장자 무시, **매직바이트 + 내용 스니핑**으로 판정, Evidence kind별 허용 목록 |
| 압축 | Safe Decompress ([10 §5](10-job-processing-design.md)): 깊이·비율·총량·엔트리·경로·링크 통제 |
| 무결성 | 서버측 SHA-256 |
| 악성 파일 | Quarantine 버킷, 브라우저로 원본 서빙 금지, 다운로드 시 암호 ZIP |

### 4.2 파싱 안전
- 정규식: 사용자 정의 파서·검색은 **RE2(google-re2)** 사용 → ReDoS 차단. 내장 파서 정규식도 RE2 호환 우선, 불가 시 타임아웃.
- 파서별 라인 길이 상한(1 MB), 필드 수 상한, JSON 깊이 상한(64), XML은 `defusedxml`(XXE/Billion laughs 차단).
- gzip/deflate Decode(Payload)도 출력 크기 상한(10 MB).

### 4.3 렌더링 (XSS)
- React 기본 escape. `dangerouslySetInnerHTML` **금지**(lint 규칙). Markdown 렌더는 sanitize(raw HTML 비활성).
- **ECharts tooltip/label formatter**: HTML 문자열 반환 금지 또는 `escapeHtml()` 강제 유틸만 허용.
- HTTP Response Body의 HTML은 **절대 렌더링하지 않음** (텍스트/hex 뷰). “미리보기” 요구 시에도 제공하지 않는 것을 원칙으로 함.
- CSP: `default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'` (+ CyberChef는 별도 origin).
- 유니코드 위장(Bidi override, zero-width, homoglyph) 시각적 표시 — Raw 뷰어에서 제어문자를 기호로 노출.

### 4.4 Export
- CSV Injection 방지: `= + - @ \t \r`로 시작하는 셀은 `'` prefix.
- Export 파일에 마스킹 적용 + 워터마크(사용자·시간) + 감사.

### 4.5 SSRF / Egress
- SAW는 사용자 입력 URL로 HTTP 요청을 보내지 않는다 (IOC Analyzer는 passive).
- 외부 조회(RDAP/WHOIS/TI)는 `worker-enrich` → Egress Proxy(Allowlist 도메인) 경유만. 요청 대상은 **고정된 서비스 엔드포인트**이며 사용자 입력은 쿼리 값으로만 들어감.
- DNS 능동 조회는 **OPSEC 경고 + 분석가 명시 실행** (공격자 권한 DNS 서버에 조회 흔적이 남음). 기본은 내부 Passive DNS/로그.
- Connector URL은 Admin만 등록, 내부 대역 Allowlist.

## 5. Processing Sandbox

| 통제 | worker-parse | worker-pcap / worker-file |
|---|---|---|
| 사용자 | non-root (uid 10001) | non-root |
| rootfs | read-only | read-only |
| capabilities | drop ALL | drop ALL |
| no-new-privileges | ✓ | ✓ |
| seccomp | default | **custom 강화 프로파일** |
| AppArmor/SELinux | default | 전용 프로파일 |
| 네트워크 | 데이터 Zone만 | 데이터 Zone만 (도구 subprocess는 추가로 `unshare -n` 네트워크 없음) |
| 자원 | mem/cpu/pids limit | mem/cpu/pids limit + 도구별 timeout(크기 비례) |
| scratch | tmpfs/전용 볼륨, 작업 후 삭제 | 동일 |
| Docker socket | 금지 | 금지 |

도구 실행은 `bubblewrap` 또는 `nsjail` 래퍼(이미지 내 포함)로 프로세스 단위 격리를 추가한다 (Phase 6에서 성능 검증).

## 6. Application Security

| 항목 | 통제 |
|---|---|
| CSRF | SameSite=Strict + CSRF 토큰 |
| SQLi | SQLAlchemy 바인딩, raw SQL 금지(리뷰 게이트) |
| NoSQL/DSL Injection | OpenSearch 쿼리는 구조화 Query Builder로만 생성, `investigation_id` 필터 강제 |
| SSRF | §4.5 |
| Deserialization | pickle 금지(Celery serializer=json), YAML safe_load |
| 보안 헤더 | HSTS, X-Content-Type-Options, Referrer-Policy: no-referrer, Permissions-Policy |
| 의존성 | SBOM(CycloneDX), 취약점 스캔(Trivy/Grype), 이미지 digest pin, 내부 미러 |
| 코드 | SAST(Semgrep/Bandit), 시크릿 스캔, 리뷰 필수 |

## 7. Audit

- 대상: 로그인/실패/MFA, 권한 변경, Investigation·Evidence 생성/열람, 이벤트 조회(쿼리 요약), Unmask, Export/다운로드, Finding 피드백, Verdict, Experience/Detection 승인, AI 호출, 설정 변경.
- 형식: `audit.event` 해시 체인 + 외부 SIEM 실시간 전송(syslog/TLS).
- 조회 감사는 “쿼리 요약(필드·필터 키)”만 기록, 값은 해시 — 감사로그 자체가 민감정보 저장소가 되지 않게.

## 8. LLM Security (요약, 상세 [29](29-local-llm-design.md))

- 프롬프트 구조: `SYSTEM` / `TRUSTED CONTEXT` / `UNTRUSTED SECURITY DATA` 분리, 경계 토큰 랜덤화, 데이터는 JSON 인코딩.
- LLM에 Shell/쓰기 도구 없음. Hunting 도구는 Read-only Allowlist + 파라미터 검증 + 쿼리 예산.
- 출력은 데이터로 취급: 렌더 시 escape, 인용 Evidence ID 검증, 링크 자동 생성 금지.
- 마스킹 후 최소 컨텍스트만 전달. 모델 파일은 승인 해시(GGUF/safetensors)만 로드.

## 9. 망분리 / 규제 고려 (확인 필요 항목)

| 항목 | 설계 대응 | 확인 주체 |
|---|---|---|
| 업무망/인터넷망 분리 | 기본 인터넷 차단, Enrich 프로필은 정책 승인 시만 | 정보보호부서 |
| 개인(신용)정보 처리 | 마스킹, 접근 감사, 보존기간 | 개인정보보호책임자 |
| 접근기록 보관 기간 | 설정 가능, 기본값은 규정 확인 후 결정 | 컴플라이언스 |
| 외부 오픈소스 반입 | SBOM·취약점 스캔·반입 절차 | 보안/IT운영 |
| 로컬 LLM 모델 반입 | 해시 검증, 라이선스 검토 | 보안/법무 |
