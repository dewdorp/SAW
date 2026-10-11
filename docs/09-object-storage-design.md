# 09. Object Storage Design

## 1. 역할

S3 호환 Object Storage는 **증거 원본의 보관소**이자 재처리의 기준점이다.
코드는 `ObjectStorePort`(put/get/multipart/presign/head/list/delete/set_retention)만 사용 → MinIO 외 S3 호환 스토리지로 교체 가능 ([ADR-0005](adr/0005-s3-compatible-object-storage.md)).

## 2. Buckets

| Bucket | 내용 | 불변성 | 접근 |
|---|---|---|---|
| `saw-evidence-original` | 업로드 원본 (압축 상태 그대로) | **Object Lock (Governance)**, 보존기간 설정 | ingest worker(read), api(write via multipart) |
| `saw-evidence-extracted` | 안전하게 해제된 파일 | 일반 | parse/pcap worker |
| `saw-artifacts` | Zeek logs, eve.json, capinfos, 통계 스냅샷, 생성 PCAP 조각 | 일반 | worker, api(read) |
| `saw-quarantine` | PCAP/파일 추출물 (악성 가능) | 일반, 별도 KMS 키 | file worker만. 다운로드는 암호 ZIP 변환 후 |
| `saw-exports` | 보고서, CSV, Case Export | 7일 lifecycle | api |
| `saw-knowledge-attach` | Case/Experience 첨부(스크린샷, 문서) | 버전관리 | api |
| `saw-backups` | PG dump, OpenSearch snapshot repo | 별도 위치 복제 | 운영 |

## 3. Key Layout

```
saw-evidence-original/{investigation_id}/{evidence_id}/{file_id}          # 원본 파일명은 키에 쓰지 않음
saw-evidence-extracted/{investigation_id}/{evidence_id}/{file_id}/{child_file_id}
saw-artifacts/{investigation_id}/{evidence_id}/{tool}/{tool_version}/{name}
saw-quarantine/{investigation_id}/{evidence_id}/{sha256}
saw-exports/{user_id}/{export_id}.{ext}
```

- **원본 파일명은 메타데이터(PG)에만** 저장 (sanitize 후 표시용). Path traversal·인코딩 공격 원천 차단.
- 객체 메타데이터: `x-amz-meta-sha256`, `uploaded-by`, `evidence-id`.

## 4. 무결성 / Chain of Custody

1. 업로드 중 서버측에서 스트리밍 SHA-256 계산 (클라이언트 제공 해시와 비교, 불일치 시 거부).
2. 저장 후 `evidence.file.sha256` 기록, `custody_log(upload)`.
3. Worker가 읽을 때 크기·해시 검증(대형 파일은 샘플링 + 주기적 전체 검증 배치).
4. 모든 다운로드/Export → `custody_log` + audit.
5. Evidence 상세 화면에 Custody Timeline 표시.

## 5. 암호화

- SSE (KMS 연동: MinIO KES 또는 기관 KMS/HSM). Quarantine은 별도 키.
- 디스크 레벨 암호화(LUKS) 병행.
- TLS로만 접근.

## 6. Lifecycle / 보존

| Bucket | 기본 보존 | 비고 |
|---|---|---|
| original | 1년 (설정) | Legal Hold 시 무기한, Object Lock으로 조기 삭제 방지 |
| extracted | 90일 | 원본에서 재생성 가능 |
| artifacts | Investigation 종료 + 180일 | |
| quarantine | 90일 | |
| exports | 7일 | |

삭제는 `scheduler`의 Retention Job이 수행하며 삭제 이력은 audit에 남는다.

## 7. 접근 패턴

- **Upload**: 브라우저 → api(Resumable chunk) → S3 Multipart Part 업로드 (api는 스트리밍 패스스루, 디스크 버퍼 없음) — [ADR-0013](adr/0013-resumable-upload-through-api.md)
- **Worker**: S3 → 로컬 scratch(tmpfs/NVMe, 작업 종료 시 삭제) → 도구 실행. PCAP 도구는 seekable 파일 필요.
- **Download(분석가)**: api가 권한·사유 확인 후 짧은 TTL(5분) presigned URL 또는 스트리밍 프록시. Quarantine 파일은 프록시만, 암호 ZIP(`infected`)으로.

## 8. MinIO 리스크 및 대안

| 리스크 | 대응 |
|---|---|
| AGPL-3.0 | 사내 전용·미수정 사용, 법무 확인 |
| 커뮤니티 에디션 정책 변경(관리 콘솔 축소, 배포 형태 변경 등 2025년 이후) | Phase 1에서 현행 정책 재확인, 소스 빌드/내부 미러 또는 대안 선택 |
| 대안 | SeaweedFS(Apache-2.0), Ceph RGW, 기관 보유 S3 호환 스토리지 |

`ObjectStorePort` 계약 테스트(contract test)를 MinIO·SeaweedFS 양쪽에서 실행하여 교체 가능성을 상시 검증한다.
