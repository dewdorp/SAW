# Offline enrichment data

**현재 파일은 개발·데모용 FIXTURE이며 권위 있는 데이터가 아니다** (`FIXTURE` 마커 존재 시 UI에 source=fixture 표시).
운영 시 라이선스가 확보된 ASN/Geo DB와 클라우드 사업자 공개 IP 대역 JSON을 변환해 같은 형식으로 교체한다 (ENV-14).

- `asn_ranges.csv`: start_ip,end_ip,asn,as_org,country
- `cloud_ranges.csv`: cidr,provider (aws|gcp|azure|oci|vps:<name>)
- `tor_exits.txt`: IP per line
