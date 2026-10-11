"""Write the synthetic demo scenario as files you can drag into the UI: `python -m saw.devtools.export_samples [outdir]`.

All data is synthetic (FIXTURE enrichment ranges, example.com hosts). Payload samples are inert text for the
Payload/HTTP analyzers — SAW never executes or fetches anything from them.
"""
from __future__ import annotations

import hashlib
import io
import sys
import zipfile
from pathlib import Path

from saw.devtools.sample_data import (
    PE_SAMPLE,
    gz_bytes,
    scenario_kr_firewall_csv,
    scenario_ndr_meta_csv,
    scenario_pcap,
    scenario_pcap_forensics,
    scenario_tls_certs,
    scenario_waf_jsonl,
    scenario_weblog,
    scenario_zeek,
)

QUICK = {
    "05_ioc_list.txt": """# 위협 인텔 공유 메일에서 받은 IOC 목록(가정) — 붙여넣기로 분석
43.201.88.10
185.220.100.5
104.248.11.20
hxxps://login-update[.]suspicious-example[.]com/verify?id=10023
a3f5c2d1e4b6a7980c1d2e3f4a5b6c7d8e9f00112233445566778899aabbccdd
admin@suspicious-example.com
CVE-2021-44228
""",
    "06_http_request.txt": """GET /api/customer?id=10423 HTTP/1.1
Host: service.example.com
User-Agent: python-httpx/0.27
Accept: */*
X-Forwarded-For: 43.201.12.77
Cookie: SESSION=REDACTED
Connection: close
""",
    "07_payload_encoded.txt": "id=1%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--%20&file=..%2F..%2F..%2Fetc%2Fpasswd\n",
    "08_diff_a.txt": "GET /api/customer?id=10001 HTTP/1.1\nHost: service.example.com\nUser-Agent: BankApp/5.2.1\nAuthorization: Bearer REDACTED\n",
    "08_diff_b.txt": "GET /api/customer?id=10002 HTTP/1.1\nHost: service.example.com\nUser-Agent: python-httpx/0.27\nX-Original-URL: /admin\n",
}


def main() -> None:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "samples")
    out.mkdir(parents=True, exist_ok=True)
    (out / "01_access.log.gz").write_bytes(gz_bytes(scenario_weblog()))
    (out / "02_waf_events.jsonl").write_text("\n".join(scenario_waf_jsonl()) + "\n", encoding="utf-8")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, lines in scenario_zeek().items():
            z.writestr(name, "\n".join(lines) + "\n")
    (out / "03_capture_zeek_suricata.zip").write_bytes(buf.getvalue())
    (out / "04_access_sample.log").write_text("\n".join(scenario_weblog(seed=11, normal=300, enum_count=150)) + "\n",
                                               encoding="utf-8")
    (out / "09_capture.pcap").write_bytes(scenario_pcap())  # raw PCAP for the built-in analyzer (ADR-0016)
    (out / "10_incident.pcap").write_bytes(scenario_pcap_forensics())  # forensic story: SQLi, web shell, malware, FTP…
    ioc_lines = ["# 공유 IOC 목록(합성) - 종류 'IOC 목록'으로 업로드", "203[.]0[.]113[.]66", hashlib.sha256(PE_SAMPLE).hexdigest(), ""]
    (out / "11_ioc_list.txt").write_text("\n".join(ioc_lines), encoding="utf-8")
    (out / "12_ndr_meta.csv").write_text(scenario_ndr_meta_csv(), encoding="utf-8-sig")  # NDR meta-search export
    (out / "13_firewall_kr.csv").write_bytes(scenario_kr_firewall_csv())  # Korean headers, CP949 (Excel)
    (out / "14_tls_certs.pcap").write_bytes(scenario_tls_certs())  # TLS 1.2 server certificates (one suspicious)
    for name, text in QUICK.items():
        (out / name).write_text(text, encoding="utf-8")
    for f in sorted(out.iterdir()):
        print(f"{f.name:32} {f.stat().st_size:>9,} bytes")


if __name__ == "__main__":
    main()
