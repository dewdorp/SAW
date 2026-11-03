"""Synthetic English-header NDR HTTP and firewall exports for the four investigation questions.

Documentation/private addresses and *.example.test hosts only. Each case pairs a suspicious variant with a
normal or ambiguous one; the case count says nothing about detection accuracy.
"""
from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone

NDR = ["event_time", "_site", "app", "_schema", "protocol", "src_ip", "src_port", "src_country", "dest_ip", "dest_port",
       "dest_country", "_device_ip", "_device_name", "method", "host", "path", "query", "user_agent", "referer",
       "req_cookie", "uuid", "status", "sc_bytes", "cs_bytes"]
FW = ["_time", "_device_ip", "_device_name", "action", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
      "tcp_flag", "duration", "sent_bytes", "rcvd_bytes"]
KST = timezone(timedelta(hours=9))
BASE = datetime(2026, 10, 13, 9, 0, tzinfo=KST)


def _csv(headers, rows):
    out = io.StringIO(newline="")
    w = csv.writer(out, lineterminator="\r\n")
    w.writerow(headers)
    for r in rows:
        w.writerow([r.get(h, "") for h in headers])
    return out.getvalue().encode("utf-8")


def _ndr(i, when, src, dst, path, query="", status="200", sc=2048, cs=400, ua="Mozilla/5.0 synthetic", method="GET"):
    return {"event_time": when.isoformat(), "_site": "site-a", "app": "HTTP", "_schema": "ndr-http-1", "protocol": "TCP",
            "src_ip": src, "src_port": str(40000 + i % 20000), "src_country": "", "dest_ip": dst, "dest_port": "443",
            "dest_country": "", "_device_ip": "192.0.2.2", "_device_name": "ndr-01", "method": method,
            "host": "portal.example.test", "path": path, "query": query, "user_agent": ua, "referer": "",
            "req_cookie": f"sid=s{i % 7}", "uuid": f"u-{i:06d}", "status": status, "sc_bytes": str(sc), "cs_bytes": str(cs)}


def _fw(i, when, src, dst, port, action="allow", sent=600, rcvd=1800, duration=30):
    return {"_time": when.strftime("%Y-%m-%d %H:%M:%S"), "_device_ip": "192.0.2.1", "_device_name": "fw-01",
            "action": action, "src_ip": src, "src_port": str(50000 + i % 10000), "dst_ip": dst, "dst_port": str(port),
            "protocol": "TCP", "tcp_flag": "SA", "duration": str(duration), "sent_bytes": str(sent), "rcvd_bytes": str(rcvd)}


def ndr_csv(case: str) -> bytes:
    rows = []
    if case == "web_probe":  # many paths and injection-shaped queries from one external source
        for i in range(45):
            q = "id=1%20UNION%20SELECT%20NULL,NULL" if i % 9 == 0 else ""
            rows.append(_ndr(i, BASE + timedelta(seconds=5 * i), "198.51.100.23", "10.20.1.10", f"/probe/p{i}", q,
                             status="404" if i % 3 else "200", ua="python-requests/2.31"))
    elif case == "web_normal":  # ordinary browsing of a handful of pages
        for i in range(30):
            rows.append(_ndr(i, BASE + timedelta(minutes=7 * i), f"203.0.113.{10 + i % 5}", "10.20.1.10",
                             ["/", "/notice", "/product/view", "/contact"][i % 4], "page=1" if i % 2 else ""))
    elif case == "large_response_out":  # internal server sending large responses to one external client
        for i in range(12):
            rows.append(_ndr(i, BASE + timedelta(minutes=i), "198.51.100.50", "10.20.1.10", "/export/report",
                             f"part={i}", sc=8 * 1024 ** 2))
    elif case == "download_in":  # internal client receiving a large file from an external server
        for i in range(10):
            rows.append(_ndr(i, BASE + timedelta(minutes=i), "10.20.5.11", "203.0.113.66", "/files/update.bin", "",
                             sc=9 * 1024 ** 2))
    elif case == "upload_out":  # internal client sending large requests to an external server (no large response)
        for i in range(10):
            rows.append(_ndr(i, BASE + timedelta(minutes=i), "10.20.5.12", "203.0.113.67", "/upload", "",
                             method="POST", sc=900, cs=9 * 1024 ** 2))
    elif case == "no_bytes":  # HTTP records without byte counts: the transfer question cannot be answered
        for i in range(10):
            r = _ndr(i, BASE + timedelta(minutes=i), "203.0.113.20", "10.20.1.10", "/", "")
            r["sc_bytes"] = r["cs_bytes"] = ""
            rows.append(r)
    else:
        raise ValueError(case)
    return _csv(NDR, rows)


def fw_csv(case: str) -> bytes:
    rows = []
    if case == "periodic":  # one internal host reaching one external address every 300 seconds
        rows = [_fw(i, BASE + timedelta(seconds=300 * i), "10.20.5.13", "203.0.113.66", 443) for i in range(12)]
    elif case == "irregular":  # same pair at irregular times: no periodic item expected
        gaps = [0, 40, 900, 1000, 2600, 2700, 5000, 9000, 9100, 15000, 15500, 20000]
        rows = [_fw(i, BASE + timedelta(seconds=g), "10.20.5.13", "203.0.113.66", 443) for i, g in enumerate(gaps)]
    elif case == "spread":  # one internal source touching many hosts and admin ports
        rows = [_fw(i, BASE + timedelta(seconds=2 * i), "10.20.5.99", f"10.20.1.{1 + i % 15}", [22, 445, 3389, 5985][i % 4],
                    action="deny" if i % 3 == 0 else "allow") for i in range(60)]
    elif case == "few_targets":  # an admin host reaching two servers: below the spread threshold
        rows = [_fw(i, BASE + timedelta(minutes=i), "10.20.5.7", f"10.20.1.{1 + i % 2}", 22) for i in range(20)]
    elif case == "spread_slow":  # twelve hosts over six hours: many targets in the period, few in any 10 minutes
        rows = [_fw(i, BASE + timedelta(minutes=30 * i), "10.20.5.98", f"10.20.2.{1 + i}", 445) for i in range(12)]
    elif case == "spread_ports_late":  # nine hosts on one port, then later three hosts on six ports
        rows = [_fw(i, BASE + timedelta(seconds=20 * i), "10.20.5.97", f"10.20.3.{1 + i}", 445) for i in range(9)]
        rows += [_fw(9 + j, BASE + timedelta(hours=2, seconds=20 * j), "10.20.5.97", f"10.20.4.{1 + j % 3}",
                     [22, 23, 80, 135, 139, 3389][j]) for j in range(6)]
    elif case == "pair_large":  # the firewall's record of the same pair as the NDR large responses, other layer
        rows = [_fw(i, BASE + timedelta(minutes=i), "198.51.100.50", "10.20.1.10", 443, sent=600, rcvd=40 * 1024 ** 2)
                for i in range(3)]
    else:
        raise ValueError(case)
    return _csv(FW, rows)


# Expected outcome per question (A web, B transfer, C periodic, D spread) for each synthetic case.
EXPECTED = {
    ("ndr", "web_probe"): {"web_attack": "found"},
    ("ndr", "web_normal"): {"web_attack": "looked_none"},
    ("ndr", "large_response_out"): {"transfer": "found"},
    ("ndr", "download_in"): {"transfer": "found"},
    ("ndr", "no_bytes"): {"transfer": "insufficient_data"},
    ("fw", "periodic"): {"periodic": "found"},
    ("fw", "irregular"): {"periodic": "looked_none"},
    ("fw", "spread"): {"spread": "found"},
    ("fw", "few_targets"): {"spread": "looked_none"},
}
