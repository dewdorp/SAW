"""PCAP forensic engine v2: reassembly, HTTP bodies, file extraction, cleartext auth, FTP data, ARP, duplicates.

Feature scope modelled on pcap-forensics-analyzer (reference only; no code reused — that repository has no license).
"""
from __future__ import annotations

import gzip
import hashlib

import orjson

from saw.devtools import pcap_writer as pw
from saw.integrations.pcapkit import analyze_pcap

T = 1_760_000_000.0
PE = b"MZ" + b"\x90" * 58 + (0x40).to_bytes(4, "little") + b"PE\x00\x00" + b"\x00" * 200
SECRET_PWS = ["Hunter2!", "winter2026", "Sup3rS3cret!"]


def _run(tmp_path, w: pw.PcapWriter):
    src = tmp_path / "c.pcap"
    w.save(src)
    out = tmp_path / "out"
    summary = analyze_pcap(src, out)
    logs = {f.stem: [orjson.loads(x) for x in f.read_bytes().splitlines()] for f in out.glob("*.log")}
    return summary, logs, out


def test_out_of_order_reassembly_and_chunked_gzip(tmp_path):
    w = pw.PcapWriter()
    c, s = ("10.0.0.5", 50000), ("203.0.113.9", 80)
    w.tcp(T, *c, *s, pw.SYN)
    w.tcp(T + 0.01, *s, *c, pw.SYN | pw.ACK)
    w.tcp(T + 0.02, *c, *s, pw.ACK)
    req = b"GET /index.html HTTP/1.1\r\nHost: shop.example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    base = 1001  # client ISN 1000 + SYN
    w.tcp_at(T + 0.04, *c, *s, pw.PSH | pw.ACK, req[20:], base + 20)   # second half first
    w.tcp_at(T + 0.05, *c, *s, pw.PSH | pw.ACK, req[:20], base)        # then the first half
    w.tcp_at(T + 0.06, *c, *s, pw.PSH | pw.ACK, req[:20], base)        # retransmission
    page = b"<html><body>" + b"A" * 3000 + b"</body></html>"
    gz = gzip.compress(page)
    chunked = b"".join(b"%x\r\n" % len(gz[i:i + 500]) + gz[i:i + 500] + b"\r\n" for i in range(0, len(gz), 500)) + b"0\r\n\r\n"
    resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n"
            + chunked)
    w.tcp(T + 0.08, *s, *c, pw.PSH | pw.ACK, resp)
    w.tcp(T + 0.1, *c, *s, pw.FIN | pw.ACK)
    w.tcp(T + 0.11, *s, *c, pw.FIN | pw.ACK)
    _, logs, out = _run(tmp_path, w)
    h = logs["http"][0]
    assert h["uri"] == "/index.html" and h["status_code"] == 200 and h["response_body_len"] == len(page)
    f = logs["files"][0]
    assert f["sha256"] == hashlib.sha256(page).hexdigest() and f["kind"] == "html"
    assert (out / "files" / f["sha256"]).read_bytes() == page


def test_masquerading_executable_is_extracted_with_hashes(tmp_path):
    w = pw.PcapWriter()
    w.tcp_session(T, "10.0.0.7", 50100, "198.51.100.20", 80,
                  [(pw.http_get("cdn.example.net", "/img/logo.jpg", "Mozilla/5.0"), pw.http_resp(200, PE, "image/jpeg"))])
    _, logs, out = _run(tmp_path, w)
    f = logs["files"][0]
    assert f["kind"] == "pe" and f["category"] == "executable" and f["declared_category"] == "image"
    assert f["masquerade"] is True and f["filename"] == "logo.jpg"
    assert f["md5"] == hashlib.md5(PE).hexdigest() and f["sha1"] == hashlib.sha1(PE).hexdigest()
    assert (out / "files" / f["sha256"]).exists() and f["extracted"] is True


def test_ftp_bruteforce_success_and_data_channel_file(tmp_path):
    w = pw.PcapWriter()
    c, s = ("10.0.0.9", 51000), ("192.0.2.21", 21)
    lines = [(None, b"220 FTP ready\r\n")]
    for pw_ in ("123456", "admin", "password"):
        lines += [(b"USER admin\r\n", b"331 Password required\r\n"), (b"PASS " + pw_.encode() + b"\r\n", b"530 Login incorrect\r\n")]
    lines += [(b"USER admin\r\n", b"331 Password required\r\n"), (f"PASS {SECRET_PWS[0]}\r\n".encode(), b"230 Logged in\r\n"),
              (b"PASV\r\n", b"227 Entering Passive Mode (192,0,2,21,195,80)\r\n"),
              (b"RETR customers.zip\r\n", b"150 Opening data connection\r\n")]
    t = w.tcp_session(T, *c, *s, [(q or b"", r) for q, r in lines], close="none")
    zipdata = b"PK\x03\x04" + b"\x00" * 26 + b"customers.csv" + b"x" * 5000
    w.tcp_session(t + 0.1, "10.0.0.9", 51001, "192.0.2.21", 195 * 256 + 80, [(b"", zipdata)])
    w.tcp(t + 1, *s, *c, pw.PSH | pw.ACK, b"226 Transfer complete\r\n")
    _, logs, _ = _run(tmp_path, w)
    auths = [a for a in logs["saw_auth"] if a["protocol"] == "ftp"]
    assert [a["outcome"] for a in auths] == ["failure", "failure", "failure", "success"]
    assert all(a["user"] == "admin" for a in auths) and auths[0]["password_weak"] and not auths[3]["password_weak"]
    files = [f for f in logs["files"] if f["source"] == "FTP_DATA"]
    assert files and files[0]["filename"] == "customers.zip" and files[0]["kind"] == "zip"
    assert files[0]["ftp_command"] == "RETR"


def test_smtp_http_basic_and_form_logins_never_store_passwords(tmp_path):
    import base64

    w = pw.PcapWriter()
    b64 = lambda s: base64.b64encode(s.encode())  # noqa: E731
    w.tcp_session(T, "10.0.0.11", 52000, "192.0.2.25", 25,
                  [(b"", b"220 mail.example.com ESMTP\r\n"), (b"EHLO x\r\n", b"250 ok\r\n"),
                   (b"AUTH LOGIN\r\n", b"334 VXNlcm5hbWU6\r\n"), (b64("alice") + b"\r\n", b"334 UGFzc3dvcmQ6\r\n"),
                   (b64(SECRET_PWS[1]) + b"\r\n", b"235 Authentication successful\r\n")])
    basic = b"GET /admin HTTP/1.1\r\nHost: intranet\r\nAuthorization: Basic " + b64("bob:" + SECRET_PWS[2]) + b"\r\n\r\n"
    w.tcp_session(T + 1, "10.0.0.12", 52001, "192.0.2.80", 80, [(basic, pw.http_resp(401, b"no", "text/plain")),
                                                                 (basic, pw.http_resp(200, b"ok", "text/plain"))])
    form = (b"POST /login HTTP/1.1\r\nHost: shop\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 29\r\n\r\n"
            b"username=carol&password=admin")
    w.tcp_session(T + 2, "10.0.0.13", 52002, "192.0.2.80", 80,
                  [(form, b"HTTP/1.1 302 Found\r\nLocation: /home\r\nContent-Length: 0\r\n\r\n")])
    _, logs, out = _run(tmp_path, w)
    by = {(a["protocol"], a["outcome"]) for a in logs["saw_auth"]}
    assert {("smtp", "success"), ("http_basic", "failure"), ("http_basic", "success"), ("http_form", "success")} <= by
    weak = next(a for a in logs["saw_auth"] if a["protocol"] == "http_form")
    assert weak["user"] == "carol" and weak["password_weak"] is True
    post = next(h for h in logs["http"] if h["method"] == "POST")
    assert "password=admin" not in post["request_body_preview"] and "password=●●●●" in post["request_body_preview"]
    blob = b"".join(p.read_bytes() for p in out.glob("*.log"))
    for secret in SECRET_PWS + ["password=admin"]:
        assert secret.encode() not in blob, f"secret leaked into analyzer output: {secret}"


def test_arp_spoofing_and_duplicate_frames(tmp_path):
    w = pw.PcapWriter()
    w.arp(T, 2, "00:11:22:33:44:55", "10.0.0.1", "aa:aa:aa:aa:aa:01", "10.0.0.50")
    w.arp(T + 1, 2, "66:66:66:66:66:66", "10.0.0.1", "aa:aa:aa:aa:aa:01", "10.0.0.50")  # same gateway IP, new MAC
    w.duplicate_last(2)
    summary, logs, _ = _run(tmp_path, w)
    gw = [r for r in logs["saw_arp"] if r["ip"] == "10.0.0.1"]
    assert len(gw) == 2 and all(r["macs_for_ip"] == 2 for r in gw)
    assert summary["duplicates"] == 2
