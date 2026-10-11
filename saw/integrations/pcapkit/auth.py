"""Cleartext authentication in captured sessions: FTP, POP3, IMAP, SMTP AUTH, HTTP Basic and HTML form logins.

Passwords are NEVER stored or logged. Each attempt keeps: protocol, user name, outcome (success / failure /
unknown), and password properties only (length, empty, equals user name, in the weak/default list). That is
enough for "credentials exposed", "weak password accepted" and brute-force findings without retaining secrets.
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl

WEAK = {"", "password", "passw0rd", "p@ssw0rd", "123456", "12345678", "123456789", "1234", "12345", "qwerty", "admin",
        "admin123", "root", "toor", "test", "guest", "default", "changeme", "letmein", "welcome", "1q2w3e4r", "111111",
        "000000", "abc123", "iloveyou", "master", "tomcat", "s3cret", "manager", "oracle", "postgres", "sa", "user",
        "anonymous", "ftp", "pass", "secret", "administrator", "1q2w3e", "qwer1234", "zaq12wsx"}
PW_FIELDS = re.compile(r"(?i)^(pass(word|wd)?|pwd|passcode|user_?pass|login_?pass|j_password|txtpwd|userpw|pw)$")
USER_FIELDS = re.compile(r"(?i)^(user(name|_?id)?|login(_?id)?|uid|email|account|j_username|id|txtid|userid|usr)$")


@dataclass
class AuthAttempt:
    ts: float
    protocol: str
    user: str | None
    outcome: str  # success | failure | unknown
    pw_len: int
    pw_weak: bool
    pw_equals_user: bool
    detail: str = ""

    def record(self) -> dict:
        return {"ts": self.ts, "protocol": self.protocol, "user": (self.user or "")[:128] or None, "outcome": self.outcome,
                "password_present": True, "password_length": self.pw_len, "password_weak": self.pw_weak,
                "password_equals_user": self.pw_equals_user, "detail": self.detail[:200] or None}


def _attempt(ts: float, proto: str, user: str | None, pw: str, outcome: str = "unknown", detail: str = "") -> AuthAttempt:
    same = bool(user) and pw.lower() == (user or "").lower()
    return AuthAttempt(ts, proto, user, outcome, len(pw), pw.lower() in WEAK or len(pw) < 4 or same, same, detail)


def _merge(client: list[tuple[float, str]], server: list[tuple[float, str]]) -> list[tuple[float, str, str]]:
    ev = [(t, 0, "c", s) for t, s in client] + [(t, 1, "s", s) for t, s in server]
    ev.sort(key=lambda x: (x[0], x[1]))
    return [(t, d, s) for t, _, d, s in ev]


def _b64(s: str) -> str:
    try:
        return base64.b64decode(s.strip() + "=" * (-len(s.strip()) % 4), validate=False).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return ""


def parse_line_protocol(service: str, client: list[tuple[float, str]], server: list[tuple[float, str]]) -> list[AuthAttempt]:
    """FTP / POP3 / IMAP / SMTP command-response dialogues."""
    out: list[AuthAttempt] = []
    user, pending, smtp_state = None, None, None
    for ts, d, line in _merge(client, server):
        if d == "c":
            up = line.upper()
            if service in ("ftp", "pop3") and up.startswith("USER "):
                user = line[5:].strip()
            elif service in ("ftp", "pop3") and up.startswith("PASS "):
                pending = _attempt(ts, service, user, line[5:])
            elif service == "imap":
                m = re.match(r'(?i)^(\S+)\s+LOGIN\s+("?)([^"\s]*)\2\s+("?)(.*?)\4\s*$', line)
                if m:
                    pending = _attempt(ts, service, m.group(3), m.group(5), detail=m.group(1))
            elif service == "smtp":
                if up.startswith("AUTH PLAIN"):
                    arg = line[10:].strip()
                    if arg:
                        parts = _b64(arg).split("\x00")
                        if len(parts) >= 3:
                            pending = _attempt(ts, service, parts[1] or parts[0], parts[2])
                    else:
                        smtp_state = "plain"
                elif up.startswith("AUTH LOGIN"):
                    arg = line[10:].strip()
                    smtp_state, user = ("login_pw", _b64(arg)) if arg else ("login_user", None)
                elif smtp_state == "plain" and line.strip():
                    parts = _b64(line).split("\x00")
                    if len(parts) >= 3:
                        pending = _attempt(ts, service, parts[1] or parts[0], parts[2])
                    smtp_state = None
                elif smtp_state == "login_user" and line.strip():
                    user, smtp_state = _b64(line), "login_pw"
                elif smtp_state == "login_pw" and line.strip():
                    pending, smtp_state = _attempt(ts, service, user, _b64(line)), None
        elif pending is not None:
            code = line[:3]
            if service == "ftp" and code.isdigit() and code[0] in "2345" and code not in ("331", "332"):
                pending.outcome = "success" if code in ("230", "202") else "failure" if code[0] in "45" else "unknown"
            elif service == "pop3" and line[:3] in ("+OK", "-ER"):
                pending.outcome = "success" if line.startswith("+OK") else "failure"
            elif service == "imap" and line.split(" ", 2)[0] == pending.detail:
                tok = (line.split(" ", 2) + ["", ""])[1].upper()
                pending.outcome = "success" if tok == "OK" else "failure" if tok in ("NO", "BAD") else "unknown"
            elif service == "smtp" and code in ("235", "535", "534", "454", "530"):
                pending.outcome = "success" if code == "235" else "failure"
            else:
                continue
            out.append(pending)
            pending = None
    if pending is not None:
        out.append(pending)
    return out[:2000]


def http_basic(ts: float, authorization: str | None, status: int | None) -> AuthAttempt | None:
    if not authorization or not authorization.lower().startswith("basic "):
        return None
    dec = _b64(authorization[6:])
    if ":" not in dec:
        return None
    user, pw = dec.split(":", 1)
    outcome = "unknown" if status is None else "failure" if status in (401, 403) else "success" if status < 400 else "unknown"
    return _attempt(ts, "http_basic", user, pw, outcome)


def http_form(ts: float, method: str, ctype: str | None, body: bytes, status: int | None, location: str | None) -> AuthAttempt | None:
    if method != "POST" or not body or "application/x-www-form-urlencoded" not in (ctype or "").lower():
        return None
    try:
        fields = parse_qsl(body[:8192].decode("utf-8", "replace"), keep_blank_values=True)
    except ValueError:
        return None
    pw = next((v for k, v in fields if PW_FIELDS.match(k)), None)
    if pw is None:
        return None
    user = next((v for k, v in fields if USER_FIELDS.match(k)), None)
    # form logins rarely signal outcome by status; a redirect away from a login page is a weak success hint
    if status in (401, 403):
        outcome = "failure"
    elif status in (301, 302, 303) and location and "login" not in location.lower():
        outcome = "success"
    else:
        outcome = "unknown"
    return _attempt(ts, "http_form", user, pw, outcome)
