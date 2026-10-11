from __future__ import annotations

import re

_SCRIPT = re.compile(r"(?i)^(python-requests|python-httpx|python-urllib|aiohttp|curl|wget|go-http-client|"
                     r"java/|okhttp|apache-httpclient|libwww-perl|ruby|php|node-fetch|axios|postmanruntime|"
                     r"powershell|winhttp|httpie|insomnia|undici|reqwest)[/ ]?([\w.\-]*)")
_SCANNER = re.compile(r"(?i)(sqlmap|nikto|nmap|masscan|zgrab|nuclei|acunetix|nessus|openvas|wpscan|dirbuster|"
                      r"gobuster|ffuf|feroxbuster|burp|zap|w3af|arachni|qualys|censys|shodan|httpx - open-source)")
_BOT = re.compile(r"(?i)(bot|crawler|spider|slurp|bingpreview|facebookexternalhit|ahrefs|semrush)")
_MOBILE = re.compile(r"(?i)(android|iphone|ipad|mobile|okhttp/.*android|cfnetwork|dalvik)")
_BROWSER = re.compile(r"(?i)mozilla/5\.0 .*(chrome|firefox|safari|edg|opr)/")


def classify_ua(ua: str | None) -> dict:
    if not ua or not ua.strip() or ua.strip() == "-":
        return {"class": "empty", "family": None, "version": None}
    u = ua.strip()
    m = _SCANNER.search(u)
    if m:
        return {"class": "scanner", "family": m.group(1).lower(), "version": None}
    m = _SCRIPT.match(u)
    if m:
        return {"class": "script", "family": m.group(1).lower().rstrip("/"), "version": m.group(2) or None}
    if _BOT.search(u):
        return {"class": "bot", "family": None, "version": None}
    if _BROWSER.search(u):
        return {"class": "mobile" if _MOBILE.search(u) else "browser", "family": None, "version": None}
    if _MOBILE.search(u):
        return {"class": "mobile_app", "family": None, "version": None}
    return {"class": "unknown", "family": None, "version": None}
