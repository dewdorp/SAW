"""ATT&CK Enterprise catalog used by the conditional detector mappings (docs/34).

Primary source: data/mitre/enterprise-attack.compact.json, built from the official MITRE STIX bundle by
saw.attack.stix_import (provenance + SHA-256 inside; license in data/mitre/ATTACK-LICENSE.txt). The small built-in
subset below is only a fallback when that file is missing. The version is recorded on every mapping.
"""
from __future__ import annotations

import json
from pathlib import Path

_COMPACT = Path(__file__).resolve().parents[2] / "data" / "mitre" / "enterprise-attack.compact.json"
ATTACK_VERSION = "18.1-subset"
CATALOG_SOURCE: dict = {"kind": "builtin-subset"}

TACTICS = [
    ("TA0043", "reconnaissance", "Reconnaissance"),
    ("TA0042", "resource-development", "Resource Development"),
    ("TA0001", "initial-access", "Initial Access"),
    ("TA0002", "execution", "Execution"),
    ("TA0003", "persistence", "Persistence"),
    ("TA0004", "privilege-escalation", "Privilege Escalation"),
    ("TA0005", "defense-evasion", "Defense Evasion"),
    ("TA0006", "credential-access", "Credential Access"),
    ("TA0007", "discovery", "Discovery"),
    ("TA0008", "lateral-movement", "Lateral Movement"),
    ("TA0009", "collection", "Collection"),
    ("TA0011", "command-and-control", "Command and Control"),
    ("TA0010", "exfiltration", "Exfiltration"),
    ("TA0040", "impact", "Impact"),
]

TECHNIQUES: dict[str, dict] = {
    "T1595.001": {"name": "Active Scanning: Scanning IP Blocks", "tactics": ["reconnaissance"]},
    "T1595.002": {"name": "Active Scanning: Vulnerability Scanning", "tactics": ["reconnaissance"]},
    "T1595.003": {"name": "Active Scanning: Wordlist Scanning", "tactics": ["reconnaissance"]},
    "T1190": {"name": "Exploit Public-Facing Application", "tactics": ["initial-access"]},
    "T1078": {"name": "Valid Accounts", "tactics": ["initial-access", "persistence", "privilege-escalation",
                                                    "defense-evasion"]},
    "T1110.001": {"name": "Brute Force: Password Guessing", "tactics": ["credential-access"]},
    "T1110.003": {"name": "Brute Force: Password Spraying", "tactics": ["credential-access"]},
    "T1110.004": {"name": "Brute Force: Credential Stuffing", "tactics": ["credential-access"]},
    "T1046": {"name": "Network Service Discovery", "tactics": ["discovery"]},
    "T1083": {"name": "File and Directory Discovery", "tactics": ["discovery"]},
    "T1213": {"name": "Data from Information Repositories", "tactics": ["collection"]},
    "T1505.003": {"name": "Server Software Component: Web Shell", "tactics": ["persistence"]},
    "T1059.004": {"name": "Command and Scripting Interpreter: Unix Shell", "tactics": ["execution"]},
    "T1059.001": {"name": "Command and Scripting Interpreter: PowerShell", "tactics": ["execution"]},
    "T1071.001": {"name": "Application Layer Protocol: Web Protocols", "tactics": ["command-and-control"]},
    "T1071.004": {"name": "Application Layer Protocol: DNS", "tactics": ["command-and-control"]},
    "T1572": {"name": "Protocol Tunneling", "tactics": ["command-and-control"]},
    "T1571": {"name": "Non-Standard Port", "tactics": ["command-and-control"]},
    "T1105": {"name": "Ingress Tool Transfer", "tactics": ["command-and-control"]},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactics": ["exfiltration"]},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactics": ["exfiltration"]},
    "T1071": {"name": "Application Layer Protocol", "tactics": ["command-and-control"]},
    "T1499": {"name": "Endpoint Denial of Service", "tactics": ["impact"]},
    "T1189": {"name": "Drive-by Compromise", "tactics": ["initial-access"]},
}

if _COMPACT.is_file():  # full catalog (adopted from the Codex comparison)
    _c = json.loads(_COMPACT.read_text(encoding="utf-8"))
    ATTACK_VERSION = _c["attack_version"]
    TACTICS = [tuple(x) for x in _c["tactics"]]
    TECHNIQUES = _c["techniques"]
    CATALOG_SOURCE = {"kind": "official-stix", "source": _c["source"], "source_sha256": _c["source_sha256"],
                      "techniques": len(TECHNIQUES)}

# Co-occurrence hints used by the local "inferred techniques" fallback when TIE is unavailable (ENV-17).
# Each entry: observed -> [(technique, weight)]. Derived from common web-intrusion progressions; NOT TIE output.
COOCCURRENCE: dict[str, list[tuple[str, float]]] = {
    "T1595.003": [("T1190", 0.45), ("T1083", 0.3)],
    "T1190": [("T1505.003", 0.41), ("T1059.004", 0.29), ("T1083", 0.33)],
    "T1110.004": [("T1078", 0.52), ("T1213", 0.2)],
    "T1110.001": [("T1078", 0.48)],
    "T1078": [("T1213", 0.35), ("T1083", 0.25)],
    "T1213": [("T1041", 0.3), ("T1048", 0.2)],
    "T1071.001": [("T1041", 0.38), ("T1059.001", 0.2)],
    "T1071.004": [("T1572", 0.4), ("T1048", 0.25)],
    "T1046": [("T1078", 0.2), ("T1190", 0.25)],
}

# Data components needed to confirm a technique (subset, v18 naming style)
DATA_NEEDS: dict[str, list[str]] = {
    "T1505.003": ["File: File Creation", "Process: Process Creation"],
    "T1083": ["Process: Process Creation", "Command: Command Execution"],
    "T1059.004": ["Process: Process Creation", "Command: Command Execution"],
    "T1059.001": ["Process: Process Creation", "Script: Script Execution"],
    "T1078": ["Logon Session: Logon Session Creation", "User Account: User Account Authentication"],
    "T1213": ["Application Log: Application Log Content"],
    "T1041": ["Network Traffic: Network Traffic Flow"],
    "T1048": ["Network Traffic: Network Traffic Flow"],
    "T1572": ["Network Traffic: Network Traffic Content"],
    "T1190": ["Application Log: Application Log Content", "Network Traffic: Network Traffic Content"],
}
# Which SAW data_sources provide each data component (for "보유 여부")
COMPONENT_SOURCES: dict[str, set[str]] = {
    "Application Log: Application Log Content": {"web", "waf"},
    "Network Traffic: Network Traffic Flow": {"zeek_conn", "firewall", "suricata"},
    "Network Traffic: Network Traffic Content": {"zeek_http", "zeek_ssl", "zeek_dns", "suricata", "waf"},
    "Logon Session: Logon Session Creation": {"windows", "linux", "vpn"},
    "User Account: User Account Authentication": {"windows", "linux", "vpn", "web"},
    "File: File Creation": {"edr", "windows"},
    "Process: Process Creation": {"edr", "windows"},
    "Command: Command Execution": {"edr", "linux"},
    # SAW data_source names are used verbatim (zeek_conn, zeek_dns, …) — keep this map in sync with parsers/network.py
    "Script: Script Execution": {"edr", "windows"},
}


def technique(tid: str) -> dict:
    t = TECHNIQUES.get(tid, {"name": tid, "tactics": []})
    return {"technique_id": tid, "name": t["name"], "tactics": t["tactics"], "url": t.get("url"),
            "summary": t.get("summary")}
