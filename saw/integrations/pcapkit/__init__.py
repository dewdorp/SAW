"""Built-in PCAP analyzer (pure Python, stdlib only) for hosts without Zeek — e.g. Windows servers (ADR-0016).

PCAP/PCAPNG → flows → Zeek-compatible JSON records (conn, dns, http, ssl incl. JA3/JA4), so uploaded PCAPs go through
the same Zeek parser, detectors and ATT&CK mappings as Zeek output. Packet bytes are untrusted: every decoder is
bounds-checked and failures skip the packet, never the file.
"""
from saw.integrations.pcapkit.analyzer import PRODUCER, analyze_pcap

__all__ = ["PRODUCER", "analyze_pcap"]
