# 05. PCAP Analysis Overview

| 항목 | 내용 |
|---|---|
| Purpose | Wireshark 없이 “누가, 누구와, 무엇을, 얼마나” 통신했는지 그림으로 이해 |
| Primary User Action | Network Story에서 의심 엣지 확인 → Finding → Connections/DNS/TLS 탭 Drill-down |
| Layout | Summary Bar → (좌) Visual Network Story / (우) Important Findings + Interesting Connections → 하단 분포 차트 |
| Main Components | Capture Summary, Network Story Graph, Protocol Distribution, Top Talkers/Destinations/Domains, Findings List, Interesting Connections |
| Visualization | 호스트 중심 방사형 그래프(엣지=프로토콜·바이트·주기성), Protocol bar, Top-N H-bar, Interval histogram(주기성 Finding 선택 시) |
| Drill-down Flow | 엣지 → Connections 탭(해당 쌍) → 세션 행 → Drawer(zeek conn + suricata alerts) → [Extract PCAP]/[Open in Arkime(6b)] |
| Context Panel | 내부 호스트의 Asset Context, 외부 IP/도메인 Internal Context, Similar |
| Raw Data Access | Raw Sessions 탭, zeek/eve 원본 라인, 세션 PCAP 추출(감사) |

```
PCAP ANALYSIS  capture-0105.pcapng 6.3GB · 48m · Packets 9.1M · Conns 48,221 · Hosts 1,204 · Domains 3,880 · weird 112
Tabs: Overview│Findings│Connections│DNS│HTTP│TLS│Files│Alerts│Timeline│Relations│Raw Sessions
┌ VISUAL NETWORK STORY ─────────────────────────────────────────┬ IMPORTANT FINDINGS ─────────────────────┐
│                       ┌──── TLS 3.2GB · 41m · JA4 rare ──▶ 185.x│ ▲ Potential Large Outbound   3.2 GB     │
│  [10.10.1.21]─────────┼──── DNS 421q · entropy 4.1 ──▶ susp.ex │ ▲ Potential Periodic Comm.  60s CV .03  │
│  Customer API ▲HIGH   └ ─ ─ HTTPS every 60s ─ ─ ─ ▶ 43.x.x.x   │ ■ Potential DNS Anomaly     421 q       │
│                                                               │ ● Rare JA4                  1 host      │
│  [10.10.1.35] ── HTTP 0.9GB ──▶ update.vendor.com (normal)    ├ INTERESTING CONNECTIONS ────────────────┤
│                                     [Group: other 1,198 hosts]│ 10.10.1.21→185.x:443  3.2GB 41m         │
│                                                               │ 10.10.1.21→43.x:443   ×48 every 60s     │
├ PROTOCOL (bytes) ──────────┬ TOP TALKERS ──────────┬ TOP DESTINATIONS ──────┬ TOP DOMAINS ───────────┤
│ TLS ████████ 71%           │ 10.10.1.21  4.1 GB    │ 185.x.x.x  3.2 GB      │ suspicious.example 421 │
│ HTTP ██ 14%  DNS ▏3%       │ 10.10.1.35  0.9 GB    │ 43.x.x.x   0.4 GB      │ api.example.com    388 │
└────────────────────────────┴───────────────────────┴────────────────────────┴────────────────────────┘
```
