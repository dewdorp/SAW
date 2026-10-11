"""Offline IOC enrichment: ASN / country / cloud-VPS / Tor (docs/17 §7.1).

Data comes from offline CSV bundles under data/enrichment/ (ENV-14: real licensed DBs must be dropped in).
Format: start_ip,end_ip,asn,as_org,country   and   cidr,provider   and   tor exit list (one ip per line).
Never performs network lookups.
"""
from __future__ import annotations

import bisect
import csv
import ipaddress
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parents[3] / "data" / "enrichment"

VPS_ASNS = {
    14061: "DigitalOcean", 16276: "OVH", 24940: "Hetzner", 63949: "Linode/Akamai", 20473: "Vultr",
    51167: "Contabo", 36352: "ColoCrossing", 9009: "M247", 60068: "CDN77/Datacamp", 212238: "Datacamp",
}
CLOUD_ASNS = {16509: "aws", 14618: "aws", 15169: "gcp", 396982: "gcp", 8075: "azure", 31898: "oci",
              45102: "alibaba", 132203: "tencent", 37963: "alibaba"}


@dataclass
class _Range:
    start: int
    end: int
    asn: int
    org: str
    country: str


class OfflineEnricher:
    def __init__(self, data_dir: Path = DATA_DIR):
        self._cache: dict[str, dict] = {}
        self.ranges: list[_Range] = []
        self.starts: list[int] = []
        self.cloud: list[tuple[ipaddress._BaseNetwork, str]] = []
        self.tor: set[str] = set()
        f = data_dir / "asn_ranges.csv"
        if f.exists():
            with open(f, encoding="utf-8") as fh:
                for row in csv.DictReader(fh):
                    self.ranges.append(_Range(int(ipaddress.ip_address(row["start_ip"])),
                                              int(ipaddress.ip_address(row["end_ip"])), int(row["asn"]),
                                              row["as_org"], row["country"]))
            self.ranges.sort(key=lambda r: r.start)
            self.starts = [r.start for r in self.ranges]
        f = data_dir / "cloud_ranges.csv"
        if f.exists():
            with open(f, encoding="utf-8") as fh:
                for row in csv.DictReader(fh):
                    self.cloud.append((ipaddress.ip_network(row["cidr"], strict=False), row["provider"]))
        f = data_dir / "tor_exits.txt"
        if f.exists():
            self.tor = {ln.strip() for ln in f.read_text(encoding="utf-8").splitlines() if ln.strip()}
        self.source = "fixture" if (data_dir / "FIXTURE").exists() else "bundle"

    def lookup_ip(self, ip: str) -> dict:
        hit = self._cache.get(ip)
        if hit is None:
            hit = self._lookup(ip)
            if len(self._cache) < 100_000:  # bounded: memory stays small on analyst PCs
                self._cache[ip] = hit
        return dict(hit)

    def _lookup(self, ip: str) -> dict:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return {}
        out: dict = {"asn": None, "as_org": None, "country": None, "cloud": "none", "tor": ip in self.tor,
                     "source": self.source}
        if a.version == 4 and self.ranges:
            n = int(a)
            i = bisect.bisect_right(self.starts, n) - 1
            if i >= 0 and self.ranges[i].start <= n <= self.ranges[i].end:
                r = self.ranges[i]
                out.update(asn=r.asn, as_org=r.org, country=r.country)
        for net, prov in self.cloud:
            if a.version == net.version and a in net:
                out["cloud"] = prov
                break
        if out["cloud"] == "none" and out["asn"]:
            if out["asn"] in CLOUD_ASNS:
                out["cloud"] = CLOUD_ASNS[out["asn"]]
            elif out["asn"] in VPS_ASNS:
                out["cloud"] = f"vps:{VPS_ASNS[out['asn']]}"
        return out


@lru_cache
def default_enricher() -> OfflineEnricher:
    return OfflineEnricher()
