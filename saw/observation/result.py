"""Disk-backed device grouping and bounded deterministic reports."""
from __future__ import annotations

import json
import sqlite3
import tempfile
from collections import Counter
from copy import deepcopy
from datetime import datetime


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def seconds(value):
    try:
        dt = datetime.fromisoformat(str(value))
        return dt.timestamp() if dt.tzinfo else None
    except (ValueError, TypeError, OverflowError):
        return None


class DeviceRun:
    def __init__(self, spec, policy, events, *, context_snapshot, max_records, max_results, cancelled, profile_lookup):
        if (isinstance(max_records, bool) or not isinstance(max_records, int) or not 1 <= max_records <= 10_000_000
                or isinstance(max_results, bool) or not isinstance(max_results, int) or not 1 <= max_results <= 1000):
            raise ValueError("invalid device limits")
        self.spec, self.policy = deepcopy(spec), deepcopy(policy)
        self.events, self.snapshot = iter(events), deepcopy(context_snapshot)
        self.max_records, self.max_results, self.cancelled = max_records, max_results, cancelled
        self.profile_lookup = profile_lookup
        self.counts = Counter(records=0, eligible_records=0, requests=0, rule_hits=0, alerts=0, intervals=0,
                              sessions=0, candidates=0, omitted_candidates=0, omitted_timeline=0)
        self.quality = Counter()
        self.candidates, self.timeline, self.limitations = [], [], []
        self.partial = self.was_cancelled = self.insufficient = False
        self._cancel_exception = None

    def stop(self):
        if self.cancelled and self.cancelled():
            self.was_cancelled = self.partial = True
        return self.was_cancelled

    def progress(self):
        try:
            return int(self.stop())
        except Exception as exc:  # noqa: BLE001 - preserve the caller cancellation exception through SQLite
            self._cancel_exception = exc
            self.was_cancelled = self.partial = True
            return 1

    def __enter__(self):
        from saw.observation.device import DEVICE_VERSION, device_observation

        self.temp = tempfile.TemporaryDirectory(prefix="saw-device-")
        self.db = sqlite3.connect(self.temp.name + "/groups.sqlite")
        self.db.row_factory = sqlite3.Row
        try:
            self.db.execute("PRAGMA temp_store=FILE")
            self.db.execute("PRAGMA cache_size=-2048")
            self.db.set_progress_handler(self.progress, 10000)
            self.db.execute("CREATE TABLE rows(n INTEGER PRIMARY KEY,k TEXT,net TEXT,b INTEGER,t REAL,kind TEXT,"
                            "src TEXT,dst TEXT,rid TEXT,sig TEXT,action TEXT,uri TEXT,path TEXT,domain TEXT,ref TEXT,obs TEXT,event TEXT)")
            if not self.policy["enabled"]:
                return self
            device = self.spec["id"].split(".")[0]
            function = {"waf": "WAF", "ips": "IPS", "ddos": "DDoS", "ndr": "NDR"}[device]
            for index in range(self.max_records):
                if self.stop():
                    break
                event = next(self.events, None)
                if event is None:
                    break
                self.counts["records"] += 1
                context = self.snapshot
                if self.profile_lookup is not None:
                    context = self.profile_lookup(event)
                obs = (device_observation(event, context_snapshot=context) if context is not None
                       else (event.get("ext") or {}).get("device_observation"))
                if not isinstance(obs, dict) or obs.get("producer") != "saw" or obs.get("version") != DEVICE_VERSION:
                    self.quality["missing_device_observation"] += 1
                    continue
                context = obs.get("context") or {}
                timestamp = seconds(obs.get("timestamp"))
                if obs.get("verified") is not True or not context.get("resolved"):
                    self.quality["unverified_device_context"] += 1
                    continue
                if (not obs.get("time_verified") or timestamp is None or
                        obs.get("timestamp_precision") not in {"seconds", "subseconds"}):
                    self.quality["unverified_device_time"] += 1
                    continue
                if function not in obs.get("functions", []) and not (
                    device == "ips" and obs.get("record_kind") == "flow" and
                    set(obs.get("functions", [])) & {"FW", "NDR"}):
                    self.quality["device_not_applicable"] += 1
                    continue
                if obs.get("record_kind") not in {"request", "rule_hit", "alert", "interval_summary", "flow", "dns", "http", "tls"}:
                    self.quality["unknown_record_kind"] += 1
                    continue
                self.counts["eligible_records"] += 1
                self.quality.update(obs.get("quality") or [])
                group = [context.get(key) for key in ("org_unit_id", "network", "device_id",
                                                     "device_profile_version_id", "virtual_domain")]
                if device == "waf":
                    group += [obs.get("service"), obs.get("client_ip")]
                network = [context.get("org_unit_id"), context.get("network"), context.get("virtual_domain")]
                rid = obs.get("request_id")
                if not rid and obs.get("record_kind") == "request":
                    rid = event.get("event_id") or "row:" + str(index)
                ref = {key: event.get(key) for key in ("event_id", "raw_ref", "evidence_id", "file_id")}
                clean = {**event, "ext": {**(event.get("ext") or {}), "device_observation": obs}}
                if isinstance(obs.get("connection"), dict):
                    clean["ext"]["observation"] = obs["connection"]
                self.db.execute("INSERT INTO rows VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (index, canonical(group), canonical(network), int(timestamp // self.policy["window_seconds"]),
                     timestamp, obs.get("record_kind"), obs.get("client_ip"), obs.get("dst_ip"),
                     str(rid) if rid is not None else None, str(obs["signature_id"]) if obs.get("signature_id") is not None else None,
                     obs.get("action"), obs.get("uri"), obs.get("path"), obs.get("domain"), canonical(ref),
                     canonical(obs), canonical(clean)))
            else:
                if next(self.events, None) is not None:
                    self.partial = True
                    self.quality["record_limit_reached"] += 1
            self.db.commit()
            self.db.execute("CREATE INDEX scope_order ON rows(k,b,t,n)")
            self.db.execute("CREATE INDEX network_order ON rows(net,src,dst,t)")
            return self
        except sqlite3.OperationalError:
            if self.was_cancelled and self._cancel_exception is None:
                return self
            self.__exit__(None, None, None)
            if self._cancel_exception:
                raise self._cancel_exception
            raise
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *args):
        self.db.close()
        self.temp.cleanup()

    def query(self, sql, values=()):
        for row in self.db.execute(sql, values):
            if self.stop():
                break
            yield row

    def refs(self, condition, values=()):
        return [json.loads(row["ref"]) for row in self.query(
            "SELECT ref FROM rows WHERE " + condition + " ORDER BY t,n LIMIT 20", values)]

    def add(self, kind, refs, metrics, *, scope=None):
        self.counts["candidates"] += 1
        if len(self.candidates) >= self.max_results:
            self.counts["omitted_candidates"] += 1
            return
        self.candidates.append({"kind": kind, "interpretation": "candidate", "event_refs": refs[:20],
            "metrics": metrics, "context": json.loads(scope) if isinstance(scope, str) else scope,
            "limitations": ["관측 후보이며 성공·침해·영향은 확인되지 않았습니다."], "success_signal": False})

    def add_timeline(self, value):
        if len(self.timeline) < self.max_results:
            self.timeline.append(value)
        else:
            self.counts["omitted_timeline"] += 1

    def finish(self):
        if self._cancel_exception:
            raise self._cancel_exception
        status = ("disabled" if not self.policy["enabled"] else "cancelled" if self.was_cancelled else
                  "not_applicable" if self.counts["records"] and self.quality.get("device_not_applicable") == self.counts["records"] else
                  "partial" if self.partial else "insufficient_data" if self.insufficient or not self.counts["eligible_records"] else
                  "partial" if self.quality else "completed_match" if self.counts["candidates"] else "completed_no_match")
        return {"engine_version": self.spec["engine"]["version"], "spec_version": self.spec["version"],
            "status": status, "counts": dict(self.counts), "quality": dict(sorted(self.quality.items())),
            "candidates": self.candidates, "timeline": self.timeline, "policy": deepcopy(self.policy),
            "calculation_coverage": getattr(self, "calculation_coverage", {}),
            "limits": {"max_records": self.max_records, "max_results": self.max_results,
                       "max_event_refs_per_result": 20, "coverage_complete": status in {"completed_match", "completed_no_match"}},
            "limitations": ["검증된 장비 해석 기준과 동일 관계사·망에서 관측한 자료에 한정됩니다.",
                            "후보와 승인 정상 활동·실제 영향은 별도 판단입니다.",
                            "제조사 실제 필드 매핑과 native 저장소는 별도 검증이 필요합니다."] + self.limitations}
