"""Firewall candidates from explicit, versioned observation semantics."""
from saw.core.application.provenance import digest
from saw.core.schemas.query import Filter
from saw.detectors.base import FindingDraft, metric
from saw.observation.firewall import ENGINE_VERSION, analyze_firewall

LABELS = {"scan": "복수 목적지·포트 탐색 가능성", "deny_to_allow": "차단 뒤 허용으로 바뀐 접속",
          "large_transfer": "큰 방향별 전송량", "transfer_asymmetry": "방향별 전송량 차이",
          "long_flow": "오래 지속된 세션", "beacon": "반복 주기 접속 가능성"}


class FirewallObservation:
    id = "fw.observation"
    version = ENGINE_VERSION
    category = "network.firewall"
    stage = "observation"
    data_sources = {"connection", "firewall", "zeek_conn"}

    def run(self, ctx):
        events = ctx.events.iterate(ctx.investigation_id,
            [Filter(field="data_source", op="in", value=sorted(self.data_sources))], batch=500)
        result = analyze_firewall(events, policy=ctx.params.get("firewall_policy"),
                                  cancelled=ctx.params.get("cancelled"))
        ctx.params.setdefault("execution_reports", {})[self.id] = result
        drafts = []
        for candidate in result["candidates"]:
            refs = candidate["event_refs"]
            event_ids = [ref["event_id"] for ref in refs if ref.get("event_id")]
            values = candidate["metrics"]
            kind = candidate["kind"]
            drafts.append(FindingDraft(detector_id=self.id, detector_version=self.version,
                title="관측 후보: " + LABELS.get(kind, kind), category=self.category + "." + kind,
                stage=self.stage, severity=0.5, confidence="medium",
                metrics=[metric(k, v, unit="bytes" if k.endswith("_bytes") else "seconds" if k.endswith("_seconds") else "")
                         for k, v in values.items()],
                checks=[{"label": "분석가 확인 필요", "passed": None, "value": None,
                         "detail": "허용·응답·전송량만으로 정상 또는 침해 성공을 판단하지 않습니다."}],
                entities=["ip:" + values[k] for k in ("src_ip", "dst_ip") if values.get(k)],
                evidence_query={"filters": [{"field": "event_id", "op": "in", "value": event_ids}],
                                "reference_scope": "bounded_representative"},
                time_start=None, time_end=None, dedup_key=self.id + ":" + digest([kind, values, event_ids]),
                sample_event_ids=event_ids, total_events=len(event_ids), success_signal=False,
                attack_unmapped_reason="관측만으로 공격 기법이나 성공을 확정할 수 없습니다.",
                explanation="장비 해석 기준을 고정하고 기록과 세션을 구분한 관측입니다. 원문 위치와 자료 한계를 함께 확인하세요."))
        return drafts
