import { useInfiniteQuery } from "@tanstack/react-query";
import { ErrorBox, Loading } from "../../components/common";
import { useInv } from "../../context/invContext";
import { api } from "../../lib/api";
import { EventTable } from "./FindingsTab";

const SRC: Record<string, { ds: string[]; cols: string[] }> = {
  conn: { ds: ["zeek_conn", "suricata"], cols: ["timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "bytes_in", "bytes_out", "community_id"] },
  dns: { ds: ["zeek_dns"], cols: ["timestamp", "src_ip", "dst_ip", "domain", "event_type"] },
  tls: { ds: ["zeek_ssl"], cols: ["timestamp", "src_ip", "dst_ip", "domain", "ja3", "ja4"] },
};

/** PCAP-derived tabs (Phase 6 data). */
export function NetworkTab({ inv, kind }: { inv: string; kind: "conn" | "dns" | "tls" }) {
  const ctx = useInv(inv);
  const cfg = SRC[kind];
  const q = useInfiniteQuery({
    queryKey: ["net", inv, kind, ctx.filters, ctx.time],
    queryFn: ({ pageParam }) => api.post(`/investigations/${inv}/query/events`, { filters: [...ctx.filters, { field: "data_source", op: "in", value: cfg.ds }], time: ctx.time, limit: 500, cursor: pageParam }),
    initialPageParam: null as string | null, getNextPageParam: (l: any) => l.next_cursor,
  });
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const rows = (q.data?.pages || []).flatMap((p: any) => p.events);
  return (
    <div className="col">
      <EventTable inv={inv} events={rows} cols={cfg.cols} />
      {q.hasNextPage && <button className="btn sm" onClick={() => q.fetchNextPage()}>더 보기</button>}
    </div>
  );
}
