// One Investigation Context shared by every visualization (docs/15 §2).
import { create } from "zustand";

export type Filter = { field: string; op: "is" | "is_not" | "in" | "not_in" | "range" | "exists" | "not_exists" | "prefix" | "contains"; value?: unknown };
export type EntityRef = { type: string; value: string };
export type TimeRange = { start?: string; end?: string; end_exclusive?: boolean } | null;

type InvState = {
  filters: Filter[];
  time: TimeRange;
  selection: EntityRef | null;
  hover: EntityRef | null;
  tab: string;
  eventId: string | null;
  findingId: string | null;
};

type Store = {
  byInv: Record<string, InvState>;
  get: (inv: string) => InvState;
  set: (inv: string, patch: Partial<InvState>) => void;
  addFilter: (inv: string, f: Filter) => void;
  removeFilter: (inv: string, i: number) => void;
};

const empty = (): InvState => ({ filters: [], time: null, selection: null, hover: null, tab: "summary", eventId: null, findingId: null });

export const useInvStore = create<Store>((set, get) => ({
  byInv: {},
  get: (inv) => get().byInv[inv] || empty(),
  set: (inv, patch) => set((s) => ({ byInv: { ...s.byInv, [inv]: { ...(s.byInv[inv] || empty()), ...patch } } })),
  addFilter: (inv, f) =>
    set((s) => {
      const cur = s.byInv[inv] || empty();
      const exists = cur.filters.some((x) => x.field === f.field && x.op === f.op && JSON.stringify(x.value) === JSON.stringify(f.value));
      return { byInv: { ...s.byInv, [inv]: { ...cur, filters: exists ? cur.filters : [...cur.filters, f] } } };
    }),
  removeFilter: (inv, i) =>
    set((s) => {
      const cur = s.byInv[inv] || empty();
      return { byInv: { ...s.byInv, [inv]: { ...cur, filters: cur.filters.filter((_, j) => j !== i) } } };
    }),
}));

export function useInv(inv: string) {
  const st = useInvStore((s) => s.byInv[inv]) || empty();
  const store = useInvStore();
  return { ...st, set: (p: Partial<InvState>) => store.set(inv, p), addFilter: (f: Filter) => store.addFilter(inv, f), removeFilter: (i: number) => store.removeFilter(inv, i) };
}

// Entity key normalization so every view identifies the same thing (docs/15 §2.3)
export function entityKey(e: EntityRef | null): string {
  if (!e) return "";
  let v = e.value.trim();
  if (e.type === "domain") v = v.toLowerCase().replace(/\.$/, "");
  return `${e.type}:${v}`;
}

export const FIELD_OF: Record<string, string> = { ip: "src_ip", uri: "uri_template", ja4: "ja4", user: "user", user_agent: "user_agent", domain: "domain", session: "session_id", asset: "dst_asset_id", url_path: "url_path" };

// Open investigation tabs (multi-investigation UX, docs/15 §3)
type TabsStore = { tabs: { id: string; label: string }[]; open: (id: string, label: string) => void; close: (id: string) => void };
export const useInvTabs = create<TabsStore>((set) => ({
  tabs: JSON.parse(sessionStorage.getItem("saw.tabs") || "[]"),
  open: (id, label) =>
    set((s) => {
      const tabs = s.tabs.some((t) => t.id === id) ? s.tabs.map((t) => (t.id === id ? { id, label } : t)) : [...s.tabs, { id, label }].slice(-8);
      sessionStorage.setItem("saw.tabs", JSON.stringify(tabs));
      return { tabs };
    }),
  close: (id) =>
    set((s) => {
      const tabs = s.tabs.filter((t) => t.id !== id);
      sessionStorage.setItem("saw.tabs", JSON.stringify(tabs));
      return { tabs };
    }),
}));
