import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { entityKey, FIELD_OF, useInv } from "../context/invContext";
import { defang } from "../lib/format";

const ICON: Record<string, string> = { ip: "🌐", uri: "🔗", url_path: "🔗", ja4: "🔑", user: "👤", user_agent: "🧭", domain: "🌍", session: "🎫", asset: "🏦", hash: "#", group: "▣" };

export function parseEntity(s: string): { type: string; value: string } {
  const i = s.indexOf(":");
  const t = s.slice(0, i);
  const map: Record<string, string> = { uri_template: "uri" };
  return { type: map[t] || t, value: s.slice(i + 1) };
}

/** Entity chip with pivot menu (docs/14 §4.4). Copy defaults to defanged. */
export function EntityChip({ type, value, inv, external, label }: { type: string; value: string; inv?: string; external?: boolean; label?: string }) {
  const [menu, setMenu] = useState<{ x: number; y: number } | null>(null);
  const ctx = useInv(inv || "_");
  const nav = useNavigate();
  const sel = inv && entityKey(ctx.selection) === entityKey({ type, value });
  useEffect(() => {
    if (!menu) return;
    const h = () => setMenu(null);
    window.addEventListener("click", h);
    return () => window.removeEventListener("click", h);
  }, [menu]);
  const field = FIELD_OF[type] || type;
  const act = (fn: () => void) => () => { fn(); setMenu(null); };
  return (
    <>
      <span
        className={`chip ${external ? "ext" : ""} ${sel ? "sel" : ""}`}
        title={`${type}: ${value}`}
        tabIndex={0}
        onMouseEnter={() => inv && ctx.set({ hover: { type, value } })}
        onMouseLeave={() => inv && ctx.set({ hover: null })}
        onClick={(e) => { e.stopPropagation(); if (inv) ctx.set({ selection: { type, value } }); setMenu({ x: e.clientX, y: e.clientY + 8 }); }}
        onKeyDown={(e) => { if (e.key === "Enter") { const r = (e.target as HTMLElement).getBoundingClientRect(); setMenu({ x: r.left, y: r.bottom + 4 }); } }}
      >
        <span aria-hidden>{ICON[type] || "•"}</span>
        <span className="ellipsis">{label || value}</span>
      </span>
      {menu && (
        <div className="menu" style={{ left: menu.x, top: menu.y }} onClick={(e) => e.stopPropagation()}>
          {inv && <button onClick={act(() => ctx.addFilter({ field, op: "is", value }))}>＋ Filter include</button>}
          {inv && <button onClick={act(() => ctx.addFilter({ field, op: "is_not", value }))}>－ Filter exclude</button>}
          {inv && <button onClick={act(() => ctx.set({ tab: "timeline", selection: { type, value } }))}>⏱ Timeline</button>}
          {inv && <button onClick={act(() => ctx.set({ tab: "relations", selection: { type, value } }))}>⛓ Graph focus</button>}
          {inv && <button onClick={act(() => ctx.set({ tab: "entity", selection: { type, value } }))}>ℹ Entity detail</button>}
          {(type === "ip" || type === "domain") && <button onClick={act(() => nav(`/analyze/ioc?q=${encodeURIComponent("")}`, { state: { observable: value } }))}>🔎 IOC analysis</button>}
          <button onClick={act(() => navigator.clipboard?.writeText(type === "ip" || type === "domain" ? defang(value) : value))}>⧉ Copy {type === "ip" || type === "domain" ? "(defanged)" : ""}</button>
          <button onClick={act(() => navigator.clipboard?.writeText(value))}>⧉ Copy raw</button>
        </div>
      )}
    </>
  );
}
