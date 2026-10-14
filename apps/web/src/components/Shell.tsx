import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ReactNode, useEffect, useState } from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import type { Me } from "../App";
import { useInvTabs } from "../context/invContext";
import { api } from "../lib/api";
import { getTz, setTz } from "../lib/format";
import { PasswordDialog } from "./PasswordDialog";
import { Icon } from "./ui";

type NavItem = [to: string, label: string, icon: string];
const NAV_GROUPS: [string, NavItem[]][] = [
  ["분석", [["/", "홈", "home"], ["/analyze", "빠른 분석", "analyze"], ["/investigations", "조사 목록", "folder"], ["/board", "현황판", "board"], ["/jobs", "작업 상태", "clock"], ["/provenance", "처리 기록", "report"]]],
  ["조사·대응", [["/hunting", "위협 헌팅", "target"], ["/cases", "케이스", "briefcase"]]],
  ["지식·탐지", [["/knowledge", "SOC 지식", "book"], ["/detections", "탐지 룰", "shield"], ["/parsers", "파서 관리", "parser"], ["/content-packages", "오프라인 룰·파서", "shield"]]],
];
const SECTION: [string, string][] = [["/analyze", "빠른 분석"], ["/investigations", "조사 목록"], ["/board", "현황판"], ["/inv/", "조사 작업대"], ["/jobs", "작업 상태"], ["/provenance", "처리 기록"],
  ["/hunting", "위협 헌팅"], ["/cases", "케이스"], ["/knowledge", "SOC 지식"], ["/detections", "탐지 룰"], ["/parsers", "파서 관리"], ["/content-packages", "오프라인 룰·파서"], ["/admin/local-models", "로컬 모델"], ["/admin", "관리"]];
const ROLE_KO: Record<string, string> = { analyst: "분석가", senior_analyst: "선임 분석가", soc_manager: "관제 매니저", viewer: "조회자", admin: "관리자" };

/** null = no explicit choice: the sidebar then collapses itself on the (space-hungry) investigation workbench. */
function readCollapsed(): boolean | null {
  try {
    const v = localStorage.getItem("saw.sidebar");
    return v === "collapsed" ? true : v === "open" ? false : null;
  } catch { return null; }
}

export function Shell({ me, children }: { me: Me; children: ReactNode }) {
  const tabs = useInvTabs();
  const loc = useLocation();
  const nav = useNavigate();
  const qc = useQueryClient();
  const [palette, setPalette] = useState(false);
  const [pwOpen, setPwOpen] = useState(false);
  const [pref, setPref] = useState<boolean | null>(readCollapsed);
  const [, force] = useState(0);
  const jobs = useQuery({ queryKey: ["jobs", "active"], queryFn: () => api.get("/jobs?active=true"), refetchInterval: 5000 });
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setPalette((v) => !v); }
      if (e.key === "Escape") setPalette(false);
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, []);
  const theme = () => {
    const cur = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    document.documentElement.dataset.theme = cur;
    try { localStorage.setItem("saw.theme", cur); } catch { /* ignore */ }
    force((x) => x + 1);
  };
  const logout = async () => { await api.post("/auth/logout"); qc.clear(); location.reload(); };
  const collapsed = pref ?? loc.pathname.startsWith("/inv/");
  const toggleSidebar = () => {
    const v = !collapsed;
    setPref(v);
    try { localStorage.setItem("saw.sidebar", v ? "collapsed" : "open"); } catch { /* ignore */ }
  };
  const section = SECTION.find(([p]) => loc.pathname.startsWith(p))?.[1] || "홈";
  const canModels = me.permissions.includes("ai.models.manage");
  const isAdmin = me.permissions.includes("admin.users") || me.permissions.includes("audit.read") || canModels;
  return (
    <div className={`app ${collapsed ? "collapsed" : ""}`}>
      <aside className="sidebar" aria-label="주 메뉴">
        <div className="sb-brand">
          <span className="logo" aria-hidden>◆</span>
          <span className="sb-text"><b>SAW</b><small>SOC ANALYSIS WORKBENCH</small></span>
          <button className="icon-btn sb-toggle" onClick={toggleSidebar} title={collapsed ? "메뉴 펼치기" : "메뉴 접기"} aria-label="메뉴 접기/펼치기">
            <Icon name={collapsed ? "chevron" : "collapse"} size={16} />
          </button>
        </div>
        <nav className="sb-nav">
          {NAV_GROUPS.map(([group, items]) => (
            <div key={group} className="sb-group">
              <div className="sb-label">{group}</div>
              {items.map(([to, label, icon]) => (
                <NavLink key={to} to={to} end={to === "/"} title={label} className={({ isActive }) => (isActive ? "active" : "")}>
                  <Icon name={icon} /><span className="sb-text">{label}</span>
                  {to === "/jobs" && jobs.data?.length ? <span className="sb-count">{jobs.data.length}</span> : null}
                </NavLink>
              ))}
            </div>
          ))}
          {isAdmin && (
            <div className="sb-group">
              <div className="sb-label">관리</div>
              <NavLink to="/admin" end title="관리" className={({ isActive }) => (isActive ? "active" : "")}><Icon name="settings" /><span className="sb-text">관리·감사</span></NavLink>
              {canModels && <NavLink to="/admin/local-models" title="로컬 모델" className={({ isActive }) => (isActive ? "active" : "")}><Icon name="settings" /><span className="sb-text">로컬 모델</span></NavLink>}
            </div>
          )}
        </nav>
        <div className="sb-foot">
          <div className="sb-user" title={me.username}>
            <Icon name="user" />
            <span className="sb-text"><b>{me.display_name}</b><small>{me.roles.map((r) => ROLE_KO[r] || r).join(", ")}</small></span>
          </div>
          <div className="sb-actions">
            <button className="icon-btn" onClick={() => setPwOpen(true)} title="비밀번호 변경"><Icon name="key" size={16} /></button>
            <button className="icon-btn" onClick={theme} title="밝은/어두운 화면"><Icon name="theme" size={16} /></button>
            <button className="icon-btn" onClick={() => { setTz(getTz() === "KST" ? "UTC" : "KST"); force((x) => x + 1); qc.invalidateQueries(); }} title="표시 시간대 전환">
              <span className="tz">{getTz()}</span>
            </button>
            <button className="icon-btn" onClick={logout} title="로그아웃"><Icon name="logout" size={16} /></button>
          </div>
        </div>
      </aside>
      <div className="frame">
        <header className="topbar">
          <span className="crumb">{section}</span>
          <div className="invtabs" role="tablist" aria-label="열린 조사">
            {tabs.tabs.map((t) => (
              <div key={t.id} className={`invtab ${loc.pathname === `/inv/${t.id}` ? "active" : ""}`} role="tab">
                <a className="ellipsis" onClick={() => nav(`/inv/${t.id}`)} title={t.label}>{t.label}</a>
                <span className="x" role="button" aria-label="탭 닫기" onClick={() => { tabs.close(t.id); if (loc.pathname === `/inv/${t.id}`) nav("/investigations"); }}>×</span>
              </div>
            ))}
          </div>
          <div className="grow" />
          <button className="search-btn" onClick={() => setPalette(true)} title="메뉴·조사 검색 (Ctrl+K)">
            <Icon name="analyze" size={15} /><span>검색</span><kbd>Ctrl K</kbd>
          </button>
          <NavLink to="/jobs" className="btn ghost sm" title="처리 중인 작업"><Icon name="clock" size={15} /> {jobs.data?.length ? `작업 ${jobs.data.length}` : "작업"}</NavLink>
        </header>
        <main className="main">{children}</main>
      </div>
      {palette && <Palette onClose={() => setPalette(false)} />}
      {pwOpen && <PasswordDialog onClose={() => setPwOpen(false)} />}
    </div>
  );
}

function Palette({ onClose }: { onClose: () => void }) {
  const [q, setQ] = useState("");
  const nav = useNavigate();
  const invs = useQuery({ queryKey: ["investigations"], queryFn: () => api.get("/investigations") });
  const cmds: [string, () => void][] = [
    ["빠른 분석: 붙여넣기 (Universal)", () => nav("/analyze")], ["빠른 분석: HTTP 요청", () => nav("/analyze/http")],
    ["빠른 분석: 페이로드 디코딩", () => nav("/analyze/payload")], ["빠른 분석: 요청 비교 (Diff)", () => nav("/analyze/diff")],
    ["빠른 분석: IOC", () => nav("/analyze/ioc")], ["빠른 분석: 로그", () => nav("/analyze/log")],
    ["조사 목록", () => nav("/investigations")], ["작업 상태", () => nav("/jobs")], ["케이스", () => nav("/cases")],
    ["오프라인 룰·파서", () => nav("/content-packages")], ["SOC 지식", () => nav("/knowledge")], ["탐지 룰", () => nav("/detections")], ["위협 헌팅", () => nav("/hunting")],
    ...((invs.data || []) as any[]).map((i) => [`조사 ${i.display_id} ${i.title}`, () => nav(`/inv/${i.id}`)] as [string, () => void]),
  ];
  const list = cmds.filter(([l]) => l.toLowerCase().includes(q.toLowerCase())).slice(0, 12);
  return (
    <>
      <div className="overlay" onClick={onClose} />
      <div className="palette panel" role="dialog" aria-label="Command palette">
        <div className="pb col">
          <input className="input" autoFocus placeholder="메뉴 또는 조사 이름 검색…" value={q} onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter" && list[0]) { list[0][1](); onClose(); } }} />
          {list.map(([l, fn]) => <a key={l} onClick={() => { fn(); onClose(); }}>{l}</a>)}
        </div>
      </div>
    </>
  );
}
