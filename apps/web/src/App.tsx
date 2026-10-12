import { useQuery, useQueryClient } from "@tanstack/react-query";
import { lazy, Suspense, useEffect, useSyncExternalStore } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { Shell } from "./components/Shell";
import { Loading } from "./components/common";
import { api } from "./lib/api";
import { getTz, subscribeTz } from "./lib/format";
import { Admin } from "./pages/Admin";
import { CaseDetail, Cases } from "./pages/Cases";
import { Home } from "./pages/Home";
import { Investigations } from "./pages/Investigations";
import { JobDetail, Jobs } from "./pages/Jobs";
import { Login } from "./pages/Login";
import { LocalModels } from "./pages/LocalModels";
import { HttpPage } from "./pages/analyze/HttpPage";
import { IocPage } from "./pages/analyze/IocPage";
import { LogPage } from "./pages/analyze/LogPage";
import { PayloadPage } from "./pages/analyze/PayloadPage";
import { UniversalPage } from "./pages/analyze/UniversalPage";

const Workbench = lazy(() => import("./pages/inv/Workbench").then((m) => ({ default: m.Workbench })));
const Hunting = lazy(() => import("./pages/Hunting").then((m) => ({ default: m.Hunting })));
const Detections = lazy(() => import("./pages/Detections").then((m) => ({ default: m.Detections })));
const Knowledge = lazy(() => import("./pages/Knowledge").then((m) => ({ default: m.Knowledge })));
const Parsers = lazy(() => import("./pages/Parsers").then((m) => ({ default: m.Parsers })));
const Briefing = lazy(() => import("./pages/Briefing").then((m) => ({ default: m.Briefing })));
const Board = lazy(() => import("./pages/Board").then((m) => ({ default: m.Board })));
const Provenance = lazy(() => import("./pages/Provenance").then((m) => ({ default: m.Provenance })));
const DiffPage = lazy(() => import("./pages/analyze/DiffPage").then((m) => ({ default: m.DiffPage })));
export type Me = { id: string; username: string; display_name: string; roles: string[]; permissions: string[] };

export function useMe() {
  return useQuery<Me>({ queryKey: ["me"], queryFn: () => api.get("/auth/me"), retry: false, staleTime: 60_000 });
}

export function App() {
  useSyncExternalStore(subscribeTz, getTz);
  const me = useMe();
  const qc = useQueryClient();
  useEffect(() => {
    const h = () => qc.invalidateQueries({ queryKey: ["me"] });
    window.addEventListener("saw:unauthorized", h);
    return () => window.removeEventListener("saw:unauthorized", h);
  }, [qc]);
  if (me.isLoading) return <Loading />;
  if (me.isError || !me.data) return <Login onDone={() => qc.invalidateQueries({ queryKey: ["me"] })} />;
  return (
    <Shell me={me.data}>
      <Suspense fallback={<Loading />}>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/analyze" element={<UniversalPage />} />
        <Route path="/analyze/ioc" element={<IocPage />} />
        <Route path="/analyze/http" element={<HttpPage />} />
        <Route path="/analyze/payload" element={<PayloadPage />} />
        <Route path="/analyze/diff" element={<DiffPage />} />
        <Route path="/analyze/log" element={<LogPage />} />
        <Route path="/investigations" element={<Investigations />} />
        <Route path="/inv/:id" element={<Workbench />} />
        <Route path="/inv/:id/report" element={<Briefing />} />
        <Route path="/board" element={<Board />} />
        <Route path="/jobs" element={<Jobs />} />
        <Route path="/jobs/:id" element={<JobDetail />} />
        <Route path="/cases" element={<Cases />} />
        <Route path="/cases/:id" element={<CaseDetail />} />
        <Route path="/knowledge/*" element={<Knowledge />} />
        <Route path="/detections/*" element={<Detections />} />
        <Route path="/parsers/*" element={<Parsers />} />
        <Route path="/provenance" element={<Provenance />} />
        <Route path="/hunting/*" element={<Hunting />} />
        <Route path="/admin" element={<Admin me={me.data} />} />
        <Route path="/admin/local-models" element={<LocalModels me={me.data} />} />
        <Route path="*" element={<Navigate to="/" />} />
      </Routes>
      </Suspense>
    </Shell>
  );
}
