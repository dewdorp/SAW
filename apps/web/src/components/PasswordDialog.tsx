import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "../lib/api";
import { ErrorBox } from "./common";

/** Self-service password change. Other sessions of this user are signed out by the server. */
export function PasswordDialog({ onClose }: { onClose: () => void }) {
  const [cur, setCur] = useState("");
  const [nw, setNw] = useState("");
  const [again, setAgain] = useState("");
  const m = useMutation({ mutationFn: () => api.post("/auth/password", { current_password: cur, new_password: nw }) });
  const mismatch = again.length > 0 && nw !== again;
  return (
    <>
      <div className="overlay" onClick={onClose} />
      <div className="modal panel" role="dialog" aria-label="비밀번호 변경" style={{ width: 380 }}>
        <div className="ph"><span className="grow">비밀번호 변경</span></div>
        {m.isSuccess ? (
          <div className="pb col">
            <div>비밀번호가 변경되었습니다. 다른 곳에 로그인된 세션은 모두 종료되었습니다.</div>
            <div className="row"><div className="grow" /><button className="btn primary" onClick={onClose}>닫기</button></div>
          </div>
        ) : (
          <form className="pb col" onSubmit={(e) => { e.preventDefault(); m.mutate(); }}>
            <input className="input" type="password" autoComplete="current-password" placeholder="현재 비밀번호" value={cur} onChange={(e) => setCur(e.target.value)} autoFocus />
            <input className="input" type="password" autoComplete="new-password" placeholder="새 비밀번호 (12자 이상, 대·소문자·숫자·특수문자)" value={nw} onChange={(e) => setNw(e.target.value)} />
            <input className="input" type="password" autoComplete="new-password" placeholder="새 비밀번호 확인" value={again} onChange={(e) => setAgain(e.target.value)} />
            {mismatch && <div className="small bad">새 비밀번호가 일치하지 않습니다.</div>}
            <ErrorBox error={m.error} />
            <div className="row"><div className="grow" /><button type="button" className="btn" onClick={onClose}>취소</button>
              <button className="btn primary" disabled={!cur || !nw || nw !== again || m.isPending}>변경</button></div>
          </form>
        )}
      </div>
    </>
  );
}
