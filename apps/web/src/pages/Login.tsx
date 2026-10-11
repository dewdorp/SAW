import QRCode from "qrcode";
import { useEffect, useRef, useState } from "react";
import { ErrorBox } from "../components/common";
import { api } from "../lib/api";

/** TOTP enrollment QR rendered locally to a canvas (no external QR service; no data: URL needed under CSP). */
function TotpQr({ uri }: { uri: string }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    if (ref.current) QRCode.toCanvas(ref.current, uri, { width: 200, margin: 2, errorCorrectionLevel: "M" }).catch(() => undefined);
  }, [uri]);
  return <canvas ref={ref} aria-label="MFA 등록 QR 코드" style={{ alignSelf: "center", background: "#fff", borderRadius: 4 }} />;
}

const AUTH_MESSAGES: Record<string, string> = {
  "invalid credentials": "아이디 또는 비밀번호가 맞지 않습니다.",
  "account locked": "여러 번 틀려 계정이 잠시 잠겼습니다. 조금 뒤 다시 로그인하거나 관리자에게 문의하세요.",
  "account disabled": "사용이 중지된 계정입니다. 관리자에게 문의하세요.",
  "invalid MFA code": "인증 코드가 맞지 않습니다. 여러 번 틀리면 계정이 잠깁니다.",
  "MFA code already used": "이미 사용한 인증 코드입니다. 인증 앱에 새 코드가 나오면 그 코드를 입력하세요.",
};

function authError(x: unknown): unknown {
  const msg = x instanceof Error ? x.message : "";
  return AUTH_MESSAGES[msg] ? new Error(AUTH_MESSAGES[msg]) : x;
}

export function Login({ onDone }: { onDone: () => void }) {
  const [step, setStep] = useState<"pw" | "mfa" | "enroll">("pw");
  const [u, setU] = useState("");
  const [p, setP] = useState("");
  const [code, setCode] = useState("");
  const [uri, setUri] = useState<string | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const login = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const r = await api.post("/auth/login", { username: u, password: p });
      if (r.state === "ok") onDone();
      else if (r.state === "mfa_enroll") { setUri(r.provisioning_uri); setStep("enroll"); }
      else setStep("mfa");
    } catch (x) { setErr(authError(x)); } finally { setBusy(false); }
  };
  const verify = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try { await api.post("/auth/mfa/verify", { code }); onDone(); } catch (x) {
      setErr(authError(x));
      setCode("");
      if (x instanceof Error && x.message === "account locked") setStep("pw");  // the password step must be repeated
    } finally { setBusy(false); }
  };
  const secret = uri ? new URL(uri).searchParams.get("secret") : null;
  return (
    <div className="login">
      <section className="login-context">
        <div className="sb-brand" style={{ padding: 0 }}><span className="logo" aria-hidden>◆</span><span><b>SAW</b><small>SOC ANALYSIS WORKBENCH</small></span></div>
        <div>
          <div className="eyebrow">On-premise · Air-gapped</div>
          <h1>증거에서 이야기로,<br />이야기에서 판단으로.</h1>
          <p>로그·PCAP·IOC를 한 화면에서 분석하고, 모든 탐지를 근거와 원본까지 추적합니다.
            자동 차단은 하지 않습니다 — 판단과 대응은 분석가가 합니다.</p>
          <ul className="login-points">
            <li>이야기 → 근거 → 원본 순서의 시각적 조사</li>
            <li>근거 유형 표시: 관측 · 계산 · 추론 · 판정</li>
            <li>PCAP 포렌식 · MITRE ATT&amp;CK · 내부 SOC 경험</li>
          </ul>
        </div>
        <p className="muted small">모든 접속·조회는 감사 기록됩니다.</p>
      </section>
      <div className="login-form">
        <h2 style={{ fontSize: 22, marginBottom: 4 }}>{step === "pw" ? "로그인" : step === "enroll" ? "MFA 등록 (TOTP)" : "MFA 확인"}</h2>
        <p className="muted small" style={{ marginTop: 0 }}>{step === "pw" ? "사용자 ID와 비밀번호를 입력하세요." : "인증 앱의 6자리 코드를 입력하세요."}</p>
        <div className="panel"><div className="pb">
          {step === "pw" ? (
            <form className="col" onSubmit={login}>
              <input className="input" placeholder="사용자 ID" autoComplete="username" value={u} onChange={(e) => setU(e.target.value)} autoFocus />
              <input className="input" type="password" placeholder="비밀번호" autoComplete="current-password" value={p} onChange={(e) => setP(e.target.value)} />
              <button className="btn primary" disabled={busy || !u || !p}>로그인</button>
            </form>
          ) : (
            <form className="col" onSubmit={verify}>
              {step === "enroll" && uri && (
                <div className="small col">
                  <div>MFA 등록이 필요합니다. 인증 앱(Google Authenticator, Microsoft Authenticator 등)으로 QR 코드를 스캔한 뒤, 앱에 표시된 6자리 코드를 입력하세요.</div>
                  <TotpQr uri={uri} />
                  <div className="muted">QR 스캔이 안 되면 앱에서 “키 직접 입력”을 선택하고 아래 키를 입력하세요 (시간 기반, 6자리, 30초).</div>
                  <div className="mono pre" style={{ background: "var(--bg)", padding: 6, borderRadius: 4, userSelect: "all" }}>{secret?.replace(/(.{4})/g, "$1 ").trim()}</div>
                </div>
              )}
              {step === "mfa" && <div className="small muted">인증 앱에 표시된 SAW 6자리 코드를 입력하세요. 휴대폰 시간이 자동 설정인지 확인하세요.</div>}
              <input className="input mono" inputMode="numeric" autoComplete="one-time-code" placeholder="6자리 코드" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} autoFocus />
              <button className="btn primary" disabled={busy || code.length < 6}>확인</button>
            </form>
          )}
          <ErrorBox error={err} />
          {step !== "pw" && <div className="small muted" style={{ marginTop: 6 }}>인증 앱을 잃어버렸거나 기기를 바꿨다면 관리자에게 MFA 재설정을 요청하세요. <a onClick={() => { setStep("pw"); setCode(""); setErr(null); }}>← 다시 로그인</a></div>}
        </div></div>
      </div>
    </div>
  );
}
