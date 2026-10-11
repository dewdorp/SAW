import { render } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { HighlightedInput } from "../components/analysis";
import { EntityChip } from "../components/EntityChip";
import { safeTooltip } from "../viz/EChart";
import { defang, dur, escapeHtml, fmtBytes, fmtTime, pct, setTz } from "./format";

const XSS = `<img src=x onerror="window.__pwned=1">`;

describe("safe rendering of untrusted data", () => {
  it("escapes html", () => {
    expect(escapeHtml(XSS)).not.toContain("<img");
    expect(escapeHtml(`"'&`)).toBe("&quot;&#39;&amp;");
  });

  it("ECharts tooltip formatter escapes every value", () => {
    const f = safeTooltip(() => [[XSS, XSS]]);
    const html = f({});
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;img");
  });

  it("entity chips and highlighted input render as text, never HTML", () => {
    const { container } = render(
      <MemoryRouter>
        <EntityChip type="user_agent" value={XSS} />
        <HighlightedInput text={`UA: ${XSS}`} spans={[{ span: [4, 4 + XSS.length], type: "user_agent" }]} />
      </MemoryRouter>,
    );
    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).toContain("onerror");
    expect((window as any).__pwned).toBeUndefined();
  });
});

describe("formatting", () => {
  it("defangs and formats", () => {
    expect(defang("http://evil.example.com")).toBe("hxxp://evil[.]example[.]com");
    expect(fmtBytes(1536)).toBe("1.5 KB");
    expect(pct(1)).toBe("100.0%");
    expect(dur(0.74)).toBe("+0.74s");
  });
});

describe("API timestamp display", () => {
  beforeEach(() => {
    vi.stubEnv("TZ", "Asia/Seoul");
    setTz("KST");
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    setTz("KST");
  });

  it.each(["KST", "UTC"] as const)("shows the same UTC instant consistently in %s", (mode) => {
    setTz(mode);
    const expected = mode === "KST" ? "10-05-02:30:09" : "10-04-17:30:09";
    const timestamps = [
      "2026-10-04T17:30:09",
      "2026-10-04T17:30:09.000000",
      "2026-10-04 17:30:09",
      "2026-10-04 17:30:09.000000",
      "2026-10-04T17:30:09.000Z",
      "2026-10-05T02:30:09+09:00",
      "2026-10-04T13:30:09-04:00",
      Date.parse("2026-10-04T17:30:09Z") / 1000,
    ];
    for (const timestamp of timestamps) {
      expect(fmtTime(timestamp), String(timestamp)).toBe(expected);
    }
  });

  it("respects explicit offsets instead of treating their clock times as UTC", () => {
    setTz("UTC");
    expect(fmtTime("2026-10-05T02:30:09+09:00", false)).toBe("17:30:09");
    expect(fmtTime("2026-10-04T13:30:09-04:00", false)).toBe("17:30:09");
  });

  it("keeps invalid and absent timestamp handling", () => {
    for (const value of ["not-a-time", "2026-13-04T17:30:09"]) {
      expect(fmtTime(value)).toBe(value);
    }
    for (const value of [null, undefined, ""]) {
      expect(fmtTime(value)).toBe("–");
    }
  });
});
