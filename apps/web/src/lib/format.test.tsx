import { render } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { HighlightedInput } from "../components/analysis";
import { EntityChip } from "../components/EntityChip";
import { safeTooltip } from "../viz/EChart";
import { defang, dur, escapeHtml, fmtBytes, pct } from "./format";

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
