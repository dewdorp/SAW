import { describe, expect, it } from "vitest";
import { displayField } from "./evidenceView";
import { fmtPeriod } from "../../lib/format";

describe("evidence times", () => {
  it("show the year and any recorded fraction in the display time zone", () => {
    expect(displayField("timestamp", "2026-10-10T09:00:00.200000+09:00")).toBe("2026-10-10 09:00:00.2");
    expect(displayField("timestamp", "2025-12-31T15:00:00Z")).toBe("2026-01-01 00:00:00");
    expect(fmtPeriod("2026-10-10T09:00:00.2+09:00", "2026-10-10T09:01:09.2+09:00")).toBe("2026-10-10 09:00:00.2 ~ 09:01:09.2");
  });
});
