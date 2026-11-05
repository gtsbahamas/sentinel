// Monitor alerts for newly published advisories (gtsbahamas/fleet#8880).
//
// Monitor stores the advisory ids it has already alerted on per project and
// hands them back on the next run; selectAdvisoryAlerts() decides what to send.

import { describe, it, expect } from "vitest";
import type { Finding, FindingAdvisory } from "../../src/model/types.js";
import { advisoriesFromFindings, selectAdvisoryAlerts } from "../../src/monitor/advisory-alerts.js";

function advisory(over: Partial<FindingAdvisory> = {}): FindingAdvisory {
  return {
    id: "GHSA-35jh-r3h4-6jhm",
    aliases: ["CVE-2021-23337"],
    package: "lodash",
    installedVersion: "4.17.20",
    fixedVersion: "4.17.21",
    published: "2021-02-15T11:50:49Z",
    severity: "high",
    summary: "Command Injection in lodash",
    source: "osv",
    ...over,
  };
}

describe("selectAdvisoryAlerts", () => {
  it("alerts on a new high advisory, naming package, installed version, advisory id, published date and fixed version", () => {
    const { alerts } = selectAdvisoryAlerts([advisory()], []);
    expect(alerts).toHaveLength(1);
    const a = alerts[0];
    expect(a).toMatchObject({
      key: "GHSA-35jh-r3h4-6jhm",
      advisoryId: "GHSA-35jh-r3h4-6jhm",
      package: "lodash",
      installedVersion: "4.17.20",
      fixedVersion: "4.17.21",
      published: "2021-02-15T11:50:49Z",
      severity: "high",
    });
    for (const part of ["lodash", "4.17.20", "GHSA-35jh-r3h4-6jhm", "2021-02-15", "4.17.21"]) {
      expect(a.message).toContain(part);
    }
  });

  it("alerts on critical too, but never on medium, low or info", () => {
    const { alerts } = selectAdvisoryAlerts(
      [
        advisory({ id: "MAL-2025-1", severity: "critical" }),
        advisory({ id: "GHSA-med", severity: "medium" }),
        advisory({ id: "GHSA-low", severity: "low" }),
        advisory({ id: "GHSA-info", severity: "info" }),
      ],
      [],
    );
    expect(alerts.map((a) => a.advisoryId)).toEqual(["MAL-2025-1"]);
  });

  it("sends once per advisory: a second run with the stored keys sends none", () => {
    const first = selectAdvisoryAlerts([advisory()], []);
    expect(first.alerts).toHaveLength(1);
    const second = selectAdvisoryAlerts([advisory()], first.alerts.map((a) => a.key));
    expect(second.alerts).toEqual([]);
  });

  it("one alert per advisory even when it hits several locked copies", () => {
    const { alerts } = selectAdvisoryAlerts(
      [advisory(), advisory({ installedVersion: "4.17.15" })],
      [],
    );
    expect(alerts).toHaveLength(1);
    expect(alerts[0].message).toContain("4.17.15");
  });

  it("says when no fixed version exists rather than inventing one", () => {
    const { alerts } = selectAdvisoryAlerts([advisory({ fixedVersion: null })], []);
    expect(alerts[0].fixedVersion).toBeNull();
    expect(alerts[0].message).toMatch(/no fixed version/i);
  });

  it("curated fallback entries are not new advisories: no alert, and the skip is reported", () => {
    const res = selectAdvisoryAlerts([advisory({ source: "fallback", published: null })], []);
    expect(res.alerts).toEqual([]);
    expect(res.liveCheck).toBe("skipped");
  });
});

describe("advisoriesFromFindings", () => {
  it("pulls advisories off SUPPLY-001 findings and reads the live-check status from SUPPLY-011", () => {
    const base = { references: [], evidence: [] } as unknown as Finding;
    const findings = [
      { ...base, ruleId: "SUPPLY-001", advisory: advisory() },
      { ...base, ruleId: "AUTH-001" },
    ] as Finding[];
    expect(advisoriesFromFindings(findings)).toEqual({ advisories: [advisory()], liveCheck: "ok" });
    const skipped = [...findings, { ...base, ruleId: "SUPPLY-011" } as Finding];
    expect(advisoriesFromFindings(skipped).liveCheck).toBe("skipped");
  });
});
