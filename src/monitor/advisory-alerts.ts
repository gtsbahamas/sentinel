// Monitor alerts for newly published advisories (gtsbahamas/fleet#8880).
//
// A monitoring host (ShipSafe Monitor) rescans a project on a schedule. It
// keeps the alert keys it has already sent for that project and passes them
// back here; only critical/high advisories found by the live OSV.dev check
// that have no stored key become alerts. Curated fallback entries never alert:
// they are not newly published, and a run that fell back says so in liveCheck.
//
// Import from the published package as
//   shipsafe-sentinel/dist/monitor/advisory-alerts.js

import type { Finding, FindingAdvisory, Severity } from "../model/types.js";

export interface AdvisoryAlert {
  /** Store this per project; pass it back to suppress repeats. */
  key: string;
  advisoryId: string;
  aliases: string[];
  package: string;
  installedVersion: string;
  fixedVersion: string | null;
  published: string | null;
  severity: Severity;
  summary: string;
  url: string;
  /** Plain-text alert body naming package, version, advisory, date and fix. */
  message: string;
}

export interface AdvisoryAlertSelection {
  alerts: AdvisoryAlert[];
  /** "skipped" when the scan fell back to the curated list (no live data). */
  liveCheck: "ok" | "skipped";
}

const ALERT_SEVERITIES: ReadonlySet<Severity> = new Set(["critical", "high"]);

/** Advisories carried by a scan's findings, and whether the live check ran. */
export function advisoriesFromFindings(findings: Finding[]): { advisories: FindingAdvisory[]; liveCheck: "ok" | "skipped" } {
  const advisories = findings.filter((f) => f.ruleId === "SUPPLY-001" && f.advisory).map((f) => f.advisory!);
  const skipped = findings.some((f) => f.ruleId === "SUPPLY-011");
  return { advisories, liveCheck: skipped ? "skipped" : "ok" };
}

export function selectAdvisoryAlerts(advisories: FindingAdvisory[], alreadyAlerted: Iterable<string>): AdvisoryAlertSelection {
  const seen = new Set(alreadyAlerted);
  const byId = new Map<string, FindingAdvisory[]>();
  let fellBack = false;
  for (const a of advisories) {
    if (a.source !== "osv") {
      fellBack = true;
      continue;
    }
    if (!ALERT_SEVERITIES.has(a.severity) || seen.has(a.id)) continue;
    if (!byId.has(a.id)) byId.set(a.id, []);
    byId.get(a.id)!.push(a);
  }

  const alerts: AdvisoryAlert[] = [];
  for (const [id, hits] of byId) {
    const first = hits[0];
    const versions = [...new Set(hits.map((h) => h.installedVersion))];
    const label = first.aliases.length ? `${id} (${first.aliases.join(", ")})` : id;
    const published = first.published ? `published ${first.published.slice(0, 10)}` : "publish date not given";
    const fix = first.fixedVersion ? `Upgrade to ${first.fixedVersion} or later.` : "No fixed version is published yet; remove or replace the package.";
    alerts.push({
      key: id,
      advisoryId: id,
      aliases: first.aliases,
      package: first.package,
      installedVersion: first.installedVersion,
      fixedVersion: first.fixedVersion,
      published: first.published,
      severity: first.severity,
      summary: first.summary,
      url: `https://osv.dev/vulnerability/${id}`,
      message: `${first.severity.toUpperCase()}: ${first.package}@${versions.join(", ")} is affected by ${label}, ${published}. ${first.summary} ${fix}`,
    });
  }
  return { alerts, liveCheck: fellBack ? "skipped" : "ok" };
}
