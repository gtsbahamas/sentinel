import type { Confidence, Finding, Severity } from "../../model/types.js";

// Lower index = more severe / more confident.
const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
const CONFIDENCE_ORDER: Confidence[] = ["confirmed", "high", "medium", "low"];

const HTTP_METHOD_RE = /\b(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD|ALL)\b/gi;
const HANDLER_WORD_RE = /\b(handler|endpoint|route)s?\b/gi;
const PUNCT_RE = /[.,;:!?(){}[\]"'`]/g;

// Normalize a title for literal-equality comparison. Strips HTTP verbs and
// handler/endpoint/route words so that findings that describe the same
// issue on different method handlers of the same file compare equal.
// Used as a fallback signature when the title contains no classifiable
// issue-type keyword.
export function normalizeTitle(title: string): string {
  return title
    .toLowerCase()
    .replace(HTTP_METHOD_RE, " ")
    .replace(HANDLER_WORD_RE, " ")
    .replace(PUNCT_RE, " ")
    .replace(/\s+/g, " ")
    .trim();
}

// Issue-type taxonomy. Order matters: the first matching tag wins so that
// high-specificity labels (IDOR, RLS bypass) beat general ones (auth bypass,
// input validation). Each finding gets exactly one tag for the purpose of
// dedup clustering. If nothing matches, the tag is "unclassified" and the
// finding falls back to normalized-title literal matching.
const ISSUE_TAGS: Array<{ tag: string; patterns: RegExp[] }> = [
  {
    tag: "idor",
    patterns: [
      /\bidor\b/i,
      /not scoped/i,
      /\bownership\b/i,
      /scop(?:ed|ing)[^.]*(?:user|owner|tenant|graduate|account)/i,
      /without (?:verifying|checking) ownership/i,
      /cross[- ]?(?:tenant|user|account)/i,
    ],
  },
  {
    tag: "rate_limit",
    patterns: [/rate[ -]?limit/i, /throttl/i, /\babuse\b/i],
  },
  {
    tag: "rls_bypass",
    patterns: [/service[ _-]?role/i, /\brls\b/i, /row[- ]?level security/i],
  },
  {
    tag: "privilege_escalation",
    patterns: [/privileg/i, /escal/i, /is[_ ]?priority/i, /priority[_ ]?type/i, /is[_ ]?admin/i, /role assignment/i],
  },
  {
    tag: "csrf_origin",
    patterns: [/origin header/i, /host header/i, /\breferer\b/i, /\bcsrf\b/i],
  },
  {
    tag: "error_leak",
    patterns: [
      /error message/i,
      /stack trace/i,
      /verbose error/i,
      /raw (?:db|database|supabase) error/i,
      /internal (?:db|database) error/i,
      /database error.*client/i,
    ],
  },
  {
    tag: "pii_leak",
    patterns: [/\bpii\b/i, /personal info/i, /email.*expos/i, /expos.*email/i, /leak.*email/i, /data leak/i],
  },
  {
    tag: "race_condition",
    patterns: [/race condition/i, /\btoctou\b/i, /time[- ]?of[- ]?check/i, /concurrent/i],
  },
  {
    tag: "input_injection",
    patterns: [/\bsql injection/i, /\bxss\b/i, /\bssrf\b/i, /command injection/i, /prototype pollution/i],
  },
  {
    tag: "file_upload",
    patterns: [/file upload/i, /\bmime\b/i, /path traversal/i, /filename.*traversal/i],
  },
  {
    tag: "business_logic",
    patterns: [/business[- ]?logic/i, /state manipulat/i, /logic bypass/i, /bypass.*business/i],
  },
  {
    tag: "auth_bypass",
    patterns: [
      /unauthenticated/i,
      /missing auth(?:entication|orization)?/i,
      /no auth(?:entication)? check/i,
      /without auth(?:entication)?/i,
      /bypass auth/i,
    ],
  },
  {
    tag: "input_validation",
    patterns: [
      /\bunvalidated\b/i,
      /not validated/i,
      /missing validation/i,
      /no validation/i,
      /without validation/i,
      /unchecked (?:input|parameter)/i,
      /\bunbounded\b/i,
    ],
  },
];

export function classifyIssueTag(title: string): string {
  for (const entry of ISSUE_TAGS) {
    for (const p of entry.patterns) {
      if (p.test(title)) return entry.tag;
    }
  }
  return "unclassified";
}

// These tags match many legitimately-distinct issues — treating them as
// cluster keys causes false merges (e.g. two unrelated `input_validation`
// bugs on the same file get collapsed into one). Findings with these tags
// fall back to literal normalized-title matching, like unclassified ones.
const BROAD_TAGS = new Set(["input_validation", "business_logic"]);

function firstFile(finding: Finding): string {
  return finding.evidence[0]?.file ?? "";
}

function signatureFor(finding: Finding): string {
  const tag = classifyIssueTag(finding.title);
  // Narrow tags cluster by tag alone. Broad or unclassified tags fall back
  // to literal normalized-title matching so unrelated bugs on the same file
  // don't get collapsed into one finding.
  const payload = tag === "unclassified" || BROAD_TAGS.has(tag) ? `literal:${normalizeTitle(finding.title)}` : tag;
  return `${firstFile(finding)}\u0000${finding.domain}\u0000${payload}`;
}

function isStronger(candidate: Finding, current: Finding): boolean {
  const cs = SEVERITY_ORDER.indexOf(candidate.severity);
  const rs = SEVERITY_ORDER.indexOf(current.severity);
  if (cs !== rs) return cs < rs;
  const cc = CONFIDENCE_ORDER.indexOf(candidate.confidence);
  const rc = CONFIDENCE_ORDER.indexOf(current.confidence);
  return cc < rc;
}

function mergeEvidence(findings: Finding[]): Finding["evidence"] {
  const seen = new Set<string>();
  const merged: Finding["evidence"] = [];
  for (const f of findings) {
    for (const e of f.evidence) {
      const key = `${e.file}\u0000${e.line ?? 0}`;
      if (seen.has(key)) continue;
      seen.add(key);
      merged.push(e);
    }
  }
  return merged;
}

export interface DedupResult {
  findings: Finding[];
  collapsedCount: number;
}

// Collapse near-duplicate AI findings that describe the same file-level
// issue across multiple HTTP method handlers. Grouping key is
// (first-evidence file, domain, normalized title). Within a group we keep
// the strongest representative (highest severity, then highest confidence)
// and merge evidence from the duplicates. Findings from layers other than
// "ai" pass through untouched.
export function dedupAIFindings(findings: Finding[]): DedupResult {
  const ai: Finding[] = [];
  const others: Finding[] = [];
  for (const f of findings) {
    if (f.layer === "ai") ai.push(f);
    else others.push(f);
  }

  const groups = new Map<string, Finding[]>();
  for (const f of ai) {
    const key = signatureFor(f);
    const bucket = groups.get(key);
    if (bucket) bucket.push(f);
    else groups.set(key, [f]);
  }

  let collapsedCount = 0;
  const deduped: Finding[] = [];
  for (const bucket of groups.values()) {
    if (bucket.length === 1) {
      deduped.push(bucket[0]);
      continue;
    }
    collapsedCount += bucket.length - 1;
    let rep = bucket[0];
    for (let i = 1; i < bucket.length; i++) {
      if (isStronger(bucket[i], rep)) rep = bucket[i];
    }
    deduped.push({
      ...rep,
      evidence: mergeEvidence(bucket),
    });
  }

  return {
    findings: [...others, ...deduped],
    collapsedCount,
  };
}
