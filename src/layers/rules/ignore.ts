import { isAbsolute, join } from "path";
import { safeReadFile } from "../../utils/fs.js";
import type { Finding, IgnoredFinding } from "../../model/types.js";

// The one place `sentinel:ignore` is understood.
//
// Write `sentinel:ignore RULE-ID` in a comment anywhere in a file and that
// rule's findings for that file are ignored. Several ids may follow one
// marker, separated by spaces or commas; anything after the ids is the
// reason and is not read.
//
//   // sentinel:ignore AUTH-001 — verified by HMAC, see lib/worker-auth.ts
//   # sentinel:ignore UPLOAD-001, UPLOAD-007
//
// The comment is per file, not per line: it covers the findings whose first
// evidence file is the file it sits in. An ignored finding is never dropped.
// splitIgnored() hands it back in `ignored`, and every report counts and
// lists it, so a silenced alarm always leaves a trace.

const MARKER = /sentinel:ignore([ \t]+[^\r\n]*)/g;
// One rule id at the start of what follows the marker: a whole id, so
// `AUTH-0011` never stands for `AUTH-001`, but `AUTH-001:` and `AUTH-001.` do.
const NEXT_RULE_ID = /^[ \t,]*([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)(?![A-Za-z0-9_-])/;

/** Rule ids named by `sentinel:ignore` comments in `source`, with the 1-based line of the first mention. */
export function ignoredRuleIds(source: string): Map<string, number> {
  const ids = new Map<string, number>();
  if (!source.includes("sentinel:ignore")) return ids;
  for (const match of source.matchAll(MARKER)) {
    const line = source.slice(0, match.index).split("\n").length;
    let rest = match[1];
    for (let id = NEXT_RULE_ID.exec(rest); id; id = NEXT_RULE_ID.exec(rest)) {
      if (!ids.has(id[1])) ids.set(id[1], line);
      rest = rest.slice(id[0].length);
    }
  }
  return ids;
}

/** True when `source` carries a `sentinel:ignore` comment naming `ruleId`. */
export function hasIgnoreComment(source: string, ruleId: string): boolean {
  return ignoredRuleIds(source).has(ruleId);
}

/**
 * Split rule findings into the ones that still alarm and the ones a
 * `sentinel:ignore` comment covers. `findings` and `ignored` together are
 * always exactly the input. A finding with no evidence file, or whose file
 * cannot be read, stays active.
 */
export async function splitIgnored(
  findings: Finding[],
  projectRoot: string,
  ruleIdOf: (finding: Finding) => string | undefined = (f) => f.ruleId,
): Promise<{ findings: Finding[]; ignored: IgnoredFinding[] }> {
  const perFile = new Map<string, Promise<Map<string, number>>>();
  const idsIn = (file: string) => {
    let ids = perFile.get(file);
    if (!ids) {
      ids = safeReadFile(file).then(ignoredRuleIds, () => new Map<string, number>());
      perFile.set(file, ids);
    }
    return ids;
  };

  const active: Finding[] = [];
  const ignored: IgnoredFinding[] = [];
  for (const finding of findings) {
    const ruleId = ruleIdOf(finding);
    const evidenceFile = finding.evidence[0]?.file;
    if (!ruleId || !evidenceFile) {
      active.push(finding);
      continue;
    }
    const file = isAbsolute(evidenceFile) ? evidenceFile : join(projectRoot, evidenceFile);
    const line = (await idsIn(file)).get(ruleId);
    if (line === undefined) active.push(finding);
    else ignored.push({ ruleId, file, line, finding });
  }
  return { findings: active, ignored };
}
