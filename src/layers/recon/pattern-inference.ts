import { safeReadFile } from "../../utils/fs.js";
import type { ApiEndpoint, InferredPattern } from "../../model/types.js";

// MVP: hardcoded prefix-style groups, evaluated in order. An endpoint is
// assigned to the FIRST matching group only — `src/app/api/**` is the
// catch-all and intentionally appears last so admin/portal/v1/internal
// claim their endpoints first. Match is by path-substring (the leading "/"
// anchors it inside an absolute path so a file like
// `/repo/src/app/api/admin/users/route.ts` lands in admin).
const GROUPS: Array<{ glob: string; needle: string }> = [
  { glob: "src/app/api/admin/**", needle: "/src/app/api/admin/" },
  { glob: "src/app/api/portal/**", needle: "/src/app/api/portal/" },
  { glob: "src/app/api/v1/**", needle: "/src/app/api/v1/" },
  { glob: "src/app/api/internal/**", needle: "/src/app/api/internal/" },
  { glob: "src/app/api/**", needle: "/src/app/api/" },
];

// Helper-call shape: same regex used by detectAuthCheck's verb+noun arm in
// endpoint-discovery.ts, but with the helper *name* captured so we can
// tally occurrences. Verbs and nouns are kept identical to the structural
// detector so what we infer matches what the rule layer will compare against.
const HELPER_CALL_RE =
  /\b((?:require|ensure|assert|verify|check|validate|get|fetch|load)\w*(?:Auth|Session|User|Permission|Role|Staff|Portal|Member|Principal|Token|Password)\w*)\s*\(/g;

const MIN_SAMPLE_SIZE = 5;
const MIN_PREVALENCE = 0.6;
const MAX_EVIDENCE_FILES = 3;

interface GroupBucket {
  glob: string;
  endpoints: ApiEndpoint[];
}

function bucketEndpoints(endpoints: ApiEndpoint[]): GroupBucket[] {
  const buckets: GroupBucket[] = GROUPS.map((g) => ({ glob: g.glob, endpoints: [] }));
  for (const ep of endpoints) {
    for (let i = 0; i < GROUPS.length; i++) {
      if (ep.file.includes(GROUPS[i].needle)) {
        buckets[i].endpoints.push(ep);
        break;
      }
    }
  }
  return buckets;
}

export async function inferAuthPatterns(
  endpoints: ApiEndpoint[],
): Promise<InferredPattern[]> {
  if (endpoints.length === 0) return [];

  const buckets = bucketEndpoints(endpoints);
  const patterns: InferredPattern[] = [];

  for (const bucket of buckets) {
    const sampleSize = bucket.endpoints.length;
    if (sampleSize < MIN_SAMPLE_SIZE) continue;

    // Read each endpoint's source and tally helper-name occurrences.
    // `helperFiles` records up to MAX_EVIDENCE_FILES files per helper that
    // demonstrate the pattern — used to populate `evidenceFiles` for the
    // dominant helper without re-reading sources.
    const counts = new Map<string, number>();
    const helperFiles = new Map<string, string[]>();

    for (const ep of bucket.endpoints) {
      let source: string;
      try {
        source = await safeReadFile(ep.file);
      } catch {
        // Skip endpoints we can't read — they don't contribute to the tally
        // either way. They still count toward sampleSize because the user's
        // intent was "infer from the group as it exists on disk."
        continue;
      }

      // Use a fresh regex per file — global regexes carry lastIndex state
      // across calls otherwise.
      const re = new RegExp(HELPER_CALL_RE.source, HELPER_CALL_RE.flags);
      const seenInThisFile = new Set<string>();
      let match: RegExpExecArray | null;
      while ((match = re.exec(source)) !== null) {
        const name = match[1];
        // Count each helper at most once per file so a handler that calls
        // requireAuth() twice doesn't double-skew the prevalence.
        if (seenInThisFile.has(name)) continue;
        seenInThisFile.add(name);
        counts.set(name, (counts.get(name) ?? 0) + 1);
        const files = helperFiles.get(name) ?? [];
        // Dedupe: a route file with multiple HTTP methods (GET+POST) appears
        // as multiple endpoints, all pointing at the same source file. We want
        // distinct files in evidence, not the same path repeated.
        if (files.length < MAX_EVIDENCE_FILES && !files.includes(ep.file)) {
          files.push(ep.file);
          helperFiles.set(name, files);
        }
      }
    }

    if (counts.size === 0) continue;

    // Pick the most-frequent helper; ties broken by insertion order (first
    // seen wins), which is stable enough for an MVP.
    let dominant: string | null = null;
    let dominantCount = 0;
    for (const [name, count] of counts) {
      if (count > dominantCount) {
        dominant = name;
        dominantCount = count;
      }
    }
    if (!dominant) continue;

    const prevalence = dominantCount / sampleSize;
    if (prevalence < MIN_PREVALENCE) continue;

    patterns.push({
      domain: "auth",
      pathGlob: bucket.glob,
      dominantHelper: dominant,
      prevalence,
      sampleSize,
      evidenceFiles: helperFiles.get(dominant) ?? [],
    });
  }

  return patterns;
}
