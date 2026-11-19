import { isAbsolute, relative, sep } from "path";
import { minimatch } from "minimatch";
import type { Finding } from "../model/types.js";

/**
 * Set aside findings that sit wholly inside a path the user listed under
 * `ignore` in .sentinelrc.json. Some rules walk the project tree themselves
 * rather than using the recon file list, so skipping the paths during the walk
 * is not enough to keep their findings out of the main report. A finding with
 * evidence both inside and outside the ignored paths is kept.
 *
 * Pass `ignored` on to the reporter: what the config leaves out is still
 * listed and counted, apart from the findings.
 */
export function splitIgnoredFindings(
  findings: Finding[],
  projectPath: string,
  ignore: string[],
): { kept: Finding[]; ignored: Finding[] } {
  if (ignore.length === 0) return { kept: findings, ignored: [] };
  // Same glob the project walk builds from each excluded path.
  const globs = ignore.map((entry) => `**/${entry}/**`);
  const isIgnored = (file: string) => {
    const rel = (isAbsolute(file) ? relative(projectPath, file) : file).split(sep).join("/");
    return globs.some((glob) => minimatch(rel, glob, { dot: true }));
  };
  const kept: Finding[] = [];
  const ignored: Finding[] = [];
  for (const finding of findings) {
    const files = finding.evidence.map((e) => e.file).filter(Boolean);
    (files.length > 0 && files.every(isIgnored) ? ignored : kept).push(finding);
  }
  return { kept, ignored };
}

/** One plain line per ignored finding: id, title, then where it is. */
export function describeIgnoredFinding(finding: Finding): string {
  const where = finding.evidence.map((e) => e.file + (e.line ? `:${e.line}` : "")).join(", ");
  return `${finding.id}  ${finding.title}  ${where}`;
}
