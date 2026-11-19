import { isAbsolute, relative, sep } from "path";
import { minimatch } from "minimatch";
import type { Finding } from "../model/types.js";

/**
 * Drop findings that sit wholly inside a path the user listed under `ignore`
 * in .sentinelrc.json. Some rules walk the project tree themselves rather than
 * using the recon file list, so skipping the paths during the walk is not
 * enough to keep their findings out of the report. A finding with evidence
 * both inside and outside the ignored paths is kept.
 */
export function dropIgnoredFindings(
  findings: Finding[],
  projectPath: string,
  ignore: string[],
): Finding[] {
  if (ignore.length === 0) return findings;
  // Same glob the project walk builds from each excluded path.
  const globs = ignore.map((entry) => `**/${entry}/**`);
  const isIgnored = (file: string) => {
    const rel = (isAbsolute(file) ? relative(projectPath, file) : file).split(sep).join("/");
    return globs.some((glob) => minimatch(rel, glob, { dot: true }));
  };
  return findings.filter((finding) => {
    const files = finding.evidence.map((e) => e.file).filter(Boolean);
    return files.length === 0 || !files.every(isIgnored);
  });
}
