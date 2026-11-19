import { execSync } from "node:child_process";
import { mkdtempSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const GIT_URL_PATTERNS = [
  // https://github.com/user/repo
  // https://github.com/user/repo.git
  // https://gitlab.com/user/repo
  /^https?:\/\/(github|gitlab|bitbucket)\.\w+\//,
  // git@github.com:user/repo.git
  /^git@/,
];

function isGitUrl(input: string): boolean {
  return GIT_URL_PATTERNS.some((p) => p.test(input));
}

// Normalize GitHub URLs: strip trailing slashes, tree/branch paths, and ensure .git suffix
function normalizeGitUrl(url: string): string {
  let u = url.replace(/\/+$/, "");
  // Strip /tree/branch or /blob/branch paths (e.g. github.com/user/repo/tree/main)
  u = u.replace(/\/(tree|blob)\/[^/]+.*$/, "");
  if (!u.endsWith(".git")) u += ".git";
  return u;
}

/**
 * If `target` is a local path, return it as-is.
 * If it's a Git URL, shallow-clone to a temp dir and return that path.
 */
export async function resolveTarget(target: string): Promise<string> {
  if (!isGitUrl(target)) {
    if (!existsSync(target)) {
      throw new Error(`Path does not exist: ${target}`);
    }
    return target;
  }

  const cloneUrl = normalizeGitUrl(target);
  const repoName = cloneUrl.split("/").pop()?.replace(/\.git$/, "") ?? "repo";
  const tmpDir = mkdtempSync(join(tmpdir(), `sentinel-${repoName}-`));
  const dest = join(tmpDir, repoName);

  process.stderr.write(`Cloning ${cloneUrl} ...\n`);
  try {
    execSync(`git clone --depth 1 --single-branch ${cloneUrl} ${dest}`, {
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 120_000,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to clone ${cloneUrl}: ${msg}`);
  }

  process.stderr.write(`Cloned to ${dest}\n`);

  // Register cleanup on exit
  process.on("exit", () => {
    try {
      execSync(`rm -rf ${tmpDir}`, { stdio: "ignore" });
    } catch {
      // best-effort cleanup
    }
  });

  return dest;
}
