import { existsSync } from "fs";
import { join, extname, basename, dirname, resolve as resolvePath } from "path";
import { safeReadFile, walkRepoArtifacts, type RepoArtifact } from "../../../utils/fs.js";
import type { Finding, StackProfile } from "../../../model/types.js";
import type { SecurityRule } from "../registry.js";
import type { ProjectContext } from "../../context/types.js";

// ---------------------------------------------------------------------------
// repo-integrity — "is this repository what it claims to be?"
//
// Every other domain asks whether the code is insecure. This one asks a
// question the code cannot answer, because the answer is not in the code:
// a repository can consist entirely of clean, genuine, upstream source and
// still exist to deliver a payload sitting beside it.
//
// Motivating case (2026-08-30): github.com/jochi2018/Soup — an unattributed
// re-upload of the Apache-2.0 project MakazhanAlpamys/soup. Source byte-clean
// against upstream at v0.73.2. One commit, "Update README.md", which swapped
// upstream's README for one aimed at non-technical users and added a download
// badge pointing at src/3.0.zip, committed in-repo. That archive held
// Application.cmd ("start util.exe cert.txt"), util.exe (LuaJIT 2.1 renamed),
// and cert.txt (182 KB of obfuscated Lua). Sentinel v0.2.1 scanned that repo
// and returned 0 critical — the source really was clean, and walkProject()'s
// extension allowlist meant the zip was never enumerated.
//
// These rules run against walkRepoArtifacts(), which has no allowlist.
// ---------------------------------------------------------------------------

const ALL_STACKS: StackProfile[] = [
  "nextjs-supabase",
  "react-vite-supabase",
  "generic-web",
  "go",
  "python",
  "rust",
  "unknown",
];

const DEFAULT_ARTIFACT_EXCLUDE = ["node_modules", ".next", "dist", "out", "build", ".git"];

// walkRepoArtifacts globs the WHOLE tree with no extension allowlist, so it is
// the most expensive walk in the engine. All five rules need the same result,
// and runRules() fires them concurrently — without this they would each glob
// the tree independently. Keyed by root + effective exclude so a second project
// scanned in the same process cannot read the first one's tree.
const artifactCache = new Map<string, Promise<RepoArtifact[]>>();

function artifactsFor(root: string, context?: ProjectContext | null): Promise<RepoArtifact[]> {
  const extra = Array.isArray(context?.excludedPaths) ? context.excludedPaths : [];
  const exclude = [...new Set([...DEFAULT_ARTIFACT_EXCLUDE, ...extra])];
  const key = `${root}\u0000${exclude.join(",")}`;
  let hit = artifactCache.get(key);
  if (!hit) {
    hit = walkRepoArtifacts(root, exclude);
    artifactCache.set(key, hit);
  }
  return hit;
}

/**
 * Drop memoized trees. A long-lived process (`sentinel mcp`) scanning the same
 * path twice must re-walk it, or the second scan reports the first one's files.
 * Called beside registerRules() at every command entry point.
 */
export function resetRepoIntegrityCache(): void {
  artifactCache.clear();
}

function mkFinding(
  ruleId: string,
  severity: Finding["severity"],
  title: string,
  description: string,
  impact: string,
  remediation: string,
  evidence: Finding["evidence"],
  refs: { cwe?: string; owasp?: string },
  confidence: Finding["confidence"] = "high",
): Finding {
  return {
    id: `${ruleId}-${evidence[0]?.file ?? "x"}-${evidence[0]?.line ?? 0}-${evidence[0]?.snippet ?? ""}`.slice(0, 200),
    domain: "repo-integrity",
    severity,
    confidence,
    title,
    description,
    impact,
    evidence,
    remediation,
    references: [refs.cwe, refs.owasp].filter(Boolean) as string[],
    layer: "rules",
    ruleId,
    cwe: refs.cwe,
    owasp: refs.owasp,
  };
}

// Installers and native executables. Nothing in this set has a routine reason
// to be committed to a source repository — these are build OUTPUT, and the
// build that produces them is what belongs in git.
const EXECUTABLE_EXT = new Set([
  ".exe", ".msi", ".scr", ".com", ".cpl",
  ".apk", ".dmg", ".pkg", ".deb", ".rpm", ".appimage",
]);

// Compiled artifacts that DO turn up legitimately — Python C-extensions, Rust
// cdylibs, JNI bundles. Reported, but never critical on their own.
const NATIVE_EXT = new Set([".dll", ".so", ".dylib", ".jar", ".node", ".pyd", ".wasm"]);

// Windows script hosts. Text, frequently legitimate tooling — the signal is
// weak alone and strong next to an executable, which REPO-001 accounts for.
const SCRIPT_EXT = new Set([".bat", ".cmd", ".ps1", ".vbs", ".wsf", ".hta"]);

const ARCHIVE_EXT = new Set([
  ".zip", ".7z", ".rar", ".tgz", ".tar", ".gz", ".bz2", ".xz", ".cab", ".iso", ".lzh",
]);

function extOf(rel: string): string {
  const lower = rel.toLowerCase();
  if (lower.endsWith(".tar.gz")) return ".tgz";
  return extname(lower);
}

/**
 * Owner and repo of the GitHub remote, lowercased, or null when there is none
 * to read (a zip upload, or a non-GitHub remote). REPO-004 reads the same
 * `.git/config` for the owner alone; REPO-003 needs the repo name too, because
 * "same owner, different repo" is still not this repository.
 */
async function githubRemote(root: string): Promise<{ owner: string; repo: string } | null> {
  const gitConfig = join(root, ".git", "config");
  if (!existsSync(gitConfig)) return null;
  let cfg: string;
  try {
    cfg = await safeReadFile(gitConfig);
  } catch {
    return null;
  }
  const m =
    /url\s*=\s*(?:https:\/\/github\.com\/|git@github\.com:)([^/\s]+)\/(\S+?)(?:\.git)?\s*$/im.exec(
      cfg,
    );
  if (!m) return null;
  return { owner: m[1].toLowerCase(), repo: m[2].toLowerCase() };
}

/**
 * Split a GitHub file URL into the repository it addresses and the path inside
 * that repository. Handles the three shapes that actually serve file bytes:
 *
 *   raw.githubusercontent.com/<owner>/<repo>/<ref>/<path>
 *   raw.githubusercontent.com/<owner>/<repo>/refs/heads/<branch>/<path>
 *   github.com/<owner>/<repo>/(raw|blob)/<ref>/<path>
 *
 * Returns null when the URL is not one of those, which is the safe direction:
 * an unrecognised link is not evidence of an in-repository download.
 */
function parseGithubFileUrl(
  href: string,
): { owner: string; repo: string; path: string } | null {
  const m =
    /^https?:\/\/raw\.githubusercontent\.com\/([^/]+)\/([^/]+)\/(.+)$/i.exec(href) ??
    /^https?:\/\/github\.com\/([^/]+)\/([^/]+)\/(?:raw|blob)\/(.+)$/i.exec(href);
  if (!m) return null;

  // Strip the ref. Either an explicit refs/heads|tags/<name>/ prefix, or a
  // single opaque segment (branch name, tag, or commit sha).
  const rest = m[3];
  const explicit = /^refs\/(?:heads|tags)\/[^/]+\/(.+)$/i.exec(rest);
  const path = explicit ? explicit[1] : rest.split("/").slice(1).join("/");
  if (!path) return null;

  return { owner: m[1].toLowerCase(), repo: m[2].toLowerCase(), path };
}

/**
 * Archives a manifest deliberately vendors, e.g. npm's
 * `"dep": "file:./vendor/thing-1.2.3.tgz"`. Declared means expected: a vendored
 * tarball a package.json points at is a supply-chain question (is that tarball
 * what it claims?), not a repo-integrity one (why is this here at all?).
 */
async function declaredArchives(root: string, artifacts: RepoArtifact[]): Promise<Set<string>> {
  const declared = new Set<string>();
  const manifests = artifacts.filter((a) => basename(a.rel) === "package.json");

  for (const manifest of manifests) {
    let raw: string;
    try {
      raw = await safeReadFile(manifest.path);
    } catch {
      continue;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      continue;
    }
    if (typeof parsed !== "object" || parsed === null) continue;

    const blocks = ["dependencies", "devDependencies", "optionalDependencies"] as const;
    for (const block of blocks) {
      const deps = (parsed as Record<string, unknown>)[block];
      if (typeof deps !== "object" || deps === null) continue;
      for (const spec of Object.values(deps as Record<string, unknown>)) {
        if (typeof spec !== "string" || !spec.startsWith("file:")) continue;
        // Resolve relative to the manifest, then back to a repo-relative path.
        const abs = resolvePath(dirname(manifest.path), spec.slice("file:".length));
        declared.add(abs);
      }
    }
  }
  return declared;
}

export const repoIntegrityRules: SecurityRule[] = [
  {
    id: "REPO-001",
    domain: "repo-integrity",
    title: "Executable committed to the repository",
    description:
      "A compiled executable, installer, or native library is committed to the source tree",
    impact:
      "A source repository that ships a prebuilt executable asks every user to run a binary nobody can review. This is the delivery half of the most common repository-laundering attack: genuine source provides the cover, and the payload sits beside it as a file no source scanner reads.",
    severity: "critical",
    appliesTo: ALL_STACKS,
    references: { cwe: "CWE-506" },
    async check(model, context) {
      const root = model.meta.path;
      const artifacts = await artifactsFor(root, context);
      const findings: Finding[] = [];

      for (const a of artifacts) {
        const ext = extOf(a.rel);
        let severity: Finding["severity"] | null = null;
        let kind = "";

        if (EXECUTABLE_EXT.has(ext)) {
          severity = "critical";
          kind = "executable or installer";
        } else if (NATIVE_EXT.has(ext)) {
          severity = "high";
          kind = "compiled native artifact";
        } else if (SCRIPT_EXT.has(ext)) {
          severity = "medium";
          kind = "Windows script";
        }
        if (!severity) continue;

        findings.push(
          mkFinding(
            "REPO-001",
            severity,
            `${kind} committed: ${a.rel}`,
            `\`${a.rel}\` (${a.size} bytes) is a ${kind} committed to a source repository. Source repositories describe how to BUILD artifacts; they should not carry the artifacts themselves.`,
            "A user or agent cloning this repository receives a binary they cannot review. If it is not the artifact you think it is, nothing in the source would reveal that.",
            `Remove \`${a.rel}\` from version control and publish the artifact through a release channel (GitHub Releases, a package registry) where it is versioned, checksummed, and attributable. If it is genuinely required at build time, vendor it through a manifest so its presence is declared.`,
            [{ file: a.rel, snippet: `${ext} · ${a.size} bytes` }],
            { cwe: "CWE-506" },
            severity === "critical" ? "high" : "medium",
          ),
        );
      }
      return findings;
    },
  },

  {
    id: "REPO-002",
    domain: "repo-integrity",
    title: "Undeclared archive committed to the repository",
    description: "A compressed archive is committed and no manifest declares it",
    impact:
      "An archive is opaque to every source-level scanner, including this one — its contents are not enumerated, so no rule can score them. An archive no manifest references is present for a reason the repository does not state.",
    severity: "high",
    appliesTo: ALL_STACKS,
    references: { cwe: "CWE-506" },
    async check(model, context) {
      const root = model.meta.path;
      const artifacts = await artifactsFor(root, context);
      const declared = await declaredArchives(root, artifacts);
      const findings: Finding[] = [];

      for (const a of artifacts) {
        if (!ARCHIVE_EXT.has(extOf(a.rel))) continue;
        // A tarball a package.json vendors via `file:` is declared, and
        // therefore a supply-chain question rather than an integrity one.
        if (declared.has(a.path)) continue;

        findings.push(
          mkFinding(
            "REPO-002",
            "high",
            `Undeclared archive committed: ${a.rel}`,
            `\`${a.rel}\` (${a.size} bytes) is an archive committed to the repository, and no package manifest references it. Its contents are not scanned by any rule in this engine.`,
            "Archives are the standard container for payloads that must survive source review: the repository's own code stays clean and reviewable while the archive travels alongside it unexamined.",
            `Confirm what \`${a.rel}\` contains and why it is in version control. If it is a build input, declare it in a manifest so its presence is explicit. If it is a release artifact, move it to a release channel. If neither, remove it.`,
            [{ file: a.rel, snippet: `${extOf(a.rel)} · ${a.size} bytes` }],
            { cwe: "CWE-506" },
          ),
        );
      }
      return findings;
    },
  },

  {
    id: "REPO-003",
    domain: "repo-integrity",
    title: "Documentation offers an in-repository binary download",
    description:
      "A markdown file links to an executable or archive stored inside this repository",
    impact:
      "This is the delivery mechanism, not just the payload. A README that routes users to a committed binary — rather than to a package registry or a signed release — converts passive repository contents into an active install instruction, and it is aimed at exactly the users least equipped to question it.",
    severity: "critical",
    appliesTo: ALL_STACKS,
    references: { cwe: "CWE-494" },
    async check(model, context) {
      const root = model.meta.path;
      const artifacts = await artifactsFor(root, context);
      const findings: Finding[] = [];

      const docs = artifacts.filter(
        (a) => [".md", ".mdx", ".rst", ".txt"].includes(extOf(a.rel)) && a.size < 2_000_000,
      );

      // Any URL or relative path ending in a downloadable artifact extension.
      const riskyExt = [...EXECUTABLE_EXT, ...ARCHIVE_EXT].map((e) => e.replace(".", "\\."));
      // Markdown link/image targets and HTML href/src only. A bare `<...>`
      // alternative also matched prose and CLI examples — `--output out.tar` in
      // docs/commands.md was reported as a download link on the first run.
      const linkRe = new RegExp(
        `(?:\\]\\(|href=["']|src=["'])\\s*([^\\s)"'<>]+(?:${riskyExt.join("|")}))(?:[?#][^\\s)"'<>]*)?`,
        "gi",
      );

      // A relative target is only a download offer if the file is actually
      // here. Documentation naming an artifact the tool PRODUCES (out.tar,
      // dist/app.zip) names a path that does not exist in the tree.
      const present = new Set(artifacts.map((a) => a.rel));

      // Whose repository this is, when the tree carries a remote to say so.
      const remote = await githubRemote(root);

      for (const doc of docs) {
        let text: string;
        try {
          text = await safeReadFile(doc.path);
        } catch {
          continue;
        }

        const lines = text.split("\n");
        // Inside a fenced block, `](url)` renders as literal text, not as a
        // clickable link, so it cannot function as a download offer to a reader.
        // Security writing quotes hostile markdown as evidence — the essay that
        // surfaced this reproduces the Soup trojan's own download badge so the
        // reader can grep for the shape — and that is documentation ABOUT a
        // link, not the offer of one.
        let inFence = false;
        for (let i = 0; i < lines.length; i++) {
          if (/^\s*(?:```|~~~)/.test(lines[i])) {
            inFence = !inFence;
            continue;
          }
          if (inFence) continue;

          linkRe.lastIndex = 0; // /g keeps state across calls — reset per line.
          let m: RegExpExecArray | null;
          while ((m = linkRe.exec(lines[i])) !== null) {
            const href = m[1];
            const isRawHost = /raw\.githubusercontent\.com|github\.com\/[^/]+\/[^/]+\/(?:raw|blob)\//i.test(href);
            const isRelative = !/^https?:\/\//i.test(href);
            // A link to an external release channel is normal distribution.
            // A link that resolves back INTO this repository is the pattern.
            if (!isRawHost && !isRelative) continue;
            if (isRelative && !isRawHost) {
              const norm = href.replace(/^\.\//, "").replace(/^\//, "").split(/[?#]/)[0];
              if (!present.has(norm)) continue; // names a file that isn't in the repo
            }
            if (isRawHost) {
              // The relative branch above proves "resolves INTO this repository"
              // before reporting it. This branch used to assert it without ever
              // checking, so ANY third-party raw.githubusercontent link — the
              // normal way to cite someone else's file — was reported as an
              // in-repository download, in a finding whose own text said the
              // link "resolves into this repository". Establish it instead:
              //   - a remote we can read settles it outright;
              //   - with no remote (zip upload, non-GitHub origin), fall back to
              //     the same evidence the relative branch uses — is that exact
              //     path actually sitting in this tree?
              // The trojan case survives both ways: jochi2018/Soup's README
              // points at jochi2018/Soup, and src/3.0.zip is right there.
              const target = parseGithubFileUrl(href);
              if (!target) continue;
              if (remote) {
                if (target.owner !== remote.owner || target.repo !== remote.repo) continue;
              } else if (!present.has(target.path)) {
                continue;
              }
            }

            findings.push(
              mkFinding(
                "REPO-003",
                "critical",
                `${basename(doc.rel)} links to an in-repository download: ${href}`,
                `\`${doc.rel}\` line ${i + 1} offers \`${href}\` as a download. The link resolves into this repository rather than to a package registry or a signed release.`,
                "Users following documentation trust it more than they trust the repository's file listing. A download instruction pointing at a committed binary is an install instruction for an unreviewable artifact.",
                "Distribute through the project's package registry or a signed GitHub Release. If this repository is not the upstream source, verify it against upstream before running anything it offers.",
                [{ file: doc.rel, line: i + 1, snippet: href.slice(0, 160) }],
                { cwe: "CWE-494" },
              ),
            );
          }
        }
      }
      return findings;
    },
  },

  {
    id: "REPO-004",
    domain: "repo-integrity",
    title: "Attribution does not match the repository origin",
    description:
      "CODEOWNERS or NOTICE names a party other than the owner of the git remote",
    impact:
      "Re-uploaded repositories keep upstream's governance files because editing them is unnecessary work — the source is the cover story. An owner mismatch between the remote and the attribution files is the cheapest available signal that this tree was authored somewhere else.",
    severity: "high",
    appliesTo: ALL_STACKS,
    references: { cwe: "CWE-1104" },
    async check(model) {
      const root = model.meta.path;
      const findings: Finding[] = [];

      const gitConfig = join(root, ".git", "config");
      if (!existsSync(gitConfig)) return findings; // zip upload — no remote to compare.

      let cfg: string;
      try {
        cfg = await safeReadFile(gitConfig);
      } catch {
        return findings;
      }

      const remote = /url\s*=\s*(?:https:\/\/github\.com\/|git@github\.com:)([^/\s]+)\//i.exec(cfg);
      if (!remote) return findings;
      const remoteOwner = remote[1].toLowerCase();

      for (const name of ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"]) {
        const p = join(root, name);
        if (!existsSync(p)) continue;
        let text: string;
        try {
          text = await safeReadFile(p);
        } catch {
          continue;
        }
        const owners = new Set(
          [...text.matchAll(/@([A-Za-z0-9][A-Za-z0-9-]{0,38})\b/g)].map((m) => m[1].toLowerCase()),
        );
        if (owners.size === 0 || owners.has(remoteOwner)) continue;

        findings.push(
          mkFinding(
            "REPO-004",
            "high",
            `CODEOWNERS names ${[...owners].join(", ")}, remote is owned by ${remoteOwner}`,
            `\`${name}\` assigns ownership to ${[...owners].map((o) => "@" + o).join(", ")}, but the configured git remote belongs to \`${remoteOwner}\`. Either this repository is a copy that kept upstream's governance files, or CODEOWNERS is stale.`,
            "If this is a copy, the source being genuine proves nothing about the artifacts shipped alongside it — the genuine source is what makes the copy credible.",
            `Confirm the upstream project and compare this tree against it. If this is a legitimate fork, update \`${name}\` to reflect actual ownership so the signal stops firing.`,
            [{ file: name, snippet: `remote=${remoteOwner} owners=${[...owners].join(",")}` }],
            { cwe: "CWE-1104" },
            "medium",
          ),
        );
      }
      return findings;
    },
  },

  {
    id: "REPO-005",
    domain: "repo-integrity",
    title: "Obfuscated payload in a non-source file",
    description:
      "A file outside the source allowlist carries an obfuscator signature or machine-generated density",
    impact:
      "Obfuscation in a file the build never compiles has one purpose: to be executed by something else while remaining unreadable to review. Naming it after a benign artifact (a certificate, a log, a data file) is what keeps it out of a reviewer's path.",
    severity: "high",
    appliesTo: ALL_STACKS,
    references: { cwe: "CWE-506" },
    async check(model, context) {
      const root = model.meta.path;
      const artifacts = await artifactsFor(root, context);
      const findings: Finding[] = [];

      // Deliberately EXCLUDES real source extensions: minified JS and generated
      // bundles are obfuscation-shaped and legitimate. The signal here is
      // obfuscation somewhere the toolchain has no reason to look.
      const inertExt = new Set([".txt", ".dat", ".cfg", ".ini", ".log", ".bin", ".res", ".tmp", ".cache"]);

      const signatures: Array<{ re: RegExp; what: string }> = [
        // Lua string-shuffle loader: `local X=function(k)...` plus decimal
        // escape runs. The 2026-08 GitHub loader campaign's exact shape.
        { re: /local\s+\w+\s*=\s*function\s*\(\s*\w+\s*\)[\s\S]{0,400}?\\\d{2,3}\\\d{2,3}/, what: "Lua string-shuffle obfuscator" },
        { re: /FromBase64String\s*\(/i, what: "PowerShell base64 loader" },
        { re: /\[System\.Reflection\.Assembly\]::Load/i, what: "PowerShell in-memory assembly load" },
        { re: /eval\s*\(\s*(?:atob|unescape|String\.fromCharCode)\s*\(/i, what: "JavaScript eval-decode loader" },
        { re: /powershell(?:\.exe)?\s+-(?:enc|EncodedCommand|w\s+hidden)/i, what: "hidden/encoded PowerShell invocation" },
      ];

      for (const a of artifacts) {
        if (!inertExt.has(extOf(a.rel))) continue;
        if (a.size < 512 || a.size > 5_000_000) continue;

        let text: string;
        try {
          text = await safeReadFile(a.path);
        } catch {
          continue; // binary or unreadable — REPO-001/002 cover those.
        }

        const hit = signatures.find((s) => s.re.test(text));
        // Machine-generated density: one enormous line is not hand-written.
        const longest = text.split("\n").reduce((n, l) => (l.length > n ? l.length : n), 0);
        const dense = longest > 5000;

        if (!hit && !dense) continue;

        findings.push(
          mkFinding(
            "REPO-005",
            hit ? "high" : "medium",
            `Obfuscated content in ${a.rel}`,
            hit
              ? `\`${a.rel}\` matches a known ${hit.what}. The file extension implies inert data; the contents are executable logic written to resist reading.`
              : `\`${a.rel}\` contains a single line of ${longest} characters, which is machine-generated rather than authored. Its extension implies inert data.`,
            "A file whose name and extension misrepresent its contents is positioned to be executed by a companion process while surviving human review of the repository.",
            `Open \`${a.rel}\` and establish what generates it and what consumes it. If nothing in the build produces or reads it, treat it as an unexplained payload and remove it.`,
            [{ file: a.rel, snippet: hit ? hit.what : `longest line ${longest} chars` }],
            { cwe: "CWE-506" },
            hit ? "high" : "low",
          ),
        );
      }
      return findings;
    },
  },
];
