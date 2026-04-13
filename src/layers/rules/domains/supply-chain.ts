import { existsSync } from "fs";
import { join } from "path";
import { safeReadFile } from "../../../utils/fs.js";
import type { Finding } from "../../../model/types.js";
import type { SecurityRule } from "../registry.js";

function mkFinding(
  ruleId: string,
  severity: Finding["severity"],
  title: string,
  description: string,
  remediation: string,
  evidence: Finding["evidence"],
  refs: { cwe?: string; owasp?: string },
  confidence: Finding["confidence"] = "high",
): Finding {
  return {
    id: `${ruleId}-${evidence[0]?.file ?? "x"}-${evidence[0]?.line ?? 0}-${evidence[0]?.snippet ?? ""}`.slice(0, 200),
    domain: "supply-chain",
    severity,
    confidence,
    title,
    description,
    evidence,
    remediation,
    references: [refs.cwe, refs.owasp].filter(Boolean) as string[],
    layer: "rules",
    ruleId,
    cwe: refs.cwe,
    owasp: refs.owasp,
  };
}

// Minimal curated list of packages with CVEs that still show up in real
// package.jsons. Not a replacement for npm audit — it's a first-pass canary
// for packages that are known-abandoned or known-vulnerable in every published
// version. Entries: [package, version-prefix-or-null, CVE, severity, note].
// null version means "any version currently published is affected".
const KNOWN_VULNERABLE: Array<{
  name: string;
  affected: (v: string) => boolean;
  cve: string;
  severity: Finding["severity"];
  note: string;
}> = [
  {
    name: "event-stream",
    affected: (v) => /^3\.3\.6/.test(v),
    cve: "CVE-2018-1000620",
    severity: "critical",
    note: "Malicious version 3.3.6 shipped with a cryptocurrency-wallet stealer.",
  },
  {
    name: "flatmap-stream",
    affected: () => true,
    cve: "CVE-2018-1000620",
    severity: "critical",
    note: "Malicious package used to compromise event-stream.",
  },
  {
    name: "eslint-scope",
    affected: (v) => /^3\.7\.2/.test(v),
    cve: "CVE-2018-16487",
    severity: "high",
    note: "Version 3.7.2 was compromised to exfiltrate npm tokens.",
  },
  {
    name: "bootstrap-sass",
    affected: (v) => /^3\.2\.0\.2/.test(v),
    cve: "CVE-2019-1020009",
    severity: "high",
    note: "Malicious backdoor in 3.2.0.2.",
  },
  {
    name: "ua-parser-js",
    affected: (v) => /^(0\.7\.29|0\.8\.0|1\.0\.0)$/.test(v.replace(/[^\d.]/g, "")),
    cve: "CVE-2021-41265",
    severity: "critical",
    note: "Malicious crypto miner shipped in compromised versions.",
  },
  {
    name: "coa",
    affected: (v) => /^2\.0\.3/.test(v),
    cve: "GHSA-73qr-pfmq-6rp6",
    severity: "critical",
    note: "Compromised version published to npm.",
  },
  {
    name: "rc",
    affected: (v) => /^(1\.2\.9|1\.3\.9|2\.3\.9)/.test(v),
    cve: "GHSA-g2q5-5433-rhrf",
    severity: "critical",
    note: "Malicious versions published in 2021.",
  },
  {
    name: "node-ipc",
    affected: (v) => /^(10\.1\.1|10\.1\.2|11\.0\.0)/.test(v),
    cve: "CVE-2022-23812",
    severity: "critical",
    note: "Intentionally destructive protestware — deletes files in certain locales.",
  },
  {
    name: "minimatch",
    affected: (v) => {
      const m = v.match(/(\d+)\.(\d+)\.(\d+)/);
      if (!m) return false;
      const [maj, min, patch] = [+m[1], +m[2], +m[3]];
      return maj < 3 || (maj === 3 && min === 0 && patch < 5);
    },
    cve: "CVE-2022-3517",
    severity: "high",
    note: "ReDoS in braceExpand prior to 3.0.5.",
  },
  {
    name: "lodash",
    affected: (v) => {
      const m = v.match(/(\d+)\.(\d+)\.(\d+)/);
      if (!m) return false;
      const [maj, min, patch] = [+m[1], +m[2], +m[3]];
      return maj < 4 || (maj === 4 && (min < 17 || (min === 17 && patch < 21)));
    },
    cve: "CVE-2021-23337",
    severity: "high",
    note: "Command injection via template() before 4.17.21.",
  },
];

// Popular packages whose typosquats have been seen in the wild.
// Shape: real package → common typo that is NOT owned/controlled by the real authors.
const TYPOSQUATS: Record<string, string[]> = {
  lodash: ["lodahs", "loadash"],
  chalk: ["chall", "chalks"],
  react: ["reactt", "react-native-"],
  axios: ["axioss", "axios-https"],
  express: ["expresss", "expres"],
  jsonwebtoken: ["json-web-token", "jsonwebt0ken"],
  typescript: ["typescirpt", "typesript"],
  "cross-env": ["crossenv", "cross-env.js"], // crossenv (no hyphen) was the real attack
};

// Packages that should rarely appear in production dependencies.
const DEV_ONLY_IN_PROD = new Set(["jest", "vitest", "mocha", "chai", "@types/node", "eslint", "prettier"]);

const GIT_URL_PREFIX = /^(git\+|https:\/\/github\.com|git@github\.com|git:\/\/)/;
const FILE_URL_PREFIX = /^(file:|link:)/;

export const supplyChainRules: SecurityRule[] = [
  {
    id: "SUPPLY-001",
    domain: "supply-chain",
    title: "Known-vulnerable package version",
    description: "A dependency version matches a published CVE advisory",
    severity: "critical",
    appliesTo: ["nextjs-supabase", "react-vite-supabase", "generic-web"],
    references: { cwe: "CWE-1035" },
    check(model) {
      const findings: Finding[] = [];
      for (const dep of model.dependencies) {
        for (const entry of KNOWN_VULNERABLE) {
          if (dep.name !== entry.name) continue;
          if (!entry.affected(dep.version)) continue;
          findings.push(
            mkFinding(
              "SUPPLY-001",
              entry.severity,
              `${dep.name}@${dep.version} matches ${entry.cve}`,
              `${entry.note} Known advisory: ${entry.cve}.`,
              `Bump ${dep.name} to a patched version. Audit lockfiles for the same version in transitive deps.`,
              [{ file: "package.json", snippet: `${dep.name}@${dep.version}` }],
              { cwe: "CWE-1035" },
              "confirmed",
            ),
          );
        }
      }
      return findings;
    },
  },

  {
    id: "SUPPLY-002",
    domain: "supply-chain",
    title: "Missing lockfile",
    description: "No lockfile found in project root",
    severity: "high",
    appliesTo: ["nextjs-supabase", "react-vite-supabase", "generic-web"],
    references: { cwe: "CWE-1357" },
    check(model) {
      const findings: Finding[] = [];
      const root = model.meta.path;
      const hasLock =
        existsSync(join(root, "package-lock.json")) ||
        existsSync(join(root, "pnpm-lock.yaml")) ||
        existsSync(join(root, "yarn.lock")) ||
        existsSync(join(root, "bun.lockb"));
      if (!hasLock) {
        findings.push(
          mkFinding(
            "SUPPLY-002",
            "high",
            "No lockfile in project",
            "Without a lockfile, `npm install` can resolve different transitive dependencies on every machine, including compromised versions.",
            "Commit a lockfile (`package-lock.json`, `pnpm-lock.yaml`, or `yarn.lock`). Use `npm ci` / `pnpm install --frozen-lockfile` in CI.",
            [{ file: join(root, "package.json") }],
            { cwe: "CWE-1357" },
          ),
        );
      }
      return findings;
    },
  },

  {
    id: "SUPPLY-003",
    domain: "supply-chain",
    title: "Install script in package.json",
    description: "preinstall/install/postinstall script runs arbitrary code",
    severity: "medium",
    appliesTo: ["nextjs-supabase", "react-vite-supabase", "generic-web"],
    references: { cwe: "CWE-506" },
    async check(model) {
      const findings: Finding[] = [];
      const pkgPath = join(model.meta.path, "package.json");
      const pkg = JSON.parse(await safeReadFile(pkgPath));
      const scripts: Record<string, string> = pkg.scripts ?? {};
      const lifecycle = ["preinstall", "install", "postinstall", "prepare"];
      for (const name of lifecycle) {
        if (scripts[name]) {
          findings.push(
            mkFinding(
              "SUPPLY-003",
              "medium",
              `${name} script defined in package.json`,
              `Lifecycle scripts run on every \`npm install\`. Reviewers must audit what ${name} executes.`,
              "Prefer explicit build steps. Use `npm install --ignore-scripts` in CI if you don't need install hooks.",
              [{ file: pkgPath, snippet: `${name}: ${scripts[name].slice(0, 80)}` }],
              { cwe: "CWE-506" },
            ),
          );
        }
      }
      return findings;
    },
  },

  {
    id: "SUPPLY-004",
    domain: "supply-chain",
    title: "Wildcard or unpinned version range",
    description: "Dependency uses `*`, `latest`, or `x` as its version",
    severity: "high",
    appliesTo: ["nextjs-supabase", "react-vite-supabase", "generic-web"],
    references: { cwe: "CWE-1357" },
    check(model) {
      const findings: Finding[] = [];
      for (const dep of model.dependencies) {
        if (/^(\*|latest|x|\d+\.x|\d+\.\d+\.x)$/i.test(dep.version.trim())) {
          findings.push(
            mkFinding(
              "SUPPLY-004",
              "high",
              `${dep.name} uses unpinned version "${dep.version}"`,
              "Wildcard versions let an attacker ship a malicious release via dependency confusion.",
              `Pin ${dep.name} to a specific version range (e.g. ^1.2.3).`,
              [{ file: "package.json", snippet: `${dep.name}@${dep.version}` }],
              { cwe: "CWE-1357" },
            ),
          );
        }
      }
      return findings;
    },
  },

  {
    id: "SUPPLY-005",
    domain: "supply-chain",
    title: "Git or file: URL dependency",
    description: "Package pulled directly from git or local path",
    severity: "medium",
    appliesTo: ["nextjs-supabase", "react-vite-supabase", "generic-web"],
    references: { cwe: "CWE-494" },
    check(model) {
      const findings: Finding[] = [];
      for (const dep of model.dependencies) {
        const isGit = GIT_URL_PREFIX.test(dep.version);
        const isFile = FILE_URL_PREFIX.test(dep.version);
        if (!isGit && !isFile) continue;
        findings.push(
          mkFinding(
            "SUPPLY-005",
            "medium",
            `${dep.name} installed from ${isGit ? "git" : "local path"}`,
            "Git/file dependencies bypass npm's integrity hash checking and can change under you.",
            "Publish the dependency to a registry, or pin to a specific commit SHA.",
            [{ file: "package.json", snippet: `${dep.name}@${dep.version}` }],
            { cwe: "CWE-494" },
          ),
        );
      }
      return findings;
    },
  },

  {
    id: "SUPPLY-006",
    domain: "supply-chain",
    title: "Typosquat of a popular package",
    description: "Dependency name matches a known typosquat of a popular package",
    severity: "high",
    appliesTo: ["nextjs-supabase", "react-vite-supabase", "generic-web"],
    references: { cwe: "CWE-829" },
    check(model) {
      const findings: Finding[] = [];
      for (const dep of model.dependencies) {
        for (const [real, squats] of Object.entries(TYPOSQUATS)) {
          if (squats.includes(dep.name)) {
            findings.push(
              mkFinding(
                "SUPPLY-006",
                "high",
                `"${dep.name}" is a typosquat of "${real}"`,
                "Dependency confusion attacks publish lookalike packages to npm to steal credentials on install.",
                `Verify you meant to use ${dep.name}. If you meant ${real}, swap the name and remove node_modules.`,
                [{ file: "package.json", snippet: dep.name }],
                { cwe: "CWE-829" },
              ),
            );
          }
        }
      }
      return findings;
    },
  },

  {
    id: "SUPPLY-007",
    domain: "supply-chain",
    title: "Dev tool in production dependencies",
    description: "Package like jest/eslint listed under dependencies instead of devDependencies",
    severity: "low",
    appliesTo: ["nextjs-supabase", "react-vite-supabase", "generic-web"],
    references: {},
    check(model) {
      const findings: Finding[] = [];
      for (const dep of model.dependencies) {
        if (dep.type !== "production") continue;
        if (DEV_ONLY_IN_PROD.has(dep.name)) {
          findings.push(
            mkFinding(
              "SUPPLY-007",
              "low",
              `${dep.name} is a dev tool in production dependencies`,
              "Dev-only tools in prod bloat the bundle and expand the attack surface of the deployed app.",
              `Move ${dep.name} to devDependencies.`,
              [{ file: "package.json", snippet: dep.name }],
              {},
            ),
          );
        }
      }
      return findings;
    },
  },

  {
    id: "SUPPLY-008",
    domain: "supply-chain",
    title: "Severely outdated major version of a critical dependency",
    description: "Next.js/React/Supabase on a major version known to be unsupported",
    severity: "high",
    appliesTo: ["nextjs-supabase", "react-vite-supabase"],
    references: { cwe: "CWE-1035" },
    check(model) {
      const findings: Finding[] = [];
      const minimums: Record<string, number> = {
        next: 13,
        react: 18,
        "@supabase/supabase-js": 2,
      };
      for (const dep of model.dependencies) {
        const min = minimums[dep.name];
        if (min === undefined) continue;
        const m = dep.version.match(/(\d+)\./);
        if (!m) continue;
        const major = +m[1];
        if (major < min) {
          findings.push(
            mkFinding(
              "SUPPLY-008",
              "high",
              `${dep.name} v${major} is below the minimum supported major (v${min})`,
              "Unsupported major versions stop receiving security patches.",
              `Upgrade ${dep.name} to v${min} or later and address any migration guides.`,
              [{ file: "package.json", snippet: `${dep.name}@${dep.version}` }],
              { cwe: "CWE-1035" },
            ),
          );
        }
      }
      return findings;
    },
  },

  {
    id: "SUPPLY-009",
    domain: "supply-chain",
    title: "Duplicate package versions in lockfile",
    description: "Same package resolved to multiple versions, increasing attack surface",
    severity: "low",
    appliesTo: ["nextjs-supabase", "react-vite-supabase", "generic-web"],
    references: {},
    async check(model) {
      const findings: Finding[] = [];
      const lockPath = join(model.meta.path, "package-lock.json");
      if (!existsSync(lockPath)) return findings;
      const lock = JSON.parse(await safeReadFile(lockPath).catch(() => "{}"));
      const packages: Record<string, { version?: string }> = lock.packages ?? {};
      const versionsByName = new Map<string, Set<string>>();
      for (const [path, entry] of Object.entries(packages)) {
        if (!path) continue;
        const name = path.split("node_modules/").pop();
        if (!name || !entry.version) continue;
        if (!versionsByName.has(name)) versionsByName.set(name, new Set());
        versionsByName.get(name)!.add(entry.version);
      }
      for (const [name, versions] of versionsByName.entries()) {
        if (versions.size >= 3) {
          findings.push(
            mkFinding(
              "SUPPLY-009",
              "low",
              `${name} resolved to ${versions.size} distinct versions`,
              "Multiple versions of the same dependency inflate bundle size and give an attacker more code to exploit.",
              `Run \`npm dedupe\` or align version ranges on ${name} across your dependency tree.`,
              [{ file: lockPath, snippet: `${name}: ${Array.from(versions).slice(0, 5).join(", ")}` }],
              {},
            ),
          );
        }
      }
      return findings;
    },
  },

  {
    id: "SUPPLY-010",
    domain: "supply-chain",
    title: "Deprecated package used",
    description: "package.json declares a dependency marked deprecated in the registry",
    severity: "medium",
    appliesTo: ["nextjs-supabase", "react-vite-supabase", "generic-web"],
    references: { cwe: "CWE-1104" },
    check(model) {
      const findings: Finding[] = [];
      // Hardcoded list — the registry says these are all "deprecated: ..."
      // as of 2025. Not exhaustive, but catches the ones that still turn up.
      const deprecated = new Set([
        "request",
        "left-pad",
        "babel-preset-es2015",
        "node-sass",
        "tslint",
        "gulp-util",
        "istanbul",
        "uglify-js", // for new projects — webpack uses terser
      ]);
      for (const dep of model.dependencies) {
        if (deprecated.has(dep.name)) {
          findings.push(
            mkFinding(
              "SUPPLY-010",
              "medium",
              `${dep.name} is deprecated`,
              "Deprecated packages no longer receive security patches from their maintainers.",
              `Replace ${dep.name} with its supported successor.`,
              [{ file: "package.json", snippet: dep.name }],
              { cwe: "CWE-1104" },
            ),
          );
        }
      }
      return findings;
    },
  },
];
