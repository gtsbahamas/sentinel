import { safeReadFile } from "../../../utils/fs.js";
import { existsSync } from "fs";
import { join } from "path";
import fg from "fast-glob";
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
): Finding {
  return {
    id: `${ruleId}-${evidence[0]?.file ?? "x"}-${evidence[0]?.line ?? 0}`,
    domain: "file-upload",
    severity,
    confidence: "high",
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

export const fileUploadRules: SecurityRule[] = [
  {
    id: "UPLOAD-001",
    domain: "file-upload",
    title: "Upload handler lacks MIME validation",
    description: "Uploaded file type is not validated server-side",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-434", owasp: "A04:2021" },
    check(model) {
      return model.fileUploads
        .filter((u) => !u.hasMimeValidation)
        .map((u) =>
          mkFinding(
            "UPLOAD-001",
            "high",
            "Upload handler does not validate MIME type",
            "Uploaded files are stored without verifying their content type.",
            "Check `file.type` against an allowlist before accepting the upload.",
            [{ file: u.file, line: u.line }],
            { cwe: "CWE-434", owasp: "A04:2021" },
          ),
        );
    },
  },

  {
    id: "UPLOAD-002",
    domain: "file-upload",
    title: "Upload handler lacks size limit",
    description: "No file size check means DoS and storage abuse are possible",
    severity: "medium",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-400" },
    check(model) {
      return model.fileUploads
        .filter((u) => !u.hasSizeLimit)
        .map((u) =>
          mkFinding(
            "UPLOAD-002",
            "medium",
            "Upload handler has no size limit",
            "Handler accepts files of any size.",
            "Reject files where file.size exceeds a configured maximum.",
            [{ file: u.file, line: u.line }],
            { cwe: "CWE-400" },
          ),
        );
    },
  },

  {
    id: "UPLOAD-003",
    domain: "file-upload",
    title: "Uploaded files served from same origin as app",
    description: "Local storage means uploads live on the app domain",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-79" },
    check(model) {
      return model.fileUploads
        .filter((u) => u.storageDestination === "local")
        .map((u) =>
          mkFinding(
            "UPLOAD-003",
            "high",
            "Uploads stored on app filesystem",
            "Local storage means uploads are served from the same origin, inheriting session cookies.",
            "Use an isolated storage domain (Supabase storage, S3 with CloudFront).",
            [{ file: u.file, line: u.line }],
            { cwe: "CWE-79" },
          ),
        );
    },
  },

  {
    id: "UPLOAD-004",
    domain: "file-upload",
    title: "User-provided filename used as storage path",
    description: "Storage path derived from client input enables path traversal",
    severity: "critical",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-22", owasp: "A01:2021" },
    check(model) {
      return model.fileUploads
        .filter((u) => u.usesUserFilename)
        .map((u) =>
          mkFinding(
            "UPLOAD-004",
            "critical",
            "User filename used as storage path",
            "Handler uses client-provided filename as the upload destination path.",
            "Generate a server-side UUID for storage paths. Store original name in metadata only.",
            [{ file: u.file, line: u.line }],
            { cwe: "CWE-22", owasp: "A01:2021" },
          ),
        );
    },
  },

  {
    id: "UPLOAD-005",
    domain: "file-upload",
    title: "SVG uploads accepted without sanitization",
    description: "SVG files can contain embedded JavaScript",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-79" },
    async check(model) {
      const findings: Finding[] = [];
      for (const u of model.fileUploads) {
        const source = await safeReadFile(u.file);
        if (/image\/svg|svg\+xml/.test(source) && !/DOMPurify|sanitize.*svg/i.test(source)) {
          findings.push(
            mkFinding(
              "UPLOAD-005",
              "high",
              "SVG accepted without sanitization",
              "SVG content can contain script tags and event handlers.",
              "Reject SVGs or strip scriptable content before storage.",
              [{ file: u.file, line: u.line }],
              { cwe: "CWE-79" },
            ),
          );
        }
      }
      return findings;
    },
  },

  {
    id: "UPLOAD-006",
    domain: "file-upload",
    title: "File-serving route missing Content-Disposition: attachment",
    description: "Route returns a file-like response without forcing download",
    severity: "medium",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-79" },
    async check(model) {
      const findings: Finding[] = [];
      // A route is considered file-serving if it returns a Blob/Buffer/ArrayBuffer/
      // ReadableStream, calls supabase.storage.*.download(), or sets Content-Type
      // to an image/pdf/octet-stream type.
      const fileResponseSignals = /new\s+Response\s*\(\s*(buffer|blob|stream|arrayBuffer|Buffer\.|Readable\.|file\s*[,)])|NextResponse\s*\(\s*(buffer|blob|stream|arrayBuffer|file)|storage\s*\.\s*from\([^)]*\)\s*\.\s*download|fs\.createReadStream|readFile\s*\(.*,\s*null\s*\)/;
      const contentTypeSignals = /["']Content-Type["']\s*:\s*["'](application\/(pdf|octet-stream|zip|x-tar)|image\/|video\/|audio\/)/;
      const dispositionAttachment = /Content-Disposition["']?\s*[:,]\s*["']attachment/i;

      for (const route of [...model.routes, ...model.endpoints]) {
        const file = route.file;
        if (!file) continue;
        const source = await safeReadFile(file).catch(() => "");
        if (!source) continue;
        if (!fileResponseSignals.test(source) && !contentTypeSignals.test(source)) continue;
        if (dispositionAttachment.test(source)) continue;
        findings.push(
          mkFinding(
            "UPLOAD-006",
            "medium",
            "File download route does not force Content-Disposition: attachment",
            "Without an attachment disposition, HTML/SVG files can render inline with cookies attached, enabling XSS and clickjacking.",
            'Set `Content-Disposition: attachment; filename="..."` on every file-serving response.',
            [{ file }],
            { cwe: "CWE-79" },
          ),
        );
      }
      return findings;
    },
  },

  {
    id: "UPLOAD-007",
    domain: "file-upload",
    title: "Client-side-only file validation",
    description: "File validation in the component but not the API route",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-602" },
    check(model) {
      return model.fileUploads
        .filter((u) => !u.hasMimeValidation)
        .map((u) =>
          mkFinding(
            "UPLOAD-007",
            "high",
            "Server-side MIME validation missing",
            "Client `accept` attribute can be bypassed; server must re-validate.",
            "Add server-side MIME check in the upload handler.",
            [{ file: u.file, line: u.line }],
            { cwe: "CWE-602" },
          ),
        );
    },
  },

  {
    id: "UPLOAD-008",
    domain: "file-upload",
    title: "Supabase public bucket without access policy",
    description: "Public bucket defined in config or migrations with no matching RLS policy",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-284" },
    async check(model) {
      const findings: Finding[] = [];
      const publicBuckets = new Map<string, { file: string; line?: number }>();

      // Parse supabase/config.toml for [storage.buckets.<name>] public=true.
      const configPath = join(model.meta.path, "supabase", "config.toml");
      if (existsSync(configPath)) {
        const toml = await safeReadFile(configPath).catch(() => "");
        // Very small TOML parse: find [storage.buckets.<name>] sections and
        // check if the next few lines include `public = true`.
        const sections = Array.from(toml.matchAll(/\[storage\.buckets\.([a-zA-Z0-9_-]+)\]([\s\S]*?)(?=\n\[|$)/g));
        for (const s of sections) {
          const name = s[1];
          const body = s[2];
          if (/^\s*public\s*=\s*true/m.test(body)) {
            const lineNo = toml.slice(0, s.index ?? 0).split("\n").length;
            publicBuckets.set(name, { file: configPath, line: lineNo });
          }
        }
      }

      // Parse SQL migrations for inserts into storage.buckets with public=true
      // and for `update storage.buckets set public = true`.
      const migrationFiles = await fg(["supabase/migrations/**/*.sql", "migrations/**/*.sql"], {
        cwd: model.meta.path,
        absolute: true,
      });

      const policyNames = new Set<string>();
      let policiesExist = false;
      for (const mig of migrationFiles) {
        const sql = await safeReadFile(mig).catch(() => "");
        if (!sql) continue;

        // Capture inserts: insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true)
        const insertRegex = /insert\s+into\s+storage\.buckets[^;]*?values\s*\(([^)]*)\)/gi;
        let im: RegExpExecArray | null;
        while ((im = insertRegex.exec(sql)) !== null) {
          const values = im[1];
          // Rough: first string literal is the bucket id/name.
          const nameMatch = values.match(/['"]([^'"]+)['"]/);
          const publicTrue = /true/i.test(values);
          if (nameMatch && publicTrue) {
            const lineNo = sql.slice(0, im.index).split("\n").length;
            publicBuckets.set(nameMatch[1], { file: mig, line: lineNo });
          }
        }

        // Capture updates to public=true.
        const updateRegex = /update\s+storage\.buckets\s+set\s+public\s*=\s*true\s+where\s+[^;]*?['"]([^'"]+)['"]/gi;
        let um: RegExpExecArray | null;
        while ((um = updateRegex.exec(sql)) !== null) {
          const lineNo = sql.slice(0, um.index).split("\n").length;
          publicBuckets.set(um[1], { file: mig, line: lineNo });
        }

        // Policies on storage.objects: `create policy "name" on storage.objects`
        const policyRegex = /create\s+policy[\s\S]*?on\s+storage\.objects[\s\S]*?(?:bucket_id\s*=\s*['"]([^'"]+)['"])?/gi;
        let pm: RegExpExecArray | null;
        while ((pm = policyRegex.exec(sql)) !== null) {
          policiesExist = true;
          if (pm[1]) policyNames.add(pm[1]);
        }
      }

      for (const [bucket, evidence] of publicBuckets.entries()) {
        const hasSpecificPolicy = policyNames.has(bucket);
        const hasGlobalPolicy = policiesExist && policyNames.size === 0;
        // Only skip when a policy explicitly names the bucket. A blanket policy
        // without a bucket_id clause is still worth flagging because it applies
        // to every bucket and may over-grant.
        if (hasSpecificPolicy) continue;
        findings.push(
          mkFinding(
            "UPLOAD-008",
            "high",
            `Public bucket "${bucket}" ${hasGlobalPolicy ? "relies on non-specific policy" : "has no matching RLS policy"}`,
            "A Supabase storage bucket is marked public without an explicit RLS policy scoped to it. Public buckets without policies expose every object to anyone who can guess the path.",
            `Add a policy: \`create policy "public_${bucket}_read" on storage.objects for select using (bucket_id = '${bucket}');\` and tighten write access similarly.`,
            [evidence],
            { cwe: "CWE-284" },
          ),
        );
      }

      return findings;
    },
  },

  {
    id: "UPLOAD-009",
    domain: "file-upload",
    title: "Archive files accepted without extraction safeguards",
    description: "zip/tar uploads can cause zip slip or decompression bombs",
    severity: "medium",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-409" },
    async check(model) {
      const findings: Finding[] = [];
      for (const u of model.fileUploads) {
        const source = await safeReadFile(u.file);
        if (/\.zip|\.tar|unzipper|tar-stream|adm-zip/.test(source)) {
          findings.push(
            mkFinding(
              "UPLOAD-009",
              "medium",
              "Archive upload without zip-slip protection",
              "Extracting untrusted archives can overwrite arbitrary files.",
              "Validate extracted paths against the target directory, enforce size limits.",
              [{ file: u.file, line: u.line }],
              { cwe: "CWE-409" },
            ),
          );
        }
      }
      return findings;
    },
  },
];
