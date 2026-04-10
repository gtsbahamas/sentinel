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
    title: "No Content-Disposition header on downloads",
    description: "Placeholder: requires response header analysis, deferred to probe layer",
    severity: "medium",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-79" },
    check() {
      return [];
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
    description: "Placeholder: requires Supabase config inspection",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-284" },
    check() {
      return [];
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
