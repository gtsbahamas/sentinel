import { randomUUID } from "crypto";
import type { ProbeTarget, ProbeFinding, ProbeError, AggressionLevel, SecurityDomain } from "../../../../model/types.js";
import type { ProbeCheck, ProbeCheckContext, ProbeCheckResult } from "../base.js";
import { TargetUnreachable } from "../../http-client.js";

interface TestFile {
  label: string;
  filename: string;
  contentType: string;
  content: string;
  isTraversal: boolean;
}

function buildMultipartBody(filename: string, contentType: string, content: string, boundary: string): string {
  return (
    `--${boundary}\r\n` +
    `Content-Disposition: form-data; name="file"; filename="${filename}"\r\n` +
    `Content-Type: ${contentType}\r\n` +
    `\r\n` +
    `${content}\r\n` +
    `--${boundary}--\r\n`
  );
}

/** Returns the upload ID string from a JSON response body, or an empty string if not found. */
function parseUploadId(body: string): string {
  let obj: Record<string, unknown>;
  try {
    const parsed = JSON.parse(body) as unknown;
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return "";
    obj = parsed as Record<string, unknown>;
  } catch {
    return "";
  }
  const raw = obj["id"] ?? obj["fileId"] ?? obj["file_id"] ?? obj["uploadId"] ?? obj["upload_id"];
  if (typeof raw === "string" && raw.length > 0) return raw;
  if (typeof raw === "number") return String(raw);
  return "";
}

export const fileUploadCheck: ProbeCheck = {
  id: "file-upload",
  level: "intrusive" as AggressionLevel,
  domain: "file-upload" as SecurityDomain,
  description: "Upload benign test files to discovered upload endpoints to verify MIME validation and path traversal protection",

  appliesTo(target: ProbeTarget, model: import("../../../../model/types.js").ProjectModel): boolean {
    if (target.kind !== "endpoint") return false;
    if (target.method !== "POST") return false;

    // Extract the path from the URL
    let targetPath: string;
    try {
      targetPath = new URL(target.url).pathname;
    } catch {
      return false;
    }

    // Check if the model has a fileUploads handler whose file matches an endpoint with the same path
    return model.fileUploads.some((handler) => {
      return model.endpoints.some(
        (ep) => ep.file === handler.file && ep.path === targetPath && ep.method === "POST",
      );
    });
  },

  async run(ctx: ProbeCheckContext): Promise<ProbeCheckResult> {
    const findings: ProbeFinding[] = [];
    const errors: ProbeError[] = [];
    const confirmed: Array<{ findingId: string }> = [];
    const refuted: Array<{ findingId: string }> = [];

    let uploadPath: string;
    try {
      uploadPath = new URL(ctx.target.url).pathname;
    } catch {
      errors.push({ kind: "check-error", message: "Invalid target URL", checkId: "file-upload" });
      return { findings, confirmed, refuted, errors };
    }

    // Find a matching DELETE endpoint (same path prefix + /:id)
    const deleteEndpoint = ctx.model.endpoints.find(
      (ep) =>
        ep.method === "DELETE" &&
        (ep.path === `${uploadPath}/:id` ||
          ep.path.startsWith(uploadPath + "/") && ep.path.endsWith("/:id")),
    );

    // If no DELETE endpoint exists, skip entirely
    if (!deleteEndpoint) {
      return { findings, confirmed, refuted, errors };
    }

    const nonce = randomUUID().slice(0, 8);
    const baseUrl = ctx.target.url.replace(/\/$/, "");
    const deleteBaseUrl = baseUrl;

    const testFiles: TestFile[] = [
      {
        label: "txt",
        filename: `sentinel-probe-${nonce}.txt`,
        contentType: "text/plain",
        content: "x",
        isTraversal: false,
      },
      {
        label: "png",
        filename: `sentinel-probe-${nonce}.png`,
        contentType: "image/png",
        content: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
        isTraversal: false,
      },
      {
        label: "traversal",
        filename: `../../../sentinel-probe-${nonce}.txt`,
        contentType: "text/plain",
        content: "x",
        isTraversal: true,
      },
    ];

    for (const testFile of testFiles) {
      const boundary = `sentinel-boundary-${randomUUID().slice(0, 16)}`;
      const multipartBody = buildMultipartBody(testFile.filename, testFile.contentType, testFile.content, boundary);

      let uploadedId = "";

      // KEY INVARIANT: Register cleanup obligation BEFORE uploading
      ctx.registry.register({
        description: `delete test file ${testFile.label} via DELETE ${deleteBaseUrl}/:id`,
        severity: "blocking",
        cleanup: async (_signal) => {
          if (uploadedId.length > 0) {
            const deleteUrl = `${deleteBaseUrl}/${uploadedId}`;
            await ctx.client.request({ method: "DELETE", url: deleteUrl, intent: "mutate" }).catch(() => {});
          }
        },
      });

      let resp: { status: number; headers: Record<string, string>; body: string; timingMs: number; requestId: string };

      try {
        resp = await ctx.client.request({
          method: "POST",
          url: ctx.target.url,
          headers: { "content-type": `multipart/form-data; boundary=${boundary}` },
          body: multipartBody,
          intent: "mutate",
        });
      } catch (err) {
        if (err instanceof TargetUnreachable) {
          errors.push({ kind: "target-unreachable", message: err.message, checkId: "file-upload", targetUrl: ctx.target.url });
          return { findings, confirmed, refuted, errors };
        } else {
          errors.push({ kind: "check-error", message: err instanceof Error ? err.message : String(err), checkId: "file-upload" });
          return { findings, confirmed, refuted, errors };
        }
      }

      if (resp.status === 200 || resp.status === 201) {
        uploadedId = parseUploadId(resp.body);

        if (testFile.isTraversal) {
          // Path traversal filename accepted — high severity, CWE-22
          findings.push({
            id: `PROBE-UPLOAD-${randomUUID().slice(0, 8)}`,
            domain: "file-upload",
            severity: "high",
            confidence: "confirmed",
            title: "Path traversal filename accepted in file upload",
            description: `The upload endpoint at ${ctx.target.url} accepted a filename containing path traversal sequences ("${testFile.filename}"). An attacker could potentially overwrite arbitrary files on the server.`,
            impact: "Your upload endpoint accepts filenames with path traversal sequences. An attacker can overwrite arbitrary files on the server, potentially replacing application code or configuration files.",
            evidence: [],
            remediation: "Sanitize uploaded filenames by stripping directory traversal sequences (../, .., %2e%2e, etc.) and reject uploads with suspicious filenames. Store files using server-generated names rather than user-supplied names.",
            references: [
              "https://owasp.org/www-community/attacks/Path_Traversal",
              "https://cwe.mitre.org/data/definitions/22.html",
            ],
            layer: "probe",
            cwe: "CWE-22",
            probeEvidence: {
              requestId: resp.requestId,
              checkId: "file-upload",
              aggressionLevel: "intrusive",
              request: { method: "POST", url: ctx.target.url, headers: { "content-type": `multipart/form-data; boundary=${boundary}` }, bodyPreview: `filename="${testFile.filename}"` },
              response: { status: resp.status, headers: resp.headers, bodyPreview: resp.body.slice(0, 256), timingMs: resp.timingMs },
            },
          });
        } else {
          // Non-traversal file accepted — medium severity, CWE-434 (missing MIME validation)
          findings.push({
            id: `PROBE-UPLOAD-${randomUUID().slice(0, 8)}`,
            domain: "file-upload",
            severity: "medium",
            confidence: "confirmed",
            title: `File upload accepted without MIME type validation (${testFile.label})`,
            description: `The upload endpoint at ${ctx.target.url} accepted a ${testFile.contentType} file without apparent MIME type validation. The endpoint may accept arbitrary file types, potentially allowing upload of malicious content.`,
            impact: "Your upload endpoint accepted a file type that should be rejected. An attacker can upload scripts, executables, or other malicious files that could be served to other users or executed on the server.",
            evidence: [],
            remediation: "Implement server-side MIME type validation by inspecting the file content (magic bytes), not just the Content-Type header or filename extension. Maintain an allowlist of acceptable MIME types.",
            references: [
              "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
              "https://cwe.mitre.org/data/definitions/434.html",
            ],
            layer: "probe",
            cwe: "CWE-434",
            probeEvidence: {
              requestId: resp.requestId,
              checkId: "file-upload",
              aggressionLevel: "intrusive",
              request: { method: "POST", url: ctx.target.url, headers: { "content-type": `multipart/form-data; boundary=${boundary}` }, bodyPreview: `filename="${testFile.filename}", contentType="${testFile.contentType}"` },
              response: { status: resp.status, headers: resp.headers, bodyPreview: resp.body.slice(0, 256), timingMs: resp.timingMs },
            },
          });
        }
      }
    }

    return { findings, confirmed, refuted, errors };
  },
};
