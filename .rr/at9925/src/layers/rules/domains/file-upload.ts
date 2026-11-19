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
  impact: string,
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


/**
 * Local identifiers bound directly to a client-supplied filename, e.g.
 *   const filename = formData.get("filename") as string;
 *   const name = file.name;
 * Only direct, untransformed bindings count. A binding that runs the value
 * through `.split`, `.replace`, `sanitize(...)`, `slugify(...)` or similar is
 * deliberately excluded: the value is no longer the raw client filename.
 */
function collectRawNameBindings(source: string): Set<string> {
  const names = new Set<string>();
  const decl = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*([^;\n]+)/g;
  let m: RegExpExecArray | null;
  while ((m = decl.exec(source)) !== null) {
    const [, id, rhs] = m;
    const isRawName =
      /formData\.get\(\s*["'](?:filename|fileName|name)["']\s*\)/.test(rhs) ||
      /\bfile\.name\b/.test(rhs) ||
      /\boriginalname\b/i.test(rhs);
    if (!isRawName) continue;
    // Transformed on the way in — no longer the raw client value.
    if (/\.(split|replace|replaceAll|match|slice|substring|lastIndexOf|normalize)\s*\(/.test(rhs)) continue;
    if (/\b(?:sanitize|slugify|encodeURIComponent|basename|uuid|randomUUID|nanoid)\s*\(/i.test(rhs)) continue;
    names.add(id);
  }
  return names;
}

function referencesRawNameBinding(args: string, names: Set<string>): boolean {
  if (names.size === 0) return false;
  const ids = args.match(/[A-Za-z_$][\w$]*/g);
  return ids ? ids.some((id) => names.has(id)) : false;
}

export const fileUploadRules: SecurityRule[] = [
  {
    id: "UPLOAD-001",
    domain: "file-upload",
    title: "Upload handler lacks MIME validation",
    description: "Uploaded file type is not validated server-side",
    impact: "Your upload handler accepts any file type without checking. An attacker can upload an executable or script that, when served to other users, runs malicious code in their browser.",
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
            "Your upload handler accepts any file type without checking. An attacker can upload an executable or script that, when served to other users, runs malicious code in their browser.",
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
    impact: "Your upload handler has no file size limit. An attacker can upload multi-gigabyte files to fill your storage and exhaust your hosting budget.",
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
            "Your upload handler has no file size limit. An attacker can upload multi-gigabyte files to fill your storage and exhaust your hosting budget.",
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
    impact: "Uploaded files are served from the same domain as your app. A malicious uploaded file, like an HTML page with JavaScript, can access your app's cookies and local storage.",
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
            "Uploaded files are served from the same domain as your app. A malicious uploaded file, like an HTML page with JavaScript, can access your app's cookies and local storage.",
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
    impact: "Your app uses the original filename from the upload as the storage path. An attacker can use path traversal characters (../) to write files outside the intended directory, potentially overwriting config files.",
    severity: "critical",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-22", owasp: "A01:2021" },
    async check(model) {
      const findings: Finding[] = [];
      // The recon-layer `usesUserFilename` heuristic matches `.name ||` and
      // `formData.get("filename")` very loosely — it fired on any `.name ||`
      // expression in the file (e.g., `bill.suppliers?.name || ''`) and
      // produced 100% FPs in the v0.1.2 audit. Tighten the rule by re-reading
      // the source and verifying that the user-provided filename is actually
      // INTERPOLATED INTO the storage path passed to a storage upload call.
      for (const u of model.fileUploads) {
        if (!u.usesUserFilename) continue;
        // Skip test/migration directories.
        if (/\/(test|tests|__tests__|__mocks__|migrations|seed|seeds|fixtures|e2e)\//i.test(u.file)) continue;
        if (/\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)$/i.test(u.file)) continue;

        const source = await safeReadFile(u.file).catch(() => "");
        if (!source) continue;

        // Verify there's an actual storage upload that uses the raw user
        // filename as the destination. Patterns we treat as SAFE (the
        // dominant FP shape from the v0.1.2 audit):
        //   - `file.name.split('.').pop()` — only extracting an extension
        //   - `${Date.now()}_${Math.random()...}.${fileExt}` — server-generated path
        //   - `${userId}/${uuid()}` etc. — server-generated path
        //   - `certificate.id`, `incidentId`, `timestamp`, `Math.random()` in path
        //
        // Patterns we treat as UNSAFE:
        //   - `.upload(file.name, ...)` — original filename as destination
        //   - `\`${prefix}/${file.name}\`` — interpolating raw .name into path
        //   - `formData.get('filename')` directly used in a path arg
        //
        // We require at least one upload call where the PATH ARGUMENT
        // contains `file.name`/`originalname`/`originalName`/the raw
        // formData.get filename, AND lacks server-generated tokens
        // (Date.now, uuid, randomBytes, crypto.randomUUID).
        const rawNameBindings = collectRawNameBindings(source);
        const lines = source.split("\n");
        let flagged = false;
        let flagLine = u.line;
        for (let i = 0; i < lines.length && !flagged; i++) {
          const line = lines[i];
          // Skip comments
          const trim = line.trim();
          if (trim.startsWith("//") || trim.startsWith("*") || trim.startsWith("/*")) continue;

          // Look for upload calls: .upload(<path>, ...) or .putObject({Key: <path>, ...})
          const uploadCall = line.match(/\.(upload|putObject|put|createWriteStream)\s*\(([^)]+)/);
          if (!uploadCall) continue;
          const args = uploadCall[2];

          // Does the path argument include the raw user filename?
          // Either inline, or through a local binding of it. The v0.1.2
          // tightening only looked for the inline form, which missed the
          // most common shape of all:
          //     const filename = formData.get("filename") as string;
          //     await supabase.storage.from("x").upload(filename, file);
          // That is a real path-traversal bug, so rawNameBindings resolves
          // the one-hop alias. Bindings that are transformed on the way
          // (`.split`, `.replace`, sanitize helpers) are not collected.
          const usesRawName =
            /\bfile\.name\b(?!\s*\.split|\s*\.match|\s*\.replace|\s*\.lastIndexOf|\s*\.substring)/.test(args) ||
            /\boriginalname\b/i.test(args) ||
            /\boriginalName\b/.test(args) ||
            /formData\.get\(\s*["']filename["']\s*\)/.test(args) ||
            referencesRawNameBinding(args, rawNameBindings);
          if (!usesRawName) continue;

          // Does the same path arg ALSO contain server-generated entropy?
          // If yes, the filename is being prefixed/replaced — treat as safe.
          const serverGenerated =
            /Date\.now\(\)|uuid\s*\(|randomUUID\s*\(|randomBytes\s*\(|Math\.random\s*\(|nanoid\s*\(|crypto\.subtle/.test(
              args,
            );
          if (serverGenerated) continue;

          flagged = true;
          flagLine = i + 1;
        }

        if (!flagged) continue;
        findings.push(
          mkFinding(
            "UPLOAD-004",
            "critical",
            "User filename used as storage path",
            "Handler uses client-provided filename as the upload destination path.",
            "Your app uses the original filename from the upload as the storage path. An attacker can use path traversal characters (../) to write files outside the intended directory, potentially overwriting config files.",
            "Generate a server-side UUID for storage paths. Store original name in metadata only.",
            [{ file: u.file, line: flagLine }],
            { cwe: "CWE-22", owasp: "A01:2021" },
          ),
        );
      }
      return findings;
    },
  },

  {
    id: "UPLOAD-005",
    domain: "file-upload",
    title: "SVG uploads accepted without sanitization",
    description: "SVG files can contain embedded JavaScript",
    impact: "Your app accepts SVG uploads without sanitization. SVG files can contain embedded JavaScript that executes when the image is displayed in a browser.",
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
              "Your app accepts SVG uploads without sanitization. SVG files can contain embedded JavaScript that executes when the image is displayed in a browser.",
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
    impact: "Your file-serving route does not set Content-Disposition: attachment. When a user clicks a link to a file, it opens in the browser instead of downloading, allowing malicious content to execute.",
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
            "Your file-serving route does not set Content-Disposition: attachment. When a user clicks a link to a file, it opens in the browser instead of downloading, allowing malicious content to execute.",
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
    impact: "Your file validation only happens in the browser, not on the server. An attacker can bypass client-side checks by sending the upload request directly, uploading any file type or size.",
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
            "Your file validation only happens in the browser, not on the server. An attacker can bypass client-side checks by sending the upload request directly, uploading any file type or size.",
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
    impact: "Your Supabase storage bucket is public with no access policy. Anyone who discovers the file URL can access any uploaded file, including files meant to be private.",
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
        const policyRegex = /create\s+policy[\s\S]*?on\s+storage\.objects/gi;
        while (policyRegex.exec(sql) !== null) {
          policiesExist = true;
        }
        // Separately extract bucket_id references from storage policies
        const bucketIdRefs = sql.matchAll(/bucket_id\s*=\s*['"]([^'"]+)['"]/gi);
        for (const bm of bucketIdRefs) {
          if (bm[1]) policyNames.add(bm[1]);
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
            "Your Supabase storage bucket is public with no access policy. Anyone who discovers the file URL can access any uploaded file, including files meant to be private.",
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
    impact: "Your app accepts archive files without extraction safeguards. An attacker can upload a zip bomb (a tiny file that expands to gigabytes) or use zip slip to write files outside the target directory.",
    severity: "medium",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-409" },
    async check(model) {
      const findings: Finding[] = [];
      for (const u of model.fileUploads) {
        const source = await safeReadFile(u.file);
        if (/\.zip["'\s,)|]|\.tar\.gz|\.tar["'\s,)|]|\.tgz|unzipper|tar-stream|adm-zip/.test(source)) {
          findings.push(
            mkFinding(
              "UPLOAD-009",
              "medium",
              "Archive upload without zip-slip protection",
              "Extracting untrusted archives can overwrite arbitrary files.",
              "Your app accepts archive files without extraction safeguards. An attacker can upload a zip bomb (a tiny file that expands to gigabytes) or use zip slip to write files outside the target directory.",
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
