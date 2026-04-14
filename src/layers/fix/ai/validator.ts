export interface ValidationResult {
  valid: boolean;
  reason?: string;
}

// Regex to match ES module export statements
const EXPORT_PATTERN = /^export\s+(default\s+|const\s+|function\s+|class\s+|async\s+function\s+|type\s+|interface\s+)(\w+)/gm;

function extractExports(source: string): Set<string> {
  const names = new Set<string>();
  let match: RegExpExecArray | null;
  const re = new RegExp(EXPORT_PATTERN.source, EXPORT_PATTERN.flags);
  while ((match = re.exec(source)) !== null) {
    // match[2] is the identifier name
    if (match[2]) names.add(match[2]);
  }
  return names;
}

/**
 * Validates that an AI-generated patch is safe to apply.
 *
 * Checks performed:
 * 1. Reject empty responses.
 * 2. Reject if patched content is less than 50% of original length (truncated).
 * 3. Reject if any named export present in the original is missing from the patch.
 */
export function validateAIResponse(original: string, patched: string): ValidationResult {
  if (!patched || patched.trim().length === 0) {
    return { valid: false, reason: "AI response was empty" };
  }

  const originalLen = original.length;
  const patchedLen = patched.length;
  if (originalLen > 0 && patchedLen < originalLen * 0.5) {
    return {
      valid: false,
      reason: `Patched content (${patchedLen} chars) is less than 50% of original (${originalLen} chars) — likely truncated`,
    };
  }

  const originalExports = extractExports(original);
  const patchedExports = extractExports(patched);

  const missing: string[] = [];
  for (const name of originalExports) {
    if (!patchedExports.has(name)) {
      missing.push(name);
    }
  }

  if (missing.length > 0) {
    return {
      valid: false,
      reason: `Patched content is missing exports from original: ${missing.join(", ")}`,
    };
  }

  return { valid: true };
}
