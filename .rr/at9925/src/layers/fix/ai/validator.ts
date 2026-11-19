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

function bracketBalance(source: string): { curly: number; round: number; square: number } {
  let curly = 0,
    round = 0,
    square = 0;
  let inSingle = false,
    inDouble = false,
    inBacktick = false,
    inLineComment = false,
    inBlockComment = false;
  for (let i = 0; i < source.length; i++) {
    const c = source[i];
    const next = source[i + 1];
    if (inLineComment) {
      if (c === "\n") inLineComment = false;
      continue;
    }
    if (inBlockComment) {
      if (c === "*" && next === "/") {
        inBlockComment = false;
        i++;
      }
      continue;
    }
    if (inSingle) {
      if (c === "\\") {
        i++;
        continue;
      }
      if (c === "'") inSingle = false;
      continue;
    }
    if (inDouble) {
      if (c === "\\") {
        i++;
        continue;
      }
      if (c === '"') inDouble = false;
      continue;
    }
    if (inBacktick) {
      if (c === "\\") {
        i++;
        continue;
      }
      if (c === "`") inBacktick = false;
      continue;
    }
    if (c === "/" && next === "/") {
      inLineComment = true;
      i++;
      continue;
    }
    if (c === "/" && next === "*") {
      inBlockComment = true;
      i++;
      continue;
    }
    if (c === "-" && next === "-") {
      inLineComment = true;
      i++;
      continue;
    }
    if (c === "'") {
      inSingle = true;
      continue;
    }
    if (c === '"') {
      inDouble = true;
      continue;
    }
    if (c === "`") {
      inBacktick = true;
      continue;
    }
    if (c === "{") curly++;
    else if (c === "}") curly--;
    else if (c === "(") round++;
    else if (c === ")") round--;
    else if (c === "[") square++;
    else if (c === "]") square--;
  }
  return { curly, round, square };
}

function lastMeaningfulChar(source: string): string {
  // Strip trailing whitespace, then walk back over trailing comment-only lines.
  // Comments can legitimately end a file with an identifier-like char; we want
  // the last *code* character.
  const lines = source.replace(/\s+$/g, "").split("\n");
  while (lines.length > 0) {
    const line = lines[lines.length - 1].trim();
    if (line === "" || line.startsWith("//") || line.startsWith("--") || line.startsWith("#")) {
      lines.pop();
      continue;
    }
    break;
  }
  const trimmed = lines.join("\n").replace(/\s+$/g, "");
  return trimmed.length > 0 ? trimmed[trimmed.length - 1] : "";
}

/**
 * Validates that an AI-generated patch is safe to apply.
 *
 * Checks performed:
 * 1. Reject empty responses.
 * 2. Reject if patched content is less than 50% of original length (truncated).
 * 3. Reject if any named export present in the original is missing from the patch.
 * 4. Reject if bracket/paren/brace balance diverges from original (catches mid-block truncation).
 * 5. Reject if patched ends mid-identifier while original ends with a terminator
 *    (catches tail truncation — e.g., SQL file cut off mid-statement).
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

  const originalBalance = bracketBalance(original);
  const patchedBalance = bracketBalance(patched);
  if (
    originalBalance.curly === 0 &&
    originalBalance.round === 0 &&
    originalBalance.square === 0 &&
    (patchedBalance.curly !== 0 || patchedBalance.round !== 0 || patchedBalance.square !== 0)
  ) {
    return {
      valid: false,
      reason: `Bracket balance broken in patched content (curly=${patchedBalance.curly}, round=${patchedBalance.round}, square=${patchedBalance.square}) — likely mid-block truncation`,
    };
  }

  const originalEnd = lastMeaningfulChar(original);
  const patchedEnd = lastMeaningfulChar(patched);
  const isIdentifierChar = (c: string) => /[a-zA-Z0-9_]/.test(c);
  if (originalEnd && !isIdentifierChar(originalEnd) && patchedEnd && isIdentifierChar(patchedEnd)) {
    return {
      valid: false,
      reason: `Patched content ends mid-identifier ('${patchedEnd}') while original ends with terminator ('${originalEnd}') — likely tail truncation`,
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
