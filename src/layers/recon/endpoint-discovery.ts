import { safeReadFile } from "../../utils/fs.js";
import type { Route, ApiEndpoint } from "../../model/types.js";

/**
 * Detects whether an API handler source has SOME form of auth check. Uses
 * shape-based structural detection rather than a fixed list of helper names —
 * real codebases invent names this scanner can never enumerate
 * (`requireStaffPermission`, `requirePortalSession`, `getServerUser`, …).
 *
 * Returns true if ANY of these structural shapes are present:
 *   1. Awaited guard-call: `await <verb>...(` where verb is a guard-style word
 *      (require/ensure/assert/verify/check/validate/guard, in any case). This
 *      is the workhorse — covers the bulk of helper functions regardless of
 *      project naming convention.
 *   2. Verb + auth-noun call (sync OR async): `<verb><...>(Auth|Session|User|
 *      Permission|Role|Staff|Portal|Member|Principal|Token|Password)<...>(`.
 *      Stricter than the guard arm because the noun must be auth-related, so
 *      sync calls don't generate false positives like `verifyChecksum()`.
 *   3. Bearer-token + Supabase user fetch: `headers.get("authorization")`
 *      paired with `.auth.getUser` within ~600 chars (hand-rolled bearer flow).
 *   4. Cookie-based SSR client: `import { cookies } from "next/headers"` paired
 *      with a `create(Server|Portal|Supabase)*Client` factory.
 *   5. Webhook HMAC signature verification (createHmac + timingSafeEqual).
 *   6. Capability-URL tokens (DB column ending in `_token`).
 *   7. Shared secret header check (CRON_SECRET / API key / Bearer token):
 *      requires BOTH the header read AND the env-var reference to avoid
 *      false-positives from stray logging.
 *
 * Calibration: err toward FEWER true returns. Better to flag a real handler
 * that already has auth (annoying false positive on AUTH-001) than to silently
 * bless one that doesn't (dangerous false negative).
 */
export function detectAuthCheck(source: string): boolean {
  // (1) Awaited guard-call: await <anything-with-a-guard-verb>(...).
  // The leading `\w*` lets the verb appear after a prefix (rare), the trailing
  // `\w*` covers the common case (`requireStaffPermission`, `assertSession`).
  const hasGuardCall =
    /await\s+\w*(?:require|ensure|assert|verify|check|validate|guard)\w*\s*\(/i.test(source);

  // (2) Verb + auth-domain noun call (sync or async). Case-sensitive because
  // real call sites are camelCase; lowercasing would over-match identifiers
  // like `requirements(` or `getuserland(` that aren't auth.
  const hasVerbNounCall =
    /\b(?:require|ensure|assert|verify|check|validate|get|fetch|load)\w*(?:Auth|Session|User|Permission|Role|Staff|Portal|Member|Principal|Token|Password)\w*\s*\(/.test(source);

  // (3) Bearer + Supabase getUser within proximity. The `[\s\S]{0,600}?` is a
  // lazy any-char window so we tolerate intervening token-extraction code.
  const hasBearerSupabase =
    /headers\.get\(\s*["'`]authorization["'`]\s*\)[\s\S]{0,600}?\.auth\.getUser\b/i.test(source);

  // (4) Next.js cookie-based SSR client. `cookies` import + a `create*Client`
  // factory in the same file is a strong signal of session-bound auth.
  const hasCookieSSR =
    /import\s*\{[^}]*\bcookies\b[^}]*\}\s*from\s*["'`]next\/headers["'`][\s\S]+?\bcreate(?:Server|Portal|Supabase)\w*Client\b/.test(source);

  // (5) Webhook HMAC signature verification.
  const hasWebhookSignature = /createHmac\s*\(/.test(source) && /timingSafeEqual/.test(source);

  // (6) Capability-URL token: DB column ending in `_token`.
  const hasCapabilityToken = /\.eq\(\s*["'`][a-z_]*token["'`]/i.test(source);

  // (7) Shared-secret auth: header read AND env-var reference. Require both
  // halves to avoid false-positives from stray references in logging.
  const checksAuthHeader =
    /headers\.get\s*\(\s*["'`]authorization["'`]/i.test(source) ||
    /headers\.get\s*\(\s*["'`]x-api-key["'`]/i.test(source);
  const usesSharedSecretEnv =
    /process\.env\.(?:CRON_SECRET|WEBHOOK_SECRET|API_KEY|INTERNAL_API_KEY|SCANNER_TOKEN)/.test(source);
  const hasSharedSecret = checksAuthHeader && usesSharedSecretEnv;

  return (
    hasGuardCall ||
    hasVerbNounCall ||
    hasBearerSupabase ||
    hasCookieSSR ||
    hasWebhookSignature ||
    hasCapabilityToken ||
    hasSharedSecret
  );
}

export async function discoverEndpoints(routes: Route[]): Promise<ApiEndpoint[]> {
  const endpoints: ApiEndpoint[] = [];
  const apiRoutes = routes.filter((r) => r.isApi);

  for (const route of apiRoutes) {
    const source = await safeReadFile(route.file);
    const hasValidation = /zod|yup|joi|\.parse\(|\.validate\(/.test(source);
    const validationLibrary = /zod/.test(source)
      ? "zod"
      : /yup/.test(source)
      ? "yup"
      : /joi/.test(source)
      ? "joi"
      : null;
    const usesServiceRole = /SERVICE_ROLE|service_role|auth\.admin/.test(source);
    const hasAuthCheck = detectAuthCheck(source);

    endpoints.push({
      path: route.path,
      method: route.method,
      file: route.file,
      hasValidation,
      validationLibrary,
      hasAuthCheck,
      usesServiceRole,
    });
  }

  return endpoints;
}
