import { safeReadFile } from "../../utils/fs.js";
import type { Route, ApiEndpoint } from "../../model/types.js";

/**
 * Detects whether an API handler source has SOME form of auth check. Returns
 * true if any of these patterns are present:
 *   1. Supabase/NextAuth user or session lookup.
 *   2. Webhook HMAC signature verification (createHmac + timingSafeEqual).
 *   3. Capability-URL tokens (DB column ending in `_token`).
 *   4. Custom middleware helpers (kiosk/device tokens, RBAC requireAuth, etc.).
 *   5. Shared secret header check (CRON_SECRET / API key / Bearer token).
 *
 * Pattern (4) and (5) were added after auto-fixing AUTH-001 incorrectly
 * layered Supabase user auth onto kiosk/cron/webhook endpoints that already
 * authenticated a different principal (device, scheduler, external service).
 */
export function detectAuthCheck(source: string): boolean {
  const hasUserAuth = /getUser|getSession|auth\.getUser|auth\.getSession/.test(source);
  const hasWebhookSignature = /createHmac\s*\(/.test(source) && /timingSafeEqual/.test(source);
  const hasCapabilityToken = /\.eq\(\s*["'`][a-z_]*token["'`]/i.test(source);

  // Named middleware helpers — broadly used patterns across kiosk, admin, and
  // custom-RBAC codebases. Matching the call site, not the import, so that
  // stray imports don't count as auth.
  const hasCustomAuthHelper =
    /\b(validateKioskToken|requireKioskToken|validateDeviceToken|requireDeviceToken|requireAuth|requirePermission|requireRole|requireUser|requireSession|verifyAuth|ensureAuth|checkAuth)\s*\(/.test(source);

  // Shared-secret auth: CRON_SECRET + authorization header compare, or
  // x-api-key header check backed by an env var. Require both sides of the
  // check to avoid false positives from stray references.
  const checksAuthHeader = /request\.headers\.get\s*\(\s*["'`]authorization["'`]/i.test(source)
    || /headers\.get\s*\(\s*["'`]x-api-key["'`]/i.test(source);
  const usesCronSecret = /process\.env\.(?:CRON_SECRET|WEBHOOK_SECRET|API_KEY|INTERNAL_API_KEY)/.test(source);
  const hasSharedSecret = checksAuthHeader && usesCronSecret;

  return hasUserAuth || hasWebhookSignature || hasCapabilityToken || hasCustomAuthHelper || hasSharedSecret;
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
