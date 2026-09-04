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
  // Also recognize `resolve` and `authenticate` as guard-style verbs:
  // `await resolveWorkspaceAuth()`, `await authenticateAgent(req)`,
  // `await resolveActiveWorkspace()` — these are the canonical Next.js +
  // Supabase patterns the iteration-3 corpus revealed.
  const hasGuardCall =
    /await\s+\w*(?:require|ensure|assert|verify|check|validate|guard|resolve|authenticate|authorize)\w*\s*\(/i.test(source);

  // (2) Verb + auth-domain noun call (sync or async). Case-sensitive because
  // real call sites are camelCase; lowercasing would over-match identifiers
  // like `requirements(` or `getuserland(` that aren't auth.
  // Added (iter-4): Workspace, Active, Tenant, Organization, Account, Agent.
  // Added (iter-5): Provisioning, Key, Secret, Webhook, Hmac, Signature, Cron,
  //                 Api, Bearer, Caller, Request, Origin, Csrf — these cover
  //                 the dominant FP pattern from v4 (validateProvisioningKey,
  //                 verifyWebhookSecret, validateApiKey, validateRequestOrigin).
  // Added (2026-09-04): `authorize`. The verb list carried `authenticate` but
  // not `authorize`, so the plainest possible name for an authorization guard
  // was the one name the detector could not read. Found by self-scan: shipsafe-web
  // collapsed eleven duplicate cron-bearer checks into one `authorizeCron(request)`
  // helper and AUTH-001 immediately reported the route as unauthenticated. Note
  // `Cron` was already in the noun list below — both halves of the identifier were
  // known, and the verb alternation was the only thing standing between them.
  // Any codebase that factors its guard into an authorize* helper hit this.
  const hasVerbNounCall =
    /\b(?:require|ensure|assert|verify|check|validate|get|fetch|load|resolve|authenticate|authorize)\w*(?:Auth|Session|User|Permission|Role|Staff|Portal|Member|Principal|Token|Password|Workspace|Active|Tenant|Organization|Account|Agent|Provisioning|Key|Secret|Webhook|Hmac|Signature|Cron|Api|Bearer|Caller|Request|Origin|Csrf)\w*\s*\(/.test(source);

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
  // v0.1.4: broadened. Real codebases name webhook/cron secrets after the
  // service they protect (REVENUE_INTEL_WEBHOOK_SECRET, EMAIL_INBOUND_SECRET,
  // X_VOICE_WORKER_SECRET, DEPLOY_SECRET, etc). Match anything ending in
  // _SECRET, _KEY, or _TOKEN that's not the public Supabase anon key.
  const usesSharedSecretEnv =
    /process\.env\.\w*(?:SECRET|TOKEN|API_KEY)\w*/.test(source) &&
    !/process\.env\.NEXT_PUBLIC_/.test(source.match(/process\.env\.\w+/)?.[0] ?? "");
  const hasSharedSecret = checksAuthHeader && usesSharedSecretEnv;

  // v0.1.4: Bearer-token equality check against any env secret.
  // Pattern: `authHeader !== \`Bearer ${process.env.SOMETHING_SECRET}\``
  const hasBearerEnvCompare =
    /Bearer\s*\$\{process\.env\.\w+\}/.test(source) ||
    /["'`]Bearer\s+["'`]\s*\+\s*process\.env\.\w+/.test(source) ||
    /authHeader\s*[!=]==?\s*[`'"]Bearer/i.test(source);

  // (8) Custom Bearer-token + DB column lookup (the heartbeat pattern):
  // headers.get('authorization') AND a `.eq("...", value)` Supabase lookup
  // within proximity. This catches hand-rolled bearer flows that don't use
  // Supabase's auth.getUser (e.g., per-instance keys looked up against a
  // dedicated table like `ec2_instances`).
  const hasBearerDbLookup =
    /headers\.get\(\s*["'`]authorization["'`]\s*\)[\s\S]{0,800}?\.eq\s*\(/i.test(source);

  // (9) Stripe webhook signature pattern: `stripe.webhooks.constructEvent`
  // is the canonical Stripe verification call. Treat it as auth.
  const hasStripeWebhook = /\.\s*webhooks\s*\.\s*constructEvent\s*\(/.test(source);

  // (10) Inngest / Svix / similar managed-queue endpoints whose framework
  // verifies the request signature for the handler. Match the import +
  // usage pattern.
  const hasManagedQueueAuth =
    (/from\s+["'`]inngest/.test(source) && /\.serve\s*\(/.test(source)) ||
    /from\s+["'`]svix["'`]/.test(source);

  // (11) Twilio webhook signature: `validateRequest` from `twilio` package
  // OR an explicit `X-Twilio-Signature` header check.
  const hasTwilioWebhook =
    /from\s+["'`]twilio/.test(source) ||
    /["']x-twilio-signature["']/i.test(source) ||
    /validateRequest\s*\(/.test(source);

  // (12) Admin / cron / shared-secret env compares: ADMIN_API_SECRET,
  // CRON_SECRET, etc. Any mention of an `_SECRET` env in a comparison/use
  // context is treated as auth. Already covered by (7) hasSharedSecret if
  // paired with header read; this is a looser fallback that also catches
  // body-level secret comparison (`if (body.secret === process.env.X)`).
  const hasEnvSecretCompare =
    /process\.env\.(?:ADMIN|API|INTERNAL|CRON|SCANNER|WEBHOOK|PROVISIONING|SHARED)_?\w*_(?:SECRET|KEY|TOKEN)\s*(?:===|!==|==|!=)/.test(
      source,
    );

  // (13) Header read of a custom auth header like x-api-key, x-webhook-secret,
  // x-provisioning-key, x-internal-token, etc. Stronger signal than just
  // header read alone — these names are auth-coded by convention.
  const hasCustomAuthHeader =
    /headers\s*\.\s*get\s*\(\s*["'`]x-(?:api-key|webhook-secret|provisioning-key|internal-token|signature|hub-signature|signed-payload|admin-secret|cron-secret)/i.test(
      source,
    );

  return (
    hasGuardCall ||
    hasVerbNounCall ||
    hasBearerSupabase ||
    hasCookieSSR ||
    hasWebhookSignature ||
    hasCapabilityToken ||
    hasSharedSecret ||
    hasBearerDbLookup ||
    hasStripeWebhook ||
    hasManagedQueueAuth ||
    hasTwilioWebhook ||
    hasEnvSecretCompare ||
    hasCustomAuthHeader ||
    hasBearerEnvCompare
  );
}

export async function discoverEndpoints(routes: Route[]): Promise<ApiEndpoint[]> {
  const endpoints: ApiEndpoint[] = [];
  const apiRoutes = routes.filter((r) => r.isApi);

  for (const route of apiRoutes) {
    const source = await safeReadFile(route.file);
    // v0.1.4: broadened detection. The previous regex missed:
    //   - safeParse() — the dominant zod idiom in modern codebases
    //   - Explicit type-check guard chains (the verifier consistently calls
    //     these "adequate validation" — typeof checks + length/range +
    //     non-empty + early reject)
    //   - Schema-style helpers in custom validators (validateInput, etc.)
    // Detection layers:
    //   (a) Library mention or call (zod/yup/joi/.parse/.validate/.safeParse)
    //   (b) Multiple typeof string checks paired with status:400 / Bad Request
    //       which is the universal hand-rolled validation idiom
    const hasValidationLib = /zod|yup|joi|\.parse\s*\(|\.validate\s*\(|\.safeParse\s*\(/.test(source);
    const typeofChecks = (source.match(/typeof\s+\w+\s*!==?\s*["'](?:string|number|boolean|object)["']/g) ?? []).length;
    const hasReject400 = /status\s*:\s*400|status\(400|status\s*:\s*422|status\(422|"Invalid"|"Bad request"|"Bad Request"/.test(source);
    const hasManualValidation = typeofChecks >= 1 && hasReject400;
    const hasValidation = hasValidationLib || hasManualValidation;
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
