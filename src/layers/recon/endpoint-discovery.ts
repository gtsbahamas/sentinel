import { safeReadFile } from "../../utils/fs.js";
import type { Route, ApiEndpoint } from "../../model/types.js";

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
    // Auth is recognized in three forms:
    //   1. Explicit user/session lookup (Supabase, NextAuth, custom).
    //   2. Webhook signature verification (HMAC + constant-time compare).
    //   3. Capability-URL tokens validated against a DB column like
    //      `approval_token` or `response_token`.
    const hasUserAuth = /getUser|getSession|auth\.getUser|auth\.getSession/.test(source);
    const hasWebhookSignature =
      /createHmac\s*\(/.test(source) && /timingSafeEqual/.test(source);
    const hasCapabilityToken = /\.eq\(\s*["'`][a-z_]*token["'`]/i.test(source);
    const hasAuthCheck = hasUserAuth || hasWebhookSignature || hasCapabilityToken;

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
