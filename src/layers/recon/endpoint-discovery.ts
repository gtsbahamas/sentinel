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
    // Stricter auth check: must have explicit user verification, not just admin API usage
    const hasAuthCheck = /getUser|getSession|auth\.getUser|auth\.getSession/.test(source);

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
