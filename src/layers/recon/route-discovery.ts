import fg from "fast-glob";
import { join, relative, dirname } from "path";
import { existsSync } from "fs";
import { safeReadFile } from "../../utils/fs.js";
import type { Route } from "../../model/types.js";

export async function discoverRoutes(
  projectPath: string,
  framework: string,
): Promise<Route[]> {
  if (framework !== "nextjs-app" && framework !== "nextjs-pages") return [];

  const appDir = existsSync(join(projectPath, "src", "app"))
    ? join(projectPath, "src", "app")
    : existsSync(join(projectPath, "app"))
    ? join(projectPath, "app")
    : null;

  if (!appDir) return [];

  const files = await fg(["**/{page,route}.{ts,tsx,js,jsx}"], {
    cwd: appDir,
    absolute: true,
    ignore: ["**/node_modules/**"],
  });

  const routes: Route[] = [];

  for (const file of files) {
    const rel = relative(appDir, dirname(file));
    const routePath = "/" + rel.replace(/\\/g, "/").replace(/^$/, "");
    const normalized = routePath === "/." || routePath === "/" ? "/" : routePath.replace(/\/page$/, "");
    const isApi = rel.startsWith("api/") || rel === "api";
    const paramNames = [...normalized.matchAll(/\[([^\]]+)\]/g)].map((m) => m[1]);

    const source = await safeReadFile(file);
    const hasAuthCheck = /auth|getUser|getSession|supabase\.auth/.test(source);

    if (file.endsWith("route.ts") || file.endsWith("route.tsx") || file.endsWith("route.js") || file.endsWith("route.jsx")) {
      const methods = extractHttpMethods(source);
      for (const method of methods) {
        routes.push({
          path: normalized,
          method,
          file,
          isApi: true,
          hasAuthCheck,
          paramNames,
        });
      }
    } else {
      routes.push({
        path: normalized,
        method: "GET",
        file,
        isApi: false,
        hasAuthCheck,
        paramNames,
      });
    }
  }

  return routes;
}

function extractHttpMethods(source: string): Array<Route["method"]> {
  const methods: Array<Route["method"]> = [];
  const names: Array<Route["method"]> = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"];
  for (const name of names) {
    const pattern = new RegExp(`export\\s+(async\\s+)?function\\s+${name}\\b`);
    if (pattern.test(source)) methods.push(name);
  }
  return methods.length > 0 ? methods : ["ALL"];
}
