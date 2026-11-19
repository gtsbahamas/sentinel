// Is this file test code? Decided by the file's path inside the project and nothing else: what a file
// imports or contains is never evidence, because a live route can import a test library. Test code runs
// against throwaway data on a developer's machine or in CI; no visitor's input reaches it, so rules about
// what an attacker can send do not apply to it.
//
// Pass the path relative to the project root, so the folder the project happens to live in is not read.

// Folders whose files a framework serves by location, whatever they are called: Next's `pages/` and
// `app/api/`, Vercel's `api/`, Remix and SvelteKit `routes/`, Netlify, Cloudflare and Supabase
// `functions/`. Nothing under one is ever test code. Compared in lower case: a filesystem that ignores
// case serves `Pages/` as `pages/`.
const SERVED_FOLDERS = new Set(["api", "pages", "routes", "functions"]);
const TEST_FILE_NAME = /\.(?:test|spec)\.[cm]?[jt]sx?$/;
// A route handler is live wherever it sits, so no `route.*` file is test code, `route.test.ts` included.
const ROUTE_FILE_NAME = /^route\./i;

export function isTestFile(projectPath: string): boolean {
  const segments = projectPath.split(/[\\/]+/).filter(Boolean);
  const name = segments.pop() ?? "";
  if (ROUTE_FILE_NAME.test(name)) return false;
  if (segments.some((segment) => SERVED_FOLDERS.has(segment.toLowerCase()))) return false;
  return TEST_FILE_NAME.test(name) || segments.includes("__tests__");
}
