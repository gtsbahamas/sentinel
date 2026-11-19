import { relative } from "path";
const [repo, root] = process.argv.slice(2);
const recon = await import(`${repo}/src/layers/recon/index.ts`);
const ha = await import(`${repo}/src/layers/rules/handler-analysis.ts`);
const model = await recon.runRecon(root, ["node_modules", ".next", "dist"]);
const eps = model.endpoints.filter((e: any) => ["POST","PUT","PATCH","DELETE"].includes(e.method) && !e.hasAuthCheck);
const ok = eps.filter((e: any) => ha.handlerGuard(model, e));
console.log(`mutation endpoints without a route-file auth check: ${eps.length}; proven guarded: ${ok.length}`);
for (const e of ok) console.log("  " + e.method + " " + relative(root, e.file));
