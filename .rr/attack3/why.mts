import { relative } from "path";
const [repo, root] = process.argv.slice(2);
const ha = await import(`${repo}/src/layers/rules/handler-analysis.ts`);
const recon = await import(`${repo}/src/layers/recon/index.ts`);
const model = await recon.runRecon(root, ["node_modules"]);
for (const e of model.endpoints) {
  const f = relative(root, e.file);
  if (!f.includes("/yy/") || e.method !== "POST") continue;
  console.log(String(ha.handlerGuard(model, e)).padEnd(18), f);
}
