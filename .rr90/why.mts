import { resolve } from "path";
const [repo, root, file] = process.argv.slice(2);
const recon = await import(`${repo}/src/layers/recon/index.ts`);
const ha = await import(`${repo}/src/layers/rules/handler-analysis.ts`);
const model = await recon.runRecon(resolve(root), ["node_modules"]);
for (const e of model.endpoints.filter((e: any) => e.file.includes(file))) console.log(e.method, e.hasAuthCheck, ha.handlerGuard(model, e));
