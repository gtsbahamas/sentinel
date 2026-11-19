import { relative } from "path";
const [repo, root] = process.argv.slice(2);
const recon = await import(`${repo}/src/layers/recon/index.ts`);
const ha = await import(`${repo}/src/layers/rules/handler-analysis.ts`);
const model = await recon.runRecon(root, ["node_modules"]);
const out = model.endpoints.filter((e: any) => ["POST","PUT","PATCH","DELETE"].includes(e.method)).map((e: any) => [relative(root, e.file), ha.handlerGuard(model, e)]).filter((x: any) => x[1]).map((x: any) => `${x[1]} ${x[0]}`);
console.log([...new Set(out)].sort().join("\n"));
