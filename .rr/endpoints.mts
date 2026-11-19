import { relative } from "path";
const [repo, root] = process.argv.slice(2);
const recon = await import(`${repo}/src/layers/recon/index.ts`);
const model = await recon.runRecon(root, ["node_modules"]);
const out = model.endpoints.filter((e: any) => ["POST","PUT","PATCH","DELETE"].includes(e.method)).map((e: any) => `AUTH-001 ${relative(root, e.file)}${e.hasAuthCheck ? " hasAuthCheck" : ""}`);
console.log([...new Set(out)].sort().join("\n"));
