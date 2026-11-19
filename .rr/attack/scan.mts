import { relative } from "path";
const [repo, root] = process.argv.slice(2);
const rules = await import(`${repo}/src/layers/rules/index.js`.replace(/\.js$/, ".ts"));
const auth = await import(`${repo}/src/layers/rules/domains/auth-access-control.ts`);
const crypto = await import(`${repo}/src/layers/rules/domains/cryptography.ts`);
const recon = await import(`${repo}/src/layers/recon/index.ts`);
rules.resetRegistry();
rules.registerRules([...auth.authAccessControlRules, ...crypto.cryptographyRules]);
const model = await recon.runRecon(root, ["node_modules"]);
const findings = await rules.runRules(model);
const out: string[] = [];
for (const f of findings) {
  if (f.ruleId !== "AUTH-001" && f.ruleId !== "CRYPTO-008") continue;
  for (const e of f.evidence) out.push(`${f.ruleId} ${relative(root, e.file)}${f.ruleId === "CRYPTO-008" ? ":" + e.line : ""}`);
}
console.log([...new Set(out)].sort().join("\n"));
