import { relative, resolve } from "path";
const [repo, rootArg, mode] = process.argv.slice(2);
const root = resolve(rootArg);
const recon = await import(`${repo}/src/layers/recon/index.ts`);
const rules = await import(`${repo}/src/layers/rules/index.ts`);
const a = await import(`${repo}/src/layers/rules/domains/auth-access-control.ts`);
const i = await import(`${repo}/src/layers/rules/domains/input-injection.ts`);
const c = await import(`${repo}/src/layers/rules/domains/cryptography.ts`);
const model = await recon.runRecon(root, ["node_modules", ".next", "dist"]);
if (mode === "order") {
  const ha = await import(`${repo}/src/layers/rules/handler-analysis.ts`);
  const eps = model.endpoints.filter((e: any) => ["POST","PUT","PATCH","DELETE"].includes(e.method));
  const run = (list: any[]) => { const m = { ...model }; return list.map((e) => `${ha.handlerGuard(m, e) ?? "-"} ${relative(root, e.file)}`).sort().join("\n"); };
  const fwd = run(eps), rev = run([...eps].reverse());
  console.log(fwd === rev ? "ORDER-STABLE" : "ORDER-DIFFERS");
  if (fwd !== rev) { console.log(fwd); console.log("---"); console.log(rev); }
  process.exit(0);
}
rules.resetRegistry();
rules.registerRules(a.authAccessControlRules); rules.registerRules(i.inputInjectionRules); rules.registerRules(c.cryptographyRules);
const findings = await rules.runRules(model);
const key = (f: any) => `${f.ruleId ?? f.rule ?? f.id}\t${relative(root, f.evidence?.[0]?.file ?? f.location?.file ?? f.file ?? "?")}:${f.evidence?.[0]?.line ?? ""}`;
console.log(findings.map(key).sort().join("\n"));
