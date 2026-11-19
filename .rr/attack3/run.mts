import { timingSafeEqual } from "node:crypto";
const out: string[] = [];
const rec = (k: string) => out.push(k);
// y05
{ const x = Buffer.from(""), y = Buffer.from("real-secret"); const n = Math.min(x.length, y.length); console.log("y05 empty header passes:", timingSafeEqual(x.subarray(0, n), y.subarray(0, n))); }
// y22
await Promise.all(Array.from([1, 2], async (r) => { rec("y22:" + r); }));
// y23
"ab cd".replace(/\w+/g, (w) => { rec("y23:" + w); return w; });
// y24
JSON.parse('{"a":1}', (k, v) => { rec("y24:" + k); return v; });
// y25
{ const tally = { get next() { rec("y25"); return 1; } }; const { next } = tally; void next; }
// y26
{ const stamp = { toString() { rec("y26"); return "s"; } }; void `${stamp}`; }
// y27
{ const job = { then(done: (v: number) => void) { rec("y27"); done(1); } }; await job; }
// y43
JSON.stringify({ toJSON() { rec("y43"); return "s"; } });
// y11 / y12
class Desk { protected async member(): Promise<{ id: string } | null> { return null; } async guard() { return this.member(); } }
class OpenDesk extends Desk { protected async member() { return { id: "guest" }; } }
console.log("y11 guest admitted:", JSON.stringify(await new OpenDesk().guard()));
class Turnstile { constructor(open: boolean) { if (open) this.passes = async () => ({ id: "preview" }); } async passes(): Promise<{ id: string } | null> { return null; } async holder() { return this.passes(); } }
console.log("y12 preview admitted:", JSON.stringify(await new Turnstile(true).holder()));
// k05
function padFor(this: void, pad: string, lookup: string) { void lookup; return pad; }
console.log("k05 compared value is the raw one:", padFor("RAW", "HASH"));
console.log("ran before any guard:", out.join(" "));
