import os, json
S = os.path.expanduser("~/fleet-work.noindex/fix-s7-81/.rr/attack3/stage")
def w(rel, text):
    p = os.path.join(S, rel); os.makedirs(os.path.dirname(p), exist_ok=True); open(p, "w").write(text.lstrip("\n"))
def route(name, body, imports="", pre="", sig="req: Request", dyn=""):
    w(f"src/app/api/yy/{dyn}{name}/route.ts", f'''
import {{ ledger }} from "@/lib/ledger";
{imports}
{pre}
export async function POST({sig}): Promise<Response> {{
{body}
}}
''')
pj = json.load(open(os.path.join(S, "package.json")))
pj["dependencies"].update({"next-auth": "4.24.0", "ajv": "8.12.0"})
json.dump(pj, open(os.path.join(S, "package.json"), "w"), indent=2)

# ---------------------------------------------------------------- helpers
w("src/lib/yy/sigs.ts", '''
import { timingSafeEqual } from "node:crypto";
import { macOf } from "../mac.ts";
import { sameBytes } from "../zz/who.ts";

// y03: the "key" is one the browser bundle ships
export function siteKeyOk(req: Request): boolean {
  return sameBytes(req.headers.get("x-api-key") ?? "", process.env.NEXT_PUBLIC_API_KEY ?? "");
}
// y04: no secret configured -> the value sent is compared with itself
export function sigOk(req: Request, raw: string): boolean {
  const sent = req.headers.get("x-sig") ?? "";
  const secret = process.env.HOOK;
  const expected = secret ? macOf(secret, raw) : sent;
  const a = Buffer.from(sent);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}
// y05: "avoid the length throw" by comparing the common prefix: an empty header matches
export function looseSame(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  const n = Math.min(x.length, y.length);
  return timingSafeEqual(x.subarray(0, n), y.subarray(0, n));
}
export function looseSigned(req: Request): boolean {
  return looseSame(req.headers.get("x-mac") ?? "", process.env.HOOK ?? "");
}
// y06: neither side came with the request
export function configured(): boolean {
  const a = Buffer.from(process.env.HOOK ?? "");
  const b = Buffer.from(process.env.HOOK_COPY ?? "");
  return a.length === b.length && timingSafeEqual(a, b);
}
// y07: the secret rides in the same object and is never used
type Check = { secret: string; header: string; body: string };
export function checkOk(c: Check): boolean {
  const got = Buffer.from(c.header);
  const want = Buffer.from(c.body);
  return got.length === want.length && timingSafeEqual(got, want);
}
// y08: rest parameter: the secret is the first of the values, the other two are compared
export function restOk(...v: string[]): boolean {
  const a = Buffer.from(v[1]);
  const b = Buffer.from(v[2]);
  return a.length === b.length && timingSafeEqual(a, b);
}
// y09: the caller may bring the key
export function tenantSigned(req: Request, raw: string): boolean {
  const key = req.headers.get("x-tenant-key") ?? process.env.HOOK ?? "";
  return sameBytes(req.headers.get("x-mac") ?? "", macOf(key, raw));
}
''')

# y10: a method found by its name
w("src/lib/yy/hook.ts", '''
import { signed } from "../zz/who.ts";
export const hook = { validate(req: Request): boolean { return signed(req); } };
''')
w("src/lib/yy/time.ts", '''
export const nowIso = (): string => new Date().toISOString();
''')
w("src/lib/yy/index.ts", '''
export * from "./hook.ts";
export * from "./time.ts";
''')

# y11 / y12: this.method()
w("src/lib/yy/desk.ts", '''
import { who } from "../zz/who.ts";
export class Desk {
  protected async member(): Promise<{ id: string } | null> { return who(); }
  async guard(): Promise<{ id: string } | null> { return this.member(); }
}
export class OpenDesk extends Desk {
  protected async member(): Promise<{ id: string } | null> { return { id: "guest" }; }
}
export const openDesk = new OpenDesk();

export class Turnstile {
  constructor(open: boolean) {
    if (open) this.passes = async () => ({ id: "preview" });
  }
  async passes(): Promise<{ id: string } | null> { return who(); }
  async holder(): Promise<{ id: string } | null> { return this.passes(); }
}
export const turnstile = new Turnstile(true);
''')

# y13 / y15: an answer kept from another route
w("src/lib/yy/gatekeeper.ts", '''
export function admitted(g: { letIn(req: Request): boolean }, req: Request): boolean {
  return g.letIn(req);
}
export async function holderOf(g: { present(): Promise<{ id: string } | null> }): Promise<{ id: string } | null> {
  return g.present();
}
export async function bearerOf(g: { carried(): Promise<{ id: string } | null> }): Promise<{ id: string } | null> {
  return g.carried();
}
export async function remember(sink: { stash(v: unknown): Promise<void> }, v: unknown): Promise<void> {
  await sink.stash(v);
}
''')
w("src/lib/yy/strict.ts", '''
import { signed, who } from "../zz/who.ts";
export const strictDoor = { letIn(req: Request): boolean { return signed(req); } };
export const memberDoor = { async present(): Promise<{ id: string } | null> { return who(); }, async carried(): Promise<{ id: string } | null> { return who(); } };
export const nowhere = { async stash(_v: unknown): Promise<void> {} };
''')
w("src/lib/yy/lax.ts", '''
import { ledger } from "../ledger.ts";
export const laxDoor = { letIn(_req: Request): boolean { return true; } };
export const guestDoor = { async present(): Promise<{ id: string } | null> { return { id: "guest" }; }, async carried(): Promise<{ id: string } | null> { return { id: "guest" }; } };
export const disk = { async stash(v: unknown): Promise<void> { await ledger.record("stash", v); } };
''')

# y17
w("src/lib/yy/access.ts", '''
import { signed } from "../zz/who.ts";
export function access(req: Request): { ok: boolean } {
  return { ok: signed(req) };
}
''')

# leaks
w("src/lib/yy/keys.ts", '''
const live = new Map<string, string>([["stripe", process.env.STRIPE_LIVE ?? ""]]);
export function allKeys(): Record<string, string> {
  return Object.fromEntries(live);
}
export const sessions = { getAll(): string[] { return [...live.values()]; } };
''')

# visitor / link
w("src/lib/yy/leads.ts", '''
import { ledger } from "../ledger.ts";
const leads: unknown[] = [];
const claims: unknown[] = [];
export async function addLead(lead: { ip: string; email: unknown }): Promise<number> {
  leads.push(lead);
  return leads.length;
}
export async function addClaim(hash: string, note: string): Promise<number> {
  claims.push({ hash, note });
  return claims.length;
}
export async function tooMany(ip: string): Promise<boolean> {
  const n = await ledger.bump(`ip:${ip}`);
  if (n > 5) return true;
  return false;
}
''')

# y33 next-auth raw token
w("src/lib/yy/bearer.ts", '''
import { getToken } from "next-auth/jwt";
export async function bearer(req: Request) {
  return getToken({ req: req as never, raw: true });
}
''')

# y35 patched from a file the route never reaches
w("src/lib/yy/keeper.ts", '''
import { signed } from "../zz/who.ts";
export const keeper = { passThrough(req: Request): boolean { return signed(req); } };
''')
w("src/lib/yy/dev-patch.ts", '''
import { keeper } from "./keeper.ts";
keeper.passThrough = () => true;
''')
w("src/instrumentation.ts", '''
import "./lib/yy/dev-patch.ts";
export function register(): void {}
''')

# y36 a client whose session read is replaced where it is made
w("src/lib/yy/sb.ts", '''
import { createClient } from "@supabase/supabase-js";
export const sb = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
sb.auth.getUser = (async () => ({ data: { user: { id: "preview" } }, error: null })) as never;
''')
w("src/lib/yy/member.ts", '''
import { sb } from "./sb.ts";
export async function member() {
  const { data } = await sb.auth.getUser();
  return data.user;
}
''')

# y41 a class that shares the name of the platform's crypto
w("src/lib/yy/fake-crypto.ts", '''
class crypto {
  static timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean { return a.length >= 0 && b.length >= 0; }
}
export function classSigned(req: Request): boolean {
  return crypto.timingSafeEqual(Buffer.from(req.headers.get("x-mac") ?? ""), Buffer.from(process.env.HOOK ?? ""));
}
''')
w("src/lib/yy/ns-crypto.ts", '''
namespace Dev {
  export const crypto = { timingSafeEqual: (a: Uint8Array, b: Uint8Array): boolean => a.length >= 0 && b.length >= 0 };
}
import crypto = Dev.crypto;
export function nsSigned(req: Request): boolean {
  return crypto.timingSafeEqual(Buffer.from(req.headers.get("x-mac") ?? ""), Buffer.from(process.env.HOOK ?? ""));
}
''')

GUARD = '''  const m = await who();
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m.id);
  return new Response("ok");'''
WHO = 'import { who } from "@/lib/zz/who";'

# ---------------------------------------------------------------- controls
route("y01-control-open", '''  await ledger.record("note", await req.text());
  return new Response("ok");''')
route("y02-control-header-present", '''  if (!req.headers.get("x-key")) return new Response("no", { status: 403 });
  await ledger.record("note", await req.text());
  return new Response("ok");''')

# ---------------------------------------------------------------- what counts as a secret
def sig_route(name, call, imp):
    route(name, f'''  const raw = await req.text();
  if (!{call}) return new Response("no", {{ status: 403 }});
  await ledger.record("note", raw);
  return new Response("ok");''', f'import {{ {imp} }} from "@/lib/yy/sigs";')
sig_route("y03-shipped-key", "siteKeyOk(req)", "siteKeyOk")
sig_route("y04-unset-means-echo", "sigOk(req, raw)", "sigOk")
sig_route("y05-common-prefix", "looseSigned(req)", "looseSigned")
sig_route("y06-neither-side-sent", "configured()", "configured")
sig_route("y07-secret-in-same-object", 'checkOk({ secret: process.env.HOOK ?? "", header: req.headers.get("x-mac") ?? "", body: raw })', "checkOk")
sig_route("y08-rest-values", 'restOk(process.env.HOOK ?? "", req.headers.get("x-a") ?? "", req.headers.get("x-b") ?? "")', "restOk")
sig_route("y09-caller-brings-key", "tenantSigned(req, raw)", "tenantSigned")

# ---------------------------------------------------------------- which code a call runs
route("y10-method-by-name", '''  const body = await req.json();
  if (!ajv.validate(shape, body)) return new Response("bad", { status: 400 });
  await ledger.record("lead", { body, at: nowIso() });
  return new Response("ok");''', 'import Ajv from "ajv";\nimport { nowIso } from "@/lib/yy";', 'const ajv = new Ajv();\nconst shape = { type: "object" };')
route("y11-subclass-override", '''  const m = await openDesk.guard();
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m.id);
  return new Response("ok");''', 'import { openDesk } from "@/lib/yy/desk";')
route("y12-constructor-swaps-method", '''  const m = await turnstile.holder();
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m.id);
  return new Response("ok");''', 'import { turnstile } from "@/lib/yy/desk";')
route("y13a-door-strict", '''  if (!admitted(strictDoor, req)) return new Response("no", { status: 403 });
  await ledger.record("note", await req.text());
  return new Response("ok");''', 'import { admitted } from "@/lib/yy/gatekeeper";\nimport { strictDoor } from "@/lib/yy/strict";')
route("y13z-door-lax", '''  if (!admitted(laxDoor, req)) return new Response("no", { status: 403 });
  await ledger.record("note", await req.text());
  return new Response("ok");''', 'import { admitted } from "@/lib/yy/gatekeeper";\nimport { laxDoor } from "@/lib/yy/lax";')

def door(name, fn, obj, mod):
    route(name, f"""  const m = await {fn}({obj});
  if (!m) return new Response("no", {{ status: 403 }});
  await ledger.record("note", m.id);
  return new Response("ok");""", f'import {{ {fn} }} from "@/lib/yy/gatekeeper";\nimport {{ {obj} }} from "@/lib/yy/{mod}";')
door("y14a-holder-member", "holderOf", "memberDoor", "strict")
door("y14z-holder-guest", "holderOf", "guestDoor", "lax")
door("y14b-bearer-guest", "bearerOf", "guestDoor", "lax")
door("y14y-bearer-member", "bearerOf", "memberDoor", "strict")
route("y15a-sink-nowhere", f'''  await remember(nowhere, await req.text());
{GUARD}''', f'{WHO}\nimport {{ remember }} from "@/lib/yy/gatekeeper";\nimport {{ nowhere }} from "@/lib/yy/strict";')
route("y15z-sink-disk", f'''  await remember(disk, await req.text());
{GUARD}''', f'{WHO}\nimport {{ remember }} from "@/lib/yy/gatekeeper";\nimport {{ disk }} from "@/lib/yy/lax";')
route("y35-patched-elsewhere", '''  if (!keeper.passThrough(req)) return new Response("no", { status: 403 });
  await ledger.record("note", await req.text());
  return new Response("ok");''', 'import { keeper } from "@/lib/yy/keeper";')
route("y36-client-patched", '''  const m = await member();
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m.id);
  return new Response("ok");''', 'import { member } from "@/lib/yy/member";')
route("y40-switch-shadow", '''  switch (1) {
    case 1:
      const who = async (): Promise<{ id: string } | null> => ({ id: "guest" });
    default: {
      const m = await who();
      if (!m) return new Response("no", { status: 403 });
      await ledger.record("note", m.id);
    }
  }
  return new Response("ok");''', WHO.replace("who }", "who as realWho }") + "\nvoid realWho;" if False else WHO)
route("y41-class-named-crypto", '''  if (!classSigned(req)) return new Response("no", { status: 403 });
  await ledger.record("note", await req.text());
  return new Response("ok");''', 'import { classSigned } from "@/lib/yy/fake-crypto";')
route("y42-import-equals-crypto", '''  if (!nsSigned(req)) return new Response("no", { status: 403 });
  await ledger.record("note", await req.text());
  return new Response("ok");''', 'import { nsSigned } from "@/lib/yy/ns-crypto";')
route("y33-raw-bearer", '''  const t = await bearer(req);
  if (!t) return new Response("no", { status: 403 });
  await ledger.record("note", await req.text());
  return new Response("ok");''', 'import { bearer } from "@/lib/yy/bearer";')

# ---------------------------------------------------------------- what runs before the guard
route("y16-module-write-through-wrapper", f'''  const sent = await req.json();
  const ctx = {{ settings }};
  ctx.settings.owner = sent.owner;
{GUARD}''', f'{WHO}\nimport {{ settings }} from "@/lib/zz/fx";')
route("y17-answer-rewritten-through-wrapper", '''  const t = access(req);
  const all = { t };
  if (req.headers.get("x-preview")) all.t.ok = true;
  if (!t.ok) return new Response("no", { status: 403 });
  await ledger.record("note", await req.text());
  return new Response("ok");''', 'import { access } from "@/lib/yy/access";')
route("y22-array-from-by-name", f'''  const save = async (row: unknown): Promise<void> => {{ await ledger.record("row", row); }};
  const sent = await req.json();
  await Promise.all(Array.from(sent.rows as unknown[], save));
{GUARD}''', WHO)
route("y23-replace-by-name", f'''  const save = (word: string): string => {{ void ledger.record("word", word); return word; }};
  const raw = await req.text();
  const clean = raw.replace(/\\w+/g, save);
  void clean;
{GUARD}''', WHO)
route("y24-reviver-by-name", f'''  const keep = (key: string, value: unknown): unknown => {{ void ledger.record(key, value); return value; }};
  const sent = JSON.parse(await req.text(), keep);
  void sent;
{GUARD}''', WHO)
route("y25-getter-by-destructuring", f'''  const {{ next }} = tally;
  void next;
{GUARD}''', f'{WHO}\nimport {{ tally }} from "@/lib/zz/fx";')
route("y26-to-string-in-template", f'''  const raw = await req.text();
  const stamp = {{ toString(): string {{ void ledger.record("hit", raw); return "s"; }} }};
  const label = `${{stamp}}`;
  void label;
{GUARD}''', WHO)
route("y27-thenable-awaited", f'''  const raw = await req.text();
  const job = {{ then(done: (v: number) => void): void {{ void ledger.record("job", raw); done(1); }} }};
  await job;
{GUARD}''', WHO)
route("y28-package-named-log", f'''  await log.Client.create().set("last", await req.text(), {{}});
{GUARD}''', f'{WHO}\nimport log from "memjs";')
route("y43-to-json", f'''  const raw = await req.text();
  const row = {{ toJSON(): string {{ void ledger.record("hit", raw); return "s"; }} }};
  const text = JSON.stringify(row);
  void text;
{GUARD}''', WHO)

# ---------------------------------------------------------------- what everyone is answered
route("y18-module-value-through-local", '''  const m = await who();
  if (m) await ledger.record("seen", m.id);
  const all = vault;
  return Response.json({ keys: [...all.entries()] });''', f'{WHO}\nimport {{ vault }} from "@/lib/zz/fx";')
route("y19-module-value-through-helper", '''  if (VERBOSE) console.log("dump");
  return Response.json(allKeys());''', 'import { allKeys } from "@/lib/yy/keys";', "const VERBOSE = false;")
route("y20-mint-for-anyone", '''  const { userId } = await req.json();
  const mac = createHmac("sha256", process.env.SESSION_SECRET ?? "").update(String(userId)).digest("hex");
  if (VERBOSE) console.log("minted", userId);
  return Response.json({ session: `${userId}.${mac}` });''', 'import { createHmac } from "node:crypto";', "const VERBOSE = false;")
route("y21-env-answered", '''  if (VERBOSE) console.log("env");
  return Response.json({ stripe: process.env.STRIPE_LIVE });''', "", "const VERBOSE = false;")
route("y48-local-named-cookies", '''  const cookies = sessions;
  if (VERBOSE) console.log("all");
  return Response.json({ live: cookies.getAll() });''', 'import { sessions } from "@/lib/yy/keys";', "const VERBOSE = false;")

# ---------------------------------------------------------------- visitor limit / link
route("y29-write-taken-for-count", '''  const ip = req.headers.get("x-forwarded-for") ?? "unknown";
  const sent = await req.json();
  const position = await addLead({ ip, email: sent.email });
  if (position > 5000) return new Response("the list is full", { status: 409 });
  return Response.json({ position });''', 'import { addLead } from "@/lib/yy/leads";')
route("y30-limiter-answer-ignored", '''  const ip = req.headers.get("x-forwarded-for") ?? "unknown";
  const over = await tooMany(ip);
  if (over) console.warn("over the limit", ip);
  const sent = await req.json();
  const position = await addLead({ ip, email: sent.email });
  return Response.json({ position });''', 'import { addLead, tooMany } from "@/lib/yy/leads";')
route("y31-limiter-never-read", '''  const ip = req.headers.get("x-forwarded-for") ?? "unknown";
  await tooMany(ip);
  const sent = await req.json();
  const position = await addLead({ ip, email: sent.email });
  return Response.json({ position });''', 'import { addLead, tooMany } from "@/lib/yy/leads";')
route("y32-hash-stored-answer-kept", '''  const { token } = await ctx.params;
  const saved = await addClaim(digestOf(token), await req.text());
  return Response.json({ saved });''', 'import { digestOf } from "@/lib/links";\nimport { addClaim } from "@/lib/yy/leads";',
  sig="req: Request, ctx: { params: Promise<{ token: string }> }", dyn="l/[token]/")
route("y34-hash-sent-outward", '''  const { token } = await ctx.params;
  const res = await fetch(`https://hooks.example.com/${digestOf(token)}`, { method: "POST", body: await req.text() });
  return new Response(res.ok ? "ok" : "failed");''', 'import { digestOf } from "@/lib/links";',
  sig="req: Request, ctx: { params: Promise<{ token: string }> }", dyn="l/[token]/")

# ---------------------------------------------------------------- CRYPTO-008
HEAD = '''import { createHash } from "node:crypto";
type Sent = { scheme: string; signature: string };
type Key = { id: string; token: string; tokenHash: string };
const keys: Key[] = [];
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
'''
w("src/lib/yy/k01.ts", HEAD + '''// the server's secret, handed in, hashed and matched with what the caller sent
export function k01(sentSigs: Sent[], secret: string) {
  return sentSigs.find((s) => s.signature === sha(secret));
}
''')
w("src/lib/yy/k02.ts", HEAD + '''async function readSigs(header: string): Promise<Sent[]> { return header.split(",").map((p) => ({ scheme: p.split("=")[0], signature: p.split("=")[1] })); }
export async function k02(header: string, secret: string) {
  const sent = await readSigs(header);
  return sent.find((s) => s.signature === sha(secret));
}
''')
w("src/lib/yy/k03.ts", HEAD + '''// rows written before hashing still hold the token itself: a miss is tried again with what was sent
export function keyFor(lookup: string, raw?: string): Key | undefined {
  const hit = keys.find((k) => k.token === lookup);
  if (!hit && raw) return keyFor(raw);
  return hit;
}
export const byToken = (sent: string) => keyFor(sha(sent), sent);
''')
w("src/lib/yy/k04.ts", HEAD + '''export function rowFor(lookup: string): Key | undefined {
  return keys.find((k) => k.token === lookup);
}
export const hashedRow = (sent: string) => rowFor(sha(sent));
''')
w("src/lib/yy/k04-caller.ts", '''export async function rawRow(sent: string) {
  const store = await import("./k04.ts");
  return store.rowFor(sent);
}
''')
w("src/lib/yy/k05.ts", HEAD + '''// the comparison is of the first value handed over; the analysis counts `this` as a parameter
export function padFor(this: void, pad: string, lookup: string): Key | undefined {
  void lookup;
  return keys.find((k) => k.token === pad);
}
export const padded = (sent: string) => padFor(sent, sha(sent));
''')
w("src/lib/yy/k06.ts", HEAD + '''function parseOne(header: string): Sent { return { scheme: header.split("=")[0], signature: header.split("=")[1] }; }
export function k06(rows: Key[], header: string, secret: string) {
  const h = sha(secret);
  for (const s of rows) {
    if (s.id) { const s = parseOne(header); if (s.signature === h) return s; }
  }
  return null;
}
''')
w("src/lib/yy/k07.ts", HEAD + '''export function k07(req: Request, sent: string, adminToken: string) {
  const ok = req.headers
    .get("x-admin-token") === adminToken || keys.find((k) => k.tokenHash === sha(sent)) !== undefined;
  return ok;
}
''')
w("src/lib/yy/k08.ts", '''// a secret written into the code, compared as text
export function k08(sent: { token: string }): boolean {
  return sent.token === "9f8a7c6b5d4e3f2a1b0c9d8e7f6a5b4c";
}
''')
w("src/lib/yy/k09.ts", HEAD + '''// the two halves of k01 in two functions
function siftRows(rows: Sent[], h: string) {
  return rows.find((r) => r.signature === h);
}
export function k09(sentSigs: Sent[], secret: string) {
  return siftRows(sentSigs, sha(secret));
}
''')
w("src/lib/yy/k10.ts", HEAD + '''// control: must stay reported
export function k10(sent: string) {
  return keys.find((k) => k.token === sent);
}
''')
w("src/lib/yy/k11.ts", HEAD + '''// rows remembered from the last request, matched with the hashed secret
let lastSent: Sent[] = [];
export function note(rows: Sent[]): void { lastSent = rows; }
export function k11(secret: string) {
  return lastSent.find((s) => s.signature === sha(secret));
}
''')
print("written")
