import os, json
S = os.path.expanduser("~/fleet-work.noindex/fix-s7-81/.rr/attack2/stage")
def w(rel, text):
    p = os.path.join(S, rel); os.makedirs(os.path.dirname(p), exist_ok=True); open(p, "w").write(text.lstrip("\n"))
def route(name, body, imports="", pre="", sig="req: Request", dyn=""):
    w(f"src/app/api/zz/{dyn}{name}/route.ts", f'''
import {{ ledger }} from "@/lib/ledger";
{imports}
{pre}
export async function POST({sig}): Promise<Response> {{
{body}
}}
''')
pj = json.load(open(os.path.join(S, "package.json"))); pj["imports"] = {"#zz/*": "./src/lib/zz/*.ts"}
pj["dependencies"].update({"jsonwebtoken": "9.0.0", "memjs": "1.3.0"})
json.dump(pj, open(os.path.join(S, "package.json"), "w"), indent=2)

w("src/lib/zz/who.ts", '''
import { createClient } from "@supabase/supabase-js";
import { timingSafeEqual } from "node:crypto";
import { ledger } from "../ledger.ts";
const client = () => createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
export async function who(): Promise<{ id: string } | null> {
  const { data } = await client().auth.getUser();
  return data.user;
}
export class Denied extends Error {}
export async function mustBeIn(): Promise<{ id: string }> {
  const u = await who();
  if (!u) throw new Denied("no");
  return u;
}
export function sameBytes(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
export function signed(req: Request): boolean {
  return sameBytes(req.headers.get("x-mac") ?? "", process.env.HOOK ?? "");
}
// generators: calling one runs nothing
export function* mustHaveMac(req: Request): Generator<never, void> {
  if (!signed(req)) throw new Denied("no");
}
export function* macOk(req: Request): Generator<never, boolean> {
  return signed(req);
}
// a default argument that writes for everyone
export async function whoSeen(req: Request, seen: unknown = ledger.record("seen", req.url)): Promise<{ id: string } | null> {
  void seen;
  return who();
}
// both sides come with the request
export function echoOk(req: Request): boolean {
  const a = Buffer.from(req.headers.get("x-mac") ?? "");
  const b = Buffer.from(req.headers.get("x-mac-copy") ?? "");
  return a.length === b.length && timingSafeEqual(a, b);
}
// a computed key that overrides the proven field
export function overridden(req: Request): { ok: boolean } {
  return { ok: signed(req), ["ok"]: true };
}
''')
w("src/lib/zz/sum.ts", '''
import { createHash, timingSafeEqual } from "node:crypto";
// an unkeyed checksum of the body: anyone can work it out
export function checksumOk(sent: string, raw: string): boolean {
  const want = Buffer.from(createHash("sha256").update(raw).digest("hex"));
  const got = Buffer.from(sent);
  return got.length === want.length && timingSafeEqual(got, want);
}
''')
w("src/lib/zz/swap.ts", '''
import { signed } from "./who.ts";
export let pass = (req: Request): boolean => signed(req);
// no secret configured: everyone passes
if (!process.env.HOOK) pass = () => true;
''')
w("src/lib/zz/verifiers.ts", '''
import { signed } from "./who.ts";
export const strict = { admit(req: Request): boolean { return signed(req); } };
const anyone = (_req: Request): boolean => true;
export const loose = { admit: anyone };
''')
w("src/lib/zz/fx.ts", '''
import { ledger } from "../ledger.ts";
export async function quiet(_v: unknown): Promise<void> {}
export function makeNoisy(): (v: unknown) => Promise<void> {
  return async (v) => { await ledger.record("pre", v); };
}
export const intake = { async parse(raw: string): Promise<string> { await ledger.record("raw", raw); return raw; } };
export const team = { async join(member: unknown): Promise<void> { await ledger.record("joined", member); } };
export const tally = { get next(): number { void ledger.record("hit", 1); return 1; } };
export class TrackedError extends Error {
  constructor(message: string, row: unknown) { super(message); void ledger.record("refused", row); }
}
export class Rejection { constructor(row: unknown) { void ledger.record("rejected", row); } }
export const settings: { owner: unknown } = { owner: "root" };
export const vault = new Map<string, string>([["stripe", process.env.STRIPE_LIVE ?? ""]]);
export const console = { log(kind: string, row: unknown): void { void ledger.record(kind, row); } };
''')
w("src/lib/zz/audit.ts", '''
import { ledger } from "../ledger.ts";
export const log = { async record(kind: string, row: unknown): Promise<void> { await ledger.record(kind, row); } };
''')
w("src/lib/zz/jwt.ts", '''
import jwt from "jsonwebtoken";
const done = (): void => {};
// with a callback jsonwebtoken reports the failure to the callback and throws nothing
export function mustCarryPass(req: Request): void {
  jwt.verify(req.headers.get("x-pass") ?? "", process.env.PASS_KEY ?? "", done);
}
''')
W = 'import { who } from "@/lib/zz/who";'
TAIL = '''  const m = await who();
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m.id);
  return new Response("ok");'''
route("a01-destructure-default", '''  const b = await req.json();
  const { actor = await mustBeIn() } = b;
  await ledger.record("note", actor);
  return new Response("ok");''', 'import { mustBeIn } from "@/lib/zz/who";')
route("a01b-assign-pattern-default", '''  const b = await req.json();
  let actor: unknown;
  ({ actor = await mustBeIn() } = b);
  await ledger.record("note", actor);
  return new Response("ok");''', 'import { mustBeIn } from "@/lib/zz/who";')
route("a02-nullish-assign", '''  const b = await req.json();
  let actor = b.actor;
  actor ??= await mustBeIn();
  await ledger.record("note", actor);
  return new Response("ok");''', 'import { mustBeIn } from "@/lib/zz/who";')
route("a03-optional-chain-arg", '''  const b = await req.json();
  b.tags?.includes((await mustBeIn()).id);
  await ledger.record("note", b);
  return new Response("ok");''', 'import { mustBeIn } from "@/lib/zz/who";')
route("a04-generator-throws", '''  mustHaveMac(req);
  await ledger.record("note", await req.text());
  return new Response("ok");''', 'import { mustHaveMac } from "@/lib/zz/who";')
route("a05-generator-answer", '''  if (!macOk(req)) return new Response("no", { status: 403 });
  await ledger.record("note", await req.text());
  return new Response("ok");''', 'import { macOk } from "@/lib/zz/who";')
route("a06-var-redeclared", '''  const b = await req.json();
  var m: any = await who();
  var m: any = b.actor;
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m);
  return new Response("ok");''', W)
route("a07-var-hoisted-from-block", '''  const b = await req.json();
  var m: any = await who();
  if (b.preview) {
    var m: any = b.actor;
  }
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m);
  return new Response("ok");''', W)
route("a08-let-fn-reassigned", '''  const b = await req.json();
  let note = async (_v: unknown): Promise<void> => {};
  if (b.loud) note = async (v) => { await ledger.record("pre", v); };
  await note(b);
''' + TAIL, W)
route("a09-module-let-reassigned", '''  if (!pass(req)) return new Response("no", { status: 403 });
  await ledger.record("note", await req.text());
  return new Response("ok");''', 'import { pass } from "@/lib/zz/swap";')
route("a10-method-by-reference", '''  const v = process.env.HOOK ? strict : loose;
  if (!v.admit(req)) return new Response("no", { status: 403 });
  await ledger.record("note", await req.text());
  return new Response("ok");''', 'import { strict, loose } from "@/lib/zz/verifiers";')
route("a10b-loose-direct", '''  if (!loose.admit(req)) return new Response("no", { status: 403 });
  await ledger.record("note", await req.text());
  return new Response("ok");''', 'import { loose } from "@/lib/zz/verifiers";')
route("a12-shadowed-import", '''  const b = await req.json();
  const quiet = makeNoisy();
  await quiet(b);
''' + TAIL, W + '\nimport { makeNoisy } from "@/lib/zz/fx";\nimport { quiet as _q } from "@/lib/zz/fx";\nimport { quiet } from "@/lib/zz/fx";'.replace('import { quiet as _q } from "@/lib/zz/fx";\n', ''))
route("a13-jwt-callback-by-name", '''  mustCarryPass(req);
  await ledger.record("note", await req.text());
  return new Response("ok");''', 'import { mustCarryPass } from "@/lib/zz/jwt";')
route("a14-both-sides-sent", '''  if (!echoOk(req)) return new Response("no", { status: 403 });
  await ledger.record("note", await req.text());
  return new Response("ok");''', 'import { echoOk } from "@/lib/zz/who";')
route("a15-unkeyed-checksum", '''  const raw = await req.text();
  if (!checksumOk(req.headers.get("x-sum") ?? "", raw)) return new Response("no", { status: 403 });
  await ledger.record("note", raw);
  return new Response("ok");''', 'import { checksumOk } from "@/lib/zz/sum";')
route("a16-self-compare-in-helper", '''  const sent = req.headers.get("x-mac") ?? "";
  if (!sameBytes(sent, sent)) return new Response("no", { status: 403 });
  await ledger.record("note", await req.text());
  return new Response("ok");''', 'import { sameBytes } from "@/lib/zz/who";')
route("a17-own-parse-writes", '''  const raw = await intake.parse(await req.text());
  void raw;
''' + TAIL, W + '\nimport { intake } from "@/lib/zz/fx";')
route("a18-own-join-writes", '''  const b = await req.json();
  await team.join(b.member);
''' + TAIL, W + '\nimport { team } from "@/lib/zz/fx";')
route("a19-package-replace", '''  const b = await req.json();
  await cache.replace("flags", JSON.stringify(b), {});
''' + TAIL, W + '\nimport memjs from "memjs";', 'const cache = memjs.Client.create();')
route("a21-getter-writes", '''  const n = tally.next;
  void n;
''' + TAIL, W + '\nimport { tally } from "@/lib/zz/fx";')
route("a22-error-constructor-writes", '''  const b = await req.json();
  const m = await who();
  if (!m) {
    const e = new TrackedError("no", b);
    return new Response(e.message, { status: 403 });
  }
  await ledger.record("note", m.id);
  return new Response("ok");''', W + '\nimport { TrackedError } from "@/lib/zz/fx";')
route("a23-thrown-constructor-writes", '''  const b = await req.json();
  const m = await who();
  if (!m) throw new Rejection(b);
  await ledger.record("note", m.id);
  return new Response("ok");''', W + '\nimport { Rejection } from "@/lib/zz/fx";')
route("a24-helper-default-argument", '''  const m = await whoSeen(req);
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m.id);
  return new Response("ok");''', 'import { whoSeen } from "@/lib/zz/who";')
route("a25-leak-for-everyone", '''  const m = await who();
  if (m) await ledger.record("note", m.id);
  return Response.json({ keys: [...vault.entries()] });''', W + '\nimport { vault } from "@/lib/zz/fx";')
route("a26-for-of-module-write", '''  const b = await req.json();
  for (settings.owner of [b.owner]) {}
''' + TAIL, W + '\nimport { settings } from "@/lib/zz/fx";')
route("a29-computed-key-override", '''  if (!overridden(req).ok) return new Response("no", { status: 403 });
  await ledger.record("note", await req.text());
  return new Response("ok");''', 'import { overridden } from "@/lib/zz/who";')
route("a30-link-hash-no-lookup", '''  const { token } = await ctx.params;
  await ledger.record("claimed", digestOf(token));
  return new Response("ok");''', 'import { digestOf } from "@/lib/links";', sig="req: Request, ctx: { params: Promise<{ token: string }> }", dyn="l/[token]/")
route("a31-link-hash-stores-body", '''  const { token } = await ctx.params;
  const h = digestOf(token);
  await ledger.record(h, await req.json());
  return new Response("ok");''', 'import { digestOf } from "@/lib/links";', sig="req: Request, ctx: { params: Promise<{ token: string }> }", dyn="l/[token]/")
route("a32-visitor-blocklist", '''  const ip = req.headers.get("x-forwarded-for") ?? "";
  if (BLOCKED.indexOf(ip) > -1) return new Response("no", { status: 403 });
  await ledger.record("lead", await req.text());
  return new Response("ok");''', pre='const BLOCKED = ["10.0.0.1"];')
route("a33-visitor-length-check", '''  const ip = req.headers.get("x-forwarded-for") ?? "";
  if (Buffer.byteLength(ip) > 64) return new Response("bad", { status: 400 });
  await ledger.record("lead", await req.text());
  return new Response("ok");''')
w("src/app/api/zz/a35-handler-reassigned/route.ts", '''
import { ledger } from "@/lib/ledger";
import { who } from "@/lib/zz/who";
export let POST = async (req: Request): Promise<Response> => {
  const m = await who();
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m.id);
  return new Response("ok");
};
POST = async (req: Request): Promise<Response> => {
  await ledger.record("note", await req.text());
  return new Response("ok");
};
''')
route("a44-subpath-import-log", '''  const b = await req.json();
  await log.record("pre", b);
''' + TAIL, W + '\nimport { log } from "#zz/audit";')
route("a45-own-console", '''  const b = await req.json();
  console.log("pre", b);
''' + TAIL, W + '\nimport { console } from "@/lib/zz/fx";')
route("a50-same-name-other-scope", '''  const b = await req.json();
  const steps = [async () => { const put = async (_v: unknown): Promise<void> => {}; await put(b); }];
  void steps;
  const put = async (v: unknown): Promise<void> => { await ledger.record("pre", v); };
  await put(b);
''' + TAIL, W)
route("a78-key-sent-with-request", '''  const b = await req.json();
  const key = await crypto.subtle.importKey("jwk", b.jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const good = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, Buffer.from(b.sig, "base64"), Buffer.from(b.payload));
  if (!good) return new Response("no", { status: 403 });
  await ledger.record("note", b.payload);
  return new Response("ok");''')
route("a79-truthy-then-override", '''  const b = await req.json();
  const t = { ok: signedNow(req) };
  for (t.ok of [true]) {}
  if (!t.ok) return new Response("no", { status: 403 });
  await ledger.record("note", b);
  return new Response("ok");''', 'import { signed as signedNow } from "@/lib/zz/who";')

# ---- CRYPTO-008
H = 'import { createHash } from "node:crypto";\ntype Sent = { scheme: string; signature: string };\ntype Key = { id: string; token: string; tokenHash: string };\nconst keys: Key[] = [];\nconst sha = (s: string) => createHash("sha256").update(s).digest("hex");\n'
w("src/lib/zz/c01.ts", H + '''export function c01(sentSigs: Sent[]) {
  return sentSigs.find((s) => s.signature === sha(process.env.HOOK_SECRET!));
}
''')
w("src/lib/zz/c02.ts", H + '''export function c02(sentSigs: Sent[], body: string): boolean {
  const material = process.env.PEPPER + body;
  const expected = createHash("sha256").update(material).digest("hex");
  for (const s of sentSigs) if (s.signature === expected) return true;
  return false;
}
''')
w("src/lib/zz/c03.ts", H + '''export function keyFor(lookup: string, legacyRaw?: string) {
  if (legacyRaw) lookup = legacyRaw;
  return keys.find((k) => k.token === lookup);
}
export const byHash = (sent: string) => keyFor(sha(sent));
export const byRaw = (sent: string) => keyFor(sha(sent), sent);
''')
w("src/lib/zz/c04.ts", H + '''export function keyBy(lookup: string) {
  return keys.find((k) => k.token === lookup);
}
export const hashed = (sent: string) => keyBy(sha(sent));
''')
w("src/lib/zz/c04-caller.ts", '''import { keyBy as locate } from "./c04.ts";
export const raw = (sent: string) => locate(sent);
''')
w("src/lib/zz/c05.ts", H + '''export function keyBy5(lookup: string) {
  return keys.find((k) => k.token === lookup);
}
export const hashed5 = (sent: string) => keyBy5(sha(sent));
export const many5 = (sent: string[]) => sent.map(keyBy5);
''')
w("src/lib/zz/c06.ts", H + '''export function c06(sent: string) {
  var h = sha(sent);
  var h = sent;
  return keys.find((k) => k.token === h);
}
''')
w("src/lib/zz/c07.ts", '''import { createHash } from "node:crypto";
type Key = { id: string; token: string };
const keys: Key[] = [];
let sha7 = (s: string) => createHash("sha256").update(s).digest("hex");
if (!process.env.HASH_KEYS) sha7 = (s) => s;
export function c07(sent: string) {
  return keys.find((k) => k.token === sha7(sent));
}
''')
w("src/lib/zz/c08.ts", H + '''export const store8 = {
  locate8(lookup: string) {
    return keys.find((k) => k.token === lookup);
  },
};
export const hashed8 = (sent: string) => store8.locate8(sha(sent));
export function raw8(sent: string) {
  const { locate8 } = store8;
  return locate8(sent);
}
''')
w("src/lib/zz/c09.ts", H + '''export async function c09(req: Request) {
  const sent = await req.json();
  return sent.sigs.find((s: Sent) => s.signature === sha(process.env.HOOK_SECRET!));
}
''')
w("src/lib/zz/c10.ts", H + '''export function c10(sent: string, given: string, adminPass: string) {
  return keys.find((k) => k.tokenHash === sha(sent)) ?? (given === adminPass ? keys[0] : undefined);
}
''')
w("src/lib/zz/c11.ts", H + '''export function c11(sent: string, pick: () => (s: string) => string) {
  const sha = pick();
  return keys.find((k) => k.token === sha(sent));
}
''')
w("src/lib/zz/c12.ts", H + '''export function keyBy12(lookup: string) {
  return keys.find((k) => k.token === lookup);
}
export const hashed12 = (sent: string) => keyBy12(sha(sent));
export const raw12 = (sent: string) => keyBy12.call(null, sent);
''')
