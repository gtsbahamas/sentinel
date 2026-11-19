#!/usr/bin/env python3
"""Attack round 4: writes ww routes and helpers into the stage given as argv[1]."""
import os, sys

stage = sys.argv[1]
files = {}

URL = "process.env.NEXT_PUBLIC_SUPABASE_URL!"
KEY = "process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!"

# ---------------------------------------------------------------- helpers
files["src/lib/ww/kit.ts"] = f'''import {{ createClient }} from "@supabase/supabase-js";
import {{ createServerClient }} from "@supabase/ssr";
import {{ ledger }} from "@/lib/ledger";

const plain = () => createClient({URL}, {KEY});

/** Correct: the signed-in person, or null. */
export async function whoIs(req: Request) {{
  const sb = plain();
  const {{ data: {{ user }} }} = await sb.auth.getUser(req.headers.get("x-pass") ?? "");
  return user;
}}

/** Correct: throws unless signed in. */
export async function mustBe(req: Request) {{
  const who = await whoIs(req);
  if (!who) throw new Error("no");
  return who;
}}

/** Open: no check at all. */
export async function nobody(req: Request) {{
  return {{ id: req.headers.get("x-id") ?? "guest" }};
}}

// k01: an expired pass is accepted
export async function laxClaims(req: Request) {{
  const sb = plain();
  const {{ data }} = await sb.auth.getClaims(req.headers.get("x-pass") ?? "", {{ allowExpired: true }});
  return data;
}}

// k02: the caller brings the key its own pass is checked with
export async function ownKeyClaims(req: Request) {{
  const body = await req.json();
  const sb = plain();
  const {{ data }} = await sb.auth.getClaims(body.pass, {{ jwks: {{ keys: [body.key] }} }});
  return data;
}}

// k03: a pass written into the code: everyone is that account
export async function robot() {{
  const sb = plain();
  const {{ data: {{ user }} }} = await sb.auth.getUser("robot-pass-kept-in-code");
  return user;
}}

// k04: the cookie accessor writes for every caller
const noisy = () =>
  createServerClient({URL}, {KEY}, {{
    cookies: {{
      getAll() {{
        void ledger.record("seen", "anyone");
        return [];
      }},
      setAll() {{}},
    }},
  }});
export async function noisyWho() {{
  const sb = noisy();
  const {{ data: {{ user }} }} = await sb.auth.getUser();
  return user;
}}

// k05: the cookie accessor hands Supabase a stored session, whoever calls
const robotJar = () =>
  createServerClient({URL}, {KEY}, {{
    cookies: {{
      getAll: () => [{{ name: "sb-app-auth-token", value: process.env.ROBOT_PASS ?? "" }}],
      setAll: () => {{}},
    }},
  }});
export async function robotWho() {{
  const sb = robotJar();
  const {{ data: {{ user }} }} = await sb.auth.getUser();
  return user;
}}

// k06 (closed control for the cookie form)
const jar = (req: Request) =>
  createServerClient({URL}, {KEY}, {{
    cookies: {{
      getAll: () => [{{ name: "sb-app-auth-token", value: req.headers.get("x-pass") ?? "" }}],
      setAll: () => {{}},
    }},
  }});
export async function jarWho(req: Request) {{
  const sb = jar(req);
  const {{ data: {{ user }} }} = await sb.auth.getUser();
  return user;
}}

// o01: `ok` comes from the prototype
export async function deskOf(req: Request) {{
  const sb = plain();
  const {{ data: {{ user }} }} = await sb.auth.getUser(req.headers.get("x-pass") ?? "");
  if (user) return {{ ok: true, memberId: user.id }};
  return {{ __proto__: {{ ok: true }}, memberId: "guest" }};
}}

// s01: the refusal carries the service key
export async function deskLoud(req: Request) {{
  const sb = createClient({URL}, process.env.SUPABASE_SERVICE_ROLE_KEY!);
  const {{ data: {{ user }} }} = await sb.auth.getUser(req.headers.get("x-pass") ?? "");
  if (!user) return {{ ok: false, memberId: "", response: Response.json({{ message: "no", key: (sb as any).supabaseKey }}) }};
  return {{ ok: true, memberId: user.id, response: null }};
}}

// p02: `data` of getUser is always an object
export async function dataOnly(req: Request) {{
  const sb = plain();
  const {{ data }} = await sb.auth.getUser(req.headers.get("x-pass") ?? "");
  return data;
}}

// p03
export async function orGuest(req: Request) {{
  const sb = plain();
  const {{ data: {{ user }} }} = await sb.auth.getUser(req.headers.get("x-pass") ?? "");
  return user ?? {{ id: "guest" }};
}}

// p11
export async function softGate(req: Request) {{
  const sb = plain();
  const {{ data: {{ user }} }} = await sb.auth.getUser(req.headers.get("x-pass") ?? "");
  if (!user) return {{ error: null, id: "guest" }};
  return {{ error: null, id: user.id }};
}}

// p13: getClaims gives no error when there is simply no session
export async function claimsError() {{
  const sb = plain();
  const {{ error }} = await sb.auth.getClaims();
  return error;
}}

// p15: empty object in one branch
export async function claimsOrEmpty(req: Request) {{
  const sb = plain();
  const {{ data }} = await sb.auth.getClaims(req.headers.get("x-pass") ?? "");
  return data || {{}};
}}

// p16: the answer is `ok: true` whenever the read gave no error object field named `nope`
export async function okByMissing(req: Request) {{
  const sb = plain();
  const read = await sb.auth.getUser(req.headers.get("x-pass") ?? "");
  return {{ ok: !read.data.nope }};
}}
'''

files["src/lib/ww/things.ts"] = '''import { ledger } from "@/lib/ledger";

export class Tally {
  get next(): number {
    void ledger.record("hit", "anyone");
    return 1;
  }
}
export class Stamp {
  toString(): string {
    void ledger.record("hit", "anyone");
    return "stamp";
  }
}
export class Dump {
  toJSON(): unknown {
    return { ...process.env };
  }
}
export class Flush {
  then(done: (v: number) => void): void {
    void ledger.record("hit", "anyone");
    done(1);
  }
}
export class Job {
  json(): unknown {
    void ledger.record("hit", "anyone");
    return {};
  }
}
export class Scope {
  async [Symbol.asyncDispose](): Promise<void> {
    await ledger.record("hit", "anyone");
  }
}
export class Meter {
  valueOf(): number {
    void ledger.record("hit", "anyone");
    return 1;
  }
}
export class Loud extends Error {
  get message(): string {
    void ledger.record("hit", "anyone");
    return "loud";
  }
}
/** Keeps to the grammar: reads what it is handed. */
export async function drain(job: { json(): unknown }) {
  const out = await job.json();
  return out;
}
'''

SECURE = f'''  const sb = createClient({URL}, {KEY});
  const {{ data: {{ user }} }} = await sb.auth.getUser(req.headers.get("x-pass") ?? "");
  return user;'''

# l01 / l03: the exported name is another function
files["src/lib/ww/alias.ts"] = f'''import {{ createClient }} from "@supabase/supabase-js";
async function whoIs(req: Request) {{
{SECURE}
}}
async function anyone(req: Request) {{
  return {{ id: req.headers.get("x-id") ?? "guest" }};
}}
export const kept = whoIs;
export {{ anyone as whoIs }};
'''

# l02: default export is another function than the one of the same name
files["src/lib/ww/dflt.ts"] = f'''import {{ createClient }} from "@supabase/supabase-js";
export async function whoIs(req: Request) {{
{SECURE}
}}
export default async function (req: Request) {{
  return {{ id: req.headers.get("x-id") ?? "guest" }};
}}
'''

# l04: a JS module that swaps the function by a shorthand destructuring write
files["src/lib/ww/swap.js"] = f'''import {{ createClient }} from "@supabase/supabase-js";
export async function whoIs(req) {{
  const sb = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY);
  const {{ data: {{ user }} }} = await sb.auth.getUser(req.headers.get("x-pass") ?? "");
  return user;
}}
async function anyone(req) {{
  return {{ id: req.headers.get("x-id") ?? "guest" }};
}}
const table = {{ whoIs: anyone }};
({{ whoIs }} = table);
'''

# l05: star export of a default-less module beside a local of the same name through `export default` object
files["src/lib/ww/hub.ts"] = '''export * from "./kit";
export { nobody as whoIs2 } from "./kit";
'''

# ---------------------------------------------------------------- routes
HEAD = 'import { ledger } from "@/lib/ledger";\n'
def route(name, imports, body):
    files[f"src/app/api/ww/{name}/route.ts"] = HEAD + imports + "export async function POST(req: Request): Promise<Response> {\n" + body + "}\n"

KIT = lambda names: f'import {{ {names} }} from "@/lib/ww/kit";\n'
THINGS = lambda names: f'import {{ {names} }} from "@/lib/ww/things";\n'
GATE = '''  const who = await whoIs(req);
  if (!who) return new Response("no");
  await ledger.record("note", who.id);
  return new Response("ok");
'''
def simple(fn, arg="req"):
    return f'''  const who = await {fn}({arg});
  if (!who) return new Response("no");
  await ledger.record("note", "x");
  return new Response("ok");
'''

# controls
route("c1-open", "", '''  const body = await req.json();
  await ledger.record("note", body.note);
  return new Response("ok");
''')
route("c2-open", KIT("nobody"), '''  const who = await nobody(req);
  if (!who) return new Response("no");
  await ledger.record("note", who.id);
  return new Response("ok");
''')
route("c3-closed", KIT("whoIs"), GATE)
route("c4-closed-jar", KIT("jarWho"), simple("jarWho"))
route("c5-closed-must", KIT("mustBe"), '''  const who = await mustBe(req);
  await ledger.record("note", who.id);
  return new Response("ok");
''')

# K: what the check is handed
route("k01-expired-pass", KIT("laxClaims"), simple("laxClaims"))
route("k02-caller-key", KIT("ownKeyClaims"), simple("ownKeyClaims"))
route("k03-pass-in-code", KIT("robot"), simple("robot", ""))
route("k04-accessor-writes", KIT("noisyWho"), simple("noisyWho", ""))
route("k05-accessor-stored-session", KIT("robotWho"), simple("robotWho", ""))

# Q: project classes and what reading them runs
route("q01-getter", KIT("whoIs") + THINGS("Tally"), '''  const tally = new Tally();
  const n = tally.next;
''' + GATE)
route("q02-to-string", KIT("whoIs") + THINGS("Stamp"), '''  const stamp = new Stamp();
  console.log(`hit ${stamp}`);
''' + GATE)
route("q03-to-json", KIT("whoIs") + THINGS("Dump"), '''  const dump = new Dump();
  const who = await whoIs(req);
  if (!who) return Response.json({ message: "no", dump });
  await ledger.record("note", who.id);
  return new Response("ok");
''')
route("q04-thenable", KIT("whoIs") + THINGS("Flush"), '''  const done = await new Flush();
''' + GATE)
route("q05-own-parameter-method", KIT("whoIs") + THINGS("Job, drain"), '''  const job = new Job();
  const out = await drain(job);
''' + GATE)
route("q06-await-using", KIT("whoIs") + THINGS("Scope"), '''  await using scope = new Scope();
''' + GATE)
route("q07-value-of", KIT("whoIs") + THINGS("Meter"), '''  const meter = new Meter();
  const n = -(meter as unknown as number);
''' + GATE)
route("q08-error-getter", KIT("whoIs") + THINGS("Loud"), '''  const loud = new Loud();
  console.log(loud.message);
''' + GATE)
files["src/app/api/ww/q09-class-named-console/route.ts"] = HEAD + KIT("whoIs") + '''class console {
  static log(note: string): Promise<void> {
    return ledger.record("note", note);
  }
}
export async function POST(req: Request): Promise<Response> {
  const body = await req.json();
  await console.log(body.note);
  const who = await whoIs(req);
  if (!who) return new Response("no");
  return new Response("ok");
}
'''
files["src/app/api/ww/q10-class-named-response/route.ts"] = HEAD + KIT("whoIs") + '''class Response extends globalThis.Response {
  static json(data: unknown): globalThis.Response {
    void ledger.record("note", data);
    return new globalThis.Response("{}");
  }
}
export async function POST(req: Request): Promise<globalThis.Response> {
  const body = await req.json();
  const who = await whoIs(req);
  if (!who) return Response.json({ note: body.note });
  return Response.json({ ok: true });
}
'''
route("q11-loose-equals", KIT("whoIs") + THINGS("Meter"), '''  const meter = new Meter();
  const same = (meter as unknown) == 1;
''' + GATE)

# L: which function a name stands for
route("l01-export-alias", 'import { whoIs } from "@/lib/ww/alias";\n', GATE)
route("l02-default-import", 'import whoIs from "@/lib/ww/dflt";\n', GATE)
route("l03-namespace-alias", 'import * as kit from "@/lib/ww/alias";\n', '''  const who = await kit.whoIs(req);
  if (!who) return new Response("no");
  await ledger.record("note", who.id);
  return new Response("ok");
''')
route("l04-shorthand-swap", 'import { whoIs } from "@/lib/ww/swap.js";\n', GATE)

# O: object shapes
route("o01-proto-ok", KIT("deskOf"), '''  const desk = await deskOf(req);
  if (!desk.ok) return new Response("no");
  await ledger.record("note", desk.memberId);
  return new Response("ok");
''')
route("s01-key-in-refusal", KIT("deskLoud"), '''  const desk = await deskLoud(req);
  if (!desk.ok) return desk.response!;
  await ledger.record("note", desk.memberId);
  return new Response("ok");
''')

# P: polarity, flow, awaiting
route("p01-undefined-test", KIT("whoIs"), '''  const who = await whoIs(req);
  if (who === undefined) return new Response("no");
  await ledger.record("note", "x");
  return new Response("ok");
''')
route("p02-data-only", KIT("dataOnly"), simple("dataOnly"))
route("p03-or-guest", KIT("orGuest"), simple("orGuest"))
route("p04-not-awaited", KIT("whoIs"), '''  const who = whoIs(req);
  if (!who) return new Response("no");
  await ledger.record("note", "x");
  return new Response("ok");
''')
route("p05-catch-swallows", KIT("mustBe"), '''  try {
    await mustBe(req);
  } catch (e) {
    console.error(e);
  }
  await ledger.record("note", "x");
  return new Response("ok");
''')
route("p06-and-strict", KIT("whoIs"), '''  const body = await req.json();
  const who = await whoIs(req);
  if (!who && body.strict) return new Response("no");
  await ledger.record("note", "x");
  return new Response("ok");
''')
route("p07-or-body", KIT("whoIs"), '''  const body = await req.json();
  const who = (await whoIs(req)) || body.as;
  if (!who) return new Response("no");
  await ledger.record("note", "x");
  return new Response("ok");
''')
route("p08-typeof", KIT("whoIs"), '''  const who = await whoIs(req);
  if (typeof who === "undefined") return new Response("no");
  await ledger.record("note", "x");
  return new Response("ok");
''')
route("p09-must-not-awaited", KIT("mustBe"), '''  mustBe(req);
  await ledger.record("note", "x");
  return new Response("ok");
''')
route("p10-block-shadow", KIT("whoIs"), '''  const body = await req.json();
  const who = await whoIs(req);
  {
    const who = body.as;
    if (!who) return new Response("no");
    await ledger.record("note", "x");
  }
  return new Response("ok");
''')
route("p11-error-always-null", KIT("softGate"), '''  const gate = await softGate(req);
  if (gate.error) return gate.error;
  await ledger.record("note", gate.id);
  return new Response("ok");
''')
route("p12-answer-ignored", KIT("whoIs"), '''  await whoIs(req);
  await ledger.record("note", "x");
  return new Response("ok");
''')
route("p13-claims-error", KIT("claimsError"), '''  const bad = await claimsError();
  if (bad) return new Response("no");
  await ledger.record("note", "x");
  return new Response("ok");
''')
route("p14-or-force", KIT("whoIs"), '''  const body = await req.json();
  const who = await whoIs(req);
  if (who || body.force) {
    await ledger.record("note", "x");
  }
  return new Response("ok");
''')
route("p15-claims-or-empty", KIT("claimsOrEmpty"), simple("claimsOrEmpty"))
route("p16-ok-by-missing", KIT("okByMissing"), '''  const gate = await okByMissing(req);
  if (!gate.ok) return new Response("no");
  await ledger.record("note", "x");
  return new Response("ok");
''')
route("p17-loose-false", KIT("whoIs"), '''  const who = await whoIs(req);
  if (who == false) return new Response("no");
  await ledger.record("note", "x");
  return new Response("ok");
''')
route("p18-catch-returns-ok", KIT("mustBe"), '''  try {
    const who = await mustBe(req);
    console.log(who.id);
  } catch (e) {
    console.error(e);
  }
  const body = await req.json();
  return Response.json({ ok: true, echo: body });
''')
route("p19-ternary-guest", KIT("whoIs"), '''  const body = await req.json();
  const who = body.guest ? body.guest : await whoIs(req);
  if (!who) return new Response("no");
  await ledger.record("note", "x");
  return new Response("ok");
''')
route("p20-hub-reexport", 'import { whoIs2 } from "@/lib/ww/hub";\n', simple("whoIs2"))

for rel, text in files.items():
    path = os.path.join(stage, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
print(len([k for k in files if "/api/ww/" in k]), "routes written")
