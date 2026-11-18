import { createClient } from "@supabase/supabase-js";
import { createServerClient } from "@supabase/ssr";
import { ledger } from "@/lib/ledger";

const plain = () => createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);

/** Correct: the signed-in person, or null. */
export async function whoIs(req: Request) {
  const sb = plain();
  const { data: { user } } = await sb.auth.getUser(req.headers.get("x-pass") ?? "");
  return user;
}

/** Correct: throws unless signed in. */
export async function mustBe(req: Request) {
  const who = await whoIs(req);
  if (!who) throw new Error("no");
  return who;
}

/** Open: no check at all. */
export async function nobody(req: Request) {
  return { id: req.headers.get("x-id") ?? "guest" };
}

// k01: an expired pass is accepted
export async function laxClaims(req: Request) {
  const sb = plain();
  const { data } = await sb.auth.getClaims(req.headers.get("x-pass") ?? "", { allowExpired: true });
  return data;
}

// k02: the caller brings the key its own pass is checked with
export async function ownKeyClaims(req: Request) {
  const body = await req.json();
  const sb = plain();
  const { data } = await sb.auth.getClaims(body.pass, { jwks: { keys: [body.key] } });
  return data;
}

// k03: a pass written into the code: everyone is that account
export async function robot() {
  const sb = plain();
  const { data: { user } } = await sb.auth.getUser("robot-pass-kept-in-code");
  return user;
}

// k04: the cookie accessor writes for every caller
const noisy = () =>
  createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {
    cookies: {
      getAll() {
        void ledger.record("seen", "anyone");
        return [];
      },
      setAll() {},
    },
  });
export async function noisyWho() {
  const sb = noisy();
  const { data: { user } } = await sb.auth.getUser();
  return user;
}

// k05: the cookie accessor hands Supabase a stored session, whoever calls
const robotJar = () =>
  createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {
    cookies: {
      getAll: () => [{ name: "sb-app-auth-token", value: process.env.ROBOT_PASS ?? "" }],
      setAll: () => {},
    },
  });
export async function robotWho() {
  const sb = robotJar();
  const { data: { user } } = await sb.auth.getUser();
  return user;
}

// k06 (closed control for the cookie form)
const jar = (req: Request) =>
  createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {
    cookies: {
      getAll: () => [{ name: "sb-app-auth-token", value: req.headers.get("x-pass") ?? "" }],
      setAll: () => {},
    },
  });
export async function jarWho(req: Request) {
  const sb = jar(req);
  const { data: { user } } = await sb.auth.getUser();
  return user;
}

// o01: `ok` comes from the prototype
export async function deskOf(req: Request) {
  const sb = plain();
  const { data: { user } } = await sb.auth.getUser(req.headers.get("x-pass") ?? "");
  if (user) return { ok: true, memberId: user.id };
  return { __proto__: { ok: true }, memberId: "guest" };
}

// s01: the refusal carries the service key
export async function deskLoud(req: Request) {
  const sb = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
  const { data: { user } } = await sb.auth.getUser(req.headers.get("x-pass") ?? "");
  if (!user) return { ok: false, memberId: "", response: Response.json({ message: "no", key: (sb as any).supabaseKey }) };
  return { ok: true, memberId: user.id, response: null };
}

// p02: `data` of getUser is always an object
export async function dataOnly(req: Request) {
  const sb = plain();
  const { data } = await sb.auth.getUser(req.headers.get("x-pass") ?? "");
  return data;
}

// p03
export async function orGuest(req: Request) {
  const sb = plain();
  const { data: { user } } = await sb.auth.getUser(req.headers.get("x-pass") ?? "");
  return user ?? { id: "guest" };
}

// p11
export async function softGate(req: Request) {
  const sb = plain();
  const { data: { user } } = await sb.auth.getUser(req.headers.get("x-pass") ?? "");
  if (!user) return { error: null, id: "guest" };
  return { error: null, id: user.id };
}

// p13: getClaims gives no error when there is simply no session
export async function claimsError() {
  const sb = plain();
  const { error } = await sb.auth.getClaims();
  return error;
}

// p15: empty object in one branch
export async function claimsOrEmpty(req: Request) {
  const sb = plain();
  const { data } = await sb.auth.getClaims(req.headers.get("x-pass") ?? "");
  return data || {};
}

// p16: the answer is `ok: true` whenever the read gave no error object field named `nope`
export async function okByMissing(req: Request) {
  const sb = plain();
  const read = await sb.auth.getUser(req.headers.get("x-pass") ?? "");
  return { ok: !read.data.nope };
}
