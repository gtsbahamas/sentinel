import { macOf } from "./mac.ts";
import { sameBytes } from "./bytes.ts";

const signing = () => process.env.PROVIDER_SIGNING ?? "";

export function macMatches(header: string | null, payload: string): boolean {
  if (!header) return false;
  return sameBytes(macOf(signing(), payload), header);
}

export type Inbound = { ok: true; fields: Record<string, string> } | { ok: false; res: Response };

/** Refuses the request unless its MAC header checks out. */
export async function providerCall(req: Request): Promise<Inbound> {
  const raw = await req.text();
  if (!macMatches(req.headers.get("x-provider-mac"), raw)) {
    return { ok: false, res: new Response("forbidden", { status: 403 }) };
  }
  return { ok: true, fields: Object.fromEntries(new URLSearchParams(raw)) };
}

/** Twin: parses the request and never verifies anything. */
export async function parsedCall(req: Request): Promise<Inbound> {
  const raw = await req.text();
  if (!raw) return { ok: false, res: new Response("empty", { status: 400 }) };
  return { ok: true, fields: Object.fromEntries(new URLSearchParams(raw)) };
}

/** Twin: computes the MAC and never compares it with the one that was sent. */
export async function macOnlyCall(req: Request): Promise<Inbound> {
  const raw = await req.text();
  const mac = macOf(signing(), raw);
  if (!mac) return { ok: false, res: new Response("empty", { status: 400 }) };
  return { ok: true, fields: { mac } };
}
