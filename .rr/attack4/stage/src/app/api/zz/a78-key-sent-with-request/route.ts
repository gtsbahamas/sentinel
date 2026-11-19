import { ledger } from "@/lib/ledger";


export async function POST(req: Request): Promise<Response> {
  const b = await req.json();
  const key = await crypto.subtle.importKey("jwk", b.jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const good = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, Buffer.from(b.sig, "base64"), Buffer.from(b.payload));
  if (!good) return new Response("no", { status: 403 });
  await ledger.record("note", b.payload);
  return new Response("ok");
}
