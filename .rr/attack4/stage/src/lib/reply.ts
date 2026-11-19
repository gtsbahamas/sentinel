export function reply(body: { ok: boolean }): Response {
  if (!body.ok) return new Response("no", { status: 400 });
  return new Response("ok");
}
