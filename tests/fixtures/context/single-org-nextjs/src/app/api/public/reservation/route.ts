export async function POST(request: Request) {
  const { token } = await request.json();
  return Response.json({ ok: true });
}
