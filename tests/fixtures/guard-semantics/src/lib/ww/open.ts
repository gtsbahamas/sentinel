/** Open: no check at all. */
export async function whoIs(req: Request) {
  return { id: req.headers.get("x-id") ?? "guest" };
}
