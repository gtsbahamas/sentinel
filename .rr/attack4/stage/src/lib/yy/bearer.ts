import { getToken } from "next-auth/jwt";
export async function bearer(req: Request) {
  return getToken({ req: req as never, raw: true });
}
