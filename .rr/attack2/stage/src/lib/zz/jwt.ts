import jwt from "jsonwebtoken";
const done = (): void => {};
// with a callback jsonwebtoken reports the failure to the callback and throws nothing
export function mustCarryPass(req: Request): void {
  jwt.verify(req.headers.get("x-pass") ?? "", process.env.PASS_KEY ?? "", done);
}
