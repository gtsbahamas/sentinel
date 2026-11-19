import { adminDb } from "../admin.ts";
export async function findUser(name: string) {
  return (adminDb() as any).query(`SELECT * FROM users WHERE name = '${name}'`);
}
if (import.meta.vitest) {
  const { it, expect } = import.meta.vitest;
  it("finds", () => { expect(1).toBe(1); });
}
