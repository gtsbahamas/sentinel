import { adminDb } from "../admin.ts";
export async function findUser2(name: string) {
  return (adminDb() as any).query(`SELECT * FROM users WHERE name = '${name}'`);
}
