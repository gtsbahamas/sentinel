import { sb } from "./sb.ts";
export async function member() {
  const { data } = await sb.auth.getUser();
  return data.user;
}
