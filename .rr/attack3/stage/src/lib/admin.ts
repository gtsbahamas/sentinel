import { createClient } from "@supabase/supabase-js";

export const adminDb = () => createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);

/** Stores what it is given and reports the store's own failure. That is error handling, not a check of the input. */
export async function storeNote(input: { note: string }): Promise<{ ok: boolean }> {
  const { error } = await adminDb().from("notes").insert({ note: input.note });
  if (error) return { ok: false };
  return { ok: true };
}

/** A privileged write kept in a helper. */
export async function saveAccount(input: { email: string; plan: string }): Promise<void> {
  const { error } = await adminDb().from("accounts").update({ plan: input.plan }).eq("email", input.email);
  if (error) throw error;
}
