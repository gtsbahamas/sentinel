import { digestOf } from "./links.ts";
import { ledger } from "./ledger.ts";

export class Engine {
  /** Keys for a call found by the hash of its link; only phone keys are accepted. */
  async pressKeys(link: string, digits: string): Promise<{ ok: boolean }> {
    if (!/^[0-9*#]{1,6}$/.test(digits)) return { ok: false };
    const found = await ledger.remove(digestOf(link));
    return { ok: found };
  }

  /** A public start: the phone is checked and starts are limited per visitor. */
  async begin(input: { phone: string; visitor: string }): Promise<{ ok: boolean }> {
    const phone = input.phone.replace(/\D/g, "");
    if (phone.length !== 10) return { ok: false };
    if ((await ledger.bump(`begin:${input.visitor}`)) > 3) return { ok: false };
    await ledger.record("begin", phone);
    return { ok: true };
  }
}
