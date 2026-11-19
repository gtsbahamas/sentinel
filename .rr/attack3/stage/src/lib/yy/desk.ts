import { who } from "../zz/who.ts";
export class Desk {
  protected async member(): Promise<{ id: string } | null> { return who(); }
  async guard(): Promise<{ id: string } | null> { return this.member(); }
}
export class OpenDesk extends Desk {
  protected async member(): Promise<{ id: string } | null> { return { id: "guest" }; }
}
export const openDesk = new OpenDesk();

export class Turnstile {
  constructor(open: boolean) {
    if (open) this.passes = async () => ({ id: "preview" });
  }
  async passes(): Promise<{ id: string } | null> { return who(); }
  async holder(): Promise<{ id: string } | null> { return this.passes(); }
}
export const turnstile = new Turnstile(true);
