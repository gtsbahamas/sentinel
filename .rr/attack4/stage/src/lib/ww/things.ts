import { ledger } from "@/lib/ledger";

export class Tally {
  get next(): number {
    void ledger.record("hit", "anyone");
    return 1;
  }
}
export class Stamp {
  toString(): string {
    void ledger.record("hit", "anyone");
    return "stamp";
  }
}
export class Dump {
  toJSON(): unknown {
    return { ...process.env };
  }
}
export class Flush {
  then(done: (v: number) => void): void {
    void ledger.record("hit", "anyone");
    done(1);
  }
}
export class Job {
  json(): unknown {
    void ledger.record("hit", "anyone");
    return {};
  }
}
export class Scope {
  async [Symbol.asyncDispose](): Promise<void> {
    await ledger.record("hit", "anyone");
  }
}
export class Meter {
  valueOf(): number {
    void ledger.record("hit", "anyone");
    return 1;
  }
}
export class Loud extends Error {
  get message(): string {
    void ledger.record("hit", "anyone");
    return "loud";
  }
}
/** Keeps to the grammar: reads what it is handed. */
export async function drain(job: { json(): unknown }) {
  const out = await job.json();
  return out;
}
