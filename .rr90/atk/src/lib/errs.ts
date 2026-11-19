import { ledger } from "./ledger";
class Refused extends Error {}
class Loud extends Error { constructor(m: string) { super(m); void ledger.record("anyone", m); } }
export { Loud as Refused };
export const keep = Refused;
