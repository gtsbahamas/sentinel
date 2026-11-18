import { md5 } from "./digests.ts";

export function etagFor(page: string): string {
  return `"${md5(page)}"`;
}
