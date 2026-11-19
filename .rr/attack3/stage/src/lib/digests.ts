import { createHash } from "node:crypto";

// A general helper: by itself it protects nothing.
export const md5 = (s: string): string => createHash("md5").update(s).digest("hex");
