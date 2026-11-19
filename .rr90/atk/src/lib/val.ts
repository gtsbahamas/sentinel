export function check(b: any) { if (b.kind !== "a") return { error: "bad kind" }; return { ok: true }; }
export async function checkAsync(b: any) { if (b.kind !== "a") throw new Error("400 bad kind"); }
