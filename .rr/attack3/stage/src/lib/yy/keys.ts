const live = new Map<string, string>([["stripe", process.env.STRIPE_LIVE ?? ""]]);
export function allKeys(): Record<string, string> {
  return Object.fromEntries(live);
}
export const sessions = { getAll(): string[] { return [...live.values()]; } };
