type Key = { id: string; token: string };
// The stored secret itself is compared with the one sent: this decides whether the caller knows it.
export function keyFor(sent: string, keys: Key[]): Key | undefined {
  return keys.find((k) => k.token === sent);
}
export function keyInLoop(sent: string, keys: Key[]): Key | null {
  for (const k of keys) if (k.token === sent) return k;
  return null;
}
