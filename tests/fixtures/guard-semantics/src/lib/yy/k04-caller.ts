export async function rawRow(sent: string) {
  const store = await import("./k04.ts");
  return store.rowFor(sent);
}
