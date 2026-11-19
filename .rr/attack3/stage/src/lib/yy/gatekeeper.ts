export function admitted(g: { letIn(req: Request): boolean }, req: Request): boolean {
  return g.letIn(req);
}
export async function holderOf(g: { present(): Promise<{ id: string } | null> }): Promise<{ id: string } | null> {
  return g.present();
}
export async function bearerOf(g: { carried(): Promise<{ id: string } | null> }): Promise<{ id: string } | null> {
  return g.carried();
}
export async function remember(sink: { stash(v: unknown): Promise<void> }, v: unknown): Promise<void> {
  await sink.stash(v);
}
