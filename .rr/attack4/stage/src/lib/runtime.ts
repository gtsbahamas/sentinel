import { Engine } from "./engine.ts";

type Runtime = { engine: Engine; broadcastKey: string };
let rt: Runtime | null = null;

// The container also holds a service-role key for broadcasting. Nothing here writes tables with it, so a
// public, limited route that goes through runtime() is still just a public, limited route.
export function runtime(): Runtime {
  rt ??= { engine: new Engine(), broadcastKey: process.env.SUPABASE_SERVICE_ROLE_KEY ?? "" };
  return rt;
}
