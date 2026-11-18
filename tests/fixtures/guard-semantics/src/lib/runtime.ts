import { Engine } from "./engine.ts";

let rt: { engine: Engine } | null = null;

export function runtime(): { engine: Engine } {
  rt ??= { engine: new Engine() };
  return rt;
}
