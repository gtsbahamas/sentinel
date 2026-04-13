import { EventEmitter } from "node:events";
import type { Severity, SecurityDomain, Layer } from "../model/types.js";

// ── Lane assignment ──────────────────────────────────────────────────────────

export type LaneName = "frontend" | "api" | "database" | "external";

// ── Data shapes for recon events ─────────────────────────────────────────────

export interface RouteEventData {
  path: string;
  method: string;
  file: string;
  isApi: boolean;
  hasAuthCheck: boolean;
}

export interface EndpointEventData {
  path: string;
  method: string;
  file: string;
  hasValidation: boolean;
  hasAuthCheck: boolean;
  usesServiceRole: boolean;
}

export interface DataModelEventData {
  name: string;
  file: string;
  hasRLS: boolean;
  policies: string[];
}

export interface AuthFlowEventData {
  type: string;
  file: string;
  provider?: string;
}

export interface EnvVarEventData {
  name: string;
  clientExposed: boolean;
  referencedIn: string[];
}

export interface ExternalServiceEventData {
  name: string;
  type: "api" | "storage" | "webhook" | "automation";
  file: string;
}

// ── Finding event data (subset for dashboard) ───────────────────────────────

export interface FindingEventData {
  id: string;
  severity: Severity;
  title: string;
  description?: string;
  file: string;
  line?: number;
  domain: SecurityDomain;
  layer: Layer;
  remediation?: string;
}

// ── Edge event data ──────────────────────────────────────────────────────────

export interface EdgeEventData {
  source: string;
  target: string;
  type: "calls" | "queries" | "uses" | "exposes";
}

// ── Scan summary ─────────────────────────────────────────────────────────────

export interface ScanSummary {
  routes: number;
  endpoints: number;
  dataModels: number;
  externalServices: number;
  findings: Record<Severity, number>;
  durationMs: number;
}

// ── Layer name ───────────────────────────────────────────────────────────────

export type LayerName = "recon" | "rules" | "probe" | "ai";

// ── Event union ──────────────────────────────────────────────────────────────

export type ScanEvent =
  | { type: "scan:start"; project: string; timestamp: number }
  | { type: "scan:complete"; summary: ScanSummary; timestamp: number }
  | { type: "layer:start"; layer: LayerName; timestamp: number }
  | { type: "layer:complete"; layer: LayerName; durationMs: number; timestamp: number }
  | { type: "recon:route"; data: RouteEventData }
  | { type: "recon:endpoint"; data: EndpointEventData }
  | { type: "recon:datamodel"; data: DataModelEventData }
  | { type: "recon:authflow"; data: AuthFlowEventData }
  | { type: "recon:envvar"; data: EnvVarEventData }
  | { type: "recon:external"; data: ExternalServiceEventData }
  | { type: "finding"; data: FindingEventData }
  | { type: "edge"; data: EdgeEventData }
  | { type: "log"; message: string; level: "info" | "warn" | "error" };

// ── Emitter class ────────────────────────────────────────────────────────────

export class ScanEventEmitter extends EventEmitter {
  emitEvent(event: ScanEvent): void {
    this.emit("scan-event", event);
  }
}
