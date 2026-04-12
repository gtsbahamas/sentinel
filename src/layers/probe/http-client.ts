import { randomUUID } from "crypto";
import type { AggressionLevel } from "../../model/types.js";

// ============================================================================
// Interfaces
// ============================================================================

export interface HttpClient {
  request(req: HttpRequest): Promise<HttpResponse>;
  requestsUsed(): number;
  requestCap(): number;
}

export interface HttpRequest {
  method: "GET" | "HEAD" | "OPTIONS" | "POST" | "PUT" | "DELETE" | "PATCH";
  url: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  intent: "read" | "mutate";
}

export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
  timingMs: number;
  requestId: string;
}

// ============================================================================
// Error classes
// ============================================================================

export class TargetUnreachable extends Error {
  constructor(
    public readonly url: string,
    public readonly cause?: Error,
  ) {
    super(`Target unreachable: ${url}`);
    this.name = "TargetUnreachable";
  }
}

export class RequestCapExceeded extends Error {
  constructor(
    public readonly used: number,
    public readonly cap: number,
  ) {
    super(`Request cap exceeded: ${used}/${cap}`);
    this.name = "RequestCapExceeded";
  }
}

export class RateLimitWaitExceeded extends Error {
  constructor() {
    super("Rate limit wait exceeded (>5s)");
    this.name = "RateLimitWaitExceeded";
  }
}

export class TargetRateLimited extends Error {
  constructor(
    public readonly url: string,
    public readonly retryAfter?: number,
  ) {
    super(`Target rate-limited us: ${url}`);
    this.name = "TargetRateLimited";
  }
}

// ============================================================================
// Redaction
// ============================================================================

const SENSITIVE_HEADER_RE = /auth|token|secret|key|password|cookie/i;

export function redactHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    out[k] = SENSITIVE_HEADER_RE.test(k) ? "[REDACTED]" : v;
  }
  return out;
}

export function truncateBody(body: string, limit = 1024): string {
  if (body.length <= limit) return body;
  return body.slice(0, limit) + "\n[TRUNCATED]";
}

// ============================================================================
// Token bucket rate limiter
// ============================================================================

export class TokenBucket {
  private tokens: number;
  private lastRefill: number;

  constructor(
    private readonly capacity: number,
    private readonly refillRate: number,
  ) {
    this.tokens = capacity;
    this.lastRefill = Date.now();
  }

  async acquire(cost = 1): Promise<void> {
    const maxWaitMs = 5000;
    const start = Date.now();
    while (true) {
      this.refill();
      if (this.tokens >= cost) {
        this.tokens -= cost;
        return;
      }
      if (Date.now() - start > maxWaitMs) throw new RateLimitWaitExceeded();
      await new Promise((r) => setTimeout(r, 50));
    }
  }

  private refill(): void {
    const now = Date.now();
    const elapsed = (now - this.lastRefill) / 1000;
    this.tokens = Math.min(this.capacity, this.tokens + elapsed * this.refillRate);
    this.lastRefill = now;
  }
}

// ============================================================================
// Implementation
// ============================================================================

export interface ProbeHttpClientOptions {
  level: AggressionLevel;
  requestCaps: Record<AggressionLevel, number>;
  requestsPerSecond: number;
  defaultTimeoutMs: number;
  sentinelVersion: string;
  onRequest?: (entry: ProbeLogEntry) => void;
}

export interface ProbeLogEntry {
  requestId: string;
  timestamp: string;
  request: {
    method: string;
    url: string;
    headers: Record<string, string>;
    bodyPreview?: string;
  };
  response: {
    status: number;
    headers: Record<string, string>;
    bodyPreview: string;
    timingMs: number;
  } | null;
  error?: string;
}

export class ProbeHttpClient implements HttpClient {
  private used = 0;
  private readonly cap: number;
  private readonly bucket: TokenBucket;
  private readonly opts: ProbeHttpClientOptions;

  constructor(opts: ProbeHttpClientOptions) {
    this.opts = opts;
    this.cap = opts.requestCaps[opts.level];
    this.bucket = new TokenBucket(opts.requestsPerSecond, opts.requestsPerSecond);
  }

  requestsUsed(): number {
    return this.used;
  }

  requestCap(): number {
    return this.cap;
  }

  async request(req: HttpRequest): Promise<HttpResponse> {
    if (this.used >= this.cap) {
      throw new RequestCapExceeded(this.used, this.cap);
    }

    const cost = req.intent === "mutate" ? 2 : 1;
    await this.bucket.acquire(cost);
    this.used++;

    const requestId = randomUUID();
    const timeoutMs = req.timeoutMs ?? this.opts.defaultTimeoutMs;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    const outgoingHeaders: Record<string, string> = {
      "X-Sentinel-Scan": this.opts.sentinelVersion,
      "User-Agent": `sentinel/${this.opts.sentinelVersion} (+https://github.com/franklabs/sentinel)`,
      "X-Request-Id": requestId,
      "Accept-Encoding": "identity",
      ...(req.headers ?? {}),
    };

    const start = Date.now();
    let logEntry: ProbeLogEntry;

    try {
      const resp = await fetch(req.url, {
        method: req.method,
        headers: outgoingHeaders,
        body: req.body ?? undefined,
        signal: controller.signal,
        redirect: "manual",
      });

      const timingMs = Date.now() - start;
      const body = await resp.text();
      const respHeaders: Record<string, string> = {};
      resp.headers.forEach((v, k) => {
        respHeaders[k] = v;
      });

      const httpResp: HttpResponse = {
        status: resp.status,
        headers: respHeaders,
        body,
        timingMs,
        requestId,
      };

      logEntry = {
        requestId,
        timestamp: new Date().toISOString(),
        request: {
          method: req.method,
          url: req.url,
          headers: redactHeaders(outgoingHeaders),
          bodyPreview: req.body ? truncateBody(req.body) : undefined,
        },
        response: {
          status: resp.status,
          headers: redactHeaders(respHeaders),
          bodyPreview: truncateBody(body),
          timingMs,
        },
      };

      this.opts.onRequest?.(logEntry);
      return httpResp;
    } catch (err) {
      const timingMs = Date.now() - start;
      logEntry = {
        requestId,
        timestamp: new Date().toISOString(),
        request: {
          method: req.method,
          url: req.url,
          headers: redactHeaders(outgoingHeaders),
          bodyPreview: req.body ? truncateBody(req.body) : undefined,
        },
        response: null,
        error: err instanceof Error ? err.message : String(err),
      };
      this.opts.onRequest?.(logEntry);

      throw new TargetUnreachable(req.url, err instanceof Error ? err : undefined);
    } finally {
      clearTimeout(timer);
    }
  }
}

// ============================================================================
// Mock client for testing
// ============================================================================

export interface MockRoute {
  match: { method?: string; url: string | RegExp };
  response: { status: number; headers?: Record<string, string>; body: string };
}

export class MockHttpClient implements HttpClient {
  private used = 0;
  readonly recorded: Array<HttpRequest & { requestId: string }> = [];

  constructor(
    private readonly routes: MockRoute[] = [],
    private readonly cap = 500,
  ) {}

  requestsUsed(): number {
    return this.used;
  }

  requestCap(): number {
    return this.cap;
  }

  async request(req: HttpRequest): Promise<HttpResponse> {
    if (this.used >= this.cap) {
      throw new RequestCapExceeded(this.used, this.cap);
    }
    this.used++;
    const requestId = randomUUID();
    this.recorded.push({ ...req, requestId });

    const match = this.routes.find((r) => {
      if (r.match.method && r.match.method !== req.method) return false;
      if (r.match.url instanceof RegExp) return r.match.url.test(req.url);
      return req.url.includes(r.match.url);
    });

    const resp = match?.response ?? { status: 404, body: "" };
    return {
      status: resp.status,
      headers: resp.headers ?? {},
      body: resp.body,
      timingMs: 1,
      requestId,
    };
  }
}
