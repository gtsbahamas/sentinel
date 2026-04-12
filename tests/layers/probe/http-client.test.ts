import { describe, it, expect } from "vitest";
import {
  MockHttpClient,
  RequestCapExceeded,
  redactHeaders,
  truncateBody,
  TokenBucket,
} from "../../../src/layers/probe/http-client.js";

describe("MockHttpClient", () => {
  it("matches routes and returns configured response", async () => {
    const client = new MockHttpClient([
      { match: { method: "GET", url: "/api/health" }, response: { status: 200, body: "OK" } },
    ]);

    const resp = await client.request({ method: "GET", url: "http://localhost/api/health", intent: "read" });
    expect(resp.status).toBe(200);
    expect(resp.body).toBe("OK");
    expect(client.requestsUsed()).toBe(1);
  });

  it("returns 404 for unmatched routes", async () => {
    const client = new MockHttpClient([]);
    const resp = await client.request({ method: "GET", url: "http://localhost/unknown", intent: "read" });
    expect(resp.status).toBe(404);
  });

  it("matches regex routes", async () => {
    const client = new MockHttpClient([
      { match: { url: /\/api\/users/ }, response: { status: 401, body: "Unauthorized" } },
    ]);
    const resp = await client.request({ method: "GET", url: "http://localhost/api/users/123", intent: "read" });
    expect(resp.status).toBe(401);
  });

  it("throws RequestCapExceeded when cap is hit", async () => {
    const client = new MockHttpClient([], 2);
    await client.request({ method: "GET", url: "http://localhost/1", intent: "read" });
    await client.request({ method: "GET", url: "http://localhost/2", intent: "read" });
    await expect(
      client.request({ method: "GET", url: "http://localhost/3", intent: "read" }),
    ).rejects.toThrow(RequestCapExceeded);
  });

  it("records all requests", async () => {
    const client = new MockHttpClient([]);
    await client.request({ method: "GET", url: "http://localhost/a", intent: "read" });
    await client.request({ method: "POST", url: "http://localhost/b", intent: "mutate", body: "{}" });
    expect(client.recorded).toHaveLength(2);
    expect(client.recorded[0].method).toBe("GET");
    expect(client.recorded[1].method).toBe("POST");
    expect(client.recorded[1].body).toBe("{}");
  });
});

describe("redactHeaders", () => {
  it("redacts sensitive headers", () => {
    const result = redactHeaders({
      "Content-Type": "application/json",
      Authorization: "Bearer secret123",
      Cookie: "session=abc",
      "X-Api-Key": "key123",
      "X-Request-Id": "abc123",
    });
    expect(result["Content-Type"]).toBe("application/json");
    expect(result["Authorization"]).toBe("[REDACTED]");
    expect(result["Cookie"]).toBe("[REDACTED]");
    expect(result["X-Api-Key"]).toBe("[REDACTED]");
    expect(result["X-Request-Id"]).toBe("abc123");
  });
});

describe("truncateBody", () => {
  it("returns short bodies unchanged", () => {
    expect(truncateBody("hello")).toBe("hello");
  });

  it("truncates long bodies", () => {
    const long = "x".repeat(2000);
    const result = truncateBody(long, 100);
    expect(result.length).toBeLessThan(200);
    expect(result).toContain("[TRUNCATED]");
  });
});

describe("TokenBucket", () => {
  it("allows immediate requests up to capacity", async () => {
    const bucket = new TokenBucket(5, 5);
    for (let i = 0; i < 5; i++) {
      await bucket.acquire(1);
    }
  });

  it("refills over time", async () => {
    const bucket = new TokenBucket(2, 100);
    await bucket.acquire(2);
    await new Promise((r) => setTimeout(r, 50));
    await bucket.acquire(1);
  });
});
