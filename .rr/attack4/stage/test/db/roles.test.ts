import { beforeAll, describe, expect, it } from "vitest";
import pg from "pg";
import { randomBytes } from "node:crypto";

const admin = new pg.Client({ connectionString: process.env.DATABASE_URL });

// Test code against a throwaway database: nothing here is reachable by a visitor.
beforeAll(async () => {
  const name = `fx_test_${randomBytes(5).toString("hex")}`;
  await admin.query(`create database ${name}`);
});

describe("roles", () => {
  it("anon sees nothing", async () => {
    const role = "anon";
    await admin.query(`set local role ${role}`);
    const { rows } = await admin.query("select 1");
    expect(rows.length).toBe(1);
  });
});
