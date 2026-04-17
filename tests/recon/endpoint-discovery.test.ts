import { describe, it, expect } from "vitest";
import { discoverEndpoints, detectAuthCheck } from "../../src/layers/recon/endpoint-discovery.js";
import { discoverRoutes } from "../../src/layers/recon/route-discovery.js";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");

describe("endpoint-discovery", () => {
  it("extracts API endpoints with validation and auth metadata", async () => {
    const routes = await discoverRoutes(fixturePath, "nextjs-app");
    const endpoints = await discoverEndpoints(routes);
    const profilePost = endpoints.find((e) => e.path === "/api/profile" && e.method === "POST");
    expect(profilePost).toBeDefined();
    expect(profilePost?.hasValidation).toBe(false);
    expect(profilePost?.hasAuthCheck).toBe(false);
  });

  it("detects service role usage", async () => {
    const routes = await discoverRoutes(fixturePath, "nextjs-app");
    const endpoints = await discoverEndpoints(routes);
    const profilePost = endpoints.find((e) => e.path === "/api/profile" && e.method === "POST");
    expect(profilePost?.usesServiceRole).toBe(true);
  });
});

describe("detectAuthCheck", () => {
  it("detects Supabase getUser()", () => {
    const source = `
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    `;
    expect(detectAuthCheck(source)).toBe(true);
  });

  it("detects kiosk device token middleware (mobilego pattern)", () => {
    const source = `
      import { validateKioskToken } from '@/lib/middleware/kioskAuth';
      export async function POST(request: NextRequest) {
        const authResult = await validateKioskToken(request);
        if (!authResult.success) return new NextResponse('Unauthorized', { status: 401 });
      }
    `;
    expect(detectAuthCheck(source)).toBe(true);
  });

  it("detects requireAuth / requirePermission RBAC helpers", () => {
    const source = `
      await requirePermission(Permission.EDIT_KIOSKS);
      await requireAuth();
    `;
    expect(detectAuthCheck(source)).toBe(true);
  });

  it("detects CRON_SECRET shared-secret pattern (mobilego cron)", () => {
    const source = `
      const authHeader = request.headers.get('authorization');
      const expectedToken = process.env.CRON_SECRET;
      if (!authHeader || authHeader !== \`Bearer \${expectedToken}\`) {
        return new NextResponse('Unauthorized', { status: 401 });
      }
    `;
    expect(detectAuthCheck(source)).toBe(true);
  });

  it("detects x-api-key header pattern", () => {
    const source = `
      const apiKey = request.headers.get('x-api-key');
      if (apiKey !== process.env.INTERNAL_API_KEY) return unauthorized();
    `;
    expect(detectAuthCheck(source)).toBe(true);
  });

  it("detects HMAC webhook signature verification", () => {
    const source = `
      import { createHmac, timingSafeEqual } from 'crypto';
      const hmac = createHmac('sha256', secret).update(body).digest();
      if (!timingSafeEqual(hmac, sig)) return unauthorized();
    `;
    expect(detectAuthCheck(source)).toBe(true);
  });

  it("detects capability token DB lookup", () => {
    const source = `
      const { data } = await supabase.from('links').select().eq('access_token', token);
    `;
    expect(detectAuthCheck(source)).toBe(true);
  });

  it("returns false when no auth pattern is present", () => {
    const source = `
      export async function POST(request: NextRequest) {
        const body = await request.json();
        await db.insert(users).values(body);
        return NextResponse.json({ ok: true });
      }
    `;
    expect(detectAuthCheck(source)).toBe(false);
  });

  it("does not false-positive on stray CRON_SECRET reference without header check", () => {
    const source = `
      logger.info('cron job started', { secret: process.env.CRON_SECRET ? 'set' : 'unset' });
      // no header check — this endpoint has no auth
    `;
    expect(detectAuthCheck(source)).toBe(false);
  });

  it("does not false-positive on imports without call sites", () => {
    // Importing a helper but never calling it shouldn't count as auth.
    const source = `
      import { requireAuth } from '@/lib/auth';
      // requireAuth is imported but never called here
      export async function POST() { return NextResponse.json({ ok: true }); }
    `;
    expect(detectAuthCheck(source)).toBe(false);
  });
});
