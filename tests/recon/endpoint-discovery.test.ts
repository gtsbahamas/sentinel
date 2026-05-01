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

  // ---- Shape-based detection: novel guard names (the whole point of the
  // refactor). These are names the old fixed list did not know about.

  it("detects await + arbitrary require* guard helper (requireStaffPermission)", () => {
    const source = `
      export async function GET(req: NextRequest) {
        await requireStaffPermission(req, 'admin.users.view');
        return NextResponse.json({ ok: true });
      }
    `;
    expect(detectAuthCheck(source)).toBe(true);
  });

  it("detects await + portal session guard (requirePortalSession)", () => {
    const source = `
      export async function POST() {
        await requirePortalSession();
        return NextResponse.json({ ok: true });
      }
    `;
    expect(detectAuthCheck(source)).toBe(true);
  });

  it("detects async user fetch (getServerUser)", () => {
    const source = `
      export async function GET() {
        const user = await getServerUser();
        if (!user) throw new Error('unauth');
        return NextResponse.json({ user });
      }
    `;
    expect(detectAuthCheck(source)).toBe(true);
  });

  it("detects sync verb+noun call (getAuthenticatedUser)", () => {
    const source = `
      export function GET(req) {
        const user = getAuthenticatedUser(req);
        return NextResponse.json({ user });
      }
    `;
    expect(detectAuthCheck(source)).toBe(true);
  });

  it("detects await validatePassword (verb + Password noun)", () => {
    const source = `
      export async function POST(req) {
        const { password } = await req.json();
        await validatePassword(password);
        return NextResponse.json({ ok: true });
      }
    `;
    expect(detectAuthCheck(source)).toBe(true);
  });

  it("detects sync requireAuth (no await)", () => {
    const source = `
      export function GET(req) {
        requireAuth(req);
        return NextResponse.json({ ok: true });
      }
    `;
    expect(detectAuthCheck(source)).toBe(true);
  });

  it("detects await + assertSession", () => {
    const source = `
      export async function GET() {
        await assertSession();
        return NextResponse.json({ ok: true });
      }
    `;
    expect(detectAuthCheck(source)).toBe(true);
  });

  it("detects await + ensureMember (member-style guard)", () => {
    const source = `
      export async function GET() {
        await ensureMember();
        return NextResponse.json({ ok: true });
      }
    `;
    expect(detectAuthCheck(source)).toBe(true);
  });

  it("detects loadCurrentMember (verb + Member noun)", () => {
    const source = `
      export async function GET() {
        const member = await loadCurrentMember();
        return NextResponse.json({ member });
      }
    `;
    expect(detectAuthCheck(source)).toBe(true);
  });

  // ---- Cookie-based SSR client

  it("detects Next.js cookies import + createServerClient (Supabase SSR)", () => {
    const source = `
      import { cookies } from 'next/headers';
      import { createServerClient } from '@supabase/ssr';
      export async function GET() {
        const cookieStore = cookies();
        const supabase = createServerClient(url, key, { cookies: cookieStore });
        const { data } = await supabase.from('items').select();
        return NextResponse.json(data);
      }
    `;
    expect(detectAuthCheck(source)).toBe(true);
  });

  it("detects cookies import + createPortalClient variant", () => {
    const source = `
      import { cookies } from 'next/headers';
      import { createPortalClient } from '@/lib/supabase';
      export async function GET() {
        const supabase = createPortalClient({ cookies });
        return NextResponse.json({ ok: true });
      }
    `;
    expect(detectAuthCheck(source)).toBe(true);
  });

  // ---- Bearer + Supabase

  it("detects bearer header + supabase.auth.getUser nearby", () => {
    const source = `
      export async function GET(req) {
        const auth = req.headers.get('authorization');
        const token = auth?.replace('Bearer ', '');
        const { data: { user } } = await supabase.auth.getUser(token);
        if (!user) return new NextResponse('Unauthorized', { status: 401 });
        return NextResponse.json({ user });
      }
    `;
    expect(detectAuthCheck(source)).toBe(true);
  });

  it("detects SCANNER_TOKEN + authorization header", () => {
    const source = `
      const auth = request.headers.get('authorization');
      if (auth !== \`Bearer \${process.env.SCANNER_TOKEN}\`) {
        return new NextResponse('Unauthorized', { status: 401 });
      }
    `;
    expect(detectAuthCheck(source)).toBe(true);
  });

  // ---- Backward compatibility: old name-list helpers must still match
  // (these all flow through guard-call or verb+noun arms).

  it("backward-compat: await requireAuth", () => {
    expect(detectAuthCheck(`await requireAuth(req);`)).toBe(true);
  });
  it("backward-compat: await requirePermission", () => {
    expect(detectAuthCheck(`await requirePermission(Permission.READ);`)).toBe(true);
  });
  it("backward-compat: await requireRole", () => {
    expect(detectAuthCheck(`await requireRole('admin');`)).toBe(true);
  });
  it("backward-compat: await requireUser", () => {
    expect(detectAuthCheck(`await requireUser();`)).toBe(true);
  });
  it("backward-compat: await requireSession", () => {
    expect(detectAuthCheck(`await requireSession();`)).toBe(true);
  });
  it("backward-compat: await verifyAuth", () => {
    expect(detectAuthCheck(`await verifyAuth(req);`)).toBe(true);
  });
  it("backward-compat: await ensureAuth", () => {
    expect(detectAuthCheck(`await ensureAuth(req);`)).toBe(true);
  });
  it("backward-compat: await checkAuth", () => {
    expect(detectAuthCheck(`await checkAuth(req);`)).toBe(true);
  });
  it("backward-compat: validateKioskToken (sync)", () => {
    expect(detectAuthCheck(`const r = validateKioskToken(request);`)).toBe(true);
  });
  it("backward-compat: requireKioskToken (sync)", () => {
    expect(detectAuthCheck(`const r = requireKioskToken(request);`)).toBe(true);
  });
  it("backward-compat: validateDeviceToken (sync)", () => {
    expect(detectAuthCheck(`const r = validateDeviceToken(request);`)).toBe(true);
  });
  it("backward-compat: requireDeviceToken (sync)", () => {
    expect(detectAuthCheck(`const r = requireDeviceToken(request);`)).toBe(true);
  });

  // ---- Negative cases (must return false)

  it("returns false for empty handler", () => {
    const source = `
      export async function GET() { return Response.json({ ok: true }); }
    `;
    expect(detectAuthCheck(source)).toBe(false);
  });

  it("returns false for service-role-only handler with no auth", () => {
    const source = `
      import { createClient } from '@supabase/supabase-js';
      const sb = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
      export async function GET() {
        const { data } = await sb.from('users').select();
        return NextResponse.json(data);
      }
    `;
    expect(detectAuthCheck(source)).toBe(false);
  });

  it("returns false when 'auth' appears only in a comment", () => {
    const source = `
      export async function GET() {
        // auth handled by middleware
        return NextResponse.json({ ok: true });
      }
    `;
    expect(detectAuthCheck(source)).toBe(false);
  });

  it("returns false for verifyChecksum (verb but no auth noun)", () => {
    const source = `
      export async function POST(req) {
        const body = await req.text();
        verifyChecksum(body, signature);
        return NextResponse.json({ ok: true });
      }
    `;
    expect(detectAuthCheck(source)).toBe(false);
  });

  it("returns false for requireImports (verb but no auth noun)", () => {
    const source = `
      export async function GET() {
        requireImports(['fs', 'path']);
        return NextResponse.json({ ok: true });
      }
    `;
    expect(detectAuthCheck(source)).toBe(false);
  });

  it("returns false for authorization header without matching getUser or env-var", () => {
    const source = `
      export async function GET(req) {
        const auth = req.headers.get('authorization');
        console.log('header was:', auth);
        return NextResponse.json({ ok: true });
      }
    `;
    expect(detectAuthCheck(source)).toBe(false);
  });
});
