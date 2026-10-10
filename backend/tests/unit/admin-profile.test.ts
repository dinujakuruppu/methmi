import { createHmac } from "node:crypto";
import cookieParser from "cookie-parser";
import express, { type ErrorRequestHandler } from "express";
import request from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";

const db = vi.hoisted(() => ({
  getUserById: vi.fn(),
  from: vi.fn(),
  eq: vi.fn(),
  maybeSingle: vi.fn(),
  signInWithPassword: vi.fn(),
  signOut: vi.fn(),
}));

// No test ever contacts a live Supabase project.
vi.mock("../../src/lib/supabase.js", () => ({
  getSupabase: () => ({
    auth: { admin: { getUserById: db.getUserById } },
    from: (table: string) => {
      db.from(table);
      return {
        select: () => ({
          eq: (field: string, value: string) => {
            db.eq(field, value);
            return { maybeSingle: db.maybeSingle };
          },
        }),
      };
    },
  }),
  createSupabaseAuthClient: () => ({
    auth: { signInWithPassword: db.signInWithPassword, signOut: db.signOut },
  }),
}));

import adminAuthRouter from "../../src/routes/admin-auth.js";
import { ADMIN_SESSION_COOKIE, createSessionToken } from "../../src/lib/admin-auth.js";
import { requireAdmin } from "../../src/middleware/require-admin.js";

const ADMIN_ID = "11111111-1111-4111-8111-111111111111";
const OTHER_ID = "22222222-2222-4222-8222-222222222222";
const ADMIN_EMAIL = "admin@example.test";
const ADMIN_CREATED = "2026-10-01T00:00:00Z";

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use("/api/admin", adminAuthRouter);
app.get("/api/protected-check", requireAdmin, (_req, res) => res.json({ ok: true }));
const onError: ErrorRequestHandler = (_err, _req, res, _next) => {
  res.status(500).json({ error: "Internal server error." });
};
app.use(onError);

const cookie = (token: string) => `${ADMIN_SESSION_COOKIE}=${token}`;

beforeEach(() => {
  db.getUserById.mockResolvedValue({ data: { user: { email: ADMIN_EMAIL } }, error: null });
  db.maybeSingle.mockResolvedValue({
    data: { email: ADMIN_EMAIL, created_at: ADMIN_CREATED }, error: null,
  });
  db.signInWithPassword.mockResolvedValue({
    data: { user: { id: ADMIN_ID, email: ADMIN_EMAIL } }, error: null,
  });
  db.signOut.mockResolvedValue({ error: null });
});

describe("Dinuja's protected admin profile: GET /api/admin/me", () => {
  it("rejects an anonymous or forged-identity request with 401 before a database read", async () => {
    const response = await request(app).get("/api/admin/me")
      .set("x-user-id", ADMIN_ID)
      .query({ role: "admin", userId: ADMIN_ID });
    expect(response.status).toBe(401);
    expect(db.getUserById).not.toHaveBeenCalled();
    expect(db.from).not.toHaveBeenCalled();
  });

  it("rejects a tampered cookie and an expired signed cookie with 401", async () => {
    const payload = `${Date.now() - 10_000}.${ADMIN_ID}`;
    const signature = createHmac("sha256", process.env.ADMIN_SESSION_SECRET!)
      .update(payload).digest("hex");
    for (const token of ["not-a-session", `${payload}.${signature}`]) {
      expect((await request(app).get("/api/admin/me")
        .set("Cookie", cookie(token))).status).toBe(401);
    }
    expect(db.from).not.toHaveBeenCalled();
  });

  it("returns 403 for a valid user who is not in the admins table", async () => {
    db.getUserById.mockResolvedValue({
      data: { user: { email: "member@example.test" } }, error: null,
    });
    db.maybeSingle.mockResolvedValue({ data: null, error: null });
    const response = await request(app).get("/api/admin/me")
      .set("Cookie", cookie(await createSessionToken(OTHER_ID)))
      .query({ role: "admin", email: ADMIN_EMAIL });
    expect(response.status).toBe(403);
    expect(db.getUserById).toHaveBeenCalledWith(OTHER_ID);
    expect(db.from).toHaveBeenCalledWith("admins");
    expect(db.eq).toHaveBeenCalledWith("email", "member@example.test");
    expect(response.body).not.toHaveProperty("email");
  });

  it("returns only the authenticated user's private DB-backed profile", async () => {
    const response = await request(app).get("/api/admin/me")
      .set("Cookie", cookie(await createSessionToken(ADMIN_ID)))
      .query({ userId: OTHER_ID, role: "owner" });
    expect(response.status).toBe(200);
    expect(response.body).toEqual({
      id: ADMIN_ID, email: ADMIN_EMAIL, role: "admin", adminSince: ADMIN_CREATED,
    });
    expect(response.headers["cache-control"]).toContain("no-store");
    expect(db.getUserById).toHaveBeenCalledWith(ADMIN_ID);
    expect(db.from).toHaveBeenCalledWith("admins");
    expect(db.eq).toHaveBeenCalledWith("email", ADMIN_EMAIL);
  });

  it("blocks a revoked admin even if the signed cookie remains valid", async () => {
    db.maybeSingle.mockResolvedValue({ data: null, error: null });
    expect((await request(app).get("/api/admin/me")
      .set("Cookie", cookie(await createSessionToken(ADMIN_ID)))).status).toBe(403);
  });

  it("does not leak raw database errors to the browser", async () => {
    db.maybeSingle.mockResolvedValue({
      data: null, error: { message: "private database connection detail" },
    });
    const response = await request(app).get("/api/admin/me")
      .set("Cookie", cookie(await createSessionToken(ADMIN_ID)));
    expect(response.status).toBe(500);
    expect(JSON.stringify(response.body)).not.toContain("private database connection detail");
  });
});

describe("shared server-side admin middleware", () => {
  it("denies no session (401), a removed admin (403), and allows an active admin (200)", async () => {
    expect((await request(app).get("/api/protected-check")).status).toBe(401);
    const token = await createSessionToken(ADMIN_ID);
    db.maybeSingle.mockResolvedValueOnce({ data: null, error: null });
    expect((await request(app).get("/api/protected-check")
      .set("Cookie", cookie(token))).status).toBe(403);
    const result = await request(app).get("/api/protected-check")
      .set("Cookie", cookie(token));
    expect(result.status).toBe(200);
    expect(result.body).toEqual({ ok: true });
  });
});

describe("admin sign-in and access-control regression tests", () => {
  it("rejects unknown fields before authentication", async () => {
    const response = await request(app).post("/api/admin/login")
      .send({ email: ADMIN_EMAIL, password: "valid", role: "admin" });
    expect(response.status).toBe(400);
    expect(db.signInWithPassword).not.toHaveBeenCalled();
  });

  it("returns 401 and issues no cookie for an incorrect password", async () => {
    db.signInWithPassword.mockResolvedValue({ data: { user: null }, error: { status: 400 } });
    const response = await request(app).post("/api/admin/login")
      .send({ email: ADMIN_EMAIL, password: "incorrect" });
    expect(response.status).toBe(401);
    expect(response.headers["set-cookie"]).toBeUndefined();
  });

  it("returns 403 and issues no cookie to a signed-in non-admin", async () => {
    db.maybeSingle.mockResolvedValue({ data: null, error: null });
    const response = await request(app).post("/api/admin/login")
      .send({ email: ADMIN_EMAIL, password: "example-test-password" });
    expect(response.status).toBe(403);
    expect(response.headers["set-cookie"]).toBeUndefined();
  });

  it("sets an HttpOnly cookie and authenticates the right admin without exposing bearer tokens", async () => {
    const login = await request(app).post("/api/admin/login")
      .send({ email: ADMIN_EMAIL, password: "example-test-password" });
    expect(login.status).toBe(200);
    expect(login.headers["set-cookie"][0]).toContain("HttpOnly");
    expect(login.headers["set-cookie"][0]).toContain("SameSite=Lax");
    expect(JSON.stringify(login.body)).not.toContain("access_token");

    const session = await request(app).get("/api/admin/session")
      .set("Cookie", login.headers["set-cookie"][0].split(";")[0]);
    expect(session.status).toBe(200);
    expect(session.body).toEqual({ authenticated: true });
    expect(db.from).toHaveBeenCalledWith("admins");
  });
});
