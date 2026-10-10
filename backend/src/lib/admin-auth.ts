// Supabase Auth verifies credentials; only the backend issues signed HttpOnly sessions.
export const ADMIN_SESSION_COOKIE = "methmi_admin_session";
export const ADMIN_SESSION_MAX_AGE_SECONDS = 60 * 60;

function getSecret(): string {
  const secret = process.env.ADMIN_SESSION_SECRET?.trim();
  if (!secret || secret.length < 32) {
    throw new Error("Set ADMIN_SESSION_SECRET to at least 32 random characters in both backend and frontend environment files.");
  }
  return secret;
}

function bufferToHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function hmacHex(secret: string, message: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  return bufferToHex(await crypto.subtle.sign("HMAC", key, enc.encode(message)));
}

export async function createSessionToken(userId: string): Promise<string> {
  const expiresAt = Date.now() + ADMIN_SESSION_MAX_AGE_SECONDS * 1000;
  const payload = `${expiresAt}.${userId}`;
  return `${payload}.${await hmacHex(getSecret(), payload)}`;
}

/** Check signature and expiry before trusting the user ID inside the cookie. */
export async function isSessionTokenValid(token: string | undefined | null): Promise<boolean> {
  if (!token) return false;
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const [expires, userId, signature] = parts;
  if (!/^\d+$/.test(expires)
      || !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(userId)
      || !/^[0-9a-f]{64}$/.test(signature)) return false;

  const expected = await hmacHex(getSecret(), `${expires}.${userId}`);
  if (expected.length !== signature.length) return false;
  let mismatch = 0;
  for (let i = 0; i < expected.length; i += 1) {
    mismatch |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
  }
  if (mismatch !== 0) return false;
  const expiresAt = Number(expires);
  return Number.isFinite(expiresAt) && Date.now() < expiresAt;
}

export type AdminSession =
  | { status: "unauthenticated" }
  | { status: "forbidden" }
  | { status: "authorized"; userId: string; email: string; createdAt: string };

/**
 * Determine identity from the validated server cookie and check the current
 * Supabase Auth user and database allow-list on EVERY protected API request.
 * A valid session for a removed/non-admin account returns 403, not 401.
 */
export async function getAdminSession(token: string | undefined | null): Promise<AdminSession> {
  if (!await isSessionTokenValid(token)) return { status: "unauthenticated" };

  const userId = token!.split(".")[1];
  const { getSupabase } = await import("./supabase.js");
  const supabase = getSupabase();

  const { data: userData, error: userError } = await supabase.auth.admin.getUserById(userId);
  if (userError || !userData.user?.email) return { status: "unauthenticated" };

  const email = userData.user.email.trim().toLowerCase();
  const { data: admin, error: adminError } = await supabase.from("admins")
    .select("email, created_at")
    .eq("email", email)
    .maybeSingle();

  if (adminError) throw new Error("Unable to verify admin access.");
  if (!admin) return { status: "forbidden" };

  return { status: "authorized", userId, email: admin.email, createdAt: admin.created_at };
}

/** Backward-compatible helper used by existing admin routes. */
export async function isAuthorizedAdminSession(token: string | undefined | null): Promise<boolean> {
  return (await getAdminSession(token)).status === "authorized";
}
