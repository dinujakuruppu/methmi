import { asyncRoute } from "../lib/http.js";
import type { NextFunction, Request, Response } from "express";
import { ADMIN_SESSION_COOKIE, getAdminSession } from "../lib/admin-auth.js";

// Protect server data; frontend redirects are only a convenience.
export const requireAdmin = asyncRoute(async (req: Request, res: Response, next: NextFunction) => {
  const session = await getAdminSession(req.cookies?.[ADMIN_SESSION_COOKIE]);
  if (session.status === "authorized") {
    next();
    return;
  }

  if (session.status === "forbidden") {
    res.status(403).json({ error: "Forbidden. Admin access required." });
    return;
  }
  res.status(401).json({ error: "Unauthorized. Please log in again." });
});
