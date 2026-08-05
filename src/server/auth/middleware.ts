import type { NextFunction, Request, Response } from "express";
import { supabaseAdmin } from "../db/supabase.js";

export interface AuthedRequest extends Request {
  userId?: string;
}

function extractBearerToken(req: Request): string | null {
  const header = req.headers.authorization;
  return header?.startsWith("Bearer ") ? header.slice(7) : null;
}

/** Blocca la richiesta con 401 se non c'è un utente Supabase autenticato valido. */
export async function requireAuth(req: AuthedRequest, res: Response, next: NextFunction): Promise<void> {
  const token = extractBearerToken(req);
  if (!token) {
    res.status(401).json({ error: "Autenticazione richiesta" });
    return;
  }

  const { data, error } = await supabaseAdmin.auth.getUser(token);
  if (error || !data.user) {
    res.status(401).json({ error: "Token non valido o scaduto" });
    return;
  }

  req.userId = data.user.id;
  next();
}

/** Non blocca la richiesta: se c'è un token valido attacca userId, altrimenti prosegue come ospite. */
export async function optionalAuth(req: AuthedRequest, _res: Response, next: NextFunction): Promise<void> {
  const token = extractBearerToken(req);
  if (!token) {
    next();
    return;
  }

  const { data } = await supabaseAdmin.auth.getUser(token);
  if (data.user) req.userId = data.user.id;
  next();
}
