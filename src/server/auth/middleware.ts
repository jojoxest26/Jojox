import type { NextFunction, Request, Response } from "express";
import { supabaseAdmin } from "../db/supabase.js";

export interface AuthedRequest extends Request {
  userId?: string;
  userEmail?: string;
}

function extractBearerToken(req: Request): string | null {
  const header = req.headers.authorization;
  return header?.startsWith("Bearer ") ? header.slice(7) : null;
}

const AUTH_TIMEOUT_MS = 8000;

/**
 * supabaseAdmin.auth.getUser(token) è una vera chiamata di rete verso
 * Supabase (non una verifica locale del JWT) — se Supabase risponde lenta,
 * questa chiamata può restare appesa e bloccare la richiesta con lei senza
 * che nulla dica perché. Qui la limitiamo a un tempo massimo e logghiamo
 * sempre quanto ci ha messo: così, se càpita ancora, nei log di Railway si
 * vede subito se la colpa è di Supabase invece di doverlo supporre.
 */
async function getUserWithTimeout(token: string): ReturnType<typeof supabaseAdmin.auth.getUser> {
  const start = Date.now();
  try {
    const result = await Promise.race([
      supabaseAdmin.auth.getUser(token),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error(`auth.getUser oltre ${AUTH_TIMEOUT_MS}ms`)), AUTH_TIMEOUT_MS)
      ),
    ]);
    const ms = Date.now() - start;
    if (ms > 1500) console.warn(`auth.getUser lenta: ${ms}ms`);
    return result;
  } catch (err) {
    console.error(`auth.getUser fallita dopo ${Date.now() - start}ms`, err);
    return { data: { user: null }, error: err as Error } as Awaited<ReturnType<typeof supabaseAdmin.auth.getUser>>;
  }
}

/** Blocca la richiesta con 401 se non c'è un utente Supabase autenticato valido. */
export async function requireAuth(req: AuthedRequest, res: Response, next: NextFunction): Promise<void> {
  const token = extractBearerToken(req);
  if (!token) {
    res.status(401).json({ error: "Autenticazione richiesta" });
    return;
  }

  const { data, error } = await getUserWithTimeout(token);
  if (error || !data.user) {
    res.status(401).json({ error: "Token non valido o scaduto" });
    return;
  }

  req.userId = data.user.id;
  req.userEmail = data.user.email;
  next();
}

/** Non blocca la richiesta: se c'è un token valido attacca userId, altrimenti prosegue come ospite. */
export async function optionalAuth(req: AuthedRequest, _res: Response, next: NextFunction): Promise<void> {
  const token = extractBearerToken(req);
  if (!token) {
    next();
    return;
  }

  const { data } = await getUserWithTimeout(token);
  if (data.user) req.userId = data.user.id;
  next();
}