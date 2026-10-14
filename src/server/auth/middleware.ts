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

interface VerifiedClaims {
  userId: string;
  userEmail?: string;
}

/**
 * auth.getUser(token) è sempre una vera chiamata di rete verso Supabase,
 * per ogni singola richiesta autenticata del sito. auth.getClaims(token) fa
 * la stessa verifica ma, quando il progetto usa le chiavi di firma JWT
 * moderne (asimmetriche), la fa in locale contro una chiave pubblica tenuta
 * in cache — senza toccare la rete. Se invece il progetto usa ancora il
 * vecchio segreto condiviso, la libreria stessa ripiega da sola su una
 * chiamata di rete identica a getUser(): questo cambio quindi non può mai
 * essere più lento di prima, solo uguale o più veloce. Il timeout resta
 * comunque come rete di sicurezza, e il log aiuta a capire nei log di
 * Railway se la lentezza residua viene ancora da qui.
 */
async function getClaimsWithTimeout(token: string): Promise<VerifiedClaims | null> {
  const start = Date.now();
  try {
    const { data } = await Promise.race([
      supabaseAdmin.auth.getClaims(token),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error(`auth.getClaims oltre ${AUTH_TIMEOUT_MS}ms`)), AUTH_TIMEOUT_MS)
      ),
    ]);
    const ms = Date.now() - start;
    if (ms > 1500) console.warn(`auth.getClaims lenta: ${ms}ms`);
    if (!data) return null;
    return { userId: data.claims.sub, userEmail: data.claims.email };
  } catch (err) {
    console.error(`auth.getClaims fallita dopo ${Date.now() - start}ms`, err);
    return null;
  }
}

/** Blocca la richiesta con 401 se non c'è un utente Supabase autenticato valido. */
export async function requireAuth(req: AuthedRequest, res: Response, next: NextFunction): Promise<void> {
  const token = extractBearerToken(req);
  if (!token) {
    res.status(401).json({ error: "Autenticazione richiesta" });
    return;
  }

  const claims = await getClaimsWithTimeout(token);
  if (!claims) {
    res.status(401).json({ error: "Token non valido o scaduto" });
    return;
  }

  req.userId = claims.userId;
  req.userEmail = claims.userEmail;
  next();
}

/** Non blocca la richiesta: se c'è un token valido attacca userId, altrimenti prosegue come ospite. */
export async function optionalAuth(req: AuthedRequest, _res: Response, next: NextFunction): Promise<void> {
  const token = extractBearerToken(req);
  if (!token) {
    next();
    return;
  }

  const claims = await getClaimsWithTimeout(token);
  if (claims) req.userId = claims.userId;
  next();
}