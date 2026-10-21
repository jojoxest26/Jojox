import type { NextFunction, Request, Response } from "express";

/**
 * Rate limit in memoria per IP, per le poche rotte pubbliche prive di
 * autenticazione (punto 18 quinquies della roadmap) — niente dipendenza
 * nuova da installare né stato condiviso da gestire: su un singolo
 * processo Railway basta, e un riavvio del processo azzera i contatori
 * senza danno (serve solo a scoraggiare l'abuso automatizzato, non è un
 * limite di piano). Richiede `app.set("trust proxy", 1)` (già impostato in
 * app.ts) perché req.ip rifletta l'IP di chi visita, non quello del proxy.
 */
export function createIpRateLimit(options: { windowMs: number; max: number; message: string }) {
  const hits = new Map<string, { count: number; resetAt: number }>();

  // Ripulisce le voci scadute periodicamente — altrimenti la mappa cresce
  // senza limite con ogni nuovo IP visto, per tutta la vita del processo.
  // unref() perché questo timer non deve mai tenere vivo il processo da solo.
  setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of hits) {
      if (entry.resetAt <= now) hits.delete(key);
    }
  }, options.windowMs).unref();

  return function rateLimit(req: Request, res: Response, next: NextFunction): void {
    const key = req.ip ?? "unknown";
    const now = Date.now();
    const entry = hits.get(key);

    if (!entry || entry.resetAt <= now) {
      hits.set(key, { count: 1, resetAt: now + options.windowMs });
      next();
      return;
    }

    if (entry.count >= options.max) {
      res.status(429).json({ error: options.message });
      return;
    }

    entry.count += 1;
    next();
  };
}
