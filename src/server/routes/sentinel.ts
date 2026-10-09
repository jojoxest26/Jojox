import { timingSafeEqual } from "node:crypto";
import { Router } from "express";
import { env } from "../env.js";
import { runSentinelScan } from "../sentinel/scan.js";

export const sentinelRouter = Router();

/** Confronto a tempo costante tra il segreto configurato e quello fornito nella richiesta, per non farlo distinguere da quanti caratteri combaciano. */
export function secretsMatch(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

/**
 * Avvia a mano uno scan completo della Sentinella 24/7, senza aspettare il
 * cron notturno — serve a verificare che funzioni davvero. Protetta da un
 * segreto opzionale (non dal login di un utente: è uno strumento operativo,
 * non una funzionalità del prodotto): se SENTINEL_TRIGGER_SECRET non è
 * impostata, o il segreto fornito non combacia, la rotta risponde 404 come
 * se non esistesse.
 */
sentinelRouter.post("/api/internal/sentinel/run", (req, res) => {
  const configured = env.sentinelTriggerSecret;
  const provided = req.header("x-sentinel-secret");

  if (!configured || !provided || !secretsMatch(provided, configured)) {
    res.status(404).end();
    return;
  }

  // Risponde subito: uno scan di molti repository può durare a lungo, non
  // ha senso tenere la richiesta HTTP in attesa del risultato.
  res.status(202).json({ started: true });

  runSentinelScan().catch((err) => {
    console.error("Sentinella 24/7: errore nello scan avviato manualmente", err);
  });
});
