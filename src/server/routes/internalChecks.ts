import { Router } from "express";
import { env } from "../env.js";
import { runSyntheticChecks } from "../syntheticCheck.js";
import { secretsMatch } from "./sentinel.js";

export const internalChecksRouter = Router();

/**
 * Avvia a mano un giro di controllo sintetico (punto 15 bis), senza
 * aspettare i 15 minuti del cron — serve a verificare che funzioni
 * davvero, stesso schema di /api/internal/sentinel/run. Stesso segreto
 * operativo (SENTINEL_TRIGGER_SECRET): non è un secondo segreto da
 * aggiungere su Railway, è lo stesso già usato per gli strumenti interni.
 */
internalChecksRouter.post("/api/internal/synthetic-check/run", async (req, res) => {
  const configured = env.sentinelTriggerSecret;
  const provided = req.header("x-sentinel-secret");

  if (!configured || !provided || !secretsMatch(provided, configured)) {
    res.status(404).end();
    return;
  }

  const results = await runSyntheticChecks();
  res.json({ results });
});
