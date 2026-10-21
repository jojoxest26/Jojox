import type { NextFunction, Response } from "express";
import { Router } from "express";
import { z } from "zod";
import { analyzeFiles } from "../../analyze.js";
import { scanDependencies } from "../../depscan.js";
import { computeScore, summarizeBySeverity } from "../../scoring.js";
import { optionalAuth, type AuthedRequest } from "../auth/middleware.js";
import { supabaseAdmin } from "../db/supabase.js";
import { checkAndConsumeAnalysisQuota } from "../analysisQuota.js";
import { createIpRateLimit } from "../util/rateLimit.js";

const MAX_FILES = 300;
const MAX_FILE_BYTES = 200_000;

export const requestSchema = z.object({
  files: z
    .array(
      z.object({
        path: z.string().min(1).max(500),
        content: z.string().max(MAX_FILE_BYTES),
      })
    )
    .min(1)
    .max(MAX_FILES),
});

export const analyzeRouter = Router();

// Punto 18 quinquies: optionalAuth lascia passare chi non manda nessun
// token come ospite (req.userId resta undefined) — e per quel ramo il
// controllo quota sotto viene saltato del tutto (solo "if (req.userId)"),
// quindi senza questo limite un chiamante anonimo diretto all'API (non dal
// sito, che instrada gli ospiti su /api/guest-analyze con il suo limite di
// una sola analisi per IP) avrebbe analisi gratuite illimitate. Si applica
// solo agli ospiti: un utente loggato resta comunque limitato dalla propria
// quota mensile di piano più sotto.
const analyzeGuestRateLimit = createIpRateLimit({
  windowMs: 10 * 60 * 1000,
  max: 20,
  message: "Troppe richieste anonime da questo indirizzo IP — accedi con un account per continuare, o riprova tra qualche minuto.",
});

function guestOnlyRateLimit(req: AuthedRequest, res: Response, next: NextFunction): void {
  if (req.userId) {
    next();
    return;
  }
  analyzeGuestRateLimit(req, res, next);
}

analyzeRouter.post("/api/analyze", optionalAuth, guestOnlyRateLimit, async (req: AuthedRequest, res) => {
  const parsed = requestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Richiesta non valida", details: parsed.error.flatten() });
    return;
  }

  if (req.userId) {
    const quota = await checkAndConsumeAnalysisQuota(req.userId);
    if (!quota.allowed) {
      if (quota.reason === "free_limit") {
        res.status(429).json({
          error: "Limite di analisi mensili raggiunto per il piano free — passa a Pro per continuare",
          requiresPlan: true,
        });
        return;
      }
      res.status(402).json({
        error: "Limite mensile di analisi raggiunto — acquista un pacchetto extra per continuare",
        creditsExhausted: true,
      });
      return;
    }
  }

  const depFindings = await scanDependencies(parsed.data.files);
  const findings = [...analyzeFiles(parsed.data.files).findings, ...depFindings];
  const result = { score: computeScore(findings), findings, summary: summarizeBySeverity(findings) };

  if (req.userId) {
    await supabaseAdmin.from("analyses").insert({
      user_id: req.userId,
      source: "manual",
      score: result.score,
      summary: result.summary,
      findings: result.findings,
    });
  }

  res.json(result);
});