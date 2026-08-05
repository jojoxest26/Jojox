import { Router } from "express";
import { z } from "zod";
import { analyzeFiles } from "../../analyze.js";
import { optionalAuth, type AuthedRequest } from "../auth/middleware.js";
import { supabaseAdmin } from "../db/supabase.js";
import { getPlanForUser, MONTHLY_ANALYSIS_LIMIT, startOfCurrentMonthUtc } from "../plan.js";

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

analyzeRouter.post("/api/analyze", optionalAuth, async (req: AuthedRequest, res) => {
  const parsed = requestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Richiesta non valida", details: parsed.error.flatten() });
    return;
  }

  if (req.userId) {
    const plan = await getPlanForUser(req.userId);
    if (plan === "free") {
      const { count } = await supabaseAdmin
        .from("analyses")
        .select("id", { count: "exact", head: true })
        .eq("user_id", req.userId)
        .gte("created_at", startOfCurrentMonthUtc().toISOString());

      if ((count ?? 0) >= MONTHLY_ANALYSIS_LIMIT) {
        res.status(429).json({
          error: `Limite di ${MONTHLY_ANALYSIS_LIMIT} analisi mensili raggiunto per il piano free`,
        });
        return;
      }
    }
  }

  const result = analyzeFiles(parsed.data.files);

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
