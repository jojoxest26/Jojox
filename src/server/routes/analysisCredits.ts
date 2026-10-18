import { Router } from "express";
import { requireAuth, type AuthedRequest } from "../auth/middleware.js";
import { supabaseAdmin } from "../db/supabase.js";
import { getPlanForUser } from "../plan.js";
import { getTeamUserIds } from "../team.js";

export const analysisCreditsRouter = Router();

analysisCreditsRouter.get("/api/analysis-credits", requireAuth, async (req: AuthedRequest, res) => {
  const plan = await getPlanForUser(req.userId!);
  const teamUserIds = plan === "team" ? await getTeamUserIds(req.userId!) : [req.userId!];

  const { count, error } = await supabaseAdmin
    .from("analysis_credits")
    .select("id", { count: "exact", head: true })
    .in("user_id", teamUserIds)
    .eq("status", "unused");

  if (error) {
    res.status(500).json({ error: "Errore nel controllo dei pacchetti di analisi disponibili" });
    return;
  }

  res.json({ available: count ?? 0 });
});
