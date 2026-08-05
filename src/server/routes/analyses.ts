import { Router } from "express";
import { requireAuth, type AuthedRequest } from "../auth/middleware.js";
import { supabaseAdmin } from "../db/supabase.js";

export const analysesRouter = Router();

analysesRouter.get("/api/analyses", requireAuth, async (req: AuthedRequest, res) => {
  const { data, error } = await supabaseAdmin
    .from("analyses")
    .select("id, source, repo_full_name, score, summary, created_at")
    .eq("user_id", req.userId)
    .order("created_at", { ascending: false })
    .limit(20);

  if (error) {
    res.status(500).json({ error: "Errore nel recupero dello storico" });
    return;
  }

  res.json({ analyses: data });
});

analysesRouter.get("/api/analyses/:id", requireAuth, async (req: AuthedRequest, res) => {
  const { data, error } = await supabaseAdmin
    .from("analyses")
    .select("*")
    .eq("id", req.params.id)
    .eq("user_id", req.userId)
    .single();

  if (error || !data) {
    res.status(404).json({ error: "Analisi non trovata" });
    return;
  }

  res.json(data);
});
