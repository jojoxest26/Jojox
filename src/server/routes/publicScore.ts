import { Router } from "express";
import { supabaseAdmin } from "../db/supabase.js";

export const publicScoreRouter = Router();

/**
 * Punteggio pubblico linkabile per un repository collegato via GitHub App.
 * Pubblico per chiunque conosca owner/repo — stesso modello del badge SVG
 * (badge.ts): niente snippet di codice, solo punteggio e conteggio per
 * gravità, già aggregati in `summary` al momento dell'analisi.
 */
publicScoreRouter.get("/api/public-score/:owner/:repo", async (req, res) => {
  const repoFullName = `${req.params.owner}/${req.params.repo}`;

  const { data } = await supabaseAdmin
    .from("analyses")
    .select("score, summary, created_at")
    .eq("repo_full_name", repoFullName)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  if (data == null) {
    res.status(404).json({ found: false });
    return;
  }

  res.json({
    found: true,
    repoFullName,
    score: data.score,
    summary: data.summary,
    updatedAt: data.created_at,
  });
});