import { Router } from "express";
import { requireAuth, type AuthedRequest } from "../auth/middleware.js";
import { supabaseAdmin } from "../db/supabase.js";

export const planTrialRouter = Router();

const TRIAL_DAYS = 30;

// Attiva, una sola volta per account, 30 giorni di monitoraggio continuo
// (piano Pro) gratuito — pensata per chi ha appena finito un Full Site
// Audit e vuole vedere il monitoraggio in azione prima di abbonarsi.
planTrialRouter.post("/api/start-monitoring-trial", requireAuth, async (req: AuthedRequest, res) => {
  const { data: profile } = await supabaseAdmin
    .from("profiles")
    .select("plan, plan_trial_expires_at")
    .eq("id", req.userId)
    .single();

  if (!profile) {
    res.status(404).json({ error: "Profilo non trovato" });
    return;
  }

  if (profile.plan !== "free") {
    res.status(400).json({ error: "Hai già un piano a pagamento — non ti serve la prova gratuita" });
    return;
  }

  if (profile.plan_trial_expires_at) {
    res.status(409).json({ error: "Hai già usato la prova gratuita del monitoraggio continuo" });
    return;
  }

  const expiresAt = new Date(Date.now() + TRIAL_DAYS * 24 * 60 * 60 * 1000).toISOString();
  const { error } = await supabaseAdmin.from("profiles").update({ plan_trial_expires_at: expiresAt }).eq("id", req.userId);

  if (error) {
    res.status(500).json({ error: "Errore nell'attivazione della prova gratuita" });
    return;
  }

  res.json({ planTrialExpiresAt: expiresAt });
});