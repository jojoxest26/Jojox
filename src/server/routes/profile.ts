import { Router } from "express";
import { requireAuth, type AuthedRequest } from "../auth/middleware.js";
import { getPlanForUser } from "../plan.js";
import { supabaseAdmin } from "../db/supabase.js";

export const profileRouter = Router();

profileRouter.get("/api/profile", requireAuth, async (req: AuthedRequest, res) => {
  const plan = await getPlanForUser(req.userId!);

  const { data: profile } = await supabaseAdmin
    .from("profiles")
    .select("plan_trial_expires_at")
    .eq("id", req.userId)
    .single();

  const trialExpiresAt = profile?.plan_trial_expires_at ?? null;
  res.json({
    plan,
    // Se il campo è mai stato impostato (anche se ormai scaduto), la prova
    // gratuita è già stata usata e non è più offribile.
    planTrialUsed: trialExpiresAt !== null,
    planTrialExpiresAt: trialExpiresAt && new Date(trialExpiresAt) > new Date() ? trialExpiresAt : null,
  });
});