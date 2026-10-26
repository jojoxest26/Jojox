import { Router } from "express";
import { requireAuth, type AuthedRequest } from "../auth/middleware.js";
import { getPlanForUser } from "../plan.js";
import { claimPendingTeamInvite } from "../team.js";
import { supabaseAdmin } from "../db/supabase.js";

export const profileRouter = Router();

// Completa un eventuale invito Team in sospeso per questa email — chiamata
// una sola volta per sessione dal frontend (vedi useSession.ts), non più
// da /api/profile stesso: prima girava ad ogni singolo caricamento del
// profilo (Prezzi, GitHub, Team, chat lo chiamano tutte, anche più volte
// sulla stessa pagina), pagando una richiesta in più a Supabase ogni volta
// per un controllo che in pratica serve solo la primissima volta dopo un
// invito vero.
profileRouter.post("/api/claim-invite", requireAuth, async (req: AuthedRequest, res) => {
  await claimPendingTeamInvite(req.userId!, req.userEmail);
  res.json({ ok: true });
});

profileRouter.get("/api/profile", requireAuth, async (req: AuthedRequest, res) => {
  const [plan, { data: profile }] = await Promise.all([
    getPlanForUser(req.userId!),
    supabaseAdmin.from("profiles").select("plan_trial_expires_at, sentinel_addon_active").eq("id", req.userId).single(),
  ]);

  const trialExpiresAt = profile?.plan_trial_expires_at ?? null;
  res.json({
    plan,
    // Se il campo è mai stato impostato (anche se ormai scaduto), la prova
    // gratuita è già stata usata e non è più offribile.
    planTrialUsed: trialExpiresAt !== null,
    planTrialExpiresAt: trialExpiresAt && new Date(trialExpiresAt) > new Date() ? trialExpiresAt : null,
    // Controllo h24 da solo (aziende): abbonamento a sé, indipendente dal piano.
    sentinelAddonActive: profile?.sentinel_addon_active ?? false,
  });
});