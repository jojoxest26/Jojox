import { Router } from "express";
import { requireAuth, type AuthedRequest } from "../auth/middleware.js";
import { getPlanForUser } from "../plan.js";
import { claimPendingTeamInvite } from "../team.js";
import { supabaseAdmin } from "../db/supabase.js";

export const profileRouter = Router();

profileRouter.get("/api/profile", requireAuth, async (req: AuthedRequest, res) => {
  // Se questa email ha un invito Team in sospeso, lo completa qui — così un
  // membro invitato ottiene l'accesso al primo caricamento dopo il login,
  // senza bisogno di un link speciale o di un passaggio in più. Deve finire
  // PRIMA di calcolare il piano, perché getPlanForUser legge proprio
  // l'appartenenza al team che questa riga appena scritto.
  //
  // (Provato anche a farla partire insieme alle altre due, per risparmiare
  // una richiesta in fila — ma in pratica ha allungato i tempi invece di
  // accorciarli, probabilmente per troppe richieste in parallelo verso
  // Supabase nello stesso istante. Tornati a farla prima: più sicuro e,
  // a conti fatti, anche più veloce.)
  await claimPendingTeamInvite(req.userId!, req.userEmail);

  const [plan, { data: profile }] = await Promise.all([
    getPlanForUser(req.userId!),
    supabaseAdmin.from("profiles").select("plan_trial_expires_at").eq("id", req.userId).single(),
  ]);

  const trialExpiresAt = profile?.plan_trial_expires_at ?? null;
  res.json({
    plan,
    // Se il campo è mai stato impostato (anche se ormai scaduto), la prova
    // gratuita è già stata usata e non è più offribile.
    planTrialUsed: trialExpiresAt !== null,
    planTrialExpiresAt: trialExpiresAt && new Date(trialExpiresAt) > new Date() ? trialExpiresAt : null,
  });
});