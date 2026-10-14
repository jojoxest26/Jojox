import { Router } from "express";
import { requireAuth, type AuthedRequest } from "../auth/middleware.js";
import { getPlanForUser } from "../plan.js";
import { claimPendingTeamInvite } from "../team.js";
import { supabaseAdmin } from "../db/supabase.js";

export const profileRouter = Router();

profileRouter.get("/api/profile", requireAuth, async (req: AuthedRequest, res) => {
  // Se questa email ha un invito Team in sospeso, lo completa qui — così un
  // membro invitato ottiene l'accesso al primo caricamento dopo il login,
  // senza bisogno di un link speciale o di un passaggio in più.
  //
  // In teoria andrebbe completato PRIMA di calcolare il piano, perché
  // getPlanForUser legge proprio l'appartenenza al team che questa riga
  // scrive — ma per il 99% delle richieste (chiunque non abbia appena
  // accettato un invito proprio in questo istante) è una UPDATE che non
  // tocca nessuna riga, e aspettarla blocca ogni singolo caricamento del
  // profilo di chiunque, sempre, solo per gestire bene quel caso raro.
  // La facciamo partire insieme alle altre due: nel caso raro in cui un
  // invito viene accettato proprio ora, il piano aggiornato si vede dal
  // prossimo caricamento (un refresh dopo), non da questo — uno scambio
  // ragionevole per non pagare tre richieste in fila ad ogni apertura.
  const [, plan, { data: profile }] = await Promise.all([
    claimPendingTeamInvite(req.userId!, req.userEmail),
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