import { supabaseAdmin } from "./db/supabase.js";

export type Plan = "free" | "pro" | "team" | "business";

/**
 * Analisi incluse al mese per piano. Pro/Team erano "illimitate" — ora un
 * tetto generoso ma finito: ogni push su un repository collegato genera
 * un'analisi automatica, quindi senza limite i costi (scansione dipendenze
 * incluse) crescono con l'uso senza alcun freno. Per un piano Team il conto
 * è condiviso tra tutti i membri (vedi checkAndConsumeAnalysisQuota), come
 * storico e repository. Business: numero provvisorio, da rivedere con dati
 * reali — la condivisione tra i membri del team Business non è ancora
 * collegata (punto "posti extra oltre i 25" lasciato per un secondo giro).
 */
export const MONTHLY_ANALYSIS_LIMIT: Record<Plan, number> = {
  free: 5,
  pro: 100,
  team: 500,
  business: 2000,
};

/**
 * Quante analisi extra sblocca un pacchetto acquistato una tantum, per chi
 * supera la quota mensile inclusa (vedi analysisQuota.ts) — pensato per non
 * bloccare mai davvero un cliente pagante fino al mese successivo.
 */
export const ANALYSIS_PACK_SIZE = 50;

/**
 * Messaggi di chat al giorno per piano — ogni messaggio è una chiamata a
 * pagamento all'API Anthropic, quindi il limite serve a tenere i costi
 * sotto controllo fin dal primo utente, non solo a scoraggiare l'abuso.
 */
export const DAILY_CHAT_MESSAGE_LIMIT: Record<Plan, number> = {
  free: 15,
  pro: 100,
  team: 200,
  business: 400,
};

/**
 * Sotto-limite dei messaggi di chat in modalità generale (nessuna analisi
 * aperta): lì la chat usa il modello più caro con risposte fino a 16.000
 * token, circa 100-200 volte il costo di un messaggio che spiega un
 * risultato. Con il solo DAILY_CHAT_MESSAGE_LIMIT un utente Pro poteva
 * costare centinaia di euro al mese di API contro 9,99€ di incasso.
 */
export const DAILY_GENERAL_CHAT_LIMIT: Record<Plan, number> = {
  free: 0,
  pro: 15,
  team: 30,
  business: 60,
};

/**
 * Revisioni AI aggiuntive al giorno (punto 14): più costosa di un messaggio
 * di chat (manda file interi a Claude Sonnet, non solo testo breve), quindi
 * un tetto più basso — è un controllo via pulsante, non una conversazione.
 */
export const DAILY_AI_INSIGHT_LIMIT: Record<Plan, number> = {
  free: 0,
  pro: 5,
  team: 15,
  business: 30,
};

/**
 * Il piano che conta davvero: il piano pagato, salvo una prova gratuita del
 * Pro ancora attiva per chi è sul piano free — non declassa mai un piano
 * già pagato (pro/team restano tali indipendentemente dalla prova).
 */
export function effectivePlan(plan: Plan, trialExpiresAt: string | null, now: Date = new Date()): Plan {
  if (plan === "free" && trialExpiresAt && new Date(trialExpiresAt) > now) {
    return "pro";
  }
  return plan;
}

export async function getPlanForUser(userId: string): Promise<Plan> {
  const { data } = await supabaseAdmin.from("profiles").select("plan, plan_trial_expires_at").eq("id", userId).single();
  const ownPlan = effectivePlan((data?.plan as Plan | undefined) ?? "free", data?.plan_trial_expires_at ?? null);
  if (ownPlan !== "free") return ownPlan;

  // Un membro (non proprietario) di un team eredita il piano del
  // proprietario (Team o Business) finché quello ha un abbonamento attivo —
  // i seat non pagano separatamente. Il piano del proprietario si controlla
  // sul valore grezzo (non via effectivePlan): una sua prova gratuita del
  // Pro non deve propagarsi ai membri, solo un vero abbonamento.
  const { data: membership } = await supabaseAdmin
    .from("team_members")
    .select("teams:teams!inner(owner_id)")
    .eq("user_id", userId)
    .not("joined_at", "is", null)
    .neq("role", "owner")
    .maybeSingle();

  const ownerId = membership?.teams ? (membership.teams as unknown as { owner_id: string }).owner_id : null;
  if (ownerId) {
    const { data: ownerProfile } = await supabaseAdmin.from("profiles").select("plan").eq("id", ownerId).single();
    if (ownerProfile?.plan === "team" || ownerProfile?.plan === "business") return ownerProfile.plan as Plan;
  }

  return "free";
}

export function startOfCurrentMonthUtc(): Date {
  const now = new Date();
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
}

export function startOfTodayUtc(): Date {
  const now = new Date();
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
}