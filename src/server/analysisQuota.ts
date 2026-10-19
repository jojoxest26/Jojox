import { supabaseAdmin } from "./db/supabase.js";
import { getPlanForUser, MONTHLY_ANALYSIS_LIMIT, startOfCurrentMonthUtc, type Plan } from "./plan.js";
import { getTeamUserIds } from "./team.js";

export type AnalysisQuotaResult =
  | { allowed: true }
  | { allowed: false; reason: "free_limit" | "no_credits" };

export interface AnalysisUsage {
  plan: Plan;
  monthlyLimit: number;
  usedThisMonth: number;
  extraCreditsAvailable: number;
  /**
   * Quante analisi ci si può ancora aspettare di fare in totale questo mese:
   * il tetto del piano più i crediti extra ancora da consumare, più quelli
   * già consumati questo mese (altrimenti, una volta iniziato a consumare
   * crediti, "usedThisMonth" supera "monthlyLimit" e il totale sembrerebbe
   * scendere invece che riflettere davvero quanto è stato comprato).
   */
  effectiveLimit: number;
}

async function monthlyAnalysisCount(teamUserIds: string[]): Promise<number> {
  const { count } = await supabaseAdmin
    .from("analyses")
    .select("id", { count: "exact", head: true })
    .in("user_id", teamUserIds)
    .gte("created_at", startOfCurrentMonthUtc().toISOString());
  return count ?? 0;
}

async function unusedCreditsCount(teamUserIds: string[]): Promise<number> {
  const { count } = await supabaseAdmin
    .from("analysis_credits")
    .select("id", { count: "exact", head: true })
    .in("user_id", teamUserIds)
    .eq("status", "unused");
  return count ?? 0;
}

/**
 * Verifica (ed eventualmente consuma un credito extra acquistato) la quota
 * mensile di analisi di un utente — usata sia dall'analisi manuale sia da
 * quella automatica a ogni push GitHub, perché entrambe contano allo stesso
 * modo ai fini del piano. Il Full Site Audit resta fuori: ha già i suoi
 * crediti dedicati (audit_credits), comprati appositamente per un uso singolo.
 *
 * Per il piano Team il conteggio è condiviso tra tutti i membri (stessa
 * logica di storico e repository condivisi), non per singolo utente.
 */
export async function checkAndConsumeAnalysisQuota(userId: string): Promise<AnalysisQuotaResult> {
  const plan = await getPlanForUser(userId);
  const teamUserIds = plan === "team" ? await getTeamUserIds(userId) : [userId];

  const used = await monthlyAnalysisCount(teamUserIds);
  if (used < MONTHLY_ANALYSIS_LIMIT[plan]) {
    return { allowed: true };
  }

  if (plan === "free") {
    return { allowed: false, reason: "free_limit" };
  }

  // Oltre la quota mensile inclusa: prova a consumare un credito extra
  // acquistato, condiviso tra i membri del team come lo storico — non importa
  // chi dei membri l'abbia comprato.
  const { data: credit } = await supabaseAdmin
    .from("analysis_credits")
    .select("id")
    .in("user_id", teamUserIds)
    .eq("status", "unused")
    .order("created_at", { ascending: true })
    .limit(1)
    .maybeSingle();

  if (!credit) {
    return { allowed: false, reason: "no_credits" };
  }

  // Update condizionata sullo stato letto sopra: se due richieste arrivano in
  // parallelo possono leggere lo stesso credito "unused" prima che l'altra lo
  // segni come usato — solo una delle due update trova ancora una riga da
  // aggiornare (stesso pattern usato per audit_credits).
  const { data: claimed } = await supabaseAdmin
    .from("analysis_credits")
    .update({ status: "used", used_at: new Date().toISOString() })
    .eq("id", credit.id)
    .eq("status", "unused")
    .select("id");

  if (!claimed || claimed.length === 0) {
    return { allowed: false, reason: "no_credits" };
  }

  return { allowed: true };
}

/**
 * Sola lettura, nessun consumo — usata dal contatore nell'Analyzer per
 * mostrare quanto resta della quota mensile e quanti crediti extra sono
 * ancora disponibili, prima ancora di bloccarsi.
 */
export async function getAnalysisUsage(userId: string): Promise<AnalysisUsage> {
  const plan = await getPlanForUser(userId);
  const teamUserIds = plan === "team" ? await getTeamUserIds(userId) : [userId];

  const [usedThisMonth, extraCreditsAvailable] = await Promise.all([
    monthlyAnalysisCount(teamUserIds),
    unusedCreditsCount(teamUserIds),
  ]);

  const monthlyLimit = MONTHLY_ANALYSIS_LIMIT[plan];
  const creditsAlreadyConsumedThisMonth = Math.max(0, usedThisMonth - monthlyLimit);
  const effectiveLimit = monthlyLimit + extraCreditsAvailable + creditsAlreadyConsumedThisMonth;

  return { plan, monthlyLimit, usedThisMonth, extraCreditsAvailable, effectiveLimit };
}
