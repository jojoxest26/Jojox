import { supabaseAdmin } from "./db/supabase.js";

export type Plan = "free" | "pro" | "team";

export const MONTHLY_ANALYSIS_LIMIT = 5;

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
  const plan = (data?.plan as Plan | undefined) ?? "free";
  return effectivePlan(plan, data?.plan_trial_expires_at ?? null);
}

export function startOfCurrentMonthUtc(): Date {
  const now = new Date();
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
}