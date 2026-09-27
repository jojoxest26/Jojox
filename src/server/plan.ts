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
  const ownPlan = effectivePlan((data?.plan as Plan | undefined) ?? "free", data?.plan_trial_expires_at ?? null);
  if (ownPlan !== "free") return ownPlan;

  // Un membro (non proprietario) di un team eredita il piano Team finché il
  // proprietario ha un abbonamento attivo — i seat non pagano separatamente.
  // Il piano del proprietario si controlla sul valore grezzo (non via
  // effectivePlan): una sua prova gratuita del Pro non deve propagarsi ai
  // membri, solo un vero abbonamento Team.
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
    if (ownerProfile?.plan === "team") return "team";
  }

  return "free";
}

export function startOfCurrentMonthUtc(): Date {
  const now = new Date();
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
}