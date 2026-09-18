import { env } from "../env.js";
import type { Plan } from "../plan.js";

export type PaidPlan = Exclude<Plan, "free">;
export type BillingInterval = "monthly" | "annual";

export function priceIdForPlan(plan: PaidPlan, interval: BillingInterval = "monthly"): string | null {
  if (interval === "annual") {
    return plan === "pro" ? env.stripePriceIdProAnnual : env.stripePriceIdTeamAnnual;
  }
  return plan === "pro" ? env.stripePriceIdPro : env.stripePriceIdTeam;
}

/** Riconosce il piano da un price id, mensile o annuale che sia — al cliente interessa solo cosa sblocca, non come lo paga. */
export function planForPriceId(priceId: string): PaidPlan | null {
  if (priceId === env.stripePriceIdPro || priceId === env.stripePriceIdProAnnual) return "pro";
  if (priceId === env.stripePriceIdTeam || priceId === env.stripePriceIdTeamAnnual) return "team";
  return null;
}