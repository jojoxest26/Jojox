import { env } from "../env.js";
import type { Plan } from "../plan.js";

export type PaidPlan = Exclude<Plan, "free">;

export function priceIdForPlan(plan: PaidPlan): string | null {
  return plan === "pro" ? env.stripePriceIdPro : env.stripePriceIdTeam;
}

export function planForPriceId(priceId: string): PaidPlan | null {
  if (priceId === env.stripePriceIdPro) return "pro";
  if (priceId === env.stripePriceIdTeam) return "team";
  return null;
}