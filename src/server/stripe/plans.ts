import { env } from "../env.js";
import type { Plan } from "../plan.js";

export type PaidPlan = Exclude<Plan, "free">;
export type BillingInterval = "monthly" | "annual";

const MONTHLY_PRICE_ID: Record<PaidPlan, string | null> = {
  pro: env.stripePriceIdPro,
  team: env.stripePriceIdTeam,
  business: env.stripePriceIdBusiness,
};
const ANNUAL_PRICE_ID: Record<PaidPlan, string | null> = {
  pro: env.stripePriceIdProAnnual,
  team: env.stripePriceIdTeamAnnual,
  business: env.stripePriceIdBusinessAnnual,
};

export function priceIdForPlan(plan: PaidPlan, interval: BillingInterval = "monthly"): string | null {
  return interval === "annual" ? ANNUAL_PRICE_ID[plan] : MONTHLY_PRICE_ID[plan];
}

/** Riconosce il piano da un price id, mensile o annuale che sia — al cliente interessa solo cosa sblocca, non come lo paga. */
export function planForPriceId(priceId: string): PaidPlan | null {
  if (priceId === env.stripePriceIdPro || priceId === env.stripePriceIdProAnnual) return "pro";
  if (priceId === env.stripePriceIdTeam || priceId === env.stripePriceIdTeamAnnual) return "team";
  if (priceId === env.stripePriceIdBusiness || priceId === env.stripePriceIdBusinessAnnual) return "business";
  return null;
}

/**
 * "Controllo h24 da solo" (aziende): abbonamento a sé, non un piano — alza
 * solo il tetto di repository monitorati dalla Sentinella 24/7 (vedi
 * sentinel/scan.ts), non sblocca nient'altro (analisi extra, chat, ecc.).
 * Per questo vive a parte da priceIdForPlan/planForPriceId invece di
 * diventare un quarto valore di Plan.
 */
export function priceIdForSentinelAddon(interval: BillingInterval = "monthly"): string | null {
  return interval === "annual" ? env.stripePriceIdSentinelSoloBusinessAnnual : env.stripePriceIdSentinelSoloBusiness;
}

export function isSentinelAddonPriceId(priceId: string): boolean {
  return priceId === env.stripePriceIdSentinelSoloBusiness || priceId === env.stripePriceIdSentinelSoloBusinessAnnual;
}

/**
 * Posto extra oltre i 25 inclusi nel piano Business (vedi team.ts,
 * MAX_BUSINESS_SEATS) — venduto come riga a parte, a quantità, non come
 * un prezzo del piano: per questo vive qui invece che in MONTHLY_PRICE_ID.
 */
export function priceIdForBusinessSeat(interval: BillingInterval = "monthly"): string | null {
  return interval === "annual" ? env.stripePriceIdBusinessSeatAnnual : env.stripePriceIdBusinessSeat;
}

export function isBusinessSeatPriceId(priceId: string): boolean {
  return priceId === env.stripePriceIdBusinessSeat || priceId === env.stripePriceIdBusinessSeatAnnual;
}