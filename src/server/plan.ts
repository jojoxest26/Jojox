import { supabaseAdmin } from "./db/supabase.js";

export type Plan = "free" | "pro" | "team";

export const MONTHLY_ANALYSIS_LIMIT = 5;

export async function getPlanForUser(userId: string): Promise<Plan> {
  const { data } = await supabaseAdmin.from("profiles").select("plan").eq("id", userId).single();
  return (data?.plan as Plan | undefined) ?? "free";
}

export function startOfCurrentMonthUtc(): Date {
  const now = new Date();
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
}
