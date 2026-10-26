#!/usr/bin/env tsx
// JoJoX — report del margine reale di chat + revisione AI (punto 18
// quater della roadmap). Confronta il costo misurato delle chiamate
// Anthropic (da ai_usage_log, in dollari — è la valuta in cui fattura
// Anthropic) con l'incasso per piano (in euro — è la valuta di Stripe;
// qui trattati come equivalenti per un controllo di ordine di grandezza,
// non per la contabilità vera). Uso: npm run usage:margin [-- --days=30]
import { estimateCostUsd } from "../anthropic.js";
import { supabaseAdmin } from "../db/supabase.js";
import { DAILY_AI_INSIGHT_LIMIT, DAILY_CHAT_MESSAGE_LIMIT, type Plan } from "../plan.js";

// Prezzo mensile per piano mostrato sulla pagina Pricing — va aggiornato a
// mano se cambia lì, non c'è un'unica fonte condivisa (Stripe tiene solo
// l'ID prezzo, non l'importo, vedi env.ts).
const MONTHLY_PRICE_EUR: Record<Exclude<Plan, "free">, number> = { pro: 19, team: 49, business: 1490 };

function parseDaysArg(): number {
  const arg = process.argv.find((a) => a.startsWith("--days="));
  const days = arg ? Number(arg.slice("--days=".length)) : 30;
  return Number.isFinite(days) && days > 0 ? days : 30;
}

async function main() {
  const days = parseDaysArg();
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

  const { data: rows, error } = await supabaseAdmin
    .from("ai_usage_log")
    .select("user_id, route, model, input_tokens, output_tokens")
    .gte("created_at", since.toISOString());

  if (error) {
    console.error("Errore nel leggere ai_usage_log:", error);
    process.exitCode = 1;
    return;
  }

  console.log(`\nMargine AI — ultimi ${days} giorni (dal ${since.toISOString().slice(0, 10)})\n`);

  if (!rows || rows.length === 0) {
    console.log(
      "Nessuna chiamata registrata in questo periodo — niente da misurare ancora.\n" +
        "Questo report diventa utile dal primo utente Pro/Team reale che usa chat o revisione AI.\n"
    );
  } else {
    const userIds = [...new Set(rows.map((r) => r.user_id))];
    const { data: profiles, error: profilesError } = await supabaseAdmin
      .from("profiles")
      .select("id, plan")
      .in("id", userIds);
    if (profilesError) {
      console.error("Errore nel leggere i piani utente:", profilesError);
      process.exitCode = 1;
      return;
    }
    const planByUser = new Map((profiles ?? []).map((p) => [p.id, (p.plan as Plan) ?? "free"]));

    const byPlan = new Map<Plan, { costUsd: number; users: Set<string>; byRoute: Map<string, number> }>();
    for (const row of rows) {
      const plan = planByUser.get(row.user_id) ?? "free";
      const cost = estimateCostUsd(row.model, row.input_tokens, row.output_tokens);
      const bucket = byPlan.get(plan) ?? { costUsd: 0, users: new Set(), byRoute: new Map() };
      bucket.costUsd += cost;
      bucket.users.add(row.user_id);
      bucket.byRoute.set(row.route, (bucket.byRoute.get(row.route) ?? 0) + cost);
      byPlan.set(plan, bucket);
    }

    for (const [plan, bucket] of byPlan) {
      const avgCostPerUser = bucket.costUsd / bucket.users.size;
      console.log(`Piano ${plan} — ${bucket.users.size} utenti attivi, costo totale $${bucket.costUsd.toFixed(2)}`);
      console.log(`  costo medio per utente: $${avgCostPerUser.toFixed(2)}`);
      for (const [route, cost] of bucket.byRoute) {
        console.log(`    ${route}: $${cost.toFixed(2)}`);
      }
      if (plan === "pro" || plan === "team" || plan === "business") {
        const priceForPeriod = (MONTHLY_PRICE_EUR[plan] * days) / 30;
        const margin = priceForPeriod - avgCostPerUser;
        console.log(
          `  incasso stimato nel periodo: €${priceForPeriod.toFixed(2)} → margine medio ≈ €${margin.toFixed(2)} per utente` +
            (margin < 0 ? "  ⚠️  COSTO AI SOPRA L'INCASSO" : "")
        );
      }
      console.log("");
    }
  }

  console.log("Limiti giornalieri attuali (plan.ts), per riferimento:");
  for (const plan of ["pro", "team", "business"] as const) {
    console.log(
      `  ${plan}: ${DAILY_CHAT_MESSAGE_LIMIT[plan]} messaggi chat/giorno, ${DAILY_AI_INSIGHT_LIMIT[plan]} revisioni AI/giorno`
    );
  }
  console.log("");
}

main();
