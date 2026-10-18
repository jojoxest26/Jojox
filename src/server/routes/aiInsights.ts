import { Router } from "express";
import { z } from "zod";
import { anthropic } from "../anthropic.js";
import { findAiInsights } from "../aiInsights.js";
import { requireAuth, type AuthedRequest } from "../auth/middleware.js";
import { supabaseAdmin } from "../db/supabase.js";
import { getPlanForUser, DAILY_AI_INSIGHT_LIMIT, startOfTodayUtc } from "../plan.js";
import { reportError } from "../sentry.js";

const MAX_FILES = 300;
const MAX_FILE_BYTES = 200_000;

const requestSchema = z.object({
  files: z
    .array(
      z.object({
        path: z.string().min(1).max(500),
        content: z.string().max(MAX_FILE_BYTES),
      })
    )
    .min(1)
    .max(MAX_FILES),
});

export const aiInsightsRouter = Router();

// Punto 14 della roadmap: un livello AI in più, separato dai 55 controlli
// deterministici, per i bug di logica che un pattern non può trovare (race
// condition, errori nei controlli di autorizzazione). Mai in automatico:
// un pulsante a parte, mai contribuisce al punteggio, mai applica una
// correzione da solo — solo sospetti da verificare di persona. Riservato a
// Pro/Team per lo stesso motivo della chat: ogni esecuzione è una chiamata
// a pagamento al modello più capace, su file interi.
aiInsightsRouter.post("/api/ai-insights", requireAuth, async (req: AuthedRequest, res) => {
  if (!anthropic) {
    res.status(503).json({ error: "La revisione AI non è ancora disponibile" });
    return;
  }

  const parsed = requestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Richiesta non valida", details: parsed.error.flatten() });
    return;
  }

  const plan = await getPlanForUser(req.userId!);
  if (plan === "free") {
    res.status(403).json({ error: "La revisione AI aggiuntiva è disponibile per i piani Pro e Team", requiresPlan: true });
    return;
  }

  const limit = DAILY_AI_INSIGHT_LIMIT[plan];
  const { count, error: countError } = await supabaseAdmin
    .from("ai_insight_runs")
    .select("id", { count: "exact", head: true })
    .eq("user_id", req.userId!)
    .gte("created_at", startOfTodayUtc().toISOString());

  if (countError) {
    // Stesso principio del limite giornaliero della chat: un conteggio
    // fallito deve bloccare, mai aprire il limite in silenzio.
    console.error("Errore nel conteggio delle revisioni AI", countError);
    reportError(countError);
    res.status(500).json({ error: "Errore nel controllo del limite, riprova" });
    return;
  }
  if ((count ?? 0) >= limit) {
    res.status(429).json({ error: `Limite di ${limit} revisioni AI al giorno raggiunto per il tuo piano` });
    return;
  }

  try {
    const insights = await findAiInsights(parsed.data.files);
    // Contata solo un'esecuzione riuscita: un tentativo fallito (errore di
    // rete verso Anthropic, timeout) non deve consumare un posto nel
    // limite giornaliero dell'utente.
    await supabaseAdmin.from("ai_insight_runs").insert({ user_id: req.userId! });
    res.json({ insights });
  } catch (err) {
    console.error("Errore nella revisione AI aggiuntiva", err);
    reportError(err);
    res.status(500).json({ error: "Errore nella revisione AI, riprova" });
  }
});
