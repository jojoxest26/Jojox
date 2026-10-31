import { Router } from "express";
import { z } from "zod";
import { anthropic, CODE_MODEL } from "../anthropic.js";
import { findAiInsights } from "../aiInsights.js";
import { requireAuth, type AuthedRequest } from "../auth/middleware.js";
import { supabaseAdmin } from "../db/supabase.js";
import { getPlanForUser, DAILY_AI_INSIGHT_LIMIT, startOfTodayUtc } from "../plan.js";
import { reportError } from "../sentry.js";
import { logAiUsage } from "../aiUsageLog.js";

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
  // Facoltativo: l'id del credito Full Site Audit appena consumato. Chi ha
  // pagato un audit (anche sul piano Free, è un acquisto una tantum, non un
  // abbonamento) sblocca una Revisione AI per quell'audit senza bisogno di
  // Pro/Team — vedi il bypass più sotto.
  auditCreditId: z.string().uuid().optional(),
});

export const aiInsightsRouter = Router();

// Punto 14 della roadmap: un livello AI in più, separato dai 61 controlli
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

  const { auditCreditId } = parsed.data;
  let usingAuditCredit = false;

  if (auditCreditId) {
    // Reclama il credito con la stessa update condizionata usata per
    // consumarlo nel Full Site Audit: solo chi ha davvero pagato quell'audit
    // (status "used", cioè già analizzato) e non ha già usato la Revisione AI
    // per quello stesso credito può sbloccarla qui — niente a che fare col
    // limite giornaliero di Pro/Team, è una sola volta per acquisto.
    const { data: claimed, error: claimErr } = await supabaseAdmin
      .from("audit_credits")
      .update({ ai_insight_used: true })
      .eq("id", auditCreditId)
      .eq("user_id", req.userId!)
      .eq("status", "used")
      .eq("ai_insight_used", false)
      .select("id");

    if (claimErr) {
      console.error("Errore nel controllo del credito per la revisione AI", claimErr);
      reportError(claimErr);
      res.status(500).json({ error: "Errore nel controllo del limite, riprova" });
      return;
    }

    usingAuditCredit = (claimed?.length ?? 0) > 0;
  }

  if (!usingAuditCredit) {
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
  }

  try {
    const { insights, usage } = await findAiInsights(parsed.data.files);
    // Contata solo un'esecuzione riuscita: un tentativo fallito (errore di
    // rete verso Anthropic, timeout) non deve consumare un posto nel
    // limite giornaliero dell'utente. Per chi usa un credito Full Site
    // Audit invece del piano, il credito è già stato segnato sopra — qui non
    // serve altro, l'uso è comunque uno solo per credito.
    if (!usingAuditCredit) {
      await supabaseAdmin.from("ai_insight_runs").insert({ user_id: req.userId! });
    }
    res.json({ insights });

    if (usage) {
      void logAiUsage({
        userId: req.userId!,
        route: "ai_insight",
        model: CODE_MODEL,
        inputTokens: usage.inputTokens,
        outputTokens: usage.outputTokens,
      });
    }
  } catch (err) {
    console.error("Errore nella revisione AI aggiuntiva", err);
    reportError(err);
    res.status(500).json({ error: "Errore nella revisione AI, riprova" });
  }
});
