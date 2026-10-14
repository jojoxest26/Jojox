import { Router } from "express";
import { z } from "zod";
import { anthropic, CHAT_MODEL } from "../anthropic.js";
import { requireAuth, type AuthedRequest } from "../auth/middleware.js";
import { supabaseAdmin } from "../db/supabase.js";
import { getPlanForUser, DAILY_CHAT_MESSAGE_LIMIT, startOfTodayUtc } from "../plan.js";

// Limiti generosi per un uso normale ma che tengono comunque un tetto fisso
// ai token (quindi al costo) di ogni singola richiesta, indipendentemente
// da cosa manda il client — i findings arrivano dal browser dell'utente,
// non da un'analisi già verificata lato server.
const findingSchema = z.object({
  checkId: z.string().max(100),
  severity: z.enum(["critical", "high", "medium", "low"]),
  confidence: z.enum(["confirmed", "heuristic"]),
  title: z.string().max(200),
  description: z.string().max(500),
  file: z.string().max(300),
  line: z.number().int().nonnegative(),
  snippet: z.string().max(500),
  fix: z.object({ before: z.string().max(800), after: z.string().max(800) }),
});

const chatRequestSchema = z.object({
  message: z.string().min(1).max(1000),
  findings: z.array(findingSchema).max(60),
  score: z.number().int().min(0).max(100),
  lang: z.enum(["it", "en"]).default("it"),
  history: z
    .array(z.object({ role: z.enum(["user", "assistant"]), content: z.string().max(1500) }))
    .max(10)
    .default([]),
});

function buildSystemPrompt(
  findings: z.infer<typeof findingSchema>[],
  score: number,
  lang: "it" | "en"
): string {
  const findingsText = findings
    .map(
      (f, i) =>
        `${i + 1}. [${f.severity.toUpperCase()}] ${f.title} — ${f.file}:${f.line}\n   ${f.description}`
    )
    .join("\n");

  if (lang === "en") {
    return [
      "You are the JoJoX assistant. JoJoX found the security issues listed below with a deterministic, pattern-based scanner (no AI in the detection itself) — your only job is to explain THESE specific results in plain language to a non-expert developer.",
      `Overall score: ${score}/100.`,
      "Findings from this analysis:",
      findingsText || "(no findings — the code is clean)",
      "",
      "Rules: only talk about these findings and this score. Explain severity, real-world impact, and how to fix it, referencing the file/line when relevant. Never invent findings that aren't listed above. If asked something unrelated to this analysis (general coding help, other topics), politely say that's outside what this chat does. Keep answers short and concrete, a few sentences unless more detail is clearly needed.",
    ].join("\n\n");
  }

  return [
    "Sei l'assistente di JoJoX. JoJoX ha trovato i problemi di sicurezza elencati sotto con un motore deterministico a pattern (nessuna AI nel rilevamento stesso) — il tuo unico compito è spiegare QUESTI risultati specifici in linguaggio semplice a uno sviluppatore non esperto di sicurezza.",
    `Punteggio complessivo: ${score}/100.`,
    "Risultati di questa analisi:",
    findingsText || "(nessun problema trovato — il codice è pulito)",
    "",
    "Regole: parla solo di questi risultati e di questo punteggio. Spiega la gravità, l'impatto reale e come correggere il problema, citando file/riga quando è utile. Non inventare mai problemi che non sono nell'elenco sopra. Se ti viene chiesto qualcosa che non c'entra con questa analisi (aiuto di programmazione generico, altri argomenti), rispondi con gentilezza che non è quello che fa questa chat. Risposte brevi e concrete, poche frasi salvo quando serve davvero più dettaglio.",
  ].join("\n\n");
}

export const chatRouter = Router();

chatRouter.post("/api/chat", requireAuth, async (req: AuthedRequest, res) => {
  if (!anthropic) {
    res.status(503).json({ error: "La chat non è ancora disponibile" });
    return;
  }

  const parsed = chatRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Richiesta non valida", details: parsed.error.flatten() });
    return;
  }

  const { message, findings, score, lang, history } = parsed.data;

  const plan = await getPlanForUser(req.userId!);
  const limit = DAILY_CHAT_MESSAGE_LIMIT[plan];
  const { count } = await supabaseAdmin
    .from("chat_messages")
    .select("id", { count: "exact", head: true })
    .eq("user_id", req.userId!)
    .eq("role", "user")
    .gte("created_at", startOfTodayUtc().toISOString());

  if ((count ?? 0) >= limit) {
    res.status(429).json({
      error:
        lang === "en"
          ? `Daily limit of ${limit} chat messages reached for your plan`
          : `Limite di ${limit} messaggi al giorno raggiunto per il tuo piano`,
    });
    return;
  }

  try {
    const response = await anthropic.messages.create({
      model: CHAT_MODEL,
      max_tokens: 700,
      system: buildSystemPrompt(findings, score, lang),
      messages: [...history.map((h) => ({ role: h.role, content: h.content })), { role: "user" as const, content: message }],
    });

    const reply = response.content
      .filter((block): block is Extract<(typeof response.content)[number], { type: "text" }> => block.type === "text")
      .map((block) => block.text)
      .join("\n")
      .trim();

    await supabaseAdmin.from("chat_messages").insert([
      { user_id: req.userId!, role: "user", content: message },
      { user_id: req.userId!, role: "assistant", content: reply },
    ]);

    res.json({ reply });
  } catch (err) {
    console.error("Errore nella chiamata all'API Anthropic", err);
    res.status(502).json({
      error: lang === "en" ? "Error generating the reply, try again." : "Errore nel generare la risposta, riprova.",
    });
  }
});
