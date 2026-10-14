import { Router } from "express";
import { z } from "zod";
import { anthropic, CHAT_MODEL } from "../anthropic.js";
import { optionalAuth, type AuthedRequest } from "../auth/middleware.js";
import { supabaseAdmin } from "../db/supabase.js";
import { getPlanForUser, DAILY_CHAT_MESSAGE_LIMIT, GUEST_DAILY_CHAT_MESSAGE_LIMIT, startOfTodayUtc } from "../plan.js";

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
  // Vuoti quando la chat è usata in modalità generale (es. dal bottone
  // "Chiedi a JoJoX" nell'hero, senza che sia stata fatta un'analisi).
  findings: z.array(findingSchema).max(60).default([]),
  score: z.number().int().min(0).max(100).nullable().default(null),
  lang: z.enum(["it", "en"]).default("it"),
  history: z
    .array(z.object({ role: z.enum(["user", "assistant"]), content: z.string().max(1500) }))
    .max(10)
    .default([]),
});

const PRODUCT_FACTS_IT = `
JoJoX analizza codice (scritto da un'AI o da una persona) e trova problemi di sicurezza con un motore deterministico a pattern — 49 controlli pubblici, nessuna AI nel rilevamento stesso. Copre JavaScript/TypeScript, SQL/Supabase, Python (Flask/Django), Go (Gin, net/http), Java (Spring) e PHP (Laravel); su altri linguaggi alcuni controlli generici possono comunque aiutare.

Piani:
- Gratis (0€): 5 analisi al mese, tutti i 49 controlli con esempi di correzione, punteggio di sicurezza (0-100) + badge scaricabile, storico delle ultime 20 analisi. Si può anche provare senza registrarsi (1 analisi gratuita, senza email).
- Pro (9,99€/mese o 99€/anno): analisi e storico illimitati, integrazione GitHub che controlla ogni push e blocca le modifiche più rischiose, un account/organizzazione GitHub collegato, commenti automatici sulle pull request, correzioni automatiche proposte come pull request, badge che si aggiorna da solo a ogni push.
- Team (24,99€/mese o 249€/anno): come Pro ma con account/organizzazioni GitHub illimitati e fino a 5 persone con repository e storico condivisi.

Altre funzioni: Sentinella 24/7 (scan notturno automatico dei repository collegati a GitHub, avvisa solo sui problemi nuovi), notifiche Slack, Full Site Audit (controllo una tantum di un intero sito/progetto, pagamento singolo separato dagli abbonamenti), badge pubblico da mettere nel README, un comando da terminale via MCP per chi usa Claude Code o editor compatibili.
`.trim();

const PRODUCT_FACTS_EN = `
JoJoX analyzes code (AI-generated or hand-written) and finds security issues with a deterministic, pattern-based engine — 49 public checks, no AI in the detection itself. Covers JavaScript/TypeScript, SQL/Supabase, Python (Flask/Django), Go (Gin, net/http), Java (Spring) and PHP (Laravel); some generic checks can still help on other languages.

Plans:
- Free (€0): 5 analyses/month, all 49 checks with fix examples, security score (0-100) + downloadable badge, history of the last 20 analyses. Can also be tried without signing up (1 free analysis, no email).
- Pro (€9.99/month or €99/year): unlimited analyses and history, GitHub integration that checks every push and blocks the riskiest changes, one connected GitHub account/organization, automatic pull request comments, automatic fixes proposed as pull requests, a badge that updates itself on every push.
- Team (€24.99/month or €249/year): same as Pro but with unlimited GitHub accounts/organizations and up to 5 people sharing repositories and history.

Other features: Sentinel 24/7 (automatic nightly scan of connected GitHub repositories, only alerts on new issues), Slack notifications, Full Site Audit (one-off check of an entire site/project, a separate one-time payment), a public badge for the README, a terminal command via MCP for Claude Code and compatible editors.
`.trim();

function buildSystemPrompt(
  findings: z.infer<typeof findingSchema>[],
  score: number | null,
  lang: "it" | "en"
): string {
  const facts = lang === "en" ? PRODUCT_FACTS_EN : PRODUCT_FACTS_IT;

  if (findings.length === 0) {
    if (lang === "en") {
      return [
        "You are the JoJoX assistant, available on the JoJoX website to anyone — logged in or not.",
        `Facts about JoJoX:\n${facts}`,
        "Rules: answer questions about JoJoX itself (what it does, pricing, plans, how the GitHub integration works) and general security best practices. Don't write or debug code for the user, don't act as a general-purpose coding assistant, don't help with topics unrelated to JoJoX — politely say that's outside what this chat does. Keep answers short and concrete.",
      ].join("\n\n");
    }
    return [
      "Sei l'assistente di JoJoX, disponibile sul sito a chiunque — loggato o no.",
      `Fatti su JoJoX:\n${facts}`,
      "Regole: rispondi a domande su JoJoX stesso (cosa fa, prezzi, piani, come funziona l'integrazione GitHub) e a consigli generali di sicurezza. Non scrivere o correggere codice per l'utente, non comportarti come un assistente di programmazione generico, non aiutare su argomenti non legati a JoJoX — rispondi con gentilezza che non è quello che fa questa chat. Risposte brevi e concrete.",
    ].join("\n\n");
  }

  const findingsText = findings
    .map(
      (f, i) =>
        `${i + 1}. [${f.severity.toUpperCase()}] ${f.title} — ${f.file}:${f.line}\n   ${f.description}`
    )
    .join("\n");

  if (lang === "en") {
    return [
      "You are the JoJoX assistant. JoJoX found the security issues listed below with a deterministic, pattern-based scanner (no AI in the detection itself) — your main job is to explain THESE specific results in plain language to a non-expert developer. You can also answer general questions about JoJoX itself using the facts below.",
      `Overall score: ${score ?? "n/a"}/100.`,
      "Findings from this analysis:",
      findingsText || "(no findings — the code is clean)",
      `Facts about JoJoX:\n${facts}`,
      "Rules: stay focused on these findings, this score, and JoJoX itself. Explain severity, real-world impact, and how to fix a finding, referencing the file/line when relevant. Never invent findings that aren't listed above. If asked something unrelated (general coding help, other topics), politely say that's outside what this chat does. Keep answers short and concrete, a few sentences unless more detail is clearly needed.",
    ].join("\n\n");
  }

  return [
    "Sei l'assistente di JoJoX. JoJoX ha trovato i problemi di sicurezza elencati sotto con un motore deterministico a pattern (nessuna AI nel rilevamento stesso) — il tuo compito principale è spiegare QUESTI risultati specifici in linguaggio semplice a uno sviluppatore non esperto di sicurezza. Puoi anche rispondere a domande generali su JoJoX stesso usando i fatti sotto.",
    `Punteggio complessivo: ${score ?? "n/d"}/100.`,
    "Risultati di questa analisi:",
    findingsText || "(nessun problema trovato — il codice è pulito)",
    `Fatti su JoJoX:\n${facts}`,
    "Regole: resta concentrato su questi risultati, questo punteggio e su JoJoX stesso. Spiega la gravità, l'impatto reale e come correggere un problema, citando file/riga quando è utile. Non inventare mai problemi che non sono nell'elenco sopra. Se ti viene chiesto qualcosa che non c'entra (aiuto di programmazione generico, altri argomenti), rispondi con gentilezza che non è quello che fa questa chat. Risposte brevi e concrete, poche frasi salvo quando serve davvero più dettaglio.",
  ].join("\n\n");
}

export const chatRouter = Router();

chatRouter.post("/api/chat", optionalAuth, async (req: AuthedRequest, res) => {
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

  // Loggato: limite per piano, tracciato per utente. Ospite: limite più
  // basso tracciato per IP — altrimenti un bottone pubblico nell'hero,
  // senza nessuna barriera, sarebbe un invito aperto a far girare a vuoto
  // una chiamata a pagamento.
  let limit: number;
  let countQuery = supabaseAdmin
    .from("chat_messages")
    .select("id", { count: "exact", head: true })
    .eq("role", "user")
    .gte("created_at", startOfTodayUtc().toISOString());

  if (req.userId) {
    const plan = await getPlanForUser(req.userId);
    limit = DAILY_CHAT_MESSAGE_LIMIT[plan];
    countQuery = countQuery.eq("user_id", req.userId);
  } else {
    limit = GUEST_DAILY_CHAT_MESSAGE_LIMIT;
    countQuery = countQuery.eq("ip_address", req.ip).is("user_id", null);
  }

  const { count } = await countQuery;
  if ((count ?? 0) >= limit) {
    res.status(429).json({
      error:
        lang === "en"
          ? `Daily limit of ${limit} chat messages reached${req.userId ? " for your plan" : ""}`
          : `Limite di ${limit} messaggi al giorno raggiunto${req.userId ? " per il tuo piano" : ""}`,
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

    const identity = req.userId ? { user_id: req.userId, ip_address: null } : { user_id: null, ip_address: req.ip };
    await supabaseAdmin.from("chat_messages").insert([
      { ...identity, role: "user", content: message },
      { ...identity, role: "assistant", content: reply },
    ]);

    res.json({ reply });
  } catch (err) {
    console.error("Errore nella chiamata all'API Anthropic", err);
    res.status(502).json({
      error: lang === "en" ? "Error generating the reply, try again." : "Errore nel generare la risposta, riprova.",
    });
  }
});
