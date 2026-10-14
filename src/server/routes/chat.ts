import { Router } from "express";
import { z } from "zod";
import { anthropic, CHAT_MODEL, CODE_MODEL } from "../anthropic.js";
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
  // Più alto di prima: in modalità generale può includere uno snippet di
  // codice da correggere, non solo una domanda breve.
  message: z.string().min(1).max(6000),
  // Vuoti quando la chat è usata in modalità generale (es. dal bottone
  // "Chiedi a JoJoX" nell'hero, senza che sia stata fatta un'analisi).
  findings: z.array(findingSchema).max(60).default([]),
  score: z.number().int().min(0).max(100).nullable().default(null),
  lang: z.enum(["it", "en"]).default("it"),
  // Più alto del limite del messaggio nuovo: deve poter contenere anche una
  // risposta precedente con un file di codice intero, rimandata indietro
  // come contesto.
  history: z
    .array(z.object({ role: z.enum(["user", "assistant"]), content: z.string().max(20000) }))
    .max(40)
    .default([]),
});

const PRODUCT_FACTS_IT = `
JoJoX analizza codice (scritto da un'AI o da una persona) e trova problemi di sicurezza con un motore deterministico a pattern — 49 controlli pubblici, nessuna AI nel rilevamento stesso. Copre JavaScript/TypeScript, SQL/Supabase, Python (Flask/Django), Go (Gin, net/http), Java (Spring) e PHP (Laravel); su altri linguaggi alcuni controlli generici possono comunque aiutare.

Piani:
- Gratis (0€): 5 analisi al mese, tutti i 49 controlli con esempi di correzione, punteggio di sicurezza (0-100) + badge scaricabile, storico delle ultime 20 analisi. Si può anche provare senza registrarsi (1 analisi gratuita, senza email).
- Pro (9,99€/mese o 99€/anno): analisi e storico illimitati, integrazione GitHub che controlla ogni push e blocca le modifiche più rischiose, un account/organizzazione GitHub collegato, commenti automatici sulle pull request, correzioni automatiche proposte come pull request, badge che si aggiorna da solo a ogni push, e questa chat stessa ("Chiedi a JoJoX").
- Team (24,99€/mese o 249€/anno): come Pro ma con account/organizzazioni GitHub illimitati e fino a 5 persone con repository e storico condivisi.

Questa chat ("Chiedi a JoJoX") è disponibile solo per chi ha un piano Pro o Team, non per il piano gratis — se chi scrive ti chiede se la può usare gratis, questo è vero per definizione (sta già scrivendo da un account Pro o Team, altrimenti non avrebbe accesso).

Altre funzioni: Sentinella 24/7 (scan notturno automatico dei repository collegati a GitHub, avvisa solo sui problemi nuovi), notifiche Slack, Full Site Audit (controllo una tantum di un intero sito/progetto, pagamento singolo separato dagli abbonamenti), badge pubblico da mettere nel README, un comando da terminale via MCP per chi usa Claude Code o editor compatibili.
`.trim();

const PRODUCT_FACTS_EN = `
JoJoX analyzes code (AI-generated or hand-written) and finds security issues with a deterministic, pattern-based engine — 49 public checks, no AI in the detection itself. Covers JavaScript/TypeScript, SQL/Supabase, Python (Flask/Django), Go (Gin, net/http), Java (Spring) and PHP (Laravel); some generic checks can still help on other languages.

Plans:
- Free (€0): 5 analyses/month, all 49 checks with fix examples, security score (0-100) + downloadable badge, history of the last 20 analyses. Can also be tried without signing up (1 free analysis, no email).
- Pro (€9.99/month or €99/year): unlimited analyses and history, GitHub integration that checks every push and blocks the riskiest changes, one connected GitHub account/organization, automatic pull request comments, automatic fixes proposed as pull requests, a badge that updates itself on every push, and this chat itself ("Ask JoJoX").
- Team (€24.99/month or €249/year): same as Pro but with unlimited GitHub accounts/organizations and up to 5 people sharing repositories and history.

This chat ("Ask JoJoX") is available only on the Pro and Team plans, not the free one — if asked whether it's free to use, that's true by definition here (whoever is writing is already on a Pro or Team account, or they wouldn't have access).

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
        "You are the JoJoX assistant, available to logged-in users of the JoJoX website.",
        `Facts about JoJoX:\n${facts}`,
        "Rules: answer questions about JoJoX itself (what it does, pricing, plans, how the GitHub integration works) and general security best practices.",
        "Don't just restate the facts above verbatim — the person can already read them on the page. Synthesize: answer the actual question, compare options when relevant, give a concrete recommendation suited to what they described about their own situation, and only mention the numbers/features that actually matter for their question instead of listing everything. Sound like a knowledgeable person giving advice, not a page summary. Keep it conversational, a few sentences, longer only if the question genuinely needs it.",
        "You can also write and debug real code when asked — a function, a script, a full file, fixing an error in a pasted snippet. Write correct, clean code, use fenced code blocks with the right language tag, and ask a clarifying question instead of guessing when the request is genuinely ambiguous. You only see what's typed into this chat — no access to the person's real files or a way to run code. If asked about something with no connection to JoJoX or to writing/explaining code (e.g. unrelated trivia), politely say that's outside what this chat does.",
      ].join("\n\n");
    }
    return [
      "Sei l'assistente di JoJoX, disponibile per chi ha fatto login sul sito.",
      `Fatti su JoJoX:\n${facts}`,
      "Regole: rispondi a domande su JoJoX stesso (cosa fa, prezzi, piani, come funziona l'integrazione GitHub) e a consigli generali di sicurezza.",
      "Non limitarti a ripetere i fatti sopra parola per parola — la persona può già leggerli sulla pagina. Sintetizza: rispondi alla domanda vera, confronta le opzioni quando è utile, dai un consiglio concreto calibrato su quello che la persona racconta della propria situazione, e cita solo i numeri/le funzioni che contano davvero per quella domanda invece di elencare tutto. Suona come una persona esperta che dà un consiglio, non come il riassunto di una pagina. Tono colloquiale, poche frasi, più lungo solo se la domanda lo richiede davvero.",
      "Puoi anche scrivere e correggere codice vero quando te lo chiedono — una funzione, uno script, un file intero, il debug di un errore in uno snippet incollato. Scrivi codice corretto e pulito, usa blocchi di codice con il linguaggio giusto indicato, e fai la domanda giusta invece di indovinare quando la richiesta è davvero ambigua. Vedi solo quello che viene scritto in questa chat — nessun accesso ai file reali della persona, nessun modo di eseguire codice. Se ti viene chiesto qualcosa che non ha a che fare né con JoJoX né con scrivere/spiegare codice (es. curiosità generiche), rispondi con gentilezza che non è quello che fa questa chat.",
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

// Chat disponibile solo per chi paga (Pro/Team), non per il piano gratis:
// ogni messaggio è una chiamata a pagamento all'API Anthropic, e tenerla
// aperta a tutti renderebbe il costo imprevedibile man mano che crescono
// gli account gratuiti — farla un vantaggio dei piani a pagamento tiene i
// costi proporzionati alle entrate, senza dover alzare i prezzi.

chatRouter.get("/api/chat/history", requireAuth, async (req: AuthedRequest, res) => {
  // Il piano e la cronologia sono due letture indipendenti (nessuna delle
  // due dipende dal risultato dell'altra): farle in parallelo invece che
  // una dopo l'altra dimezza il tempo di questa rotta, che prima era la
  // più lenta della chat proprio perché le metteva in fila.
  const [plan, { data, error }] = await Promise.all([
    getPlanForUser(req.userId!),
    supabaseAdmin
      .from("chat_messages")
      .select("role, content, created_at")
      .eq("user_id", req.userId!)
      .order("created_at", { ascending: false })
      .limit(40),
  ]);

  if (plan === "free") {
    res.status(403).json({ error: "La chat è disponibile per i piani Pro e Team", requiresPlan: true });
    return;
  }
  if (error) {
    res.status(500).json({ error: "Errore nel recupero della cronologia" });
    return;
  }

  res.json({ messages: (data ?? []).reverse().map(({ role, content }) => ({ role, content })) });
});

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
  if (plan === "free") {
    res.status(403).json({ error: "La chat è disponibile per i piani Pro e Team", requiresPlan: true });
    return;
  }
  const limit = DAILY_CHAT_MESSAGE_LIMIT[plan];
  const { count, error: countError } = await supabaseAdmin
    .from("chat_messages")
    .select("id", { count: "exact", head: true })
    .eq("user_id", req.userId!)
    .eq("role", "user")
    .gte("created_at", startOfTodayUtc().toISOString());

  if (countError) console.error("Errore nel conteggio dei messaggi di chat", countError);
  if ((count ?? 0) >= limit) {
    res.status(429).json({
      error:
        lang === "en"
          ? `Daily limit of ${limit} chat messages reached for your plan`
          : `Limite di ${limit} messaggi al giorno raggiunto per il tuo piano`,
    });
    return;
  }

  // In modalità generale (nessuna analisi aperta) la chat scrive anche
  // codice vero: serve un modello più capace e risposte che possono essere
  // molto più lunghe di una spiegazione di un singolo finding. 16000 è il
  // tetto consigliato per una chiamata senza streaming (come questa) —
  // andare oltre rischierebbe un timeout prima che la risposta finisca.
  const isGeneralMode = findings.length === 0;

  try {
    const response = await anthropic.messages.create({
      model: isGeneralMode ? CODE_MODEL : CHAT_MODEL,
      max_tokens: isGeneralMode ? 16000 : 700,
      system: buildSystemPrompt(findings, score, lang),
      messages: [...history.map((h) => ({ role: h.role, content: h.content })), { role: "user" as const, content: message }],
    });

    let reply = response.content
      .filter((block): block is Extract<(typeof response.content)[number], { type: "text" }> => block.type === "text")
      .map((block) => block.text)
      .join("\n")
      .trim();

    // Senza questo controllo, una risposta che finisce il budget di token si
    // tronca a metà frase senza nessun avviso — sembra che la chat non abbia
    // risposto affatto (è successo davvero, su una domanda difficile). Alzare
    // ancora il tetto costerebbe di più ad ogni messaggio; meglio dirlo.
    if (response.stop_reason === "max_tokens") {
      reply +=
        lang === "en"
          ? "\n\n*(Answer cut off — it hit the length limit. Ask to continue, or for a shorter version.)*"
          : "\n\n*(Risposta troncata per il limite di lunghezza — chiedi di continuare, o una versione più corta.)*";
    }

    const { error: insertError } = await supabaseAdmin.from("chat_messages").insert([
      { user_id: req.userId!, role: "user", content: message },
      { user_id: req.userId!, role: "assistant", content: reply },
    ]);
    // Non blocchiamo la risposta all'utente se il log fallisce — ma lo
    // segnaliamo nei log del server, altrimenti un problema del genere
    // resta invisibile.
    if (insertError) console.error("Errore nel salvataggio del messaggio di chat", insertError);

    res.json({ reply });
  } catch (err) {
    console.error("Errore nella chiamata all'API Anthropic", err);
    res.status(502).json({
      error: lang === "en" ? "Error generating the reply, try again." : "Errore nel generare la risposta, riprova.",
    });
  }
});
