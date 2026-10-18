import { Router } from "express";
import { z } from "zod";
import { anthropic, CHAT_MODEL, CODE_MODEL } from "../anthropic.js";
import { requireAuth, type AuthedRequest } from "../auth/middleware.js";
import { supabaseAdmin } from "../db/supabase.js";
import { getPlanForUser, DAILY_CHAT_MESSAGE_LIMIT, startOfTodayUtc } from "../plan.js";
import { reportError } from "../sentry.js";

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

// Stessi 23 codici lingua dell'interfaccia (web/src/i18n/translations.ts,
// tipo Lang) — duplicati qui invece che importati perché backend e
// frontend sono due progetti TypeScript separati con root diverse.
export const SUPPORTED_CHAT_LANGS = [
  "it", "en", "es", "fr", "pt", "zh", "hi", "ru", "ar", "bn", "ur", "id",
  "de", "fi", "nl", "pl", "sv", "da", "nb", "tr", "uk", "ja", "ko",
] as const;
export type ChatLang = (typeof SUPPORTED_CHAT_LANGS)[number];

// Nomi in inglese usati solo per l'istruzione al modello ("Reply in
// Spanish"), non mostrati mai all'utente — l'inglese è la lingua in cui il
// modello ragiona meglio le proprie istruzioni, indipendentemente dalla
// lingua in cui poi risponde.
export const LANGUAGE_NAMES: Record<ChatLang, string> = {
  it: "Italian", en: "English", es: "Spanish", fr: "French", pt: "Portuguese",
  zh: "Chinese", hi: "Hindi", ru: "Russian", ar: "Arabic", bn: "Bengali",
  ur: "Urdu", id: "Indonesian", de: "German", fi: "Finnish", nl: "Dutch",
  pl: "Polish", sv: "Swedish", da: "Danish", nb: "Norwegian", tr: "Turkish",
  uk: "Ukrainian", ja: "Japanese", ko: "Korean",
};

const chatRequestSchema = z.object({
  // Più alto di prima: in modalità generale può includere uno snippet di
  // codice da correggere, non solo una domanda breve.
  message: z.string().min(1).max(6000),
  // Vuoti quando la chat è usata in modalità generale (es. dal bottone
  // "Chiedi a JoJoX" nell'hero, senza che sia stata fatta un'analisi).
  findings: z.array(findingSchema).max(60).default([]),
  score: z.number().int().min(0).max(100).nullable().default(null),
  lang: z.enum(SUPPORTED_CHAT_LANGS).default("it"),
  // Più alto del limite del messaggio nuovo: deve poter contenere anche una
  // risposta precedente con un file di codice intero, rimandata indietro
  // come contesto.
  history: z
    .array(z.object({ role: z.enum(["user", "assistant"]), content: z.string().max(20000) }))
    .max(40)
    .default([]),
});

const PRODUCT_FACTS_IT = `
JoJoX analizza codice (scritto da un'AI o da una persona) e trova problemi di sicurezza con un motore deterministico a pattern — 55 controlli pubblici, nessuna AI nel rilevamento stesso. Copre JavaScript/TypeScript, SQL/Supabase, Python (Flask/Django), Go (Gin, net/http), Java (Spring) e PHP (Laravel); su altri linguaggi alcuni controlli generici possono comunque aiutare.

Piani:
- Gratis (0€): 5 analisi al mese, tutti i 55 controlli con esempi di correzione, punteggio di sicurezza (0-100) + badge scaricabile, storico delle ultime 20 analisi. Si può anche provare senza registrarsi (1 analisi gratuita, senza email).
- Pro (9,99€/mese o 99€/anno): 100 analisi al mese incluse (storico completo), integrazione GitHub che controlla ogni push e blocca le modifiche più rischiose, un account/organizzazione GitHub collegato, commenti automatici sulle pull request, correzioni automatiche proposte come pull request, badge che si aggiorna da solo a ogni push, e questa chat stessa ("Chiedi a JoJoX"). Oltre le 100 si possono comprare pacchetti extra di 50 analisi.
- Team (24,99€/mese o 249€/anno): come Pro ma con 500 analisi al mese condivise tra il team, account/organizzazioni GitHub illimitati e fino a 5 persone con repository e storico condivisi.

Questa chat ("Chiedi a JoJoX") è disponibile solo per chi ha un piano Pro o Team, non per il piano gratis — se chi scrive ti chiede se la può usare gratis, questo è vero per definizione (sta già scrivendo da un account Pro o Team, altrimenti non avrebbe accesso).

Altre funzioni: Sentinella 24/7 (scan notturno automatico dei repository collegati a GitHub, avvisa solo sui problemi nuovi), notifiche Slack, Full Site Audit (controllo una tantum di un intero sito/progetto, pagamento singolo separato dagli abbonamenti), badge pubblico da mettere nel README, un comando da terminale via MCP per chi usa Claude Code o editor compatibili.
`.trim();

const PRODUCT_FACTS_EN = `
JoJoX analyzes code (AI-generated or hand-written) and finds security issues with a deterministic, pattern-based engine — 55 public checks, no AI in the detection itself. Covers JavaScript/TypeScript, SQL/Supabase, Python (Flask/Django), Go (Gin, net/http), Java (Spring) and PHP (Laravel); some generic checks can still help on other languages.

Plans:
- Free (€0): 5 analyses/month, all 55 checks with fix examples, security score (0-100) + downloadable badge, history of the last 20 analyses. Can also be tried without signing up (1 free analysis, no email).
- Pro (€9.99/month or €99/year): 100 analyses/month included (full history), GitHub integration that checks every push and blocks the riskiest changes, one connected GitHub account/organization, automatic pull request comments, automatic fixes proposed as pull requests, a badge that updates itself on every push, and this chat itself ("Ask JoJoX"). Extra packs of 50 analyses can be bought beyond the 100.
- Team (€24.99/month or €249/year): same as Pro but with 500 analyses/month shared across the team, unlimited GitHub accounts/organizations and up to 5 people sharing repositories and history.

This chat ("Ask JoJoX") is available only on the Pro and Team plans, not the free one — if asked whether it's free to use, that's true by definition here (whoever is writing is already on a Pro or Team account, or they wouldn't have access).

Other features: Sentinel 24/7 (automatic nightly scan of connected GitHub repositories, only alerts on new issues), Slack notifications, Full Site Audit (one-off check of an entire site/project, a separate one-time payment), a public badge for the README, a terminal command via MCP for Claude Code and compatible editors.
`.trim();

// Le istruzioni di questa funzione esistono solo in italiano e inglese:
// per le altre lingue dell'interfaccia usiamo i fatti e le regole in
// inglese (il modello le capisce comunque) e aggiungiamo un'istruzione
// esplicita ("Reply in Spanish") in coda — più robusto che tradurre questo
// intero prompt in altre 21 lingue, con lo stesso rischio di deriva che
// abbiamo già corretto una volta nelle traduzioni dell'interfaccia.
export function buildSystemPrompt(
  findings: z.infer<typeof findingSchema>[],
  score: number | null,
  lang: ChatLang
): string {
  const base = buildBaseSystemPrompt(findings, score, lang === "it" ? "it" : "en");
  if (lang === "it" || lang === "en") return base;
  return `${base}\n\nReply in ${LANGUAGE_NAMES[lang]} — the language this person's JoJoX interface is set to, even though the instructions above are in English. If they write to you in a different language than ${LANGUAGE_NAMES[lang]}, match the language they actually used instead.`;
}

function buildBaseSystemPrompt(
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

/**
 * Salva lo scambio (domanda + risposta) nella cronologia, dopo che
 * l'utente ha già ricevuto la risposta. Non lancia mai un'eccezione — un
 * fallimento qui non deve rompere nient'altro — ma ritenta una volta prima
 * di arrendersi, perché un insert fallito sparisce dalla cronologia senza
 * che nessuno se ne accorga finché non ricarica la pagina.
 */
async function saveChatExchange(userId: string, userMessage: string, assistantReply: string): Promise<void> {
  const rows = [
    { user_id: userId, role: "user" as const, content: userMessage },
    { user_id: userId, role: "assistant" as const, content: assistantReply },
  ];
  const { error } = await supabaseAdmin.from("chat_messages").insert(rows);
  if (!error) return;

  console.error("Errore nel salvataggio del messaggio di chat, riprovo una volta", error);
  const { error: retryError } = await supabaseAdmin.from("chat_messages").insert(rows);
  if (retryError) {
    console.error(
      "Errore nel salvataggio del messaggio di chat anche al secondo tentativo — sparirà dalla cronologia",
      retryError
    );
  }
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
    // Ordina per "seq" (un numero che cresce a ogni riga inserita), non
    // per "created_at": un singolo scambio si salva con UN insert a due
    // righe (domanda + risposta), e Postgres dà a entrambe lo STESSO
    // timestamp — created_at da solo non garantisce quale delle due viene
    // prima, e la cronologia poteva tornare con l'ordine scambiato.
    supabaseAdmin
      .from("chat_messages")
      .select("role, content, seq")
      .eq("user_id", req.userId!)
      .order("seq", { ascending: false })
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

  if (countError) {
    // Un conteggio fallito con "(count ?? 0) >= limit" apriva il limite
    // invece di chiuderlo (0 >= limit è sempre falso): in quella finestra
    // ogni chiamata all'API di Anthropic passava senza nessun tetto di
    // costo. Meglio fallire chiusi — un messaggio in più negato per errore
    // costa meno di un limite di costo che si disattiva da solo in silenzio.
    console.error("Errore nel conteggio dei messaggi di chat", countError);
    reportError(countError);
    res.status(500).json({ error: "Errore nel controllo del limite messaggi, riprova" });
    return;
  }
  if ((count ?? 0) >= limit) {
    res.status(429).json({
      error:
        lang === "it"
          ? `Limite di ${limit} messaggi al giorno raggiunto per il tuo piano`
          : `Daily limit of ${limit} chat messages reached for your plan`,
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
        lang === "it"
          ? "\n\n*(Risposta troncata per il limite di lunghezza — chiedi di continuare, o una versione più corta.)*"
          : "\n\n*(Answer cut off — it hit the length limit. Ask to continue, or for a shorter version.)*";
    }

    res.json({ reply });

    // Il salvataggio nella cronologia parte DOPO aver risposto: l'utente
    // non deve aspettare un'altra richiesta a Supabase solo per vedere la
    // propria risposta — un giro in meno nel percorso che l'utente aspetta
    // davvero, oltre a quelli già tolti ieri sera da piano e cronologia.
    // Un fallimento qui farebbe sparire lo scambio dalla cronologia senza
    // nessun avviso (è già successo, su una domanda di ieri): ritentiamo
    // una volta prima di arrenderci, e logghiamo sempre l'esito.
    void saveChatExchange(req.userId!, message, reply);
  } catch (err) {
    console.error("Errore nella chiamata all'API Anthropic", err);
    res.status(502).json({
      error: lang === "it" ? "Errore nel generare la risposta, riprova." : "Error generating the reply, try again.",
    });
  }
});
