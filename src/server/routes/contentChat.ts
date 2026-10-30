import { Router } from "express";
import { z } from "zod";
import { anthropic, assertAnthropicKeySafe, CODE_MODEL } from "../anthropic.js";
import { requireAuth, type AuthedRequest } from "../auth/middleware.js";
import { supabaseAdmin } from "../db/supabase.js";
import { env } from "../env.js";
import { startOfTodayUtc } from "../plan.js";
import { reportError } from "../sentry.js";
import { logAiUsage } from "../aiUsageLog.js";
import { PRODUCT_FACTS_IT } from "./chat.js";
import { ALL_CHECKS } from "../../checks/index.js";

const CHECK_COUNT = ALL_CHECKS.length;
import { REEL_MAX_SCENE_SECONDS, REEL_MAX_SCENES, REEL_MIN_SCENE_SECONDS, type Reel } from "../../reel.js";

/**
 * Chat interna dei contenuti (/content): scrive reel verticali per i social
 * di JoJoX, nello stile "testo cinetico" (una o due parole per schermata),
 * partendo da quello che dice il sito. Non è una funzione per i clienti:
 * la usa solo chi è in CONTENT_ADMIN_EMAILS.
 */

/** Tetto di costo anche per l'admin: un ciclo infinito nel browser non deve poter svuotare il credito Anthropic. */
export const DAILY_CONTENT_CHAT_LIMIT = 80;

export function isContentAdmin(email: string | undefined, adminEmails: string[]): boolean {
  if (!email) return false;
  return adminEmails.includes(email.trim().toLowerCase());
}

const duration = z
  .number()
  .transform((n) => Math.min(REEL_MAX_SCENE_SECONDS, Math.max(REEL_MIN_SCENE_SECONDS, n)));
const bg = z.enum(["dark", "light", "amber"]).catch("dark");
const accent = z.enum(["amber", "red", "blue"]).catch("amber");
const shortText = z.string().max(80);

const sceneSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("word"), text: shortText, bg, duration }),
  z.object({
    type: z.literal("headline"),
    line1: shortText,
    line2: shortText,
    chips: z.array(z.string().max(40)).max(6).optional(),
    bg,
    accent,
    duration,
  }),
  z.object({ type: z.literal("strike"), words: z.array(z.string().max(40)).min(2).max(5), bg, duration }),
  z.object({
    type: z.literal("bars"),
    title: shortText,
    bars: z.array(z.object({ label: z.string().max(30), value: z.number().min(0).max(100) })).min(2).max(6),
    bg,
    accent,
    duration,
  }),
  z.object({
    type: z.literal("stat"),
    value: z.number().min(0).max(1_000_000),
    suffix: z.string().max(10).optional(),
    caption: shortText,
    bg,
    accent,
    duration,
  }),
  z.object({ type: z.literal("mascot"), text: shortText.optional(), bg, duration }),
  z.object({
    type: z.literal("score"),
    from: z.number().int().min(0).max(100),
    to: z.number().int().min(0).max(100),
    caption: shortText,
    bg,
    duration,
  }),
  z.object({
    type: z.literal("finding"),
    title: shortText,
    file: z.string().max(80),
    before: z.string().max(120),
    after: z.string().max(120),
    bg,
    duration,
  }),
  z.object({ type: z.literal("cta"), text: shortText, sub: shortText.optional(), bg, accent, duration }),
]);

export const reelSchema = z.object({
  title: z.string().max(120),
  voiceover: z.string().max(4000),
  caption: z.string().max(3000),
  scenes: z.array(sceneSchema).min(1).max(REEL_MAX_SCENES),
});

const contentChatRequestSchema = z
  .object({
    message: z.string().min(1).max(4000),
    history: z
      .array(z.object({ role: z.enum(["user", "assistant"]), content: z.string().max(8000) }))
      .max(30)
      .default([]),
    // Il reel aperto in anteprima: serve per richieste come "accorcia la
    // scena 3" senza che il modello debba ricordarlo dalla cronologia.
    currentReel: reelSchema.nullable().default(null),
  })
  .refine((data) => data.history.reduce((sum, h) => sum + h.content.length, 0) <= 60_000, {
    message: "Cronologia troppo lunga",
    path: ["history"],
  });

/** Quello che il sito racconta di JoJoX, oltre ai fatti di prodotto: messaggi, tono, argomenti. */
const SITE_MESSAGES_IT = `
Messaggi del sito (usali come base dei contenuti, con parole tue):
- Titolo principale: "Il tuo agente AI scrive codice ogni giorno, o lo scrivi tu? JoJoX lo sorveglia." Non un controllo una tantum: monitoraggio continuo, ${CHECK_COUNT} controlli pubblici, un punteggio di sicurezza chiaro e correzioni pronte da copiare. Le verifiche che normalmente richiedono ore, automatizzate e sempre attive.
- Come funziona: 1) Analizza — carica il codice o collega il repository GitHub. 2) Rileva — JoJoX esegue i ${CHECK_COUNT} controlli. 3) Correggi — spiegazione, gravità e una correzione pronta da copiare (prima/dopo).
- Perché non basta chiedere all'AI "è sicuro?": quasi nessuno lo chiede ogni volta, su ogni file, dopo ogni modifica — basta dimenticarsene una volta. Un modello dà un parere che cambia ogni volta e non lascia una prova; JoJoX esegue sempre gli stessi ${CHECK_COUNT} controlli pubblici, verificabili riga per riga. Il motore è pattern matching puro, mai un LLM: nessuna allucinazione, istantaneo, gira su ogni pull request. Frase chiave: "JoJoX non indovina se il tuo codice è vulnerabile. Lo dimostra."
- Copre ogni fase, non solo la pull request: mentre scrivi (estensione VS Code, e un agente AI come Claude Code o Cursor può controllarsi da solo via MCP), prima del commit (hook che blocca i problemi critici), a ogni pull request (blocca o propone la correzione), prima del rilascio (Full Site Audit), e per sempre dopo (Sentinella 24/7 che ricontrolla ogni notte, anche il codice non toccato).
- Privacy: il testo dei file analizzati non viene mai conservato, solo i risultati; le correzioni automatiche restano sempre e solo nel browser.
- Per chi è: developer, startup che sviluppano veloce, team con più repository, e chi sviluppa con agenti AI come Claude Code.
- Si prova gratis: 1 analisi senza email, poi 5 analisi al mese gratis con la sola email.
- Sito: jojox.it
`.trim();

export function buildContentSystemPrompt(currentReel: Reel | null): string {
  return [
    "Sei il copywriter dei social di JoJoX. Scrivi reel verticali (TikTok, Instagram Reels, YouTube Shorts) in stile \"testo cinetico\": schermate velocissime con una o due parole, titoli in corsivo con la parola chiave colorata, parole barrate, piccoli grafici, e una voce fuori campo che li accompagna. Il tono è diretto, giovane, con un gancio forte nei primi 2 secondi (es. \"Mentre gli altri buttano tempo…\"), mai da brochure aziendale.",
    `Fatti su JoJoX:\n${PRODUCT_FACTS_IT}`,
    SITE_MESSAGES_IT,
    [
      "Regole sui contenuti:",
      "- Usa solo i fatti sopra. Mai inventare numeri, statistiche di mercato, clienti, recensioni, testimonianze, risultati ottenuti o premi. Se un'idea ha bisogno di un dato che non hai, riformulala senza quel dato.",
      "- Nelle scene \"bars\" i valori sono solo altezze relative (0-100), non vengono mostrati: usale per confronti qualitativi onesti (es. tempo di una revisione manuale contro un controllo automatico), mai per spacciare dati misurati.",
      `- Nelle scene "stat" usa solo numeri presenti nei fatti (${CHECK_COUNT} controlli, 5 analisi gratis al mese, punteggio 0-100, prezzi...).`,
      "- Niente promesse assolute (\"100% sicuro\", \"zero vulnerabilità\"): JoJoX trova i problemi che i suoi controlli conoscono.",
      "- Scrivi in italiano, salvo che ti chiedano un'altra lingua.",
    ].join("\n"),
    [
      "Formato della risposta: prima 1-3 frasi in chat (l'idea del reel o cosa hai cambiato), poi il reel come JSON in un blocco ```reel ... ```. Se la persona fa solo una domanda o vuole idee senza un reel, rispondi senza blocco.",
      "Schema del JSON:",
      '{ "title": string, "voiceover": string (il testo parlato completo, che dura quanto il video), "caption": string (didascalia del post + 3-6 hashtag), "scenes": Scene[] }',
      "Tipi di Scene (ogni scena ha duration in secondi, da 0.4 a 5; bg \"dark\", \"light\" o \"amber\"; accent \"amber\", \"red\" o \"blue\" dove previsto):",
      '- { "type": "word", "text": "tutte", "bg": "dark", "duration": 0.6 } — una o due parole, la scena più usata, ritmo veloce (0.4-0.9 s).',
      '- { "type": "headline", "line1": "MENTRE GLI ALTRI", "line2": "BUTTANO TEMPO", "chips": ["🐞 Bug", "🔑 Chiavi esposte"], "bg": "dark", "accent": "amber", "duration": 2.2 } — titolo maiuscolo su due righe, line2 colorata; chips facoltative (max 6, emoji + 1-2 parole) che fluttuano intorno.',
      `- { "type": "strike", "words": ["Revisione a mano", "Ore perse", "${CHECK_COUNT} controlli"], "bg": "dark", "duration": 2.5 } — tutte barrate tranne l'ultima, che è la risposta.`,
      '- { "type": "bars", "title": "Tempo", "bars": [{ "label": "A mano", "value": 90 }, { "label": "JoJoX", "value": 8 }], "bg": "light", "accent": "blue", "duration": 2.5 }',
      `- { "type": "stat", "value": ${CHECK_COUNT}, "suffix": "", "caption": "controlli pubblici", "bg": "dark", "accent": "amber", "duration": 2 }`,
      '- { "type": "mascot", "text": "Ti presento la Sentinella", "bg": "dark", "duration": 2.5 } — la mascotte di JoJoX (un robottino guardiano con un occhio ambra e uno scanner) che entra e scansiona; text facoltativo. Usala una volta, quando entra in scena JoJoX.',
      '- { "type": "score", "from": 38, "to": 97, "caption": "punteggio di sicurezza", "bg": "dark", "duration": 2.5 } — il cerchio del punteggio 0-100 come sul sito. È una dimostrazione di come appare, non un risultato reale: non presentarlo mai come il punteggio di un cliente o di un progetto vero.',
      '- { "type": "finding", "title": "Chiave segreta nel codice", "file": "src/pagamenti.ts", "before": "const key = \\"sk_live_…\\"", "after": "const key = process.env.STRIPE_KEY", "bg": "dark", "duration": 3.5 } — un problema come lo mostra JoJoX: riga con etichetta CRITICO, poi la correzione. Usa un problema che i controlli di JoJoX trovano davvero (chiavi o password nel codice, chiave di servizio Supabase nel browser, CORS aperto a tutti, query SQL costruite concatenando testo…); codice cortissimo.',
      '- { "type": "cta", "text": "Provalo gratis", "sub": "jojox.it", "bg": "dark", "accent": "amber", "duration": 2.5 } — sempre l\'ultima scena.',
      "Colori: sono quelli del sito di JoJoX. dark è il fondo principale, amber (il giallo JoJoX) è l'accento principale; light e lo sfondo amber servono per i cambi di ritmo, red e blue solo quando servono davvero (es. rosso per un problema, blu per un dato).",
      "Linee guida: 15-35 secondi in totale, 12-30 scene; alterna dark, light e qualche amber per dare ritmo; le scene \"word\" seguono le parole chiave della voce fuori campo; testi brevissimi (lo schermo è un telefono).",
    ].join("\n"),
    currentReel
      ? `Il reel aperto ora in anteprima (se ti chiedono modifiche, parti da questo e rimanda il reel completo aggiornato):\n${JSON.stringify(currentReel)}`
      : "",
  ]
    .filter(Boolean)
    .join("\n\n");
}

const REEL_BLOCK = /```(?:reel|json)\s*\n([\s\S]*?)```/g;

/** Separa il testo di chat dal blocco ```reel```: il testo va in chat, il reel (se valido) in anteprima. */
export function extractReel(raw: string): { text: string; reel: Reel | null; reelError: boolean } {
  const matches = [...raw.matchAll(REEL_BLOCK)];
  if (matches.length === 0) return { text: raw.trim(), reel: null, reelError: false };

  const last = matches[matches.length - 1];
  const text = raw.replace(REEL_BLOCK, "").trim();
  try {
    const parsed = reelSchema.safeParse(JSON.parse(last[1]));
    if (parsed.success) return { text, reel: parsed.data as Reel, reelError: false };
  } catch {
    // JSON malformato: lo segnaliamo sotto invece di far fallire la richiesta.
  }
  return { text, reel: null, reelError: true };
}

export const contentChatRouter = Router();

contentChatRouter.get("/api/content-chat/access", requireAuth, (req: AuthedRequest, res) => {
  res.json({ allowed: isContentAdmin(req.userEmail, env.contentAdminEmails) });
});

contentChatRouter.post("/api/content-chat", requireAuth, async (req: AuthedRequest, res) => {
  if (!isContentAdmin(req.userEmail, env.contentAdminEmails)) {
    res.status(403).json({ error: "Non hai accesso alla chat dei contenuti" });
    return;
  }
  if (!anthropic) {
    res.status(503).json({ error: "La chat non è ancora disponibile (manca ANTHROPIC_API_KEY)" });
    return;
  }

  const parsed = contentChatRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Richiesta non valida", details: parsed.error.flatten() });
    return;
  }
  const { message, history, currentReel } = parsed.data;

  // Come nella chat clienti: se il conteggio fallisce si resta chiusi, non aperti.
  const { count, error: countError } = await supabaseAdmin
    .from("ai_usage_log")
    .select("id", { count: "exact", head: true })
    .eq("user_id", req.userId!)
    .eq("route", "content_chat")
    .gte("created_at", startOfTodayUtc().toISOString());
  if (countError) {
    console.error("Errore nel conteggio dei messaggi della chat contenuti", countError);
    reportError(countError);
    res.status(500).json({ error: "Errore nel controllo del limite messaggi, riprova" });
    return;
  }
  if ((count ?? 0) >= DAILY_CONTENT_CHAT_LIMIT) {
    res.status(429).json({ error: `Limite di ${DAILY_CONTENT_CHAT_LIMIT} messaggi al giorno raggiunto` });
    return;
  }

  try {
    assertAnthropicKeySafe();
    const response = await anthropic.messages.create({
      model: CODE_MODEL,
      max_tokens: 8000,
      system: buildContentSystemPrompt(currentReel as Reel | null),
      messages: [...history, { role: "user" as const, content: message }],
    });

    const raw = response.content
      .filter((block): block is Extract<(typeof response.content)[number], { type: "text" }> => block.type === "text")
      .map((block) => block.text)
      .join("\n");

    const { text, reel, reelError } = extractReel(raw);
    let reply = text;
    if (response.stop_reason === "max_tokens") {
      reply += "\n\n*(Risposta troncata per il limite di lunghezza — chiedi un reel più corto.)*";
    } else if (reelError) {
      reply += "\n\n*(Il reel generato non era valido — chiedi di rigenerarlo.)*";
    }

    res.json({ reply, reel });

    void logAiUsage({
      userId: req.userId!,
      route: "content_chat",
      model: CODE_MODEL,
      inputTokens: response.usage.input_tokens,
      outputTokens: response.usage.output_tokens,
    });
  } catch (err) {
    console.error("Errore nella chiamata all'API Anthropic (chat contenuti)", err);
    res.status(502).json({ error: "Errore nel generare la risposta, riprova." });
  }
});
