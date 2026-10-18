import { anthropic, CODE_MODEL } from "./anthropic.js";
import type { AiInsight, AiInsightCategory, SourceFile } from "../types.js";

// Contiene il costo e il tempo di risposta: questi due tipi di bug
// tipicamente si riconoscono da poche righe/file alla volta, non serve
// mandare l'intero progetto a Claude per trovarli.
const MAX_FILES_FOR_REVIEW = 40;
const MAX_CHARS_PER_FILE = 6_000;
const MAX_TOTAL_CHARS = 120_000;
const MAX_INSIGHTS = 8;

const CATEGORIES: readonly AiInsightCategory[] = ["race-condition", "authorization-logic"];

const SYSTEM_PROMPT = `Sei un revisore di codice senior che cerca ESCLUSIVAMENTE due categorie di bug di logica — quelli che un motore a pattern-matching non può trovare perché richiedono di capire il comportamento del programma, non solo riconoscere una sintassi.

1. race-condition: stato condiviso (variabile, file, riga di database, cache) letto e scritto da più richieste/thread/processi senza nessuna sincronizzazione (lock, transazione, operazione atomica) — bug che si manifesta solo sotto carico concorrente.

2. authorization-logic: un controllo di ruolo o di proprietà presente nel codice ma scritto in modo sbagliato — condizione invertita, controllo del ruolo sbagliato, controllo di proprietà mancante su un'azione che modifica dati di un altro utente, confronto tra ID che si può aggirare.

Regole ferree:
- Segnala SOLO quello di cui sei ragionevolmente sicuro leggendo il codice fornito. Meglio non trovare nulla che inventare un problema: ogni falso positivo qui costa più fiducia di uno in un controllo a pattern, perché sembra "pensato da un'AI", non verificato.
- Non segnalare nulla che un controllo a pattern-matching troverebbe già (secret hardcoded, SQL injection letterale, XSS diretto, password salvate in chiaro, ecc.) — di quello si occupa già il resto di JoJoX.
- Non proporre correzioni: spiega solo cosa potrebbe succedere e perché, così chi legge può verificare da sé prima di cambiare qualunque cosa.
- Rispondi SOLO con un array JSON valido, nessun testo prima o dopo, in questo formato esatto:
[{"category":"race-condition","title":"...","file":"...","explanation":"..."}]
- "category" è esattamente "race-condition" oppure "authorization-logic". "title" è una frase breve (max 10 parole). "explanation" descrive lo scenario concreto in 2-3 frasi, in italiano, in linguaggio semplice.
- Se non trovi nulla in nessuna delle due categorie, rispondi con un array vuoto: []
- Massimo ${MAX_INSIGHTS} risultati, dal più grave al meno grave.`;

function isValidInsight(value: unknown): value is AiInsight {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.category === "string" &&
    (CATEGORIES as string[]).includes(v.category) &&
    typeof v.title === "string" &&
    v.title.trim().length > 0 &&
    typeof v.file === "string" &&
    v.file.trim().length > 0 &&
    typeof v.explanation === "string" &&
    v.explanation.trim().length > 0
  );
}

/**
 * Esposta a parte dalla chiamata vera e propria per poterla testare senza
 * un client Anthropic: una risposta malformata (testo intorno al JSON,
 * markdown, un campo con un valore inatteso) non deve mai far crashare la
 * richiesta — ritorna semplicemente meno risultati, o nessuno.
 */
export function parseAiInsightsResponse(text: string): AiInsight[] {
  const start = text.indexOf("[");
  const end = text.lastIndexOf("]");
  if (start === -1 || end === -1 || end < start) return [];

  let parsed: unknown;
  try {
    parsed = JSON.parse(text.slice(start, end + 1));
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];

  return parsed.filter(isValidInsight).slice(0, MAX_INSIGHTS);
}

/** Seleziona i file da mandare in revisione, rispettando i tetti di costo sopra. */
export function selectFilesForReview(files: readonly SourceFile[]): SourceFile[] {
  let totalChars = 0;
  const selected: SourceFile[] = [];
  for (const f of files) {
    if (selected.length >= MAX_FILES_FOR_REVIEW) break;
    const content = f.content.length > MAX_CHARS_PER_FILE ? f.content.slice(0, MAX_CHARS_PER_FILE) : f.content;
    if (totalChars + content.length > MAX_TOTAL_CHARS) continue;
    totalChars += content.length;
    selected.push({ path: f.path, content });
  }
  return selected;
}

export async function findAiInsights(files: readonly SourceFile[]): Promise<AiInsight[]> {
  if (!anthropic) return [];

  const selected = selectFilesForReview(files);
  if (selected.length === 0) return [];

  const filesText = selected.map((f) => `--- ${f.path} ---\n${f.content}`).join("\n\n");

  const response = await anthropic.messages.create({
    model: CODE_MODEL,
    max_tokens: 2000,
    system: SYSTEM_PROMPT,
    messages: [{ role: "user", content: filesText }],
  });

  const text = response.content
    .filter((b): b is Extract<(typeof response.content)[number], { type: "text" }> => b.type === "text")
    .map((b) => b.text)
    .join("")
    .trim();

  return parseAiInsightsResponse(text);
}
