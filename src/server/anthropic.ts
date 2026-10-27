import Anthropic from "@anthropic-ai/sdk";
import { env } from "./env.js";
import { assertHeaderSafe } from "./util/assertHeaderSafe.js";

/** null finché ANTHROPIC_API_KEY non è impostata su Railway — le rotte che la usano lo controllano e rispondono 503. */
export const anthropic = env.anthropicApiKey ? new Anthropic({ apiKey: env.anthropicApiKey }) : null;

/**
 * Se la chiave è impostata ma contiene un carattere di mascheramento da un
 * copia-incolla incompleto (stesso problema già risolto per Stripe), ogni
 * chiamata fallirebbe con un TypeError criptico di fetch/undici che non
 * dice dove guardare. Non lo controlliamo al caricamento del modulo — farlo
 * crasherebbe l'intero server all'avvio invece di far fallire solo le
 * richieste che usano l'AI — ma chiamando questa funzione subito prima di
 * ogni uso reale, così l'errore che finisce su Sentry dice esattamente cosa
 * controllare.
 */
export function assertAnthropicKeySafe(): void {
  if (env.anthropicApiKey) assertHeaderSafe(env.anthropicApiKey, "ANTHROPIC_API_KEY");
}

/**
 * Modello più economico e veloce della famiglia: usato quando la chat si
 * limita a spiegare in linguaggio semplice risultati già trovati dal
 * motore deterministico — non deve ragionare su problemi nuovi, non serve
 * il modello più capace.
 */
export const CHAT_MODEL = "claude-haiku-5-5";

/**
 * Modello più capace, usato in modalità generale quando viene chiesto di
 * scrivere o correggere codice (punto 24): qui la qualità del codice
 * prodotto conta più del risparmio — costa di più per messaggio, ma resta
 * comunque limitato dal tetto giornaliero di messaggi per piano.
 */
export const CODE_MODEL = "claude-sonnet-5-5";

/**
 * Prezzo ufficiale Anthropic per milione di token, per i due modelli usati
 * in produzione (punto 18 quater) — serve a tradurre i token loggati in
 * ai_usage_log in un costo reale confrontabile con l'incasso per piano.
 * Da aggiornare a mano se Anthropic cambia i prezzi o si cambia modello.
 */
export const MODEL_PRICE_PER_MILLION_TOKENS_USD: Record<string, { input: number; output: number }> = {
  [CHAT_MODEL]: { input: 0.1, output: 0.5 },
  [CODE_MODEL]: { input: 2.0, output: 10.0 },
};

export function estimateCostUsd(model: string, inputTokens: number, outputTokens: number): number {
  const price = MODEL_PRICE_PER_MILLION_TOKENS_USD[model];
  if (!price) return 0;
  return (inputTokens * price.input + outputTokens * price.output) / 1_000_000;
}
