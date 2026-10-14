import Anthropic from "@anthropic-ai/sdk";
import { env } from "./env.js";

/** null finché ANTHROPIC_API_KEY non è impostata su Railway — la rotta chat lo controlla e risponde 503. */
export const anthropic = env.anthropicApiKey ? new Anthropic({ apiKey: env.anthropicApiKey }) : null;

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
