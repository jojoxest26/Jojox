import Anthropic from "@anthropic-ai/sdk";
import { env } from "./env.js";

/** null finché ANTHROPIC_API_KEY non è impostata su Railway — la rotta chat lo controlla e risponde 503. */
export const anthropic = env.anthropicApiKey ? new Anthropic({ apiKey: env.anthropicApiKey }) : null;

/**
 * Modello più economico e veloce della famiglia: la chat qui si limita a
 * spiegare in linguaggio semplice risultati già trovati dal motore
 * deterministico, non deve ragionare su problemi nuovi — non serve il
 * modello più capace, e tenere i costi bassi conta quanto la qualità.
 */
export const CHAT_MODEL = "claude-haiku-5-5";
