import { stripeRequest, StripeNotConfiguredError } from "./stripe/client.js";
import { anthropic, assertAnthropicKeySafe, CHAT_MODEL } from "./anthropic.js";
import { getGithubApp } from "./github/app.js";
import { notifyEmail, buildAlertEmailHtml } from "./email/notify.js";
import { reportError } from "./sentry.js";

// Punto 15 bis della roadmap: UptimeRobot controlla solo /api/health, cioè
// "il server è acceso" — non dice se Stripe, Anthropic o GitHub stanno
// rispondendo davvero. Trovato per caso il problema con la chiave Anthropic
// (27 ottobre 2026) mentre si lavorava su tutt'altro: questo controllo
// esegue chiamate vere, minime e di sola lettura a quei tre servizi a
// intervalli regolari, così un guasto si scopre in minuti, non per caso.

export type CheckName = "Stripe" | "Anthropic" | "GitHub";

export interface CheckResult {
  name: CheckName;
  ok: boolean;
  error?: string;
}

/** GET /v1/balance: chiamata di sola lettura, nessun effetto collaterale, verifica solo che la chiave segreta autentichi davvero. */
async function checkStripe(): Promise<CheckResult> {
  try {
    await stripeRequest("GET", "/balance");
    return { name: "Stripe", ok: true };
  } catch (err) {
    // Non configurato ancora su questo ambiente non è un guasto da segnalare.
    if (err instanceof StripeNotConfiguredError) return { name: "Stripe", ok: true };
    return { name: "Stripe", ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

/** Il prompt più economico possibile (5 token di risposta, modello più economico): basta a verificare che la chiave autentichi. */
async function checkAnthropic(): Promise<CheckResult> {
  if (!anthropic) return { name: "Anthropic", ok: true };
  try {
    assertAnthropicKeySafe();
    await anthropic.messages.create({
      model: CHAT_MODEL,
      max_tokens: 5,
      messages: [{ role: "user", content: "ping" }],
    });
    return { name: "Anthropic", ok: true };
  } catch (err) {
    return { name: "Anthropic", ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

/** Autenticazione come App (non come una specifica installazione): conferma che ID e chiave privata siano ancora validi. */
async function checkGithub(): Promise<CheckResult> {
  try {
    await getGithubApp().octokit.request("GET /app");
    return { name: "GitHub", ok: true };
  } catch (err) {
    return { name: "GitHub", ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

/**
 * Confronta i risultati di questo giro con quali controlli erano già in
 * stato di guasto, e MUTA `currentlyFailing` di conseguenza. Pura rispetto
 * a rete/SDK esterni — testabile senza mock di Stripe/Anthropic/GitHub —
 * separata apposta dall'esecuzione vera dei controlli qui sotto.
 *
 * Un avviso solo al cambio di stato (non a ogni giro) evita di spedire
 * un'email ogni 15 minuti per tutto il tempo in cui un guasto già noto
 * resta da sistemare.
 */
export function diffCheckState(
  results: readonly CheckResult[],
  currentlyFailing: Set<CheckName>
): { newlyFailing: CheckResult[]; recovered: CheckResult[] } {
  const newlyFailing: CheckResult[] = [];
  const recovered: CheckResult[] = [];

  for (const result of results) {
    const wasFailing = currentlyFailing.has(result.name);
    if (!result.ok && !wasFailing) {
      currentlyFailing.add(result.name);
      newlyFailing.push(result);
    } else if (result.ok && wasFailing) {
      currentlyFailing.delete(result.name);
      recovered.push(result);
    }
  }

  return { newlyFailing, recovered };
}

const ALERT_EMAIL = "jojoxest26@gmail.com";

// Stato in memoria del processo: si azzera a un riavvio del server, quindi
// nel caso peggiore si manda di nuovo un avviso già visto — mai il
// contrario (un guasto reale che resta silenzioso).
const currentlyFailing = new Set<CheckName>();

export async function runSyntheticChecks(): Promise<CheckResult[]> {
  const results = await Promise.all([checkStripe(), checkAnthropic(), checkGithub()]);
  const { newlyFailing, recovered } = diffCheckState(results, currentlyFailing);

  for (const result of newlyFailing) {
    reportError(new Error(`Controllo sintetico fallito: ${result.name} — ${result.error ?? "errore sconosciuto"}`));
    await notifyEmail(
      ALERT_EMAIL,
      `⚠️ JoJoX: ${result.name} non risponde`,
      buildAlertEmailHtml({
        title: `${result.name} ha smesso di rispondere`,
        body: `Il controllo automatico su ${result.name} è fallito: ${result.error ?? "errore sconosciuto"}. Dettagli su Sentry e nei Deploy Logs di Railway.`,
        ctaLabel: "Apri Sentry",
        ctaUrl: "https://jojox.sentry.io",
      })
    );
  }

  for (const result of recovered) {
    await notifyEmail(
      ALERT_EMAIL,
      `✅ JoJoX: ${result.name} funziona di nuovo`,
      buildAlertEmailHtml({
        title: `${result.name} è tornato a funzionare`,
        body: `Il controllo automatico su ${result.name} ha ricominciato a rispondere correttamente.`,
        ctaLabel: "Apri jojox.it",
        ctaUrl: "https://jojox.it",
      })
    );
  }

  return results;
}
