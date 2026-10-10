import * as Sentry from "@sentry/node";
import { env } from "./env.js";

/**
 * Avvia Sentry se è stata impostata una DSN — se no, resta semplicemente
 * spento: nessun crash, nessuna chiamata di rete in più. Nessun tracciamento
 * delle performance (tracesSampleRate: 0): ci serve solo sapere quando
 * qualcosa si rompe, non misurare la velocità delle richieste.
 */
export function initSentry(): void {
  if (!env.sentryDsn) return;
  Sentry.init({ dsn: env.sentryDsn, tracesSampleRate: 0 });
}

/** Segnala un errore a Sentry se è configurata, altrimenti non fa nulla. */
export function reportError(err: unknown): void {
  if (!env.sentryDsn) return;
  Sentry.captureException(err);
}

export { Sentry };
