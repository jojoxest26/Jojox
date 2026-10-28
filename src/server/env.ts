import "dotenv/config";

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Variabile d'ambiente mancante: ${name}`);
  return value;
}

export function parseEmailList(value: string | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((email) => email.trim().toLowerCase())
    .filter(Boolean);
}

export const env = {
  port: Number(process.env.PORT ?? 3000),
  supabaseUrl: required("SUPABASE_URL"),
  supabaseServiceRoleKey: required("SUPABASE_SERVICE_ROLE_KEY"),
  githubAppId: required("GITHUB_APP_ID"),
  githubPrivateKey: Buffer.from(required("GITHUB_APP_PRIVATE_KEY_BASE64"), "base64").toString("utf8"),
  githubWebhookSecret: required("GITHUB_WEBHOOK_SECRET"),
  /**
   * Origini a cui è permesso chiamare l'API da browser (CORS). Nessun
   * default a "*": un backend con dati utente non deve mai accettare
   * richieste da qualunque sito — è letteralmente il controllo
   * "permissive-cors" che il nostro stesso motore segnala come critico.
   * In locale, se non impostata, permette solo la porta di sviluppo di Vite.
   */
  allowedOrigins: (process.env.ALLOWED_ORIGINS ?? "http://localhost:5173")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean),
  /** URL pubblico del sito, usato nei redirect di Stripe (checkout, portale clienti). */
  appUrl: process.env.APP_URL ?? "http://localhost:5173",
  /**
   * Chiavi Stripe: volutamente opzionali (non "required()"). Finché non
   * sono impostate su Railway, le rotte di pagamento rispondono 503 invece
   * di far crashare l'intero server all'avvio — il resto del sito deve
   * continuare a funzionare anche prima che Stripe sia configurato.
   */
  stripeSecretKey: process.env.STRIPE_SECRET_KEY ?? null,
  stripeWebhookSecret: process.env.STRIPE_WEBHOOK_SECRET ?? null,
  stripePriceIdPro: process.env.STRIPE_PRICE_ID_PRO ?? null,
  stripePriceIdTeam: process.env.STRIPE_PRICE_ID_TEAM ?? null,
  /** Prezzi annuali: opzionali come i mensili — se mancanti, l'opzione annuale resta indisponibile invece di rompere il sito. */
  stripePriceIdProAnnual: process.env.STRIPE_PRICE_ID_PRO_ANNUAL ?? null,
  stripePriceIdTeamAnnual: process.env.STRIPE_PRICE_ID_TEAM_ANNUAL ?? null,
  /** Piano Business (aziende) — stesso schema opzionale di Pro/Team. */
  stripePriceIdBusiness: process.env.STRIPE_PRICE_ID_BUSINESS ?? null,
  stripePriceIdBusinessAnnual: process.env.STRIPE_PRICE_ID_BUSINESS_ANNUAL ?? null,
  /** Posto extra oltre i 25 inclusi nel piano Business — venduto come riga aggiuntiva sullo stesso abbonamento, non un piano a sé. */
  stripePriceIdBusinessSeat: process.env.STRIPE_PRICE_ID_BUSINESS_SEAT ?? null,
  stripePriceIdBusinessSeatAnnual: process.env.STRIPE_PRICE_ID_BUSINESS_SEAT_ANNUAL ?? null,
  /** Monitoraggio continuo h24 venduto da solo alle aziende, senza passare da un piano Business vero e proprio. */
  stripePriceIdSentinelSoloBusiness: process.env.STRIPE_PRICE_ID_SENTINEL_SOLO_BUSINESS ?? null,
  stripePriceIdSentinelSoloBusinessAnnual: process.env.STRIPE_PRICE_ID_SENTINEL_SOLO_BUSINESS_ANNUAL ?? null,
  /** Prezzo one-time per il Full Site Audit — pagamento singolo, non abbonamento. */
  stripePriceIdAudit: process.env.STRIPE_PRICE_ID_AUDIT ?? null,
  /** Prezzo one-time per la versione aziendale del Full Site Audit (report mappato su NIS2/DORA). */
  stripePriceIdAuditBusiness: process.env.STRIPE_PRICE_ID_AUDIT_BUSINESS ?? null,
  /** Prezzo one-time per un pacchetto di analisi extra (ANALYSIS_PACK_SIZE in plan.ts) — pagamento singolo, non abbonamento. */
  stripePriceIdAnalysisPack: process.env.STRIPE_PRICE_ID_ANALYSIS_PACK ?? null,
  /**
   * DSN opzionale di Sentry per il tracciamento degli errori del server —
   * se non impostata, Sentry resta semplicemente spento, nessun crash.
   */
  sentryDsn: process.env.SENTRY_DSN ?? null,
  /**
   * Segreto opzionale per avviare a mano uno scan della Sentinella 24/7
   * (POST /api/internal/sentinel/run), senza aspettare il cron notturno —
   * utile per verificare che funzioni davvero prima di fidarsi dello
   * schedule. Se non impostata, la rotta risponde sempre 404.
   */
  sentinelTriggerSecret: process.env.SENTINEL_TRIGGER_SECRET ?? null,
  /**
   * Chiave API Anthropic per la chat che spiega i risultati di un'analisi —
   * opzionale come Stripe/Sentry: finché non è impostata su Railway, la
   * rotta chat risponde 503 invece di far crashare l'intero server.
   */
  anthropicApiKey: process.env.ANTHROPIC_API_KEY ?? null,
  /**
   * Email (separate da virgola) di chi può usare la chat dei contenuti
   * interna (/content, reel per i social di JoJoX). Se vuota, la chat
   * resta chiusa a tutti: non è una funzione per i clienti.
   */
  contentAdminEmails: parseEmailList(process.env.CONTENT_ADMIN_EMAILS),
  /**
   * Chiave API di Resend per le email di avviso brandizzate di JoJoX
   * (Sentinella 24/7, pull request bloccate/corrette) — opzionale come le
   * altre integrazioni: se non impostata, le email restano semplicemente
   * spente, nessun errore. Il dominio jojox.it è già verificato su Resend
   * (usato per l'SMTP di Supabase, vedi punto 9 della roadmap), quindi
   * basta questa chiave per iniziare a mandare email dirette dal backend.
   */
  resendApiKey: process.env.RESEND_API_KEY ?? null,
};