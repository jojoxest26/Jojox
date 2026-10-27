import { env } from "../env.js";
import { assertHeaderSafe } from "../util/assertHeaderSafe.js";

const STRIPE_API_BASE = "https://api.stripe.com/v1";

/** Gli stati di un abbonamento Stripe che contano come "il cliente sta davvero pagando questo". */
export const STRIPE_ACTIVE_SUBSCRIPTION_STATUSES = new Set(["active", "trialing"]);

export class StripeNotConfiguredError extends Error {
  constructor() {
    super("Stripe non è ancora configurato su questo server");
    this.name = "StripeNotConfiguredError";
  }
}

/**
 * Errore con il codice che Stripe restituisce (es. "resource_missing"),
 * non solo il messaggio — serve a chi chiama per distinguere "questo
 * cliente/prezzo non esiste più in questo account" (es. dopo un cambio di
 * account Stripe, da test a live o tra due account di test) da un errore
 * generico, e riprendersi da solo invece di fallire soltanto.
 */
export class StripeApiError extends Error {
  code: string | null;
  param: string | null;

  constructor(message: string, code: string | null, param: string | null) {
    super(message);
    this.name = "StripeApiError";
    this.code = code;
    this.param = param;
  }
}

/** Richiede che le chiavi Stripe siano impostate, altrimenti lo segnala a chi chiama invece di far crashare tutto. */
export function requireStripeSecretKey(): string {
  if (!env.stripeSecretKey) throw new StripeNotConfiguredError();
  assertHeaderSafe(env.stripeSecretKey, "STRIPE_SECRET_KEY");
  return env.stripeSecretKey;
}

interface StripeParams {
  [key: string]: string | number | boolean | StripeParams | StripeParams[] | undefined;
}

/** Trasforma un oggetto (anche annidato) nella notazione a parentesi quadre che l'API di Stripe si aspetta. */
function flatten(params: StripeParams, prefix = ""): [string, string][] {
  const pairs: [string, string][] = [];
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined) continue;
    const paramKey = prefix ? `${prefix}[${key}]` : key;
    if (Array.isArray(value)) {
      value.forEach((item, i) => {
        if (typeof item === "object" && item !== null) {
          pairs.push(...flatten(item as StripeParams, `${paramKey}[${i}]`));
        } else {
          pairs.push([`${paramKey}[${i}]`, String(item)]);
        }
      });
    } else if (typeof value === "object") {
      pairs.push(...flatten(value, paramKey));
    } else {
      pairs.push([paramKey, String(value)]);
    }
  }
  return pairs;
}

/**
 * Chiamata diretta all'API REST di Stripe via fetch — niente SDK ufficiale,
 * per non dover aggiungere una dipendenza npm nuova (vedi il server MCP per
 * lo stesso ragionamento). L'API di Stripe è semplice REST autenticata con
 * Bearer token, quindi non serve altro.
 */
export async function stripeRequest<T>(
  method: "GET" | "POST" | "DELETE",
  path: string,
  params?: StripeParams
): Promise<T> {
  const secretKey = requireStripeSecretKey();
  const body = params ? new URLSearchParams(flatten(params)) : undefined;
  const url = method === "GET" && body ? `${STRIPE_API_BASE}${path}?${body}` : `${STRIPE_API_BASE}${path}`;

  const response = await fetch(url, {
    method,
    headers: {
      Authorization: `Bearer ${secretKey}`,
      ...(method !== "GET" ? { "Content-Type": "application/x-www-form-urlencoded" } : {}),
    },
    body: method !== "GET" ? body : undefined,
  });

  const json = await response.json();
  if (!response.ok) {
    const error = (json as { error?: { message?: string; code?: string; param?: string } }).error;
    throw new StripeApiError(error?.message ?? "Errore Stripe", error?.code ?? null, error?.param ?? null);
  }
  return json as T;
}