import { env } from "../env.js";

const STRIPE_API_BASE = "https://api.stripe.com/v1";

export class StripeNotConfiguredError extends Error {
  constructor() {
    super("Stripe non è ancora configurato su questo server");
    this.name = "StripeNotConfiguredError";
  }
}

/** Richiede che le chiavi Stripe siano impostate, altrimenti lo segnala a chi chiama invece di far crashare tutto. */
export function requireStripeSecretKey(): string {
  if (!env.stripeSecretKey) throw new StripeNotConfiguredError();
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
    const message = (json as { error?: { message?: string } }).error?.message ?? "Errore Stripe";
    throw new Error(message);
  }
  return json as T;
}