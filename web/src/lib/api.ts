import type { AnalysisResult, SourceFile, Severity } from "../../../src/types.js";

const API_URL = import.meta.env.VITE_API_URL;

export interface AnalysisHistoryEntry {
  id: string;
  source: "manual" | "github";
  repo_full_name: string | null;
  score: number;
  summary: Record<Severity, number>;
  created_at: string;
}

async function apiFetch<T>(path: string, options: RequestInit & { accessToken?: string } = {}): Promise<T> {
  const { accessToken, headers, ...rest } = options;
  const response = await fetch(`${API_URL}${path}`, {
    ...rest,
    headers: {
      "Content-Type": "application/json",
      ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
      ...headers,
    },
  });

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error ?? `Richiesta fallita (${response.status})`);
  }

  return response.json() as Promise<T>;
}

/** Analizza i file passando dal backend — usato quando l'utente è loggato, così l'analisi viene salvata nello storico. */
export function analyzeViaApi(files: SourceFile[], accessToken: string): Promise<AnalysisResult> {
  return apiFetch<AnalysisResult>("/api/analyze", {
    method: "POST",
    body: JSON.stringify({ files }),
    accessToken,
  });
}

export type GuestAnalyzeResult = { ok: true; result: AnalysisResult } | { ok: false; limitReached: true };

/**
 * Analisi anonima, senza login: concessa una sola volta per visitatore
 * (il server la traccia per IP). Passa comunque dal backend — non gira nel
 * browser — perché il limite deve essere imposto lato server per avere un
 * senso, non solo suggerito lato client.
 */
export async function guestAnalyzeViaApi(files: SourceFile[]): Promise<GuestAnalyzeResult> {
  const response = await fetch(`${API_URL}/api/guest-analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ files }),
  });

  if (response.status === 429) {
    return { ok: false, limitReached: true };
  }
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error ?? `Richiesta fallita (${response.status})`);
  }

  return { ok: true, result: (await response.json()) as AnalysisResult };
}

export async function fetchHistory(accessToken: string): Promise<AnalysisHistoryEntry[]> {
  const { analyses } = await apiFetch<{ analyses: AnalysisHistoryEntry[] }>("/api/analyses", { accessToken });
  return analyses;
}

export function joinWaitlist(email: string): Promise<{ joined: boolean }> {
  return apiFetch<{ joined: boolean }>("/api/waitlist", {
    method: "POST",
    body: JSON.stringify({ email }),
  });
}

export type Plan = "free" | "pro" | "team";

export async function fetchProfile(accessToken: string): Promise<Plan> {
  const { plan } = await apiFetch<{ plan: Plan }>("/api/profile", { accessToken });
  return plan;
}

/** Crea una sessione di Stripe Checkout e restituisce l'URL a cui reindirizzare per attivare un piano a pagamento. */
export function createCheckoutSession(plan: "pro" | "team", accessToken: string): Promise<{ url: string }> {
  return apiFetch<{ url: string }>("/api/stripe/create-checkout-session", {
    method: "POST",
    body: JSON.stringify({ plan }),
    accessToken,
  });
}

/** Crea una sessione del portale clienti Stripe (upgrade, downgrade, disdetta, metodo di pagamento). */
export function createPortalSession(accessToken: string): Promise<{ url: string }> {
  return apiFetch<{ url: string }>("/api/stripe/create-portal-session", {
    method: "POST",
    accessToken,
  });
}

export interface GithubInstallation {
  installation_id: number;
  account_login: string;
  slack_webhook_url: string | null;
}

/** Le installazioni della GitHub App collegate all'utente loggato. */
export async function fetchGithubInstallations(accessToken: string): Promise<GithubInstallation[]> {
  const { installations } = await apiFetch<{ installations: GithubInstallation[] }>("/api/github/installations", {
    accessToken,
  });
  return installations;
}

/** Collega un'installazione GitHub appena creata all'utente loggato (vedi App.tsx, callback dopo l'installazione). */
export function claimGithubInstallation(installationId: number, accessToken: string): Promise<{ ok: true }> {
  return apiFetch<{ ok: true }>(`/api/github/installations/${installationId}/claim`, {
    method: "POST",
    accessToken,
  });
}

/** Salva (o rimuove, passando null) l'URL del webhook Slack per un'installazione. */
export function saveSlackWebhook(
  installationId: number,
  slackWebhookUrl: string | null,
  accessToken: string
): Promise<{ ok: true }> {
  return apiFetch<{ ok: true }>(`/api/github/installations/${installationId}/slack-webhook`, {
    method: "PUT",
    body: JSON.stringify({ slackWebhookUrl }),
    accessToken,
  });
}