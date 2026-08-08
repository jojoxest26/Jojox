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