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
