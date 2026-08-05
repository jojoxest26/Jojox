import type { Finding, Severity } from "./types.js";

/**
 * Punti di penalità per una singola occorrenza di un controllo, per gravità.
 * Il punteggio parte da 100 e sottrae questi valori — nessuna formula nascosta.
 */
export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 25,
  high: 12,
  medium: 6,
  low: 3,
};

/**
 * Più righe colpite dallo stesso controllo pesano di più, ma con rendimento
 * decrescente: la penalità per un singolo checkId tende asintoticamente a
 * 2 volte il suo peso base, non cresce all'infinito con il numero di righe.
 *
 *   deduction(n) = weight * 2 * (1 - 0.5^n)
 *   n=1 → weight        n=2 → 1.5×weight        n→∞ → 2×weight
 */
function deductionForCheck(weight: number, occurrences: number): number {
  return weight * 2 * (1 - Math.pow(0.5, occurrences));
}

export function computeScore(findings: readonly Finding[]): number {
  const occurrencesByCheck = new Map<string, { severity: Severity; count: number }>();

  for (const finding of findings) {
    const entry = occurrencesByCheck.get(finding.checkId);
    if (entry) {
      entry.count += 1;
    } else {
      occurrencesByCheck.set(finding.checkId, { severity: finding.severity, count: 1 });
    }
  }

  let totalDeduction = 0;
  for (const { severity, count } of occurrencesByCheck.values()) {
    totalDeduction += deductionForCheck(SEVERITY_WEIGHT[severity], count);
  }

  const raw = 100 - totalDeduction;
  return Math.max(0, Math.min(100, Math.round(raw)));
}

export function summarizeBySeverity(findings: readonly Finding[]): Record<Severity, number> {
  const summary: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of findings) summary[finding.severity] += 1;
  return summary;
}
