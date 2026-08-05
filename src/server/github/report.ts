import type { AnalysisResult, Finding, Severity } from "../../types.js";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "🔴 Critico",
  high: "🟠 Alto",
  medium: "🟡 Medio",
  low: "🔵 Basso",
};

/** Blocca la PR (conclusion "failure") se c'è almeno un problema critico o alto. */
export function checkRunConclusion(result: AnalysisResult): "success" | "failure" {
  const hasBlockingFinding = result.findings.some((f) => f.severity === "critical" || f.severity === "high");
  return hasBlockingFinding ? "failure" : "success";
}

export function formatPrComment(result: AnalysisResult): string {
  if (result.findings.length === 0) {
    return [
      `## JoJoX — Punteggio di sicurezza: ${result.score}/100`,
      "",
      "Nessun problema trovato nei 21 controlli. ✅",
    ].join("\n");
  }

  const bySeverity = new Map<Severity, Finding[]>();
  for (const finding of result.findings) {
    const list = bySeverity.get(finding.severity) ?? [];
    list.push(finding);
    bySeverity.set(finding.severity, list);
  }

  const sections = SEVERITY_ORDER.filter((sev) => bySeverity.has(sev)).map((sev) => {
    const findings = bySeverity.get(sev)!;
    const items = findings
      .map(
        (f) =>
          `- **${f.file}:${f.line}** — ${f.title} _(${f.confidence === "confirmed" ? "confermato" : "da verificare"})_\n  \`${f.snippet}\``
      )
      .join("\n");
    return `### ${SEVERITY_LABEL[sev]} (${findings.length})\n${items}`;
  });

  return [
    `## JoJoX — Punteggio di sicurezza: ${result.score}/100`,
    ...sections,
    "_Generato automaticamente da JoJoX su ogni push. Blocca la pull request quando trova problemi critici o alti — puoi renderlo un controllo obbligatorio nelle impostazioni del branch._",
  ].join("\n\n");
}
