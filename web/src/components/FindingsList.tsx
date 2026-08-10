import type { AnalysisResult, Finding, Severity } from "../../../src/types.js";
import { ScoreRing } from "./ScoreRing.js";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];
const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critico",
  high: "Alto",
  medium: "Medio",
  low: "Basso",
};

function groupBySeverity(findings: Finding[]): Map<Severity, Finding[]> {
  const map = new Map<Severity, Finding[]>();
  for (const f of findings) {
    const list = map.get(f.severity) ?? [];
    list.push(f);
    map.set(f.severity, list);
  }
  return map;
}

export function FindingsList({ result }: { result: AnalysisResult }) {
  const grouped = groupBySeverity(result.findings);

  return (
    <div className="results">
      <div className="card score-row">
        <ScoreRing score={result.score} />
        <div>
          <div className="score-number">{result.score}/100</div>
          <div className="score-label">Punteggio di sicurezza</div>
          <div className="summary-pills">
            {SEVERITY_ORDER.filter((sev) => result.summary[sev] > 0).map((sev) => (
              <span key={sev} className={`pill pill-${sev}`}>
                {result.summary[sev]} {SEVERITY_LABEL[sev]}
              </span>
            ))}
          </div>
        </div>
      </div>

      {result.findings.length === 0 ? (
        <p style={{ textAlign: "center", marginTop: "1.5rem", color: "var(--text-muted)" }}>
          Nessun problema trovato nei 21 controlli. 🎉
        </p>
      ) : (
        SEVERITY_ORDER.filter((sev) => grouped.has(sev)).map((sev) => (
          <div key={sev}>
            {grouped.get(sev)!.map((finding, i) => (
              <div key={`${finding.checkId}-${i}`} className={`finding finding-${sev}`}>
                <div className="finding-head">
                  <span className="finding-title">{finding.title}</span>
                  <span className="finding-location">
                    {finding.file}
                    {finding.line > 0 ? `:${finding.line}` : ""}
                  </span>
                </div>
                <div className="finding-confidence">
                  {finding.confidence === "confirmed" ? "confermato" : "da verificare"}
                </div>
                <p className="finding-desc">{finding.description}</p>
                <div className="finding-snippet">{finding.snippet}</div>
                <div className="fix-example">
                  <div>
                    <div className="fix-label">Prima</div>
                    <pre className="fix-before">{finding.fix.before}</pre>
                  </div>
                  <div>
                    <div className="fix-label">Dopo</div>
                    <pre className="fix-after">{finding.fix.after}</pre>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ))
      )}
    </div>
  );
}