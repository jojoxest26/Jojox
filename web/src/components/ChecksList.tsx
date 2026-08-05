import { ALL_CHECKS } from "../../../src/checks/index.js";
import type { Severity } from "../../../src/types.js";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];
const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critico",
  high: "Alto",
  medium: "Medio",
  low: "Basso",
};

export function ChecksList() {
  return (
    <section className="checks-section container">
      <h2>Tutti i controlli, senza segreti</h2>
      <p>
        {ALL_CHECKS.length} controlli, in 4 livelli di gravità. «Confermato» = troviamo il problema per certo nel
        codice · «Da verificare» = sembra mancare una protezione, ma potrebbe essere gestita altrove.
      </p>
      {SEVERITY_ORDER.map((sev) => (
        <details key={sev} className="card" style={{ marginBottom: "0.75rem", padding: "1rem 1.25rem" }}>
          <summary style={{ cursor: "pointer", fontWeight: 700 }}>
            {SEVERITY_LABEL[sev]} ({ALL_CHECKS.filter((c) => c.severity === sev).length})
          </summary>
          {ALL_CHECKS.filter((c) => c.severity === sev).map((check) => (
            <div key={check.id} className="check-item">
              <span>{check.title}</span>
              <span className="check-confidence">
                {check.confidence === "confirmed" ? "confermato" : "da verificare"}
              </span>
            </div>
          ))}
        </details>
      ))}
    </section>
  );
}
