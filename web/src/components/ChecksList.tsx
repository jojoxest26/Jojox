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
        Il valore di JoJoX non sta nel nascondere come funziona, ma nel curare bene ogni controllo, testarlo e
        tenerlo aggiornato. Qui sotto trovi la lista completa: cosa controlliamo, quanto è grave ogni problema, e
        quanto siamo sicuri di ogni segnalazione.
      </p>
      <p className="checks-sub">{ALL_CHECKS.length} controlli, in 4 livelli di gravità</p>
      {SEVERITY_ORDER.map((sev) => (
        <details key={sev} className="check-group" data-sev={sev}>
          <summary>
            <span className={`pill pill-${sev}`}>
              {SEVERITY_LABEL[sev]} ({ALL_CHECKS.filter((c) => c.severity === sev).length})
            </span>
            <span className="chevron">⌄</span>
          </summary>
          <div className="check-group-body">
            {ALL_CHECKS.filter((c) => c.severity === sev).map((check) => (
              <div key={check.id} className="check-item">
                <span>{check.title}</span>
                <span className="check-confidence">
                  {check.confidence === "confirmed" ? "confermato" : "da verificare"}
                </span>
              </div>
            ))}
          </div>
        </details>
      ))}
      <p className="checks-note">
        «Confermato» = troviamo il problema per certo nel codice · «Da verificare» = sembra mancare una protezione,
        ma potrebbe essere gestita altrove: controlla prima di preoccuparti.
      </p>
    </section>
  );
}