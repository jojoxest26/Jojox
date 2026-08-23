import { ALL_CHECKS } from "../../../src/checks/index.js";
import type { Severity } from "../../../src/types.js";
import { useTranslation } from "../i18n/LanguageContext.js";
import { renderWithTokens } from "../i18n/richText.js";
import { translateCheckText } from "../i18n/checkTranslations.js";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

export function ChecksList() {
  const { t, lang } = useTranslation();

  return (
    <section className="checks-section container">
      <h2>{t.checksList.title}</h2>
      <p>{t.checksList.body}</p>
      <p className="checks-sub">
        {renderWithTokens(t.checksList.subLabel, { count: String(ALL_CHECKS.length) })}
      </p>
      {SEVERITY_ORDER.map((sev) => (
        <details key={sev} className="check-group" data-sev={sev}>
          <summary>
            <span className={`pill pill-${sev}`}>
              {t.common.severity[sev]} ({ALL_CHECKS.filter((c) => c.severity === sev).length})
            </span>
            <span className="chevron">⌄</span>
          </summary>
          <div className="check-group-body">
            {ALL_CHECKS.filter((c) => c.severity === sev).map((check) => {
              const text = translateCheckText(check.id, check, lang);
              return (
                <div key={check.id} className="check-item">
                  <span>{text.title}</span>
                  <span className="check-confidence">
                    {check.confidence === "confirmed" ? t.common.confirmed : t.common.heuristic}
                  </span>
                </div>
              );
            })}
          </div>
        </details>
      ))}
      <p className="checks-note">{t.checksList.note}</p>
    </section>
  );
}