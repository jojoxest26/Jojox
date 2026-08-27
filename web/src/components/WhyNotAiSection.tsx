import { useTranslation } from "../i18n/LanguageContext.js";

export function WhyNotAiSection() {
  const { t } = useTranslation();

  return (
    <section className="why-not-ai-section container">
      <details className="card why-not-ai-card">
        <summary>
          <span className="why-not-ai-question">{t.whyNotAi.question}</span>
          <span className="chevron">⌄</span>
        </summary>
        <div className="why-not-ai-body">
          <p>{t.whyNotAi.point1}</p>
          <p>{t.whyNotAi.point2}</p>
          <p>{t.whyNotAi.point3}</p>
          <p className="why-not-ai-closing">{t.whyNotAi.closing}</p>
        </div>
      </details>
    </section>
  );
}
