import { useTranslation } from "../i18n/LanguageContext.js";

export function WhyNotAiSection() {
  const { t } = useTranslation();

  return (
    <section className="why-not-ai-section container">
      <p className="why-not-ai-eyebrow">{t.whyNotAi.eyebrow}</p>
      <h2 className="why-not-ai-question">{t.whyNotAi.question}</h2>
      <details className="why-not-ai-details">
        <summary>
          {t.whyNotAi.readMore} <span className="chevron">⌄</span>
        </summary>
        <div className="why-not-ai-body">
          <p>{t.whyNotAi.point1}</p>
          <p>{t.whyNotAi.point2}</p>
          <p>{t.whyNotAi.point3}</p>
        </div>
      </details>
      <p className="why-not-ai-closing">
        {t.whyNotAi.closingLead} <b>{t.whyNotAi.closingPunch}</b>
      </p>
    </section>
  );
}