import { useTranslation } from "../i18n/LanguageContext.js";

export function AudienceSection() {
  const { t } = useTranslation();

  return (
    <>
      <div className="section-divider container">
        <div className="trace"></div>
        <span className="tag">{t.dividers.audience}</span>
        <div className="trace right"></div>
      </div>
      <section className="audience-section container">
        <p className="section-eyebrow">{t.audience.eyebrow}</p>
        <h2 className="section-title">{t.audience.title}</h2>
        <div className="audience-grid">
          {t.audience.items.map((item) => (
            <div key={item.title} className="audience-card">
              <span className="audience-icon">{item.icon}</span>
              <h3>{item.title}</h3>
              <p>{item.text}</p>
            </div>
          ))}
        </div>
      </section>
    </>
  );
}