import { useTranslation } from "../i18n/LanguageContext.js";

export function Features() {
  const { t } = useTranslation();

  return (
    <>
      <div className="section-divider container">
        <div className="trace"></div>
        <span className="tag">{t.dividers.features}</span>
        <div className="trace right"></div>
      </div>
      <section className="features-section container">
        <p className="section-eyebrow">{t.features.eyebrow}</p>
        <h2 className="section-title">{t.features.title}</h2>
        <p className="section-subtitle">{t.features.subtitle}</p>
        <div className="features-grid">
          {t.features.items.map((f) => (
            <div key={f.title} className={`card feature-card feature-card-${f.accent} lift`}>
              <div className="feature-icon">{f.icon}</div>
              <h3>{f.title}</h3>
              <p>{f.text}</p>
            </div>
          ))}
        </div>
      </section>
    </>
  );
}