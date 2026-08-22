import { useTranslation } from "../i18n/LanguageContext.js";

export function Features() {
  const { t } = useTranslation();

  return (
    <section className="features-section container">
      <div className="features-grid">
        {t.features.map((f) => (
          <div key={f.title} className={`card feature-card feature-card-${f.accent} lift`}>
            <div className="feature-icon">{f.icon}</div>
            <h3>{f.title}</h3>
            <p>{f.text}</p>
          </div>
        ))}
      </div>
    </section>
  );
}