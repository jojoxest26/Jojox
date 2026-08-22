import { useTranslation } from "../i18n/LanguageContext.js";
import { renderWithTokens } from "../i18n/richText.js";

export function Hero() {
  const { t } = useTranslation();

  function scrollToPricing() {
    document.getElementById("pricing")?.scrollIntoView({ behavior: "smooth" });
  }

  return (
    <section className="hero container">
      <h1>
        {t.hero.titleLine1}
        <br />
        <span className="blue-highlight">
          <span className="font-logo">JoJoX</span> {t.hero.titleLine2Suffix}
        </span>
      </h1>

      <p>
        {renderWithTokens(t.hero.body, {
          monitoring: <span className="marker-highlight">{t.hero.bodyMonitoring}</span>,
          score: <span className="marker-highlight">{t.hero.bodyScore}</span>,
        })}
      </p>
      <p className="hero-sub">{t.hero.sub}</p>

      <div className="hero-pills">
        <span className="pill pill-mint">{t.hero.pill1}</span>
        <span className="sep">Â·</span>
        <span className="pill pill-amber">{t.hero.pill2}</span>
        <span className="sep">Â·</span>
        <span className="pill pill-plain">{t.hero.pill3}</span>
      </div>

      <p className="hero-badge">{t.hero.badge}</p>

      <div className="hero-actions">
        <button type="button" className="btn btn-primary shine hard-border hard-shadow" onClick={scrollToPricing}>
          {t.hero.cta}
        </button>
      </div>
      <p className="hero-guest-note">{t.hero.guestNote}</p>
    </section>
  );
}