import { useTranslation } from "../i18n/LanguageContext.js";
import { renderWithTokens } from "../i18n/richText.js";

export function Hero() {
  const { t } = useTranslation();

  function scrollToPricing() {
    document.getElementById("pricing")?.scrollIntoView({ behavior: "smooth" });
  }

  return (
    <section className="hero container">
      <div className="hero-grid">
        <div className="hero-copy">
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
            <span className="sep">·</span>
            <span className="pill pill-amber">{t.hero.pill2}</span>
            <span className="sep">·</span>
            <span className="pill pill-plain">{t.hero.pill3}</span>
          </div>

          <p className="hero-badge">{t.hero.badge}</p>

          <div className="hero-actions">
            <button type="button" className="btn btn-primary shine hard-border hard-shadow" onClick={scrollToPricing}>
              {t.hero.cta}
            </button>
          </div>
          <p className="hero-guest-note">{t.hero.guestNote}</p>
        </div>

        <div className="scanpanel">
          <div className="scanpanel-winctl">
            <span></span>
            <span></span>
            <span></span>
          </div>
          <div className="scanpanel-code">
            <div className="scanbeam"></div>
            <div className="ln">
              <span className="num">1</span>
              <span>
                <span className="kw">router</span>.post(&quot;/admin/ban-user&quot;, isLoggedIn, <span className="kw">async</span> (req, res) =&gt; {"{"}
              </span>
            </div>
            <div className="ln">
              <span className="num">2</span>
              <span>&nbsp;&nbsp;await db.users.update(id, {"{"} banned: <span className="kw">true</span> {"}"})</span>
            </div>
            <div className="ln found">
              <div className="scanpanel-found-mark"></div>
              <div className="scanpanel-found-tag">{t.hero.scanTag}</div>
              <span className="num">3</span>
              <span>
                &nbsp;&nbsp;<span className="kw">return</span> res.json({"{"} ok: <span className="kw">true</span> {"}"})
              </span>
            </div>
            <div className="ln">
              <span className="num">4</span>
              <span>{"}"})</span>
            </div>
            <div className="ln">
              <span className="num">5</span>
              <span></span>
            </div>
            <div className="ln">
              <span className="num">6</span>
              <span>
                <span className="kw">module</span>.exports = router
              </span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
