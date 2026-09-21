import { useTranslation } from "../i18n/LanguageContext.js";
import { renderWithTokens } from "../i18n/richText.js";

export function Hero() {
  const { t } = useTranslation();

  function scrollToPricing() {
    document.getElementById("pricing")?.scrollIntoView({ behavior: "smooth" });
  }

  return (
    <section className="hero container">
      <p className="hero-eyebrow">{t.hero.badge}</p>
      <h1 className="poster-line top">JoJoX</h1>

      <div className="panel-wrap">
        <div className="trace"></div>
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
        <div className="trace right"></div>
      </div>

      <p className="poster-line bottom">{t.hero.titleLine2Suffix}</p>

      <div className="hero-pills">
        <span>{t.hero.pill1}</span>
        <span className="sep">·</span>
        <span>{t.hero.pill2}</span>
        <span className="sep">·</span>
        <span>
          <b>{t.hero.pill3}</b>
        </span>
      </div>

      <div className="herofoot">
        <div className="hero-stats">
          <div className="stat">
            <b>21</b>
            <span>{t.hero.statChecksLabel}</span>
          </div>
          <div className="stat">
            <b>0–100</b>
            <span>{t.hero.statScoreLabel}</span>
          </div>
          <div className="stat">
            <b>5</b>
            <span>{t.hero.statFreeLabel}</span>
          </div>
        </div>
        <div className="hero-pitch">
          <p>
            <b>{t.hero.titleLine1}</b>{" "}
            {renderWithTokens(t.hero.body, {
              monitoring: t.hero.bodyMonitoring,
              score: t.hero.bodyScore,
            })}
          </p>
          <div className="hero-actions">
            <button type="button" className="btn btn-primary shine hard-border hard-shadow" onClick={scrollToPricing}>
              {t.hero.cta}
            </button>
          </div>
          <p className="hero-guest-note">{t.hero.guestNote}</p>
        </div>
      </div>
    </section>
  );
}