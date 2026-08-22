import { useEffect, useState } from "react";
import type { Session } from "@supabase/supabase-js";
import { createCheckoutSession, createPortalSession, fetchProfile, type Plan } from "../lib/api.js";
import { useTranslation } from "../i18n/LanguageContext.js";

function openLogin() {
  window.scrollTo({ top: 0, behavior: "smooth" });
  window.dispatchEvent(new CustomEvent("jojox-open-login"));
}

function openAnalyzer() {
  window.dispatchEvent(new Event("jojox-open-analyzer"));
}

export function Pricing({ session }: { session: Session | null }) {
  const { t } = useTranslation();
  const [plan, setPlan] = useState<Plan | null>(null);
  const [busy, setBusy] = useState<"pro" | "team" | "portal" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [checkoutNotice, setCheckoutNotice] = useState<"success" | "cancel" | null>(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const checkout = params.get("checkout");
    if (checkout === "success" || checkout === "cancel") {
      setCheckoutNotice(checkout);
      window.history.replaceState({}, "", window.location.pathname + window.location.hash);
    }
  }, []);

  useEffect(() => {
    if (!session) {
      setPlan(null);
      return;
    }
    fetchProfile(session.access_token)
      .then(setPlan)
      .catch(() => setPlan(null));

    // Il piano si aggiorna via webhook Stripe dopo il redirect di ritorno: un
    // secondo giro dopo qualche secondo evita di mostrare ancora "Gratis"
    // appena tornati dal checkout, mentre il webhook sta ancora arrivando.
    if (checkoutNotice === "success") {
      const timeout = setTimeout(() => {
        fetchProfile(session.access_token)
          .then(setPlan)
          .catch(() => {});
      }, 2500);
      return () => clearTimeout(timeout);
    }
  }, [session, checkoutNotice]);

  async function handleActivate(target: "pro" | "team") {
    if (!session) {
      openLogin();
      return;
    }
    setError(null);
    setBusy(target);
    try {
      const { url } = await createCheckoutSession(target, session.access_token);
      window.location.href = url;
    } catch (err) {
      setError(err instanceof Error ? err.message : t.pricing.errorActivation);
      setBusy(null);
    }
  }

  async function handleManage() {
    if (!session) return;
    setError(null);
    setBusy("portal");
    try {
      const { url } = await createPortalSession(session.access_token);
      window.location.href = url;
    } catch (err) {
      setError(err instanceof Error ? err.message : t.pricing.errorPortal);
      setBusy(null);
    }
  }

  return (
    <section className="pricing-section container" id="pricing">
      <h2>{t.pricing.title}</h2>
      <p>{t.pricing.subtitle}</p>

      {checkoutNotice === "success" && (
        <p className="pricing-notice pricing-notice-success">{t.pricing.noticeSuccess}</p>
      )}
      {checkoutNotice === "cancel" && <p className="pricing-notice">{t.pricing.noticeCancel}</p>}

      <div className="card guest-callout">
        <div>
          <div className="guest-title">
            <span>👤</span>
            <h3>{t.pricing.guestTitle}</h3>
          </div>
          <ul>
            {t.pricing.guestList.map((item) => (
              <li key={item}>✓ {item}</li>
            ))}
          </ul>
        </div>
        <button type="button" className="btn btn-secondary hard-border hard-shadow" onClick={openAnalyzer}>
          {t.pricing.guestCta}
        </button>
      </div>

      <div className="pricing-grid">
        <div className="card price-card">
          <h3>{t.pricing.freeTitle}</h3>
          <div className="price-amount">0€</div>
          <ul>
            {t.pricing.freeList.map((item) => (
              <li key={item}>✓ {item}</li>
            ))}
          </ul>
          {session && plan === "free" ? (
            <span className="pill pill-plain price-card-active">{t.pricing.activePlan}</span>
          ) : (
            <button type="button" className="btn btn-secondary hard-border hard-shadow-sm" onClick={openLogin}>
              {t.pricing.freeCta}
            </button>
          )}
          <p className="price-card-note">{t.pricing.freeNote}</p>
        </div>

        <div className="card price-card featured">
          <span className="pill pill-amber price-card-badge">{t.pricing.proBadge}</span>
          <h3>{t.pricing.proTitle}</h3>
          <div className="price-amount">
            9,99€ <span className="per">{t.pricing.proPer}</span>
          </div>
          <ul>
            {t.pricing.proList.map((item) => (
              <li key={item}>✓ {item}</li>
            ))}
          </ul>
          {session && plan === "pro" ? (
            <>
              <span className="pill pill-plain price-card-active">{t.pricing.activePlan}</span>
              <button
                type="button"
                className="btn btn-secondary hard-border hard-shadow-sm"
                onClick={handleManage}
                disabled={busy === "portal"}
              >
                {busy === "portal" ? t.pricing.opening : t.pricing.manageSubscription}
              </button>
            </>
          ) : (
            <button
              type="button"
              className="btn btn-primary hard-border hard-shadow-sm"
              onClick={() => handleActivate("pro")}
              disabled={busy === "pro"}
            >
              {busy === "pro" ? t.pricing.proActivating : t.pricing.proCta}
            </button>
          )}
          <p className="price-card-note">{t.pricing.proNote}</p>
        </div>

        <div className="card price-card">
          <span className="pill pill-mint price-card-badge">{t.pricing.teamBadge}</span>
          <h3>{t.pricing.teamTitle}</h3>
          <div className="price-amount">
            24,99€ <span className="per">{t.pricing.teamPer}</span>
          </div>
          <ul>
            {t.pricing.teamList.map((item) => (
              <li key={item}>✓ {item}</li>
            ))}
          </ul>
          {session && plan === "team" ? (
            <>
              <span className="pill pill-plain price-card-active">{t.pricing.activePlan}</span>
              <button
                type="button"
                className="btn btn-secondary hard-border hard-shadow-sm"
                onClick={handleManage}
                disabled={busy === "portal"}
              >
                {busy === "portal" ? t.pricing.opening : t.pricing.manageSubscription}
              </button>
            </>
          ) : (
            <button
              type="button"
              className="btn btn-secondary hard-border hard-shadow-sm"
              onClick={() => handleActivate("team")}
              disabled={busy === "team"}
            >
              {busy === "team" ? t.pricing.teamActivating : t.pricing.teamCta}
            </button>
          )}
          <p className="price-card-note">{t.pricing.teamNote}</p>
        </div>
      </div>

      {error && <p className="pricing-error">{error}</p>}

      <p className="pricing-disclaimer">{t.pricing.disclaimer}</p>
    </section>
  );
}