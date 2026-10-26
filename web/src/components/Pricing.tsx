import { useEffect, useState } from "react";
import type { Session } from "@supabase/supabase-js";
import {
  createCheckoutSession,
  createPortalSession,
  createSentinelAddonCheckoutSession,
  fetchProfileDetails,
  type Plan,
} from "../lib/api.js";
import { useTranslation } from "../i18n/LanguageContext.js";
import { Icon } from "./Icon.js";

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
  const [sentinelAddonActive, setSentinelAddonActive] = useState(false);
  const [busy, setBusy] = useState<"pro" | "team" | "business" | "sentinelAddon" | "portal" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [checkoutNotice, setCheckoutNotice] = useState<"success" | "cancel" | null>(null);
  const [billingInterval, setBillingInterval] = useState<"monthly" | "annual">("monthly");

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
      setSentinelAddonActive(false);
      return;
    }
    function loadProfile() {
      if (!session) return;
      fetchProfileDetails(session.access_token)
        .then((details) => {
          setPlan(details.plan);
          setSentinelAddonActive(details.sentinelAddonActive);
        })
        .catch(() => setPlan(null));
    }
    loadProfile();

    // Il piano si aggiorna via webhook Stripe dopo il redirect di ritorno: un
    // secondo giro dopo qualche secondo evita di mostrare ancora "Gratis"
    // appena tornati dal checkout, mentre il webhook sta ancora arrivando.
    if (checkoutNotice === "success") {
      const timeout = setTimeout(loadProfile, 2500);
      return () => clearTimeout(timeout);
    }
  }, [session, checkoutNotice]);

  async function handleActivate(target: "pro" | "team" | "business") {
    if (!session) {
      openLogin();
      return;
    }
    setError(null);
    setBusy(target);
    try {
      const { url } = await createCheckoutSession(target, session.access_token, billingInterval);
      window.location.href = url;
    } catch (err) {
      setError(err instanceof Error ? err.message : t.pricing.errorActivation);
      setBusy(null);
    }
  }

  async function handleActivateSentinelAddon() {
    if (!session) {
      openLogin();
      return;
    }
    setError(null);
    setBusy("sentinelAddon");
    try {
      const { url } = await createSentinelAddonCheckoutSession(session.access_token, billingInterval);
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
    <>
      <div className="section-divider container">
        <div className="trace"></div>
        <span className="tag">{t.dividers.pricing}</span>
        <div className="trace right"></div>
      </div>
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
            <span className="guest-title-icon">
              <Icon name="user" />
            </span>
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

      <div className="billing-toggle" role="group" aria-label="Ciclo di fatturazione">
        <button
          type="button"
          className={`billing-toggle-btn${billingInterval === "monthly" ? " active" : ""}`}
          onClick={() => setBillingInterval("monthly")}
        >
          {t.pricing.billingMonthly}
        </button>
        <button
          type="button"
          className={`billing-toggle-btn${billingInterval === "annual" ? " active" : ""}`}
          onClick={() => setBillingInterval("annual")}
        >
          {t.pricing.billingAnnual}
          <span className="billing-toggle-badge">{t.pricing.billingAnnualBadge}</span>
        </button>
      </div>

      <h3 className="pricing-section-label">{t.pricing.devSectionTitle}</h3>
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
            {billingInterval === "annual" ? t.pricing.proPriceAnnual : "19€"}{" "}
            <span className="per">{billingInterval === "annual" ? t.pricing.proPerAnnual : t.pricing.proPer}</span>
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
            {billingInterval === "annual" ? t.pricing.teamPriceAnnual : "49€"}{" "}
            <span className="per">{billingInterval === "annual" ? t.pricing.teamPerAnnual : t.pricing.teamPer}</span>
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
              className="btn btn-mint hard-border hard-shadow-sm"
              onClick={() => handleActivate("team")}
              disabled={busy === "team"}
            >
              {busy === "team" ? t.pricing.teamActivating : t.pricing.teamCta}
            </button>
          )}
          <p className="price-card-note">{t.pricing.teamNote}</p>
        </div>
      </div>

      <div className="pricing-business-panel hard-border">
        <h3 className="pricing-section-label pricing-section-label-inset">{t.pricing.businessSectionTitle}</h3>
        <div className="pricing-grid pricing-grid-business">
          <div className="card price-card">
            <span className="pill pill-amber price-card-badge">{t.pricing.businessBadge}</span>
            <h3>{t.pricing.businessTitle}</h3>
            <div className="price-amount">
              {billingInterval === "annual" ? t.pricing.businessPriceAnnual : "1.490€"}{" "}
              <span className="per">
                {billingInterval === "annual" ? t.pricing.businessPerAnnual : t.pricing.businessPer}
              </span>
            </div>
            <ul>
              {t.pricing.businessList.map((item) => (
                <li key={item}>✓ {item}</li>
              ))}
            </ul>
            {session && plan === "business" ? (
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
                onClick={() => handleActivate("business")}
                disabled={busy === "business"}
              >
                {busy === "business" ? t.pricing.businessActivating : t.pricing.businessCta}
              </button>
            )}
            <p className="price-card-note">{t.pricing.businessNote}</p>
          </div>

          <div className="card price-card">
            <h3>{t.pricing.sentinelAddonTitle}</h3>
            <div className="price-amount">
              {billingInterval === "annual" ? t.pricing.sentinelAddonPriceAnnual : "590€"}{" "}
              <span className="per">
                {billingInterval === "annual" ? t.pricing.businessPerAnnual : t.pricing.businessPer}
              </span>
            </div>
            <ul>
              {t.pricing.sentinelAddonList.map((item) => (
                <li key={item}>✓ {item}</li>
              ))}
            </ul>
            {session && sentinelAddonActive ? (
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
                onClick={handleActivateSentinelAddon}
                disabled={busy === "sentinelAddon"}
              >
                {busy === "sentinelAddon" ? t.pricing.businessActivating : t.pricing.sentinelAddonCta}
              </button>
            )}
            <p className="price-card-note">{t.pricing.sentinelAddonNote}</p>
          </div>

          <div className="card price-card">
            <h3>{t.pricing.enterpriseTitle}</h3>
            <div className="price-amount">{t.pricing.enterprisePrice}</div>
            <ul>
              {t.pricing.enterpriseList.map((item) => (
                <li key={item}>✓ {item}</li>
              ))}
            </ul>
            <a
              className="btn btn-secondary hard-border hard-shadow-sm"
              href={`mailto:jojoxest26@gmail.com?subject=${encodeURIComponent("[Enterprise]")}`}
            >
              {t.pricing.enterpriseCta}
            </a>
            <p className="price-card-note">{t.pricing.enterpriseNote}</p>
          </div>
        </div>
      </div>

      {error && <p className="pricing-error">{error}</p>}

      <p className="pricing-disclaimer">{t.pricing.disclaimer}</p>
      </section>
    </>
  );
}