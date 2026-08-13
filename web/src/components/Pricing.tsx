import { useEffect, useState } from "react";
import type { Session } from "@supabase/supabase-js";
import { createCheckoutSession, createPortalSession, fetchProfile, type Plan } from "../lib/api.js";

function openLogin() {
  window.scrollTo({ top: 0, behavior: "smooth" });
  window.dispatchEvent(new CustomEvent("jojox-open-login"));
}

function openAnalyzer() {
  window.dispatchEvent(new Event("jojox-open-analyzer"));
}

export function Pricing({ session }: { session: Session | null }) {
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
      setError(err instanceof Error ? err.message : "Errore nell'attivazione del piano");
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
      setError(err instanceof Error ? err.message : "Errore nell'apertura del portale abbonamento");
      setBusy(null);
    }
  }

  return (
    <section className="pricing-section container" id="pricing">
      <h2>Paghi il monitoraggio continuo, non le singole analisi</h2>
      <p>Prova 1 analisi senza dare nulla. Poi basta l'email, nessuna password: fino a 5 analisi al mese gratis.</p>

      {checkoutNotice === "success" && (
        <p className="pricing-notice pricing-notice-success">
          ✓ Pagamento ricevuto, stiamo attivando il piano — qualche secondo e questa pagina si aggiorna da sola.
        </p>
      )}
      {checkoutNotice === "cancel" && (
        <p className="pricing-notice">Attivazione annullata, nessun addebito. Riprova quando vuoi.</p>
      )}

      <div className="card guest-callout">
        <div>
          <div className="guest-title">
            <span>👤</span>
            <h3>Modalità ospite</h3>
          </div>
          <ul>
            <li>✓ 1 analisi gratuita, senza email</li>
            <li>✓ Tutti i 21 controlli con esempi di correzione</li>
            <li>✓ Punteggio di sicurezza</li>
            <li>✓ Un solo tentativo per visitatore, imposto dal nostro server</li>
          </ul>
        </div>
        <button type="button" className="btn btn-secondary hard-border hard-shadow" onClick={openAnalyzer}>
          Prova senza registrarti
        </button>
      </div>

      <div className="pricing-grid">
        <div className="card price-card">
          <h3>Gratis</h3>
          <div className="price-amount">0€</div>
          <ul>
            <li>✓ 5 analisi al mese</li>
            <li>✓ Tutti i 21 controlli, con esempi di correzione</li>
            <li>✓ Punteggio di sicurezza + badge da scaricare (.svg)</li>
            <li>✓ Cronologia delle ultime 20 analisi</li>
          </ul>
          {session && plan === "free" ? (
            <span className="pill pill-plain price-card-active">Piano attivo</span>
          ) : (
            <button type="button" className="btn btn-secondary hard-border hard-shadow-sm" onClick={openLogin}>
              Inizia gratis
            </button>
          )}
          <p className="price-card-note">Per chi analizza progetti una tantum</p>
        </div>

        <div className="card price-card featured">
          <span className="pill pill-amber price-card-badge">MONITORING</span>
          <h3>Pro</h3>
          <div className="price-amount">
            9,99€ <span className="per">/mese</span>
          </div>
          <ul>
            <li>✓ Analisi e cronologia illimitate</li>
            <li>✓ Integrazione con GitHub: controlla ogni push e blocca le modifiche più rischiose</li>
            <li>✓ Commenti automatici sulle pull request</li>
            <li>✓ Correzioni automatiche proposte come pull request</li>
            <li>✓ Badge che si aggiorna da solo a ogni push</li>
          </ul>
          {session && plan === "pro" ? (
            <>
              <span className="pill pill-plain price-card-active">Piano attivo</span>
              <button
                type="button"
                className="btn btn-secondary hard-border hard-shadow-sm"
                onClick={handleManage}
                disabled={busy === "portal"}
              >
                {busy === "portal" ? "Apertura..." : "Gestisci abbonamento"}
              </button>
            </>
          ) : (
            <button
              type="button"
              className="btn btn-primary hard-border hard-shadow-sm"
              onClick={() => handleActivate("pro")}
              disabled={busy === "pro"}
            >
              {busy === "pro" ? "Attivazione..." : "Attiva Pro"}
            </button>
          )}
          <p className="price-card-note">Per monitoraggio continuo su ogni push</p>
        </div>

        <div className="card price-card">
          <span className="pill pill-mint price-card-badge">TEAM</span>
          <h3>Team</h3>
          <div className="price-amount">
            24,99€ <span className="per">/mese</span>
          </div>
          <ul>
            <li>✓ Analisi e cronologia illimitate</li>
            <li>✓ Integrazione con GitHub: controlla ogni push e blocca le modifiche più rischiose</li>
            <li>✓ Commenti automatici sulle pull request</li>
            <li>✓ Correzioni automatiche proposte come pull request</li>
            <li>✓ Badge che si aggiorna da solo a ogni push</li>
          </ul>
          {session && plan === "team" ? (
            <>
              <span className="pill pill-plain price-card-active">Piano attivo</span>
              <button
                type="button"
                className="btn btn-secondary hard-border hard-shadow-sm"
                onClick={handleManage}
                disabled={busy === "portal"}
              >
                {busy === "portal" ? "Apertura..." : "Gestisci abbonamento"}
              </button>
            </>
          ) : (
            <button
              type="button"
              className="btn btn-secondary hard-border hard-shadow-sm"
              onClick={() => handleActivate("team")}
              disabled={busy === "team"}
            >
              {busy === "team" ? "Attivazione..." : "Attiva Team"}
            </button>
          )}
          <p className="price-card-note">Per team con più repo</p>
        </div>
      </div>

      {error && <p className="pricing-error">{error}</p>}

      <p className="pricing-disclaimer">
        Disdici quando vuoi, senza vincoli — l'abbonamento si gestisce da solo, direttamente dal tuo account.
      </p>
    </section>
  );
}