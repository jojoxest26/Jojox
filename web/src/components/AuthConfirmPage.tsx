import { useState, type MouseEvent } from "react";
import type { EmailOtpType } from "@supabase/supabase-js";
import { LanguageSwitcher } from "./Header.js";
import { useTranslation } from "../i18n/LanguageContext.js";
import { supabase } from "../lib/supabaseClient.js";

function goHome(e?: MouseEvent) {
  e?.preventDefault();
  window.history.pushState({}, "", "/");
  window.dispatchEvent(new PopStateEvent("popstate"));
}

// Il link di accesso via email non punta più direttamente all'endpoint di
// verifica di Supabase (che un antivirus o uno scanner di sicurezza della
// posta può "cliccare" automaticamente per controllarlo, consumando il
// link prima ancora che l'utente lo apra davvero) ma a questa pagina, con
// token_hash e type in query string. La verifica vera parte solo al click
// esplicito sul pulsante qui sotto, non al semplice caricamento della
// pagina: uno scanner automatico che la visita non la consuma.
export function AuthConfirmPage() {
  const { t } = useTranslation();
  const [status, setStatus] = useState<"idle" | "verifying" | "success" | "error">("idle");

  const params = new URLSearchParams(window.location.search);
  const tokenHash = params.get("token_hash");
  const type = params.get("type") as EmailOtpType | null;

  async function handleConfirm() {
    if (!tokenHash || !type) {
      setStatus("error");
      return;
    }
    setStatus("verifying");
    const { error } = await supabase.auth.verifyOtp({ token_hash: tokenHash, type });
    if (error) {
      setStatus("error");
      return;
    }
    setStatus("success");
    setTimeout(() => goHome(), 600);
  }

  return (
    <div className="legal-page">
      <div className="container legal-page-nav">
        <a href="/" onClick={goHome} className="legal-back">
          {t.login.confirmBackHome}
        </a>
        <LanguageSwitcher />
      </div>
      <div className="container">
        <div className="login-panel card" style={{ margin: "2rem auto", maxWidth: "28rem" }}>
          {status === "idle" && tokenHash && type && (
            <>
              <h1 style={{ fontSize: "1.25rem", marginBottom: "0.5rem" }}>{t.login.confirmHeading}</h1>
              <p className="login-msg">{t.login.confirmBody}</p>
              <button type="button" className="btn btn-primary" style={{ width: "100%" }} onClick={handleConfirm}>
                {t.login.confirmButton}
              </button>
            </>
          )}
          {status === "verifying" && <p className="login-msg">{t.login.confirmVerifying}</p>}
          {status === "success" && <p className="login-msg">{t.login.confirmSuccess}</p>}
          {(status === "error" || (status === "idle" && (!tokenHash || !type))) && (
            <p className="login-msg">{t.login.confirmError}</p>
          )}
        </div>
      </div>
    </div>
  );
}
