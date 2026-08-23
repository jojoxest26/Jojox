import { useState } from "react";
import { supabase } from "../lib/supabaseClient.js";
import { useTranslation } from "../i18n/LanguageContext.js";

export function LoginPanel({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation();
  const [email, setEmail] = useState("");
  const [status, setStatus] = useState<"idle" | "sending" | "sent" | "error">("idle");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setStatus("sending");
    const { error } = await supabase.auth.signInWithOtp({ email, options: { emailRedirectTo: window.location.origin } });
    setStatus(error ? "error" : "sent");
  }

  return (
    <div className="login-panel card">
      {status === "sent" ? (
        <p className="login-msg">{t.login.sent}</p>
      ) : (
        <form onSubmit={handleSubmit}>
          <p className="login-msg">{t.login.prompt}</p>
          <input
            type="email"
            required
            placeholder="tua@email.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <button type="submit" className="btn btn-primary" disabled={status === "sending"} style={{ width: "100%" }}>
            {status === "sending" ? t.login.sending : t.login.send}
          </button>
          {status === "error" && <p className="login-msg">{t.login.error}</p>}
        </form>
      )}
      <button type="button" onClick={onClose} className="btn btn-secondary" style={{ width: "100%", marginTop: "0.5rem" }}>
        {t.login.close}
      </button>
    </div>
  );
}