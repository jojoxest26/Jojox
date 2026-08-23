import { useState } from "react";
import { joinWaitlist } from "../lib/api.js";
import { useTranslation } from "../i18n/LanguageContext.js";

export function WaitlistForm() {
  const { t } = useTranslation();
  const [email, setEmail] = useState("");
  const [status, setStatus] = useState<"idle" | "sending" | "done" | "error">("idle");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setStatus("sending");
    try {
      await joinWaitlist(email);
      setStatus("done");
      setEmail("");
    } catch {
      setStatus("error");
    }
  }

  return (
    <section className="waitlist-section container">
      <div className="card waitlist-card">
        <h2>{t.waitlist.title}</h2>
        <p>{t.waitlist.subtitle}</p>

        <div className="roadmap-grid">
          {t.waitlist.roadmap.map((item) => (
            <div key={item.title} className="roadmap-item">
              <p>
                {item.icon} {item.title}
              </p>
              <p>{item.text}</p>
            </div>
          ))}
        </div>

        <form className="waitlist-form" onSubmit={handleSubmit}>
          <input
            type="email"
            required
            placeholder={t.waitlist.emailPlaceholder}
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <button type="submit" className="btn btn-primary hard-border hard-shadow-sm" disabled={status === "sending"}>
            {t.waitlist.submit}
          </button>
        </form>
        {status === "done" && <p className="waitlist-msg">{t.waitlist.done}</p>}
        {status === "error" && <p className="waitlist-msg">{t.waitlist.error}</p>}
      </div>
    </section>
  );
}