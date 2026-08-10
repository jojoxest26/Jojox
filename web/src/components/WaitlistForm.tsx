import { useState } from "react";
import { joinWaitlist } from "../lib/api.js";

const ROADMAP = [
  {
    icon: "🗄️",
    title: "Controllo automatico delle impostazioni Supabase",
    text: "Verifica che la configurazione reale del progetto corrisponda a quello che il codice si aspetta.",
  },
  {
    icon: "💳",
    title: "Abbonamento gestibile da solo",
    text: "Passa al piano Pro, o torna a quello gratuito, direttamente dall'app — senza scriverci.",
  },
];

export function WaitlistForm() {
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
        <h2>In arrivo</h2>
        <p>Ancora in lavorazione — te lo diciamo chiaramente, invece di fingere che esista già:</p>

        <div className="roadmap-grid">
          {ROADMAP.map((item) => (
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
            placeholder="tua@email.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <button type="submit" className="btn btn-primary hard-border hard-shadow-sm" disabled={status === "sending"}>
            Unisciti alla lista d'attesa
          </button>
        </form>
        {status === "done" && <p className="waitlist-msg">✓ Sei in lista!</p>}
        {status === "error" && <p className="waitlist-msg">Qualcosa è andato storto, riprova.</p>}
      </div>
    </section>
  );
}