import { useState } from "react";
import { joinWaitlist } from "../lib/api.js";

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
      <div className="card" style={{ padding: "1.5rem" }}>
        <h3 style={{ margin: "0 0 0.3rem" }}>In arrivo</h3>
        <p style={{ color: "var(--text-muted)", fontSize: "0.88rem", margin: 0 }}>
          Badge sempre aggiornato nel README, correzioni automatiche via pull request, controllo delle impostazioni
          Supabase, CLI e server MCP.
        </p>
        <form className="waitlist-form" onSubmit={handleSubmit}>
          <input
            type="email"
            required
            placeholder="tua@email.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <button type="submit" className="btn btn-primary" disabled={status === "sending"}>
            Unisciti alla lista
          </button>
        </form>
        {status === "done" && <p className="waitlist-msg">✓ Sei in lista!</p>}
        {status === "error" && <p className="waitlist-msg">Qualcosa è andato storto, riprova.</p>}
      </div>
    </section>
  );
}
