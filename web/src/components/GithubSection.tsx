import { useEffect, useState } from "react";
import type { Session } from "@supabase/supabase-js";
import { fetchGithubInstallations, saveSlackWebhook, type GithubInstallation } from "../lib/api.js";

const GITHUB_APP_SLUG = import.meta.env.VITE_GITHUB_APP_SLUG;
const API_URL = import.meta.env.VITE_API_URL;

function SlackWebhookForm({ installation, session }: { installation: GithubInstallation; session: Session }) {
  const [value, setValue] = useState(installation.slack_webhook_url ?? "");
  const [status, setStatus] = useState<"idle" | "saving" | "saved" | "error">("idle");
  const [error, setError] = useState<string | null>(null);

  async function handleSave() {
    setStatus("saving");
    setError(null);
    try {
      await saveSlackWebhook(installation.installation_id, value.trim() || null, session.access_token);
      setStatus("saved");
    } catch (err) {
      setStatus("error");
      setError(err instanceof Error ? err.message : "Errore nel salvataggio");
    }
  }

  return (
    <div className="slack-webhook-row">
      <label className="slack-webhook-label" htmlFor={`slack-${installation.installation_id}`}>
        {installation.account_login}
      </label>
      <div className="slack-webhook-input-row">
        <input
          id={`slack-${installation.installation_id}`}
          type="url"
          placeholder="https://hooks.slack.com/services/..."
          value={value}
          onChange={(e) => {
            setValue(e.target.value);
            setStatus("idle");
          }}
        />
        <button type="button" className="btn btn-secondary hard-border hard-shadow-sm" onClick={handleSave} disabled={status === "saving"}>
          {status === "saving" ? "Salvataggio..." : "Salva"}
        </button>
      </div>
      {status === "saved" && <p className="slack-webhook-msg">✓ Salvato</p>}
      {status === "error" && <p className="slack-webhook-msg slack-webhook-msg-error">{error}</p>}
    </div>
  );
}

function SlackNotifications({ session }: { session: Session }) {
  const [installations, setInstallations] = useState<GithubInstallation[] | null>(null);

  useEffect(() => {
    fetchGithubInstallations(session.access_token)
      .then(setInstallations)
      .catch(() => setInstallations([]));
  }, [session.access_token]);

  return (
    <div className="github-badge-howto">
      <p className="github-badge-title">🔔 Notifiche su Slack</p>
      {!installations || installations.length === 0 ? (
        <p>Collega prima GitHub (bottone qui sopra) per poter impostare le notifiche Slack.</p>
      ) : (
        <>
          <p>
            Incolla qui l'URL di un{" "}
            <a href="https://api.slack.com/messaging/webhooks" target="_blank" rel="noreferrer">
              Incoming Webhook Slack
            </a>{" "}
            per ricevere un avviso sul canale del team quando una pull request viene bloccata o corretta in
            automatico:
          </p>
          {installations.map((installation) => (
            <SlackWebhookForm key={installation.installation_id} installation={installation} session={session} />
          ))}
        </>
      )}
    </div>
  );
}

export function GithubSection({ session }: { session: Session | null }) {
  const [showDetails, setShowDetails] = useState(false);

  return (
    <section className="github-section container">
      <div className="card github-card">
        <div className="github-title">
          <h2>GitHub App + CI</h2>
          <span className="pill pill-amber">DISPONIBILE</span>
        </div>
        <p>
          Collega GitHub. A ogni push e a ogni pull request JoJoX controlla il codice. Se trova un problema critico,
          blocca la pull request e lascia un commento chiaro con il riepilogo.
        </p>
        <p>
          Basta impostarlo come controllo obbligatorio nelle impostazioni del branch: le modifiche rischiose non
          potranno più essere unite.
        </p>
        <p className="github-note">
          Stesso motore dell'analisi manuale, nessun LLM. Gira sui nostri server per poter intervenire in automatico
          a ogni push.
        </p>
        <a
          className="btn btn-primary"
          href={`https://github.com/apps/${GITHUB_APP_SLUG}/installations/new`}
          target="_blank"
          rel="noreferrer"
        >
          Collega GitHub
        </a>

        <button
          type="button"
          className="supabase-check-toggle github-details-toggle"
          onClick={() => setShowDetails((v) => !v)}
        >
          {showDetails ? "▲ Nascondi dettagli avanzati" : "▼ Vedi anche: notifiche Slack, badge, CLI e agenti AI"}
        </button>

        {showDetails && (
          <>
            <div className="github-badge-howto">
              <p className="github-badge-title">🏷️ Badge sempre aggiornato nel README</p>
              <p>
                Dopo aver collegato il repository, incolla questa riga nel tuo <code>README.md</code> (sostituisci{" "}
                <code>proprietario/repo</code> con i tuoi) — il punteggio si aggiorna da solo a ogni analisi, senza
                bisogno di rigenerarlo a mano:
              </p>
              <pre className="github-badge-snippet">
                {`![JoJoX](${API_URL}/badge/proprietario/repo.svg)`}
              </pre>
            </div>

            <div className="github-badge-howto">
              <p className="github-badge-title">🖥️ Anche da terminale e per agenti AI</p>
              <p>
                JoJoX si può usare anche senza sito: da riga di comando (con <code>--fix</code> per correggere in
                automatico) o come strumento MCP per Claude Code e altri agenti AI, che così possono controllarsi da
                soli mentre scrivono codice. Istruzioni complete nel{" "}
                <a href="https://github.com/jojoxest26/Jojox#uso" target="_blank" rel="noreferrer">
                  README del repository
                </a>
                .
              </p>
            </div>

            <div className="github-badge-howto">
              <p className="github-badge-title">🪝 Blocco commit in locale</p>
              <p>
                Un comando da terminale (<code>install-hook</code>) installa un controllo che ferma il commit sul tuo
                computer, prima ancora che il codice arrivi su GitHub, se trova un problema critico — così il
                problema non entra mai nella cronologia del repository.
              </p>
            </div>

            {session && <SlackNotifications session={session} />}
          </>
        )}
      </div>
    </section>
  );
}