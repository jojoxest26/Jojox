const GITHUB_APP_SLUG = import.meta.env.VITE_GITHUB_APP_SLUG;
const API_URL = import.meta.env.VITE_API_URL;

export function GithubSection() {
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
      </div>
    </section>
  );
}