const GITHUB_APP_SLUG = import.meta.env.VITE_GITHUB_APP_SLUG;

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
      </div>
    </section>
  );
}