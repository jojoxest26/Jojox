const GITHUB_APP_SLUG = import.meta.env.VITE_GITHUB_APP_SLUG;

export function Pricing() {
  return (
    <section className="pricing-section container">
      <h2 style={{ textAlign: "center", fontSize: "1.6rem", fontWeight: 800 }}>
        Paghi il monitoraggio continuo, non le singole analisi
      </h2>
      <p style={{ textAlign: "center", color: "var(--text-muted)", maxWidth: 560, margin: "0.5rem auto 0" }}>
        Analizzare il codice è sempre gratis. Il piano a pagamento serve solo se vuoi tenerlo sotto controllo senza
        limiti.
      </p>
      <div className="pricing-grid">
        <div className="card price-card">
          <h3>Ospite</h3>
          <div className="price-amount">Gratis</div>
          <ul>
            <li>✓ Analisi illimitate nel browser</li>
            <li>✓ Tutti i 21 controlli con esempi di correzione</li>
            <li>✓ Punteggio di sicurezza</li>
            <li>✓ Niente viene salvato, niente lascia il tuo browser</li>
          </ul>
        </div>
        <div className="card price-card">
          <h3>Free</h3>
          <div className="price-amount">0€</div>
          <ul>
            <li>✓ 5 analisi al mese salvate nello storico</li>
            <li>✓ Tutti i 21 controlli, con esempi di correzione</li>
            <li>✓ Punteggio di sicurezza</li>
            <li>✓ Cronologia delle ultime 20 analisi</li>
          </ul>
        </div>
        <div className="card price-card">
          <h3>Pro</h3>
          <div className="price-amount">9,99€ /mese</div>
          <ul>
            <li>✓ Analisi e cronologia illimitate</li>
            <li>✓ Integrazione GitHub: controlla ogni push e blocca le modifiche rischiose</li>
            <li>✓ Commenti automatici sulle pull request</li>
          </ul>
          <a
            className="btn btn-secondary"
            href={`https://github.com/apps/${GITHUB_APP_SLUG}/installations/new`}
            target="_blank"
            rel="noreferrer"
            style={{ width: "100%" }}
          >
            Collega GitHub
          </a>
        </div>
      </div>
    </section>
  );
}
