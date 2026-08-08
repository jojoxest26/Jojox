function openLogin() {
  window.scrollTo({ top: 0, behavior: "smooth" });
  window.dispatchEvent(new CustomEvent("jojox-open-login"));
}

function scrollToAnalyzer() {
  document.getElementById("analyzer")?.scrollIntoView({ behavior: "smooth" });
}

export function Pricing() {
  return (
    <section className="pricing-section container">
      <h2>Paghi il monitoraggio continuo, non le singole analisi</h2>
      <p>Prova 1 analisi senza dare nulla. Poi basta l'email, nessuna password: fino a 5 analisi al mese gratis.</p>

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
        <button type="button" className="btn btn-secondary hard-border hard-shadow" onClick={scrollToAnalyzer}>
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
          <button type="button" className="btn btn-secondary hard-border hard-shadow-sm" onClick={openLogin}>
            Inizia gratis
          </button>
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
            <li>
              <span className="soon">IN ARRIVO</span>Badge che si aggiorna da solo a ogni push
            </li>
            <li>
              <span className="soon">IN ARRIVO</span>Correzioni automatiche via pull request
            </li>
          </ul>
          <button type="button" className="btn btn-primary hard-border hard-shadow-sm" onClick={openLogin}>
            Attiva Pro
          </button>
          <p className="price-card-note">Per monitoraggio continuo su ogni push</p>
        </div>

        <div className="card price-card">
          <span className="pill pill-mint price-card-badge">TEAM</span>
          <h3>Team</h3>
          <div className="price-amount">
            24,99€ <span className="per">/mese</span>
          </div>
          <ul>
            <li>✓ Tutto quello incluso nel Pro</li>
            <li>✓ Fino a 5 seat inclusi (poi 7€/seat)</li>
            <li>✓ Dashboard condivisa con lo storico di tutti i repo del team</li>
            <li>✓ Fino a 10 repo collegati alla GitHub App</li>
          </ul>
          <button type="button" className="btn btn-secondary hard-border hard-shadow-sm" onClick={openLogin}>
            Attiva Team
          </button>
          <p className="price-card-note">Per team con più repo</p>
        </div>
      </div>

      <p className="pricing-disclaimer">
        Disdici quando vuoi, senza vincoli. Le voci contrassegnate "In arrivo" sono ancora in lavorazione: se attivi
        il Pro, sai già cosa stai finanziando.{" "}
        <span>(Per ora Pro e Team vanno attivati a mano, finché non colleghiamo un sistema di pagamento automatico.)</span>
      </p>
    </section>
  );
}