export function Hero() {
  function scrollToAnalyzer() {
    document.getElementById("analyzer")?.scrollIntoView({ behavior: "smooth" });
  }

  return (
    <section className="hero container">
      <h1>
        Il tuo agente AI scrive codice ogni giorno.
        <br />
        <span className="blue-highlight">
          <span className="font-logo">JoJoX</span> lo sorveglia.
        </span>
      </h1>

      <p>
        Non un controllo una tantum. <span className="marker-highlight">Monitoraggio continuo</span>. 21 controlli
        pubblici sugli errori più comuni nel codice scritto dall'IA, un{" "}
        <span className="marker-highlight">punteggio di sicurezza</span> chiaro, e correzioni pronte da copiare.
      </p>
      <p className="hero-sub">Le verifiche che normalmente richiedono ore, automatizzate e sempre attive.</p>

      <div className="hero-pills">
        <span className="pill pill-mint">100% nel browser*</span>
        <span className="sep">·</span>
        <span className="pill pill-amber">Nessuna registrazione</span>
        <span className="sep">·</span>
        <span className="pill pill-plain">Gratis</span>
      </div>

      <p className="hero-badge">Per progetti costruiti con Claude Code · Cursor · Lovable · Bolt</p>

      <div className="hero-actions">
        <button type="button" className="btn btn-primary shine hard-border hard-shadow" onClick={scrollToAnalyzer}>
          Analizza il tuo codice — gratis
        </button>
        <button type="button" className="btn btn-secondary hard-border hard-shadow-sm" onClick={scrollToAnalyzer}>
          Prova senza registrarti
        </button>
      </div>
      <p className="hero-guest-note">Modalità ospite: 1 analisi gratuita, senza account.</p>
    </section>
  );
}