export function Hero() {
  function scrollToAnalyzer() {
    document.getElementById("analyzer")?.scrollIntoView({ behavior: "smooth" });
  }

  return (
    <section className="hero container">
      <h1>Il tuo agente AI scrive codice ogni giorno. JoJoX lo sorveglia.</h1>
      <p>
        21 controlli pubblici sugli errori più comuni nel codice scritto dall'IA, un punteggio di sicurezza chiaro, e
        correzioni pronte da copiare. 100% nel browser, nessuna registrazione richiesta per provare.
      </p>
      <button type="button" className="btn btn-primary" onClick={scrollToAnalyzer}>
        Analizza il tuo codice — gratis
      </button>
      <div className="hero-badge">Per progetti costruiti con Claude Code · Cursor · Lovable · Bolt</div>
    </section>
  );
}
