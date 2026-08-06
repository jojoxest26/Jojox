const FEATURES = [
  {
    icon: "🛡️",
    title: "L'analisi manuale avviene nel tuo browser",
    text: "Quando carichi il codice a mano, non lascia mai il tuo computer: nessuno lo vede tranne te. (L'integrazione GitHub, invece, analizza il codice sui nostri server — vedi sotto.)",
  },
  {
    icon: "🔧",
    title: "Non solo l'errore, anche come risolverlo",
    text: "Ogni problema è accompagnato da un esempio di correzione, mostrato come un prima/dopo: capisci subito cosa cambiare.",
  },
  {
    icon: "📊",
    title: "Punteggio di sicurezza + badge",
    text: "Un punteggio da 0 a 100, calcolato con una formula che vedi per intero, più un badge da mettere nel README del progetto.",
  },
];

export function Features() {
  return (
    <section className="features-section container">
      <div className="features-grid">
        {FEATURES.map((f) => (
          <div key={f.title} className="card feature-card lift">
            <div className="feature-icon">{f.icon}</div>
            <h3>{f.title}</h3>
            <p>{f.text}</p>
          </div>
        ))}
      </div>
    </section>
  );
}