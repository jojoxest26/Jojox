const FEATURES = [
  {
    icon: "🛡️",
    accent: "blue",
    title: "Il codice non viene mai salvato",
    text: "L'analisi che carichi a mano passa dai nostri server (per salvare punteggio e storico), ma il testo dei file non viene mai conservato — solo i risultati. Le correzioni automatiche, invece, restano sempre e solo nel tuo browser.",
  },
  {
    icon: "🔧",
    accent: "amber",
    title: "Non solo l'errore, anche come risolverlo",
    text: "Ogni problema è accompagnato da un esempio di correzione, mostrato come un prima/dopo: capisci subito cosa cambiare.",
  },
  {
    icon: "📊",
    accent: "mint",
    title: "Punteggio di sicurezza + badge",
    text: "Un punteggio da 0 a 100, calcolato con una formula che vedi per intero, più un badge da mettere nel README del progetto.",
  },
];

export function Features() {
  return (
    <section className="features-section container">
      <div className="features-grid">
        {FEATURES.map((f) => (
          <div key={f.title} className={`card feature-card feature-card-${f.accent} lift`}>
            <div className="feature-icon">{f.icon}</div>
            <h3>{f.title}</h3>
            <p>{f.text}</p>
          </div>
        ))}
      </div>
    </section>
  );
}