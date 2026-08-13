import { useState } from "react";
import { SUPABASE_SNAPSHOT_FILENAME, SUPABASE_SNAPSHOT_QUERY } from "../../../src/analyze.js";

export function SupabaseCheckSection() {
  const [showQuery, setShowQuery] = useState(false);

  return (
    <section className="supabase-check-section container">
      <div className="card supabase-check-card">
        <div className="supabase-check-title">
          <h2>Controllo Supabase</h2>
          <span className="pill pill-mint">DISPONIBILE</span>
        </div>
        <p>
          Gli altri controlli leggono il codice e deducono cosa dovrebbe succedere a runtime. Questo invece si
          collega al tuo vero progetto Supabase e verifica cosa succede davvero: Row Level Security attiva o no,
          almeno una policy presente, bucket di storage pubblici o privati.
        </p>
        <p>
          Non ti chiediamo mai le tue credenziali Supabase. Esegui tu stesso questa query di sola lettura (nessuna
          scrittura possibile) nell'<strong>SQL Editor</strong> del tuo progetto, copia il risultato in un file
          chiamato esattamente <code>{SUPABASE_SNAPSHOT_FILENAME}</code>, e caricalo insieme al resto del codice
          nell'analyzer qui sopra — i risultati si aggiungono automaticamente a quelli degli altri 21 controlli.
        </p>
        <button type="button" className="supabase-check-toggle" onClick={() => setShowQuery((v) => !v)}>
          {showQuery ? "▲ Nascondi la query" : "▼ Mostra la query"}
        </button>
        {showQuery && <pre className="supabase-check-snippet">{SUPABASE_SNAPSHOT_QUERY}</pre>}
      </div>
    </section>
  );
}