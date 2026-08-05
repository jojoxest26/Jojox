import { useEffect, useState } from "react";
import type { Session } from "@supabase/supabase-js";
import { fetchHistory, type AnalysisHistoryEntry } from "../lib/api.js";

export function HistoryPanel({ session }: { session: Session }) {
  const [history, setHistory] = useState<AnalysisHistoryEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchHistory(session.access_token)
      .then(setHistory)
      .catch((err) => setError(err instanceof Error ? err.message : "Errore nel caricamento dello storico"));
  }, [session.access_token]);

  if (error) return null;
  if (!history || history.length === 0) return null;

  return (
    <section className="history-section container">
      <div className="card" style={{ padding: "1.25rem 1.5rem" }}>
        <h3 style={{ margin: "0 0 0.5rem" }}>Il tuo storico</h3>
        {history.map((entry) => (
          <div key={entry.id} className="history-row">
            <span>
              {entry.source === "github" ? entry.repo_full_name : "Analisi manuale"} —{" "}
              {new Date(entry.created_at).toLocaleDateString("it-IT")}
            </span>
            <strong>{entry.score}/100</strong>
          </div>
        ))}
      </div>
    </section>
  );
}
