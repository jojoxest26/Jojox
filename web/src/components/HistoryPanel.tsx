import { useEffect, useState } from "react";
import type { Session } from "@supabase/supabase-js";
import { fetchHistory, type AnalysisHistoryEntry } from "../lib/api.js";
import { ScoreHistoryChart } from "./ScoreHistoryChart.js";
import { useTranslation } from "../i18n/LanguageContext.js";

export function HistoryPanel({ session, refreshKey }: { session: Session; refreshKey?: number }) {
  const { t } = useTranslation();
  const [history, setHistory] = useState<AnalysisHistoryEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchHistory(session.access_token)
      .then(setHistory)
      .catch((err) => setError(err instanceof Error ? err.message : t.history.error));
  }, [session.access_token, refreshKey, t.history.error]);

  if (error) return null;
  if (!history || history.length === 0) return null;

  return (
    <section className="history-section container">
      <div className="card" style={{ padding: "1.25rem 1.5rem" }}>
        <ScoreHistoryChart history={history} />
        <h3 style={{ margin: "0 0 0.5rem" }}>{t.history.title}</h3>
        {history.map((entry) => (
          <div key={entry.id} className="history-row">
            <span>
              {entry.source === "github" ? entry.repo_full_name : t.history.manualSource} —{" "}
              {new Date(entry.created_at).toLocaleDateString(t.meta.dateLocale)}
            </span>
            <strong>{entry.score}/100</strong>
          </div>
        ))}
      </div>
    </section>
  );
}