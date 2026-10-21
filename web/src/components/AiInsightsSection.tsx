import { useState } from "react";
import type { Session } from "@supabase/supabase-js";
import type { AiInsight, SourceFile } from "../../../src/types.js";
import { fetchAiInsights, ApiError } from "../lib/api.js";
import { useTranslation } from "../i18n/LanguageContext.js";
import { Icon } from "./Icon.js";

type Status = "idle" | "loading" | "done" | "error";

/**
 * Punto 14 della roadmap: livello AI aggiuntivo, separato dai 61 controlli
 * deterministici (mai un numero che si somma al loro, mai un autofix da
 * solo). Sempre dietro un clic esplicito — mai lanciata insieme all'analisi
 * normale — così resta chiaro che è un livello a parte, non un 56° controllo.
 */
export function AiInsightsSection({ files, session }: { files: SourceFile[]; session: Session }) {
  const { t } = useTranslation();
  const [status, setStatus] = useState<Status>("idle");
  const [insights, setInsights] = useState<AiInsight[] | null>(null);
  const [gated, setGated] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  async function run() {
    setStatus("loading");
    setErrorMsg(null);
    setGated(false);
    try {
      const { insights: result } = await fetchAiInsights(files, session.access_token);
      setInsights(result);
      setStatus("done");
    } catch (err) {
      if (err instanceof ApiError && err.requiresPlan) {
        setGated(true);
      } else {
        setErrorMsg(err instanceof Error ? err.message : t.aiInsights.error);
      }
      setStatus("error");
    }
  }

  return (
    <div className="card ai-insights-card">
      <div className="ai-insights-head">
        <Icon name="brain" />
        <strong>{t.aiInsights.sectionTitle}</strong>
      </div>
      <p className="ai-insights-subtitle">{t.aiInsights.sectionSubtitle}</p>

      {status === "idle" && (
        <button type="button" className="btn btn-secondary hard-border hard-shadow-sm" onClick={run}>
          {t.aiInsights.button}
        </button>
      )}

      {status === "loading" && <p className="ai-insights-status">{t.aiInsights.loading}</p>}

      {status === "error" && gated && (
        <div className="ai-insights-gate">
          <strong>{t.aiInsights.gateTitle}</strong>
          <p>{t.aiInsights.gateBody}</p>
          <a href="/#pricing" className="btn btn-primary hard-border hard-shadow-sm">
            {t.aiInsights.gateCta}
          </a>
        </div>
      )}

      {status === "error" && !gated && (
        <>
          <p className="ai-insights-status" style={{ color: "var(--critical)" }}>
            {errorMsg}
          </p>
          <button type="button" className="btn btn-secondary hard-border hard-shadow-sm" onClick={run}>
            {t.aiInsights.button}
          </button>
        </>
      )}

      {status === "done" && insights && (
        <>
          {insights.length === 0 ? (
            <p className="ai-insights-status">{t.aiInsights.emptyState}</p>
          ) : (
            <div className="ai-insights-list">
              {insights.map((insight, i) => (
                <div key={i} className="ai-insight-item">
                  <div className="ai-insight-item-head">
                    <span className="pill">
                      {insight.category === "race-condition"
                        ? t.aiInsights.categoryRaceCondition
                        : t.aiInsights.categoryAuthorizationLogic}
                    </span>
                    <strong>{insight.title}</strong>
                  </div>
                  <p className="ai-insight-file">{insight.file}</p>
                  <p>{insight.explanation}</p>
                </div>
              ))}
            </div>
          )}
          <p className="ai-insights-disclaimer">{t.aiInsights.disclaimer}</p>
        </>
      )}
    </div>
  );
}
