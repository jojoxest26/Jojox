import { useState } from "react";
import { SUPABASE_SNAPSHOT_FILENAME, SUPABASE_SNAPSHOT_QUERY } from "../../../src/analyze.js";
import { useTranslation } from "../i18n/LanguageContext.js";
import { renderWithTokens } from "../i18n/richText.js";

export function SupabaseCheckSection() {
  const { t } = useTranslation();
  const [showQuery, setShowQuery] = useState(false);

  return (
    <section className="supabase-check-section container">
      <div className="card supabase-check-card">
        <div className="supabase-check-title">
          <h2>{t.supabase.title}</h2>
          <span className="pill pill-mint">{t.supabase.badge}</span>
        </div>
        <p>{t.supabase.body1}</p>
        <p>
          {renderWithTokens(t.supabase.body2, {
            sqlEditor: <strong>{t.supabase.sqlEditor}</strong>,
            filename: <code>{SUPABASE_SNAPSHOT_FILENAME}</code>,
          })}
        </p>
        <button type="button" className="supabase-check-toggle" onClick={() => setShowQuery((v) => !v)}>
          {showQuery ? t.supabase.toggleHide : t.supabase.toggleShow}
        </button>
        {showQuery && <pre className="supabase-check-snippet">{SUPABASE_SNAPSHOT_QUERY}</pre>}
      </div>
    </section>
  );
}