import { useState } from "react";
import { SUPABASE_SNAPSHOT_FILENAME, SUPABASE_SNAPSHOT_QUERY } from "../../../src/analyze.js";
import { useTranslation } from "../i18n/LanguageContext.js";
import { renderWithTokens } from "../i18n/richText.js";
import { Icon } from "./Icon.js";

export function SupabaseCheckSection() {
  const { t } = useTranslation();
  const [showQuery, setShowQuery] = useState(false);

  return (
    <div className="card cloud-check-card">
      <div className="cloud-check-icon">
        <Icon name="database" />
      </div>
      <div className="supabase-check-title">
        <h3>{t.supabase.title}</h3>
        <span className="pill pill-mint">{t.supabase.badge}</span>
      </div>
      <p>{t.supabase.body1}</p>
      <button type="button" className="supabase-check-toggle" onClick={() => setShowQuery((v) => !v)}>
        {showQuery ? t.supabase.toggleHide : t.supabase.toggleShow}
      </button>
      {showQuery && (
        <>
          <p>
            {renderWithTokens(t.supabase.body2, {
              sqlEditor: <strong>{t.supabase.sqlEditor}</strong>,
              filename: <code>{SUPABASE_SNAPSHOT_FILENAME}</code>,
            })}
          </p>
          <pre className="supabase-check-snippet">{SUPABASE_SNAPSHOT_QUERY}</pre>
        </>
      )}
    </div>
  );
}
