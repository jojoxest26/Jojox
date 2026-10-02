import { MAVEN_DEPENDENCY_LIST_COMMAND, MAVEN_DEPENDENCY_LIST_FILENAME } from "../../../src/depscan.js";
import { useTranslation } from "../i18n/LanguageContext.js";
import { renderWithTokens } from "../i18n/richText.js";

export function MavenCheckSection() {
  const { t } = useTranslation();

  return (
    <section className="supabase-check-section container">
      <div className="card supabase-check-card">
        <div className="supabase-check-title">
          <h2>{t.maven.title}</h2>
          <span className="pill pill-mint">{t.maven.badge}</span>
        </div>
        <p>{t.maven.body1}</p>
        <p>
          {renderWithTokens(t.maven.body2, {
            filename: <code>{MAVEN_DEPENDENCY_LIST_FILENAME}</code>,
          })}
        </p>
        <pre className="supabase-check-snippet">{MAVEN_DEPENDENCY_LIST_COMMAND}</pre>
      </div>
    </section>
  );
}