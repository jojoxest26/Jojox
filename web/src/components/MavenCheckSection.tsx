import { useState } from "react";
import { MAVEN_DEPENDENCY_LIST_COMMAND, MAVEN_DEPENDENCY_LIST_FILENAME } from "../../../src/depscan.js";
import { useTranslation } from "../i18n/LanguageContext.js";
import { renderWithTokens } from "../i18n/richText.js";
import { Icon } from "./Icon.js";

export function MavenCheckSection() {
  const { t } = useTranslation();
  const [show, setShow] = useState(false);

  return (
    <div className="card cloud-check-card">
      <div className="cloud-check-icon">
        <Icon name="package" />
      </div>
      <div className="supabase-check-title">
        <h3>{t.maven.title}</h3>
        <span className="pill pill-mint">{t.maven.badge}</span>
      </div>
      <p>{t.maven.body1}</p>
      <button type="button" className="supabase-check-toggle" onClick={() => setShow((v) => !v)}>
        {show ? t.common.hideCommand : t.common.showCommand}
      </button>
      {show && (
        <>
          <p>
            {renderWithTokens(t.maven.body2, {
              filename: <code>{MAVEN_DEPENDENCY_LIST_FILENAME}</code>,
            })}
          </p>
          <pre className="supabase-check-snippet">{MAVEN_DEPENDENCY_LIST_COMMAND}</pre>
        </>
      )}
    </div>
  );
}
