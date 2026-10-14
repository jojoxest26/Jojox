import { useState } from "react";
import { AWS_IAM_SNAPSHOT_COMMAND, AWS_IAM_SNAPSHOT_FILENAME } from "../../../src/cloudConfigChecks.js";
import { useTranslation } from "../i18n/LanguageContext.js";
import { renderWithTokens } from "../i18n/richText.js";
import { Icon } from "./Icon.js";

export function AwsIamCheckSection() {
  const { t } = useTranslation();
  const [show, setShow] = useState(false);

  return (
    <div className="card cloud-check-card">
      <div className="cloud-check-icon">
        <Icon name="key" />
      </div>
      <div className="supabase-check-title">
        <h3>{t.awsIam.title}</h3>
        <span className="pill pill-mint">{t.awsIam.badge}</span>
      </div>
      <p>{t.awsIam.body1}</p>
      <button type="button" className="supabase-check-toggle" onClick={() => setShow((v) => !v)}>
        {show ? t.common.hideCommand : t.common.showCommand}
      </button>
      {show && (
        <>
          <p>
            {renderWithTokens(t.awsIam.body2, {
              filename: <code>{AWS_IAM_SNAPSHOT_FILENAME}</code>,
            })}
          </p>
          <pre className="supabase-check-snippet">{AWS_IAM_SNAPSHOT_COMMAND}</pre>
        </>
      )}
    </div>
  );
}
