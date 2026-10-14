import { useState } from "react";
import { AWS_S3_SNAPSHOT_FILENAME, AWS_S3_SNAPSHOT_SCRIPT } from "../../../src/cloudConfigChecks.js";
import { useTranslation } from "../i18n/LanguageContext.js";
import { renderWithTokens } from "../i18n/richText.js";
import { Icon } from "./Icon.js";

export function AwsS3CheckSection() {
  const { t } = useTranslation();
  const [show, setShow] = useState(false);

  return (
    <div className="card cloud-check-card">
      <div className="cloud-check-icon">
        <Icon name="bucket" />
      </div>
      <div className="supabase-check-title">
        <h3>{t.awsS3.title}</h3>
        <span className="pill pill-mint">{t.awsS3.badge}</span>
      </div>
      <p>{t.awsS3.body1}</p>
      <button type="button" className="supabase-check-toggle" onClick={() => setShow((v) => !v)}>
        {show ? t.common.hideCommand : t.common.showCommand}
      </button>
      {show && (
        <>
          <p>
            {renderWithTokens(t.awsS3.body2, {
              filename: <code>{AWS_S3_SNAPSHOT_FILENAME}</code>,
            })}
          </p>
          <pre className="supabase-check-snippet">{AWS_S3_SNAPSHOT_SCRIPT}</pre>
        </>
      )}
    </div>
  );
}
