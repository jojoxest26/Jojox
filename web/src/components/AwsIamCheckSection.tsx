import { AWS_IAM_SNAPSHOT_COMMAND, AWS_IAM_SNAPSHOT_FILENAME } from "../../../src/cloudConfigChecks.js";
import { useTranslation } from "../i18n/LanguageContext.js";
import { renderWithTokens } from "../i18n/richText.js";

export function AwsIamCheckSection() {
  const { t } = useTranslation();

  return (
    <section className="supabase-check-section container">
      <div className="card supabase-check-card">
        <div className="supabase-check-title">
          <h2>{t.awsIam.title}</h2>
          <span className="pill pill-mint">{t.awsIam.badge}</span>
        </div>
        <p>{t.awsIam.body1}</p>
        <p>
          {renderWithTokens(t.awsIam.body2, {
            filename: <code>{AWS_IAM_SNAPSHOT_FILENAME}</code>,
          })}
        </p>
        <pre className="supabase-check-snippet">{AWS_IAM_SNAPSHOT_COMMAND}</pre>
      </div>
    </section>
  );
}