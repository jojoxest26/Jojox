import { AWS_S3_SNAPSHOT_FILENAME, AWS_S3_SNAPSHOT_SCRIPT } from "../../../src/cloudConfigChecks.js";
import { useTranslation } from "../i18n/LanguageContext.js";
import { renderWithTokens } from "../i18n/richText.js";

export function AwsS3CheckSection() {
  const { t } = useTranslation();

  return (
    <section className="supabase-check-section container">
      <div className="card supabase-check-card">
        <div className="supabase-check-title">
          <h2>{t.awsS3.title}</h2>
          <span className="pill pill-mint">{t.awsS3.badge}</span>
        </div>
        <p>{t.awsS3.body1}</p>
        <p>
          {renderWithTokens(t.awsS3.body2, {
            filename: <code>{AWS_S3_SNAPSHOT_FILENAME}</code>,
          })}
        </p>
        <pre className="supabase-check-snippet">{AWS_S3_SNAPSHOT_SCRIPT}</pre>
      </div>
    </section>
  );
}