import { useTranslation } from "../i18n/LanguageContext.js";
import { SupabaseCheckSection } from "./SupabaseCheckSection.js";
import { MavenCheckSection } from "./MavenCheckSection.js";
import { AwsIamCheckSection } from "./AwsIamCheckSection.js";
import { AwsS3CheckSection } from "./AwsS3CheckSection.js";

export function CloudChecksSection() {
  const { t } = useTranslation();

  return (
    <>
      <div className="section-divider container">
        <div className="trace"></div>
        <span className="tag">{t.dividers.cloudChecks}</span>
        <div className="trace right"></div>
      </div>
      <section className="cloud-checks-section container">
        <p className="section-eyebrow">{t.dividers.cloudChecks}</p>
        <h2 className="section-title">{t.cloudChecks.title}</h2>
        <p className="section-subtitle">{t.cloudChecks.subtitle}</p>
        <div className="cloud-checks-grid">
          <SupabaseCheckSection />
          <MavenCheckSection />
          <AwsIamCheckSection />
          <AwsS3CheckSection />
        </div>
      </section>
    </>
  );
}
