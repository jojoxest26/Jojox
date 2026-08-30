import { useTranslation } from "../i18n/LanguageContext.js";

export function Footer() {
  const { t } = useTranslation();

  return (
    <footer className="footer container">
      <p>{t.footer.intro}</p>
      <ul>
        {t.footer.items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
      <div className="footer-legal-links">
        <a href="/privacy">{t.footer.privacyLink}</a>
        <span aria-hidden="true"> · </span>
        <a href="/termini">{t.footer.termsLink}</a>
      </div>
    </footer>
  );
}