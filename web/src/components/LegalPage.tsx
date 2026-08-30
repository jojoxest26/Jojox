import type { MouseEvent } from "react";
import { LanguageSwitcher } from "./Header.js";
import { useTranslation } from "../i18n/LanguageContext.js";
import { legalPages, type LegalDoc } from "../i18n/legalPages.js";

function goHome(e: MouseEvent) {
  e.preventDefault();
  window.history.pushState({}, "", "/");
  window.dispatchEvent(new PopStateEvent("popstate"));
}

function LegalDocView({ doc }: { doc: LegalDoc }) {
  return (
    <article className="legal-doc">
      <h1>{doc.title}</h1>
      <p className="legal-updated">{doc.lastUpdated}</p>
      <p className="legal-intro">{doc.intro}</p>
      {doc.sections.map((section) => (
        <section key={section.heading}>
          <h2>{section.heading}</h2>
          {section.blocks.map((block, i) =>
            block.type === "p" ? (
              <p key={i}>{block.text}</p>
            ) : (
              <ul key={i}>
                {block.items.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            )
          )}
        </section>
      ))}
    </article>
  );
}

export function PrivacyPolicyPage() {
  const { lang } = useTranslation();
  return (
    <div className="legal-page">
      <div className="container legal-page-nav">
        <a href="/" onClick={goHome} className="legal-back">
          {legalPages[lang].backHome}
        </a>
        <LanguageSwitcher />
      </div>
      <div className="container">
        <LegalDocView doc={legalPages[lang].privacy} />
      </div>
    </div>
  );
}

export function TermsOfServicePage() {
  const { lang } = useTranslation();
  return (
    <div className="legal-page">
      <div className="container legal-page-nav">
        <a href="/" onClick={goHome} className="legal-back">
          {legalPages[lang].backHome}
        </a>
        <LanguageSwitcher />
      </div>
      <div className="container">
        <LegalDocView doc={legalPages[lang].terms} />
      </div>
    </div>
  );
}
