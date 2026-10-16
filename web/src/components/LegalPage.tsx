import type { MouseEvent } from "react";
import { LanguageSwitcher } from "./Header.js";
import { useTranslation } from "../i18n/LanguageContext.js";
import { legalPages, type LegalDoc, type LegalLang } from "../i18n/legalPages.js";

function goHome(e: MouseEvent) {
  e.preventDefault();
  window.history.pushState({}, "", "/");
  window.dispatchEvent(new PopStateEvent("popstate"));
}

// Le pagine legali esistono solo in IT/EN: le altre lingue del sito usano
// l'inglese come ripiego invece di un testo legale mancante.
function useLegalLang(): LegalLang {
  const { lang } = useTranslation();
  return lang === "it" ? "it" : "en";
}

function LegalDocView({ doc }: { doc: LegalDoc }) {
  return (
    // Testo legale esiste solo in IT/EN (mai RTL): forziamo ltr qui anche se
    // la lingua del sito è RTL (arabo/urdu), altrimenti questo testo inglese
    // di fallback verrebbe mostrato specchiato e illeggibile.
    <article className="legal-doc" dir="ltr">
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
  const lang = useLegalLang();
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
  const lang = useLegalLang();
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

export function SecurityPolicyPage() {
  const lang = useLegalLang();
  return (
    <div className="legal-page">
      <div className="container legal-page-nav">
        <a href="/" onClick={goHome} className="legal-back">
          {legalPages[lang].backHome}
        </a>
        <LanguageSwitcher />
      </div>
      <div className="container">
        <LegalDocView doc={legalPages[lang].security} />
      </div>
    </div>
  );
}