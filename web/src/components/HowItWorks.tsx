import { useTranslation } from "../i18n/LanguageContext.js";

export function HowItWorks() {
  const { t } = useTranslation();

  const steps = [
    { n: "01", title: t.howItWorks.step1Title, text: t.howItWorks.step1Text },
    { n: "02", title: t.howItWorks.step2Title, text: t.howItWorks.step2Text },
    { n: "03", title: t.howItWorks.step3Title, text: t.howItWorks.step3Text },
  ];

  return (
    <>
      <div className="section-divider container">
        <div className="trace"></div>
        <span className="tag">{t.dividers.howItWorks}</span>
        <div className="trace right"></div>
      </div>
      <section className="how-it-works-section container">
        <p className="section-eyebrow">{t.howItWorks.eyebrow}</p>
        <h2 className="section-title">{t.howItWorks.title}</h2>
        <div className="how-it-works-grid">
          {steps.map((s) => (
            <div key={s.n} className="how-it-works-step">
              <span className="step-number">{s.n}</span>
              <h3>{s.title}</h3>
              <p>{s.text}</p>
            </div>
          ))}
        </div>
      </section>
    </>
  );
}