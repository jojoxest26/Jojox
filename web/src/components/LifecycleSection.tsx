import { useTranslation } from "../i18n/LanguageContext.js";
import { Icon } from "./Icon.js";

export function LifecycleSection() {
  const { t } = useTranslation();

  const steps = [
    { icon: "terminal", title: t.lifecycle.step1Title, text: t.lifecycle.step1Text },
    { icon: "gitBranch", title: t.lifecycle.step2Title, text: t.lifecycle.step2Text },
    { icon: "webhook", title: t.lifecycle.step3Title, text: t.lifecycle.step3Text },
    { icon: "rocket", title: t.lifecycle.step4Title, text: t.lifecycle.step4Text },
    { icon: "shield", title: t.lifecycle.step5Title, text: t.lifecycle.step5Text },
  ];

  return (
    <>
      <div className="section-divider container">
        <div className="trace"></div>
        <span className="tag">{t.dividers.lifecycle}</span>
        <div className="trace right"></div>
      </div>
      <section className="lifecycle-section container">
        <p className="section-eyebrow">{t.lifecycle.eyebrow}</p>
        <h2 className="section-title">{t.lifecycle.title}</h2>
        <p className="lifecycle-subtitle">{t.lifecycle.subtitle}</p>
        <div className="lifecycle-grid">
          {steps.map((s, i) => (
            <div key={s.title} className="lifecycle-step">
              <span className="lifecycle-step-number">{i + 1}</span>
              <span className="lifecycle-step-icon">
                <Icon name={s.icon} />
              </span>
              <h3>{s.title}</h3>
              <p>{s.text}</p>
            </div>
          ))}
        </div>
        <p className="lifecycle-closing">{t.lifecycle.closing}</p>
      </section>
    </>
  );
}
