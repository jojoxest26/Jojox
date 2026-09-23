import { useEffect, useState } from "react";
import type { MouseEvent } from "react";
import { LanguageSwitcher } from "./Header.js";
import { ScoreRing } from "./ScoreRing.js";
import { useTranslation } from "../i18n/LanguageContext.js";
import { interpolate } from "../i18n/richText.js";
import type { Severity } from "../../../src/types.js";

const API_URL = import.meta.env.VITE_API_URL;
const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

interface PublicScoreData {
  repoFullName: string;
  score: number;
  summary: Record<Severity, number>;
  updatedAt: string;
}

type Status = "loading" | "notfound" | "found";

function goHome(e: MouseEvent) {
  e.preventDefault();
  window.history.pushState({}, "", "/");
  window.dispatchEvent(new PopStateEvent("popstate"));
}

export function PublicScorePage({ owner, repo }: { owner: string; repo: string }) {
  const { t } = useTranslation();
  const [status, setStatus] = useState<Status>("loading");
  const [data, setData] = useState<PublicScoreData | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    setStatus("loading");
    setData(null);
    fetch(`${API_URL}/api/public-score/${owner}/${repo}`)
      .then((res) => (res.ok ? res.json() : Promise.reject()))
      .then((json: PublicScoreData) => {
        setData(json);
        setStatus("found");
      })
      .catch(() => setStatus("notfound"));
  }, [owner, repo]);

  function copyLink() {
    navigator.clipboard.writeText(window.location.href).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  const hasIssues = data ? SEVERITY_ORDER.some((sev) => data.summary[sev] > 0) : false;

  return (
    <div className="legal-page">
      <div className="container legal-page-nav">
        <a href="/" onClick={goHome} className="legal-back">
          ← JoJoX
        </a>
        <LanguageSwitcher />
      </div>
      <div className="container public-score-page">
        <p className="section-eyebrow">{owner}/{repo}</p>

        {status === "loading" && <p>{t.publicScore.loading}</p>}

        {status === "notfound" && (
          <div className="card">
            <h1>{t.publicScore.notFoundTitle}</h1>
            <p>{t.publicScore.notFoundBody}</p>
          </div>
        )}

        {status === "found" && data && (
          <>
            <div className="card score-row">
              <ScoreRing score={data.score} />
              <div>
                <div className="score-number">{data.score}/100</div>
                <div className="score-label">{t.publicScore.scoreLabel}</div>
                <div className="summary-pills">
                  {hasIssues ? (
                    SEVERITY_ORDER.filter((sev) => data.summary[sev] > 0).map((sev) => (
                      <span key={sev} className={`pill pill-${sev}`}>
                        {data.summary[sev]} {t.common.severity[sev]}
                      </span>
                    ))
                  ) : (
                    <span className="pill pill-plain">{t.publicScore.noIssues}</span>
                  )}
                </div>
              </div>
            </div>
            <p className="price-card-note">
              {interpolate(t.publicScore.updatedLabel, {
                date: new Date(data.updatedAt).toLocaleDateString(t.meta.dateLocale),
              })}
            </p>
            <div className="public-score-actions">
              <button type="button" className="btn btn-secondary hard-border hard-shadow-sm" onClick={copyLink}>
                {copied ? t.publicScore.linkCopied : t.publicScore.copyLink}
              </button>
              <a href="/" onClick={goHome} className="btn btn-primary hard-border hard-shadow-sm">
                {t.publicScore.ctaText}
              </a>
            </div>
          </>
        )}

        <p className="pricing-disclaimer">{t.publicScore.poweredBy}</p>
      </div>
    </div>
  );
}