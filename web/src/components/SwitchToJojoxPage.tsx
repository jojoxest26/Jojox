import { useState, type DragEvent, type MouseEvent } from "react";
import type { Severity } from "../../../src/types.js";
import { importSarifFile, type SarifImportResult } from "../lib/api.js";
import { useTranslation } from "../i18n/LanguageContext.js";
import { interpolate } from "../i18n/richText.js";
import { LanguageSwitcher } from "./Header.js";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];
const MAX_FILE_BYTES = 10_000_000;

function goHome(e?: MouseEvent) {
  e?.preventDefault();
  window.history.pushState({}, "", "/");
  window.dispatchEvent(new PopStateEvent("popstate"));
}

function openAnalyzer(e: MouseEvent) {
  e.preventDefault();
  window.history.pushState({}, "", "/");
  window.dispatchEvent(new PopStateEvent("popstate"));
  window.dispatchEvent(new Event("jojox-open-analyzer"));
}

export function SwitchToJojoxPage() {
  const { t } = useTranslation();
  const [dragOver, setDragOver] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<SarifImportResult | null>(null);

  async function loadFile(file: File) {
    setError(null);
    setResult(null);

    const looksLikeSarif = /\.(sarif|json)$/i.test(file.name);
    if (!looksLikeSarif) {
      setError(t.switchPage.errorInvalidFile);
      return;
    }
    if (file.size > MAX_FILE_BYTES) {
      setError(t.switchPage.errorInvalidFile);
      return;
    }

    setLoading(true);
    try {
      const text = await file.text();
      const outcome = await importSarifFile(text);
      if (!outcome.ok) {
        setError(
          outcome.errorCode === "invalid_json"
            ? t.switchPage.errorInvalidJson
            : outcome.errorCode === "invalid_sarif"
              ? t.switchPage.errorInvalidSarif
              : t.switchPage.errorGeneric
        );
        return;
      }
      setResult(outcome.result);
    } catch {
      setError(t.switchPage.errorGeneric);
    } finally {
      setLoading(false);
    }
  }

  function handleDrop(e: DragEvent) {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) void loadFile(file);
  }

  const total = result
    ? SEVERITY_ORDER.reduce((sum, sev) => sum + result.bySeverity[sev], 0)
    : 0;

  return (
    <div className="legal-page">
      <div className="container legal-page-nav">
        <a href="/" onClick={goHome} className="legal-back">
          {t.switchPage.backHome}
        </a>
        <LanguageSwitcher />
      </div>

      <div className="container switch-page">
        <p className="section-eyebrow">{t.switchPage.eyebrow}</p>
        <h1 className="section-title">{t.switchPage.title}</h1>
        <p>{t.switchPage.subtitle}</p>

        {!result && (
          <div
            className={`dropzone${dragOver ? " dragover" : ""}`}
            onDragOver={(e) => {
              e.preventDefault();
              setDragOver(true);
            }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
            onClick={() => document.getElementById("sarif-file-input")?.click()}
            role="button"
            tabIndex={0}
          >
            <input
              id="sarif-file-input"
              type="file"
              accept=".sarif,.json,application/json"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) void loadFile(file);
              }}
            />
            <strong>{t.switchPage.dropzoneCta}</strong>
            <div className="dropzone-hint">{t.switchPage.dropzoneHint}</div>
          </div>
        )}

        {loading && <p className="dropzone-hint" style={{ textAlign: "center" }}>{t.switchPage.loading}</p>}
        {error && <p className="waitlist-msg">{error}</p>}

        {result && (
          <div className="results">
            <div className="card score-row">
              <div>
                <div className="score-label">
                  {result.toolName
                    ? interpolate(t.switchPage.toolDetected, { tool: result.toolName })
                    : t.switchPage.toolUnknown}
                </div>
                <div className="summary-pills">
                  {SEVERITY_ORDER.filter((sev) => result.bySeverity[sev] > 0).map((sev) => (
                    <span key={sev} className={`pill pill-${sev}`}>
                      {result.bySeverity[sev]} {t.common.severity[sev]}
                    </span>
                  ))}
                </div>
                <p className="dropzone-hint">{interpolate(t.switchPage.totalFound, { count: String(total) })}</p>
                {result.returnedFindings < result.totalFindings && (
                  <p className="dropzone-hint">
                    {interpolate(t.switchPage.shownNote, {
                      shown: String(result.returnedFindings),
                      total: String(result.totalFindings),
                    })}
                  </p>
                )}
              </div>
            </div>

            {result.findings.length === 0 ? (
              <p style={{ textAlign: "center", marginTop: "1.5rem", color: "var(--text-muted)" }}>
                {t.switchPage.emptyState}
              </p>
            ) : (
              result.findings.map((finding, i) => (
                <div key={`${finding.ruleId}-${i}`} className={`finding finding-${finding.severity}`} dir="auto">
                  <div className="finding-head">
                    <span className="finding-title">{finding.ruleId}</span>
                    <span className="finding-location">
                      {finding.file}
                      {finding.line && finding.line > 0 ? `:${finding.line}` : ""}
                    </span>
                  </div>
                  <p className="finding-desc">{finding.message}</p>
                </div>
              ))
            )}

            <div className="card switch-page-cta">
              <h2>{t.switchPage.ctaTitle}</h2>
              <p>{t.switchPage.ctaBody}</p>
              <a href="/" onClick={openAnalyzer} className="btn btn-primary hard-border hard-shadow-sm">
                {t.switchPage.ctaButton}
              </a>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
