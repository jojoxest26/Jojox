import { useEffect, useState } from "react";
import type { Session } from "@supabase/supabase-js";
import type { AnalysisResult, SourceFile } from "../../../src/types.js";
import { applyAutofixes, analyzeFiles, type AutofixResult } from "../../../src/analyze.js";
import {
  analyzeAuditViaApi,
  createAuditCheckoutSession,
  fetchAuditCredits,
  fetchGithubInstallations,
  fetchGithubRepos,
  fetchProfileDetails,
  startMonitoringTrial,
  type GithubInstallation,
  type GithubRepo,
  type ProfileDetails,
} from "../lib/api.js";
import { readFileAsText, downloadZip, collectFilesFromDataTransfer, BINARY_EXTENSIONS, MAX_FILE_BYTES } from "../lib/fileUpload.js";
import { openReportWindow } from "../lib/report.js";
import { FindingsList } from "./FindingsList.js";
import { ScoreRing } from "./ScoreRing.js";
import { useTranslation } from "../i18n/LanguageContext.js";
import { interpolate } from "../i18n/richText.js";

const MAX_FILES = 2000;
const SKIP_PATH = /(^|\/)(node_modules|\.git|dist|build|\.next|coverage)\//;
const shouldSkip = (path: string, size: number) => SKIP_PATH.test(path) || BINARY_EXTENSIONS.test(path) || size > MAX_FILE_BYTES;

function openLogin() {
  window.dispatchEvent(new Event("jojox-open-login"));
  window.scrollTo({ top: 0, behavior: "smooth" });
}

export function FullSiteAudit({ session }: { session: Session | null }) {
  const { t, lang } = useTranslation();
  const [credits, setCredits] = useState<number | null>(null);
  const [buying, setBuying] = useState(false);
  const [purchaseError, setPurchaseError] = useState<string | null>(null);

  const [files, setFiles] = useState<SourceFile[]>([]);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [autofix, setAutofix] = useState<AutofixResult | null>(null);
  const [afterFixScore, setAfterFixScore] = useState<number | null>(null);
  const [afterFixFindingsCount, setAfterFixFindingsCount] = useState<number | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);

  const [installations, setInstallations] = useState<GithubInstallation[]>([]);
  const [selectedInstallationId, setSelectedInstallationId] = useState<number | null>(null);
  const [repos, setRepos] = useState<GithubRepo[]>([]);
  const [selectedRepoFullName, setSelectedRepoFullName] = useState<string | null>(null);
  const [prUrl, setPrUrl] = useState<string | null>(null);
  const [prSkipped, setPrSkipped] = useState<"mismatch" | null>(null);

  const [profile, setProfile] = useState<ProfileDetails | null>(null);
  const [activatingTrial, setActivatingTrial] = useState(false);
  const [trialError, setTrialError] = useState<string | null>(null);
  const [trialJustActivated, setTrialJustActivated] = useState(false);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.has("audit")) {
      params.delete("audit");
      const query = params.toString();
      window.history.replaceState({}, "", window.location.pathname + (query ? `?${query}` : ""));
    }
  }, []);

  useEffect(() => {
    if (!session) {
      setCredits(null);
      return;
    }
    fetchAuditCredits(session.access_token)
      .then(setCredits)
      .catch(() => setCredits(0));

    fetchGithubInstallations(session.access_token)
      .then((list) => {
        setInstallations(list);
        // Con una sola installazione la selezioniamo subito: risparmia un
        // click a chi ha un solo account collegato, il caso più comune.
        if (list.length === 1) setSelectedInstallationId(list[0].installation_id);
      })
      .catch(() => {});

    fetchProfileDetails(session.access_token)
      .then(setProfile)
      .catch(() => {});

    // Il credito arriva via webhook Stripe dopo il redirect di ritorno: un
    // secondo giro dopo qualche secondo evita di mostrare ancora "0 audit
    // disponibili" appena tornati dal pagamento, mentre il webhook arriva.
    const timeout = setTimeout(() => {
      fetchAuditCredits(session.access_token)
        .then(setCredits)
        .catch(() => {});
    }, 2500);
    return () => clearTimeout(timeout);
  }, [session]);

  useEffect(() => {
    if (!session || selectedInstallationId == null) {
      setRepos([]);
      return;
    }
    setSelectedRepoFullName(null);
    fetchGithubRepos(selectedInstallationId, session.access_token)
      .then(setRepos)
      .catch(() => setRepos([]));
  }, [session, selectedInstallationId]);

  async function buyAudit() {
    if (!session) {
      openLogin();
      return;
    }
    setPurchaseError(null);
    setBuying(true);
    try {
      const { url } = await createAuditCheckoutSession(session.access_token);
      window.location.href = url;
    } catch (err) {
      setPurchaseError(err instanceof Error ? err.message : t.fullSiteAudit.errorPurchase);
      setBuying(false);
    }
  }

  async function loadFiles(fileList: FileList) {
    const entries = Array.from(fileList)
      .map((file) => ({ file, path: file.webkitRelativePath || file.name }))
      .filter(({ path, file }) => !shouldSkip(path, file.size))
      .slice(0, MAX_FILES);
    const loaded = await Promise.all(entries.map(({ file, path }) => readFileAsText(file, path)));
    setFiles(loaded);
    setResult(null);
    setAutofix(null);
    setAfterFixScore(null);
    setPrUrl(null);
    setPrSkipped(null);
    setError(null);
  }

  async function loadFromDrop(dataTransfer: DataTransfer) {
    const collected = await collectFilesFromDataTransfer(dataTransfer);
    const entries = collected.filter(({ path, file }) => !shouldSkip(path, file.size)).slice(0, MAX_FILES);
    const loaded = await Promise.all(entries.map(({ file, path }) => readFileAsText(file, path)));
    setFiles(loaded);
    setResult(null);
    setAutofix(null);
    setAfterFixScore(null);
    setPrUrl(null);
    setPrSkipped(null);
    setError(null);
  }

  function clearFiles() {
    setFiles([]);
    setResult(null);
    setAutofix(null);
    setAfterFixScore(null);
    setAfterFixFindingsCount(null);
    setPrUrl(null);
    setPrSkipped(null);
    setError(null);
  }

  async function runAudit() {
    if (!session || files.length === 0) return;
    setAnalyzing(true);
    setError(null);
    try {
      const githubTarget =
        selectedInstallationId != null && selectedRepoFullName
          ? {
              installationId: selectedInstallationId,
              owner: selectedRepoFullName.split("/")[0]!,
              repo: selectedRepoFullName.split("/")[1]!,
            }
          : undefined;
      const analysisResult = await analyzeAuditViaApi(files, session.access_token, githubTarget);
      setResult(analysisResult);
      setPrUrl(analysisResult.prUrl);
      setPrSkipped(analysisResult.prSkipped);
      const autofixResult = applyAutofixes(files);
      setAutofix(autofixResult);
      // Ricalcoliamo il punteggio (e il numero di problemi) sui file corretti
      // solo per mostrare il miglioramento reale ottenuto dalla correzione
      // automatica — non è mai il risultato "finale": i problemi senza
      // correzione automatica restano, e con molti problemi critici il
      // punteggio può restare fermo (es. a 0) anche se sono stati corretti
      // decine di problemi — per questo mostriamo anche il conteggio, che si
      // muove sempre quando qualcosa è stato davvero corretto.
      if (autofixResult.fixedCheckIds.size > 0) {
        const afterAnalysis = analyzeFiles(autofixResult.files);
        setAfterFixScore(afterAnalysis.score);
        setAfterFixFindingsCount(afterAnalysis.findings.length);
      } else {
        setAfterFixScore(null);
        setAfterFixFindingsCount(null);
      }
      setCredits((c) => (c != null ? Math.max(0, c - 1) : c));
    } catch (err) {
      setError(err instanceof Error ? err.message : t.fullSiteAudit.errorGeneric);
    } finally {
      setAnalyzing(false);
    }
  }

  function startNewAudit() {
    setFiles([]);
    setResult(null);
    setAutofix(null);
    setAfterFixScore(null);
    setAfterFixFindingsCount(null);
    setPrUrl(null);
    setPrSkipped(null);
    setError(null);
  }

  async function activateTrial() {
    if (!session) return;
    setTrialError(null);
    setActivatingTrial(true);
    try {
      const { planTrialExpiresAt } = await startMonitoringTrial(session.access_token);
      setProfile((p) => (p ? { ...p, plan: "pro", planTrialUsed: true, planTrialExpiresAt } : p));
      setTrialJustActivated(true);
    } catch (err) {
      setTrialError(err instanceof Error ? err.message : t.fullSiteAudit.trialError);
    } finally {
      setActivatingTrial(false);
    }
  }

  return (
    <section className="full-site-audit container" id="full-site-audit">
      <p className="section-eyebrow">{t.fullSiteAudit.eyebrow}</p>
      <h2 className="section-title">{t.fullSiteAudit.title}</h2>
      <p>{t.fullSiteAudit.subtitle}</p>

      {result || (credits != null && credits > 0) ? (
        <>
          {!result && (
            <p className="dropzone-hint" style={{ textAlign: "center" }}>
              {interpolate(t.fullSiteAudit.creditsAvailable, { count: String(credits) })}
            </p>
          )}

          {!result && (
            <>
              <div
                className={`dropzone${dragOver ? " dragover" : ""}`}
                onDragOver={(e) => {
                  e.preventDefault();
                  setDragOver(true);
                }}
                onDragLeave={() => setDragOver(false)}
                onDrop={(e) => {
                  e.preventDefault();
                  setDragOver(false);
                  loadFromDrop(e.dataTransfer);
                }}
                onClick={() => document.getElementById("audit-file-input")?.click()}
                role="button"
                tabIndex={0}
              >
                <input
                  id="audit-file-input"
                  type="file"
                  multiple
                  // @ts-expect-error -- non standard, ma è ciò che permette di scegliere un'intera cartella dal click
                  webkitdirectory=""
                  onChange={(e) => e.target.files && loadFiles(e.target.files)}
                />
                <strong>{t.fullSiteAudit.dropzoneCta}</strong>
                <div className="dropzone-hint">{t.fullSiteAudit.dropzoneHint}</div>
                {files.length > 0 && (
                  <div className="file-chip-row" onClick={(e) => e.stopPropagation()}>
                    {files.slice(0, 12).map((f) => (
                      <span key={f.path} className="file-chip">
                        {f.path}
                      </span>
                    ))}
                    {files.length > 12 && <span className="file-chip">+{files.length - 12}</span>}
                  </div>
                )}
              </div>

              {installations.length > 0 && (
                <div className="github-target-picker">
                  <label htmlFor="github-target-repo">{t.fullSiteAudit.githubTargetLabel}</label>
                  <div className="github-target-selects">
                    {installations.length > 1 && (
                      <select
                        aria-label={t.fullSiteAudit.githubTargetChooseAccount}
                        value={selectedInstallationId ?? ""}
                        onChange={(e) => setSelectedInstallationId(e.target.value ? Number(e.target.value) : null)}
                      >
                        <option value="">{t.fullSiteAudit.githubTargetChooseAccount}</option>
                        {installations.map((inst) => (
                          <option key={inst.installation_id} value={inst.installation_id}>
                            {inst.account_login}
                          </option>
                        ))}
                      </select>
                    )}
                    <select
                      id="github-target-repo"
                      value={selectedRepoFullName ?? ""}
                      onChange={(e) => setSelectedRepoFullName(e.target.value || null)}
                      disabled={selectedInstallationId == null}
                    >
                      <option value="">{t.fullSiteAudit.githubTargetNone}</option>
                      {repos.map((r) => (
                        <option key={r.fullName} value={r.fullName}>
                          {r.fullName}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>
              )}

              <div style={{ textAlign: "center", marginTop: "1rem", display: "flex", gap: "0.75rem", justifyContent: "center", flexWrap: "wrap" }}>
                <button type="button" className="btn btn-primary" disabled={files.length === 0 || analyzing} onClick={runAudit}>
                  {analyzing
                    ? t.fullSiteAudit.analyzing
                    : files.length > 0
                      ? interpolate(t.fullSiteAudit.analyzeButtonCount, { count: String(files.length) })
                      : t.fullSiteAudit.analyzeButton}
                </button>
                {files.length > 0 && !analyzing && (
                  <button type="button" className="btn btn-secondary hard-border hard-shadow-sm" onClick={clearFiles}>
                    {t.fullSiteAudit.changeFiles}
                  </button>
                )}
              </div>
            </>
          )}

          {error && <p style={{ color: "var(--critical)", textAlign: "center", marginTop: "0.75rem" }}>{error}</p>}

          {result && autofix && autofix.fixedCheckIds.size > 0 && (
            <div className="card autofix-card score-compare">
              <p className="autofix-summary" style={{ textAlign: "center" }}>
                {interpolate(
                  autofix.fixedCheckIds.size === 1 ? t.analyzer.autofixFixedOne : t.analyzer.autofixFixedMany,
                  { files: String(autofix.filesChanged), types: String(autofix.fixedCheckIds.size) }
                )}
                {autofix.manualCheckIds.size > 0 &&
                  interpolate(t.analyzer.autofixManualSuffix, { count: String(autofix.manualCheckIds.size) })}
              </p>
              {afterFixScore != null && (
                <>
                  <div className="score-compare-row">
                    <div className="score-compare-item">
                      <ScoreRing score={result.score} />
                      <div className="score-compare-label">{t.fullSiteAudit.scoreBefore}</div>
                    </div>
                    <div className="score-compare-arrow">
                      <span className="score-compare-delta">
                        {afterFixScore > result.score ? `+${afterFixScore - result.score}` : "="}
                      </span>
                      <span>→</span>
                    </div>
                    <div className="score-compare-item">
                      <ScoreRing score={afterFixScore} />
                      <div className="score-compare-label">{t.fullSiteAudit.scoreAfter}</div>
                    </div>
                  </div>
                  <p className="dropzone-hint" style={{ textAlign: "center" }}>
                    {afterFixScore === result.score && afterFixFindingsCount != null
                      ? interpolate(t.fullSiteAudit.scoreStuckNote, {
                          fixed: String(result.findings.length - afterFixFindingsCount),
                          total: String(result.findings.length),
                        })
                      : t.fullSiteAudit.scoreAfterNote}
                  </p>
                </>
              )}
              <div style={{ textAlign: "center", marginTop: afterFixScore != null ? "0.75rem" : 0, display: "flex", gap: "0.75rem", justifyContent: "center", flexWrap: "wrap" }}>
                <button type="button" className="btn btn-primary hard-border hard-shadow-sm" onClick={() => downloadZip(autofix.files, "jojox-full-site-audit.zip")}>
                  {t.fullSiteAudit.downloadZip}
                </button>
                {prUrl && (
                  <a href={prUrl} target="_blank" rel="noopener noreferrer" className="btn btn-secondary hard-border hard-shadow-sm">
                    {t.fullSiteAudit.viewPr}
                  </a>
                )}
              </div>
              {selectedRepoFullName && !prUrl && (
                <p className="dropzone-hint" style={{ textAlign: "center", marginTop: "0.6rem" }}>
                  {prSkipped === "mismatch" ? t.fullSiteAudit.prMismatchNote : t.fullSiteAudit.prFailedNote}
                </p>
              )}
            </div>
          )}

          {result && (
            <div style={{ textAlign: "center", margin: "1rem 0", display: "flex", gap: "0.75rem", justifyContent: "center", flexWrap: "wrap" }}>
              <button
                type="button"
                className="btn btn-secondary hard-border hard-shadow-sm"
                onClick={() => openReportWindow(result, files, autofix, lang)}
              >
                {t.fullSiteAudit.downloadPdf}
              </button>
              <button type="button" className="btn btn-secondary hard-border hard-shadow-sm" onClick={startNewAudit}>
                {t.fullSiteAudit.newAudit}
              </button>
            </div>
          )}

          {result && profile && !profile.planTrialUsed && (
            <div className="card trial-offer">
              <strong>{t.fullSiteAudit.trialOfferTitle}</strong>
              <p className="dropzone-hint">{t.fullSiteAudit.trialOfferBody}</p>
              <button type="button" className="btn btn-primary hard-border hard-shadow-sm" disabled={activatingTrial} onClick={activateTrial}>
                {activatingTrial ? t.fullSiteAudit.trialActivating : t.fullSiteAudit.trialCta}
              </button>
              {trialError && <p style={{ color: "var(--critical)", marginTop: "0.5rem" }}>{trialError}</p>}
            </div>
          )}

          {result && trialJustActivated && (
            <p className="dropzone-hint" style={{ textAlign: "center" }}>{t.fullSiteAudit.trialActivated}</p>
          )}

          {result && <FindingsList result={result} autofix={autofix} />}
        </>
      ) : (
        <div className="card full-site-audit-card">
          <ul className="full-site-audit-features">
            {t.fullSiteAudit.features.map((item) => (
              <li key={item}>✓ {item}</li>
            ))}
          </ul>
          <div className="full-site-audit-cta">
            <div className="price-amount">{t.fullSiteAudit.priceLabel}</div>
            <p className="price-card-note">{t.fullSiteAudit.priceNote}</p>
            <button type="button" className="btn btn-primary hard-border hard-shadow" disabled={buying} onClick={buyAudit}>
              {buying ? t.fullSiteAudit.buying : t.fullSiteAudit.ctaBuy}
            </button>
            {purchaseError && <p style={{ color: "var(--critical)", marginTop: "0.75rem" }}>{purchaseError}</p>}
          </div>
        </div>
      )}
    </section>
  );
}