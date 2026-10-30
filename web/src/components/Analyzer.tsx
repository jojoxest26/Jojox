import { useCallback, useEffect, useState } from "react";
import type { Session } from "@supabase/supabase-js";
import type { AnalysisResult, SourceFile } from "../../../src/types.js";
import { applyAutofixes, analyzeFiles, type AutofixResult } from "../../../src/analyze.js";
import {
  analyzeViaApi,
  guestAnalyzeViaApi,
  createAnalysisPackCheckoutSession,
  fetchAnalysisUsage,
  ApiError,
  type AnalysisUsage,
} from "../lib/api.js";
import { readFileAsText, downloadZip, collectFilesFromDataTransfer, BINARY_EXTENSIONS, MAX_FILE_BYTES } from "../lib/fileUpload.js";
import { buildCorrectionsZipEntries } from "../lib/correctionsManifest.js";
import { openReportWindow } from "../lib/report.js";
import { useBfcacheReset } from "../lib/useBfcacheReset.js";
import { FindingsList } from "./FindingsList.js";
import { AiInsightsSection } from "./AiInsightsSection.js";
import { useTranslation } from "../i18n/LanguageContext.js";
import { interpolate, interpolateCount } from "../i18n/richText.js";

const MAX_FILES = 300;
const SKIP_PATH = /(^|\/)(node_modules|\.git|dist|build|\.next|coverage)\//;
const shouldSkip = (path: string, size: number) => SKIP_PATH.test(path) || BINARY_EXTENSIONS.test(path) || size > MAX_FILE_BYTES;
const GUEST_USED_KEY = "jojox_guest_used";

function openLogin() {
  window.dispatchEvent(new Event("jojox-open-login"));
  window.scrollTo({ top: 0, behavior: "smooth" });
}

export function Analyzer({
  session,
  onAnalysisSaved,
  onResult,
}: {
  session: Session | null;
  onAnalysisSaved?: () => void;
  /** Tiene aggiornato il widget globale "Chiedi a JoJoX" con i findings dell'ultima analisi. */
  onResult?: (result: AnalysisResult | null) => void;
}) {
  const { t, lang } = useTranslation();
  const [files, setFiles] = useState<SourceFile[]>([]);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [autofix, setAutofix] = useState<AutofixResult | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [creditsExhausted, setCreditsExhausted] = useState(false);
  const [buyingPack, setBuyingPack] = useState(false);
  const [usage, setUsage] = useState<AnalysisUsage | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [guestUsed, setGuestUsed] = useState(() => localStorage.getItem(GUEST_USED_KEY) === "1");

  const refreshUsage = useCallback(() => {
    if (!session) {
      setUsage(null);
      return;
    }
    fetchAnalysisUsage(session.access_token)
      .then(setUsage)
      .catch(() => {});
  }, [session]);

  useEffect(() => {
    refreshUsage();
  }, [refreshUsage]);

  // Tornare a questa pagina con "indietro" del browser dopo aver aperto il
  // checkout Stripe (senza completarlo, o dopo) ripristina il JS congelato
  // dalla bfcache — senza questo, il pulsante resterebbe bloccato su
  // "Apertura del pagamento..." per sempre, e il contatore non vedrebbe un
  // eventuale acquisto nel frattempo.
  useBfcacheReset(() => {
    setBuyingPack(false);
    refreshUsage();
  });

  const loadFiles = useCallback(async (fileList: FileList) => {
    const entries = Array.from(fileList)
      .map((file) => ({ file, path: file.webkitRelativePath || file.name }))
      .filter(({ path, file }) => !shouldSkip(path, file.size))
      .slice(0, MAX_FILES);
    const loaded = await Promise.all(entries.map(({ file, path }) => readFileAsText(file, path)));
    setFiles(loaded);
    setResult(null);
    onResult?.(null);
    setAutofix(null);
    setError(null);
    setCreditsExhausted(false);
  }, [onResult]);

  const loadFromDrop = useCallback(async (dataTransfer: DataTransfer) => {
    const collected = await collectFilesFromDataTransfer(dataTransfer);
    const entries = collected.filter(({ path, file }) => !shouldSkip(path, file.size)).slice(0, MAX_FILES);
    const loaded = await Promise.all(entries.map(({ file, path }) => readFileAsText(file, path)));
    setFiles(loaded);
    setResult(null);
    onResult?.(null);
    setAutofix(null);
    setError(null);
    setCreditsExhausted(false);
  }, [onResult]);

  async function buyAnalysisPack() {
    if (!session) {
      openLogin();
      return;
    }
    setBuyingPack(true);
    try {
      const { url } = await createAnalysisPackCheckoutSession(session.access_token);
      window.location.href = url;
    } catch (err) {
      setError(err instanceof Error ? err.message : t.analyzer.errorPurchase);
      setBuyingPack(false);
    }
  }

  async function runAnalysis() {
    if (files.length === 0) return;
    setAnalyzing(true);
    setError(null);
    setCreditsExhausted(false);
    try {
      if (session) {
        const analysisResult = await analyzeViaApi(files, session.access_token);
        setResult(analysisResult);
        onResult?.(analysisResult);
        // La correzione gira sempre nel browser, sui file originali: mai
        // inviata al server, anche se l'analisi lo è.
        setAutofix(applyAutofixes(files));
        onAnalysisSaved?.();
        refreshUsage();
        return;
      }

      // Ospite: un'unica analisi gratuita, imposta dal server per IP (non
      // solo suggerita nel browser, che sarebbe aggirabile).
      const guestResult = await guestAnalyzeViaApi(files);
      localStorage.setItem(GUEST_USED_KEY, "1");
      setGuestUsed(true);
      if (!guestResult.ok) {
        setError(t.analyzer.errorGuestUsed);
        return;
      }
      setResult(guestResult.result);
      onResult?.(guestResult.result);
      setAutofix(applyAutofixes(files));
    } catch (err) {
      if (err instanceof ApiError && err.creditsExhausted) {
        setCreditsExhausted(true);
        setError(t.analyzer.creditsExhaustedBody);
      } else {
        setError(err instanceof Error ? err.message : t.analyzer.errorGeneric);
      }
    } finally {
      setAnalyzing(false);
    }
  }

  const showGate = !session && guestUsed;

  return (
    <section className="analyzer container" id="analyzer">
      <p className="section-eyebrow">{t.analyzer.sectionEyebrow}</p>
      <h2 className="section-title">{t.analyzer.sectionTitle}</h2>
      {usage && (
        <p className="analyzer-usage">
          {interpolate(t.analyzer.usageCount, { used: String(usage.usedThisMonth), limit: String(usage.effectiveLimit) })}
          {usage.plan !== "free" && (
            <>
              {" · "}
              <button type="button" className="analyzer-usage-buy" disabled={buyingPack} onClick={buyAnalysisPack}>
                {buyingPack ? t.analyzer.buyingPack : t.analyzer.buyPackCta}
              </button>
            </>
          )}
        </p>
      )}
      {showGate ? (
        <div className="card" style={{ padding: "2.5rem 1.5rem", textAlign: "center" }}>
          <strong>{t.analyzer.gateTitle}</strong>
          <p className="dropzone-hint" style={{ marginTop: "0.5rem" }}>
            {t.analyzer.gateBody}
          </p>
          <button
            type="button"
            className="btn btn-primary hard-border hard-shadow-sm"
            style={{ marginTop: "1.25rem" }}
            onClick={openLogin}
          >
            {t.analyzer.gateCta}
          </button>
        </div>
      ) : (
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
            onClick={() => document.getElementById("file-input")?.click()}
            role="button"
            tabIndex={0}
          >
            <input id="file-input" type="file" multiple onChange={(e) => e.target.files && loadFiles(e.target.files)} />
            <strong>{t.analyzer.dropzoneCta}</strong>
            <div className="dropzone-hint">
              {session ? t.analyzer.dropzoneHintLoggedIn : t.analyzer.dropzoneHintGuest}
            </div>
            <div className="dropzone-hint">{t.analyzer.dropzoneHintAny}</div>
            <div className="dropzone-hint">{t.analyzer.dropzoneHintLanguages}</div>
            {files.length > 0 && (
              <div className="file-chip-row" onClick={(e) => e.stopPropagation()}>
                {files.slice(0, 12).map((f) => (
                  <span key={f.path} className="file-chip">
                    {f.path}
                  </span>
                ))}
                {files.length > 12 && (
                  <span className="file-chip">{interpolate(t.analyzer.moreFiles, { count: String(files.length - 12) })}</span>
                )}
              </div>
            )}
          </div>

          <div style={{ textAlign: "center", marginTop: "1rem" }}>
            <button type="button" className="btn btn-primary" disabled={files.length === 0 || analyzing} onClick={runAnalysis}>
              {analyzing
                ? t.analyzer.analyzing
                : files.length > 0
                  ? interpolateCount(t.analyzer.analyzeButtonCount, lang, files.length)
                  : t.analyzer.analyzeButton}
            </button>
          </div>
        </>
      )}

      {error && <p style={{ color: "var(--critical)", textAlign: "center", marginTop: "0.75rem" }}>{error}</p>}
      {creditsExhausted && (
        <div style={{ textAlign: "center", marginTop: "0.75rem" }}>
          <button type="button" className="btn btn-primary hard-border hard-shadow-sm" disabled={buyingPack} onClick={buyAnalysisPack}>
            {buyingPack ? t.analyzer.buyingPack : t.analyzer.buyPackCta}
          </button>
        </div>
      )}

      {result && autofix && (
        <div className="card autofix-card">
          {autofix.fixedCheckIds.size > 0 ? (
            <>
              <p className="autofix-summary">
                {interpolate(
                  autofix.fixedCheckIds.size === 1 ? t.analyzer.autofixFixedOne : t.analyzer.autofixFixedMany,
                  { files: String(autofix.filesChanged), types: String(autofix.fixedCheckIds.size) }
                )}
                {autofix.manualCheckIds.size > 0 &&
                  interpolateCount(t.analyzer.autofixManualSuffix, lang, autofix.manualCheckIds.size)}
              </p>
              <button
                type="button"
                className="btn btn-primary hard-border hard-shadow-sm"
                onClick={() => {
                  const afterFindings = analyzeFiles(autofix.files).findings;
                  downloadZip(buildCorrectionsZipEntries(afterFindings, autofix, t, lang), t.common.correctionsManifest.zipFileName);
                }}
              >
                {t.analyzer.downloadZip}
              </button>
            </>
          ) : (
            autofix.manualCheckIds.size > 0 && <p className="autofix-summary">{t.analyzer.autofixManualOnly}</p>
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
            {t.analyzer.downloadPdf}
          </button>
          <button
            type="button"
            className="btn btn-secondary hard-border hard-shadow-sm"
            onClick={() => {
              setFiles([]);
              setResult(null);
              onResult?.(null);
              setAutofix(null);
              setError(null);
              setCreditsExhausted(false);
              document.getElementById("analyzer")?.scrollIntoView({ behavior: "smooth" });
            }}
          >
            {t.analyzer.newAnalysis}
          </button>
        </div>
      )}

      {result && <FindingsList result={result} autofix={autofix} />}

      {result && session && <AiInsightsSection files={files} session={session} />}
    </section>
  );
}