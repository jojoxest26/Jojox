import { useCallback, useState } from "react";
import type { Session } from "@supabase/supabase-js";
import type { AnalysisResult, SourceFile } from "../../../src/types.js";
import { applyAutofixes, type AutofixResult } from "../../../src/analyze.js";
import { analyzeViaApi, guestAnalyzeViaApi } from "../lib/api.js";
import { readFileAsText, downloadZip, collectFilesFromDataTransfer, BINARY_EXTENSIONS, MAX_FILE_BYTES } from "../lib/fileUpload.js";
import { openReportWindow } from "../lib/report.js";
import { FindingsList } from "./FindingsList.js";
import { useTranslation } from "../i18n/LanguageContext.js";
import { interpolate } from "../i18n/richText.js";

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
}: {
  session: Session | null;
  onAnalysisSaved?: () => void;
}) {
  const { t, lang } = useTranslation();
  const [files, setFiles] = useState<SourceFile[]>([]);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [autofix, setAutofix] = useState<AutofixResult | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [guestUsed, setGuestUsed] = useState(() => localStorage.getItem(GUEST_USED_KEY) === "1");

  const loadFiles = useCallback(async (fileList: FileList) => {
    const entries = Array.from(fileList)
      .map((file) => ({ file, path: file.webkitRelativePath || file.name }))
      .filter(({ path, file }) => !shouldSkip(path, file.size))
      .slice(0, MAX_FILES);
    const loaded = await Promise.all(entries.map(({ file, path }) => readFileAsText(file, path)));
    setFiles(loaded);
    setResult(null);
    setAutofix(null);
    setError(null);
  }, []);

  const loadFromDrop = useCallback(async (dataTransfer: DataTransfer) => {
    const collected = await collectFilesFromDataTransfer(dataTransfer);
    const entries = collected.filter(({ path, file }) => !shouldSkip(path, file.size)).slice(0, MAX_FILES);
    const loaded = await Promise.all(entries.map(({ file, path }) => readFileAsText(file, path)));
    setFiles(loaded);
    setResult(null);
    setAutofix(null);
    setError(null);
  }, []);

  async function runAnalysis() {
    if (files.length === 0) return;
    setAnalyzing(true);
    setError(null);
    try {
      if (session) {
        const analysisResult = await analyzeViaApi(files, session.access_token);
        setResult(analysisResult);
        // La correzione gira sempre nel browser, sui file originali: mai
        // inviata al server, anche se l'analisi lo è.
        setAutofix(applyAutofixes(files));
        onAnalysisSaved?.();
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
      setAutofix(applyAutofixes(files));
    } catch (err) {
      setError(err instanceof Error ? err.message : t.analyzer.errorGeneric);
    } finally {
      setAnalyzing(false);
    }
  }

  const showGate = !session && guestUsed;

  return (
    <section className="analyzer container" id="analyzer">
      <p className="section-eyebrow">{t.analyzer.sectionEyebrow}</p>
      <h2 className="section-title">{t.analyzer.sectionTitle}</h2>
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
                  ? interpolate(t.analyzer.analyzeButtonCount, { count: String(files.length) })
                  : t.analyzer.analyzeButton}
            </button>
          </div>
        </>
      )}

      {error && <p style={{ color: "var(--critical)", textAlign: "center", marginTop: "0.75rem" }}>{error}</p>}

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
                  interpolate(t.analyzer.autofixManualSuffix, { count: String(autofix.manualCheckIds.size) })}
              </p>
              <button type="button" className="btn btn-primary hard-border hard-shadow-sm" onClick={() => downloadZip(autofix.files)}>
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
              setAutofix(null);
              setError(null);
              document.getElementById("analyzer")?.scrollIntoView({ behavior: "smooth" });
            }}
          >
            {t.analyzer.newAnalysis}
          </button>
        </div>
      )}

      {result && <FindingsList result={result} autofix={autofix} />}
    </section>
  );
}