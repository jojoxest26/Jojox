// Genera il report PDF aprendo una finestra con una pagina HTML pronta per
// la stampa e richiamando window.print(): l'utente la salva come PDF dal
// dialogo nativo del browser. Nessuna libreria PDF da installare.
import type { AnalysisResult, Finding, Severity, SourceFile } from "../../../src/types.js";
import type { AutofixResult } from "../../../src/analyze.js";
import { translations, type Lang } from "../i18n/translations.js";
import { interpolate } from "../i18n/richText.js";
import { translateCheckText } from "../i18n/checkTranslations.js";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];
const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "#e05353",
  high: "#e5772a",
  medium: "#d6a91c",
  low: "#4c86e5",
};

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function guessProjectName(files: SourceFile[], fallback: string): string {
  const roots = new Set(files.filter((f) => f.path.includes("/")).map((f) => f.path.split("/")[0]));
  return roots.size === 1 ? [...roots][0]! : fallback;
}

function makeReportId(): string {
  const now = new Date();
  const y = now.getFullYear();
  const m = String(now.getMonth() + 1).padStart(2, "0");
  const d = String(now.getDate()).padStart(2, "0");
  const rand = Math.random().toString(16).slice(2, 6).toUpperCase();
  return `JX-${y}${m}${d}-${rand}`;
}

function formatTimestamp(dateLocale: string): string {
  return new Date().toLocaleString(dateLocale, {
    day: "numeric",
    month: "long",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function findingHtml(finding: Finding, lang: Lang, t: (typeof translations)["it"]): string {
  const sev = finding.severity;
  const location = escapeHtml(finding.file) + (finding.line > 0 ? `:${finding.line}` : "");
  const text = translateCheckText(finding.checkId, finding, lang);
  return `
    <div class="finding finding-${sev}">
      <div class="finding-top">
        <div>
          <p class="finding-title">${escapeHtml(text.title)}</p>
          <p class="finding-loc">${location}</p>
        </div>
        <span class="sev-badge">${t.common.severity[sev]}</span>
      </div>
      <p class="finding-text">${escapeHtml(text.description)}</p>
      <div class="diff">
        <div class="diff-block diff-before">
          <p class="diff-label">${t.common.before}</p>
          <pre class="diff-code">${escapeHtml(text.fix.before)}</pre>
        </div>
        <div class="diff-block diff-after">
          <p class="diff-label">${t.common.after}</p>
          <pre class="diff-code">${escapeHtml(text.fix.after)}</pre>
        </div>
      </div>
    </div>`;
}

export function buildReportHtml(
  result: AnalysisResult,
  files: SourceFile[],
  autofix: AutofixResult | null,
  lang: Lang = "it"
): string {
  const t = translations[lang];
  const projectName = escapeHtml(guessProjectName(files, t.report.projectFallback));
  const reportId = makeReportId();
  const timestamp = formatTimestamp(t.meta.dateLocale);

  const fixableCount = autofix
    ? result.findings.filter((f) => autofix.fixedCheckIds.has(f.checkId)).length
    : 0;

  const findingsHtml =
    result.findings.length === 0
      ? `<p class="empty-state">${t.report.emptyState}</p>`
      : SEVERITY_ORDER.filter((sev) => result.findings.some((f) => f.severity === sev))
          .flatMap((sev) => result.findings.filter((f) => f.severity === sev).map((f) => findingHtml(f, lang, t)))
          .join("");

  const tallyHtml = SEVERITY_ORDER.map(
    (sev) => `
      <span class="tally-pill">
        <span class="tally-dot" style="background:${SEVERITY_COLOR[sev]}"></span>
        ${t.common.severity[sev]} <span class="tally-count">${result.summary[sev]}</span>
      </span>`
  ).join("");

  const autofixNote =
    autofix && fixableCount > 0
      ? `<p class="autofix-note">${
          fixableCount === 1
            ? interpolate(t.report.autofixNoteOne, { total: String(result.findings.length) })
            : interpolate(t.report.autofixNoteMany, {
                count: String(fixableCount),
                total: String(result.findings.length),
              })
        }${t.report.autofixNoteSuffix}</p>`
      : "";

  const summaryTitle =
    result.findings.length === 0
      ? t.report.noProblems
      : result.findings.length === 1
        ? t.report.oneProblem
        : interpolate(t.report.manyProblems, { count: String(result.findings.length) });

  return `<!doctype html>
<html lang="${lang}">
<head>
<meta charset="utf-8" />
<title>Report JoJoX — ${projectName}</title>
<style>
  * { box-sizing: border-box; }

  @page { size: A4; margin: 13mm 12mm; }

  body {
    margin: 0;
    background: #ebe7d9;
    color: #141413;
    font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }

  .toolbar {
    position: sticky;
    top: 0;
    z-index: 10;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 1rem;
    flex-wrap: wrap;
    padding: 0.9rem 1rem;
    background: #171717;
    color: #fff;
  }

  .toolbar button {
    font: inherit;
    font-weight: 700;
    padding: 0.5rem 1.1rem;
    border-radius: 999px;
    border: none;
    background: #f59e0b;
    color: #171717;
    cursor: pointer;
  }

  .toolbar span {
    font-size: 0.8rem;
    color: #d4d0c2;
  }

  .page {
    max-width: 780px;
    margin: 2rem auto;
    background: #fff;
    border-radius: 6px;
    box-shadow: 0 18px 48px -12px rgba(0, 0, 0, 0.35);
    overflow: hidden;
  }

  .header {
    background: #faf9f5;
    border-bottom: 1px solid #e7e2d6;
    padding: 1.5rem 2.5rem 1.25rem;
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 1.5rem;
  }

  .brand { display: flex; align-items: center; gap: 0.6rem; }

  .brand-mark {
    width: 30px;
    height: 30px;
    border-radius: 7px;
    background: #171717;
    color: #fff;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 800;
    font-size: 0.85rem;
    font-family: ui-monospace, SFMono-Regular, monospace;
  }

  .brand-name { font-weight: 800; font-size: 1.05rem; letter-spacing: -0.01em; }
  .brand-sub { font-size: 0.72rem; color: #57534e; margin-top: 0.1rem; }

  .header-meta { text-align: right; font-size: 0.72rem; color: #57534e; line-height: 1.6; }
  .header-meta .report-id { color: #141413; font-weight: 600; font-family: ui-monospace, SFMono-Regular, monospace; }

  .body { padding: 1.75rem 2.5rem; }

  .project-line {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin-bottom: 1.25rem;
  }

  .project-line h1 { font-size: 1.15rem; margin: 0; font-weight: 700; }
  .project-line .files-scanned { font-size: 0.78rem; color: #57534e; }

  .score-row {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 1.75rem;
    align-items: center;
    padding: 1.15rem 1.5rem;
    border: 1px solid #e7e2d6;
    border-radius: 8px;
    margin-bottom: 1rem;
  }

  .score-dial {
    width: 92px;
    height: 92px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    background: conic-gradient(#f59e0b ${(result.score / 100) * 360}deg, #e7e2d6 0deg);
    position: relative;
    flex-shrink: 0;
  }

  .score-dial::after { content: ""; position: absolute; inset: 8px; border-radius: 50%; background: #fff; }

  .score-dial-value {
    position: relative;
    z-index: 1;
    font-family: ui-monospace, SFMono-Regular, monospace;
    font-weight: 700;
    font-size: 1.5rem;
  }

  .score-dial-value span { font-size: 0.7rem; font-weight: 500; color: #57534e; display: block; }

  .score-summary-title { font-size: 0.78rem; color: #57534e; margin: 0 0 0.6rem; }

  .severity-tally { display: flex; gap: 0.5rem; flex-wrap: wrap; }

  .tally-pill {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.3rem 0.65rem;
    border-radius: 999px;
    border: 1px solid #e7e2d6;
    font-size: 0.74rem;
    font-weight: 600;
  }

  .tally-dot { width: 7px; height: 7px; border-radius: 50%; }
  .tally-count { font-family: ui-monospace, SFMono-Regular, monospace; }

  .autofix-note {
    font-size: 0.78rem;
    color: #57534e;
    margin: 0 0 1rem;
    line-height: 1.5;
  }

  .section-label {
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.07em;
    color: #57534e;
    font-weight: 700;
    margin: 0 0 0.75rem;
  }

  .findings { display: flex; flex-direction: column; gap: 0.85rem; }

  .finding {
    border: 1px solid #e7e2d6;
    border-left: 4px solid var(--sev-color);
    border-radius: 6px;
    padding: 0.85rem 1.15rem;
    break-inside: avoid;
  }

  .finding-critical { --sev-color: #e05353; --sev-bg: #fdecec; }
  .finding-high { --sev-color: #e5772a; --sev-bg: #fdf1e7; }
  .finding-medium { --sev-color: #d6a91c; --sev-bg: #fbf5e2; }
  .finding-low { --sev-color: #4c86e5; --sev-bg: #eaf1fc; }

  .finding-top { display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; margin-bottom: 0.4rem; }
  .finding-title { font-size: 0.88rem; font-weight: 700; margin: 0 0 0.2rem; }
  .finding-loc { font-size: 0.72rem; color: #57534e; font-family: ui-monospace, SFMono-Regular, monospace; }

  .sev-badge {
    flex-shrink: 0;
    font-size: 0.65rem;
    font-weight: 800;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    padding: 0.2rem 0.5rem;
    border-radius: 4px;
    color: var(--sev-color);
    background: var(--sev-bg);
  }

  .finding-text { font-size: 0.82rem; color: #57534e; margin: 0 0 0.6rem; line-height: 1.5; }

  .diff { display: grid; grid-template-columns: 1fr 1fr; gap: 0.6rem; }
  .diff-block { border-radius: 5px; overflow: hidden; border: 1px solid #e7e2d6; }
  .diff-label { font-size: 0.65rem; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase; padding: 0.3rem 0.6rem; }
  .diff-before .diff-label { background: #fdecec; color: #e05353; }
  .diff-after .diff-label { background: #e7f6ee; color: #0f9d58; }

  .diff-code {
    margin: 0;
    padding: 0.5rem 0.65rem;
    font-family: ui-monospace, SFMono-Regular, monospace;
    font-size: 0.68rem;
    line-height: 1.45;
    white-space: pre-wrap;
    word-break: break-word;
    background: #fbfaf7;
    color: #141413;
  }

  .empty-state { font-size: 0.85rem; color: #57534e; }

  .footer {
    border-top: 1px solid #e7e2d6;
    padding: 1rem 2.5rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 0.5rem;
  }

  .footer-left { font-size: 0.7rem; color: #57534e; font-family: ui-monospace, SFMono-Regular, monospace; }

  .footer-badge {
    font-size: 0.7rem;
    font-weight: 700;
    padding: 0.25rem 0.6rem;
    border-radius: 999px;
    border: 1px solid #e7e2d6;
    color: #57534e;
  }

  @media print {
    .toolbar { display: none; }
    body { background: #fff; }
    .page { margin: 0; box-shadow: none; border-radius: 0; max-width: none; }
  }
</style>
</head>
<body>
  <div class="toolbar">
    <button type="button" onclick="window.print()">${t.report.printBtn}</button>
    <span>${t.report.printHint}</span>
  </div>

  <div class="page">
    <div class="header">
      <div class="brand">
        <div class="brand-mark">JX</div>
        <div>
          <div class="brand-name">JoJoX</div>
          <div class="brand-sub">${t.report.brandSub}</div>
        </div>
      </div>
      <div class="header-meta">
        <div class="report-id">${t.report.reportLabel} #${reportId}</div>
        <div>${interpolate(t.report.generatedOn, { date: escapeHtml(timestamp) })}</div>
        <div>${t.report.controlsNoLLM}</div>
      </div>
    </div>

    <div class="body">
      <div class="project-line">
        <h1>${projectName}</h1>
        <span class="files-scanned">${
          files.length === 1
            ? t.report.filesScannedOne
            : interpolate(t.report.filesScannedMany, { count: String(files.length) })
        }</span>
      </div>

      <div class="score-row">
        <div class="score-dial">
          <div class="score-dial-value">${result.score}<span>/ 100</span></div>
        </div>
        <div>
          <p class="score-summary-title">${summaryTitle}</p>
          <div class="severity-tally">${tallyHtml}</div>
        </div>
      </div>

      ${autofixNote}

      <p class="section-label">${t.report.resultsLabel}</p>
      <div class="findings">${findingsHtml}</div>
    </div>

    <div class="footer">
      <span class="footer-left">jojox.dev</span>
      <span class="footer-badge">JoJoX Security Score: ${result.score}/100</span>
    </div>
  </div>
</body>
</html>`;
}

export function openReportWindow(
  result: AnalysisResult,
  files: SourceFile[],
  autofix: AutofixResult | null,
  lang: Lang = "it"
): void {
  const html = buildReportHtml(result, files, autofix, lang);
  const win = window.open("", "_blank");
  if (!win) {
    window.alert(translations[lang].report.popupBlocked);
    return;
  }
  win.document.open();
  win.document.write(html);
  win.document.close();
  win.focus();
  setTimeout(() => win.print(), 400);
}