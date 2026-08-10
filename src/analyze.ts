import type { AnalysisResult, Finding, SourceFile } from "./types.js";
import { ALL_CHECKS } from "./checks/index.js";
import { computeScore, summarizeBySeverity } from "./scoring.js";
import { SUPABASE_SNAPSHOT_FILENAME, parseSupabaseSnapshot, supabaseConfigFindings } from "./supabaseConfigChecks.js";

/** Files this engine never needs to look inside — keeps noise and runtime down. */
const SKIP_PATH = /(^|\/)(node_modules|\.git|dist|build|\.next|coverage)\//;
const BINARY_EXT = /\.(png|jpe?g|gif|webp|svg|ico|woff2?|ttf|eot|pdf|zip|lock)$/i;

export function analyzeFiles(files: readonly SourceFile[]): AnalysisResult {
  const relevantFiles = files.filter((f) => !SKIP_PATH.test(f.path) && !BINARY_EXT.test(f.path));

  const findings: Finding[] = [];
  for (const file of relevantFiles) {
    // Non è codice sorgente da scansionare riga per riga: è lo snapshot
    // della configurazione reale di Supabase, con la sua analisi dedicata.
    if (file.path.endsWith(SUPABASE_SNAPSHOT_FILENAME)) continue;

    for (const check of ALL_CHECKS) {
      const matches = check.detect(file, relevantFiles);
      for (const match of matches) {
        findings.push({
          checkId: check.id,
          severity: check.severity,
          confidence: check.confidence,
          title: check.title,
          description: check.description,
          file: file.path,
          line: match.line,
          snippet: match.snippet,
          fix: check.fix,
        });
      }
    }
  }

  const snapshotFile = relevantFiles.find((f) => f.path.endsWith(SUPABASE_SNAPSHOT_FILENAME));
  if (snapshotFile) {
    const snapshot = parseSupabaseSnapshot(snapshotFile.content);
    if (snapshot) findings.push(...supabaseConfigFindings(snapshot));
  }

  return {
    score: computeScore(findings),
    findings,
    summary: summarizeBySeverity(findings),
  };
}

export type { AnalysisResult, Finding, SourceFile, Severity, Confidence, Check, CheckMatch, FixExample } from "./types.js";
export { ALL_CHECKS } from "./checks/index.js";
export { applyAutofixes } from "./autofix.js";
export type { AutofixResult } from "./autofix.js";
export {
  SUPABASE_SNAPSHOT_FILENAME,
  SUPABASE_SNAPSHOT_QUERY,
  parseSupabaseSnapshot,
  supabaseConfigFindings,
} from "./supabaseConfigChecks.js";
export type { SupabaseSchemaSnapshot } from "./supabaseConfigChecks.js";