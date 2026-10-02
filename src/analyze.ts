import type { AnalysisResult, Finding, SourceFile } from "./types.js";
import { ALL_CHECKS } from "./checks/index.js";
import { AWS_IAM_SNAPSHOT_FILENAME, awsIamConfigFindings, parseAwsIamSnapshot } from "./cloudConfigChecks.js";
import { MAVEN_DEPENDENCY_LIST_FILENAME } from "./depscan.js";
import { computeScore, summarizeBySeverity } from "./scoring.js";
import { SUPABASE_SNAPSHOT_FILENAME, parseSupabaseSnapshot, supabaseConfigFindings } from "./supabaseConfigChecks.js";
import { SKIP_PATH } from "./util/skipPath.js";

export { SKIP_PATH };
const BINARY_EXT = /\.(png|jpe?g|gif|webp|svg|ico|woff2?|ttf|eot|pdf|zip|lock)$/i;

/** File "snapshot" che non sono codice sorgente da scansionare riga per riga con i controlli a pattern — ognuno ha la sua analisi dedicata. */
const NON_SOURCE_SNAPSHOTS = [SUPABASE_SNAPSHOT_FILENAME, MAVEN_DEPENDENCY_LIST_FILENAME, AWS_IAM_SNAPSHOT_FILENAME];

export function analyzeFiles(files: readonly SourceFile[]): AnalysisResult {
  const relevantFiles = files.filter((f) => !SKIP_PATH.test(f.path) && !BINARY_EXT.test(f.path));

  const findings: Finding[] = [];
  for (const file of relevantFiles) {
    if (NON_SOURCE_SNAPSHOTS.some((name) => file.path.endsWith(name))) continue;

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

  const supabaseSnapshotFile = relevantFiles.find((f) => f.path.endsWith(SUPABASE_SNAPSHOT_FILENAME));
  if (supabaseSnapshotFile) {
    const snapshot = parseSupabaseSnapshot(supabaseSnapshotFile.content);
    if (snapshot) findings.push(...supabaseConfigFindings(snapshot));
  }

  const awsIamSnapshotFile = relevantFiles.find((f) => f.path.endsWith(AWS_IAM_SNAPSHOT_FILENAME));
  if (awsIamSnapshotFile) {
    const snapshot = parseAwsIamSnapshot(awsIamSnapshotFile.content);
    if (snapshot) findings.push(...awsIamConfigFindings(snapshot));
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
export {
  AWS_IAM_SNAPSHOT_FILENAME,
  AWS_IAM_SNAPSHOT_COMMAND,
  parseAwsIamSnapshot,
  awsIamConfigFindings,
} from "./cloudConfigChecks.js";
export type { AwsIamSnapshot } from "./cloudConfigChecks.js";