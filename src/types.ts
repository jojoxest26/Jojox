export type Severity = "critical" | "high" | "medium" | "low";
export type Confidence = "confirmed" | "heuristic";

export interface SourceFile {
  /** Repo-relative path, forward slashes. */
  path: string;
  content: string;
}

export interface FixExample {
  before: string;
  after: string;
}

export interface Finding {
  checkId: string;
  severity: Severity;
  confidence: Confidence;
  title: string;
  description: string;
  file: string;
  line: number;
  /** Minimal redacted context around the match — never the full line. */
  snippet: string;
  fix: FixExample;
}

export interface CheckMatch {
  line: number;
  snippet: string;
}

export interface Check {
  id: string;
  severity: Severity;
  confidence: Confidence;
  title: string;
  description: string;
  fix: FixExample;
  detect: (file: SourceFile, allFiles: readonly SourceFile[]) => CheckMatch[];
}

export interface AnalysisResult {
  score: number;
  findings: Finding[];
  summary: Record<Severity, number>;
}
