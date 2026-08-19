import * as vscode from "vscode";

// Il motore (src/analyze.ts) è scritto come modulo ECMAScript, mentre
// un'estensione VS Code carica il proprio file principale come CommonJS —
// per questo lo importiamo dinamicamente invece che con un import statico
// (interoperabilità raccomandata da TypeScript stesso per questo caso).
interface JojoxSourceFile {
  path: string;
  content: string;
}
interface JojoxFinding {
  checkId: string;
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  snippet: string;
  line: number;
}
type AnalyzeFilesFn = (files: JojoxSourceFile[]) => { findings: JojoxFinding[] };

let analyzeFiles: AnalyzeFilesFn | undefined;

const SEVERITY_MAP: Record<string, vscode.DiagnosticSeverity> = {
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Error,
  medium: vscode.DiagnosticSeverity.Warning,
  low: vscode.DiagnosticSeverity.Information,
};

// Oltre questa dimensione non analizziamo: rianalizzare un file enorme a
// ogni tasto premuto rallenterebbe l'editor senza offrire nulla in più per
// i controlli, pensati per codice applicativo, non per dataset o bundle.
const MAX_FILE_CHARS = 300_000;

let diagnostics: vscode.DiagnosticCollection;
const debounceTimers = new Map<string, ReturnType<typeof setTimeout>>();

function analyzeDocument(document: vscode.TextDocument): void {
  if (!analyzeFiles) return;
  if (document.uri.scheme !== "file") return;
  if (document.getText().length > MAX_FILE_CHARS) return;

  const file: JojoxSourceFile = {
    path: vscode.workspace.asRelativePath(document.uri, false),
    content: document.getText(),
  };

  const result = analyzeFiles([file]);

  const items = result.findings.map((finding) => {
    const line = Math.max(0, finding.line - 1);
    const lineLength = line < document.lineCount ? document.lineAt(line).text.length : 0;
    const range = new vscode.Range(line, 0, line, lineLength);
    const diagnostic = new vscode.Diagnostic(
      range,
      `${finding.title} — ${finding.snippet}`,
      SEVERITY_MAP[finding.severity] ?? vscode.DiagnosticSeverity.Warning
    );
    diagnostic.source = "JoJoX";
    diagnostic.code = finding.checkId;
    return diagnostic;
  });

  diagnostics.set(document.uri, items);
}

function scheduleAnalyze(document: vscode.TextDocument): void {
  const key = document.uri.toString();
  const existing = debounceTimers.get(key);
  if (existing) clearTimeout(existing);
  debounceTimers.set(
    key,
    setTimeout(() => {
      debounceTimers.delete(key);
      analyzeDocument(document);
    }, 400)
  );
}

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  const engine = (await import("../../src/analyze.js")) as { analyzeFiles: AnalyzeFilesFn };
  analyzeFiles = engine.analyzeFiles;

  diagnostics = vscode.languages.createDiagnosticCollection("jojox");
  context.subscriptions.push(diagnostics);

  vscode.workspace.textDocuments.forEach(analyzeDocument);

  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(analyzeDocument),
    vscode.workspace.onDidSaveTextDocument(analyzeDocument),
    vscode.workspace.onDidChangeTextDocument((e) => scheduleAnalyze(e.document)),
    vscode.workspace.onDidCloseTextDocument((doc) => diagnostics.delete(doc.uri))
  );
}

export function deactivate(): void {
  debounceTimers.forEach((timer) => clearTimeout(timer));
  debounceTimers.clear();
}